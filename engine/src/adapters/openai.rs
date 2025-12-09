use crate::codemodel::{CodeModel, CodeModelError, ModelFinding};
use crate::prompt::PromptPayload;
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;
use thiserror::Error;

#[derive(Clone)]
pub struct OpenAIModel {
    client: reqwest::Client,
    model_name: String,
    api_key: String,
    base_url: String,
}

#[derive(Debug, Error)]
pub enum OpenAIAdapterError {
    #[error("http error: {0}")]
    Http(String),
    #[error("response missing content")]
    MissingContent,
    #[error("failed to parse model findings: {0}")]
    Parse(String),
}

impl OpenAIModel {
    pub fn new(model_name: String, api_key: String, base_url: Option<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            model_name,
            api_key,
            base_url: base_url.unwrap_or_else(|| "https://api.openai.com/v1".to_string()),
        }
    }
}

#[async_trait]
impl CodeModel for OpenAIModel {
    fn name(&self) -> &str {
        &self.model_name
    }

    async fn analyze_chunk(
        &self,
        prompt: &PromptPayload,
    ) -> Result<Vec<ModelFinding>, CodeModelError> {
        let file = &prompt.code_chunk.file;
        let ext = std::path::Path::new(file)
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        let body = json!({
            "model": self.model_name,
            "temperature": 0.0,
            "response_format": { "type": "json_object" },
            "messages": [
                {"role": "system", "content": "You are a security code analyzer. Use the provided file path and extension to interpret the content (e.g., README/LICENSE/config vs. source code). Do not assume code exists when the file is documentation or a license. Respond ONLY with JSON: {\"findings\":[{\"severity\":\"high|medium|low|info\",\"observation\":\"...\",\"evidence\":\"<path>:<start>-<end> <snippet>\",\"unknown_mitigations\":[\"...\"]}]}"} ,
                {"role": "user", "content": format!(
                    "Technique: {} (severity {})\nSummary: {}\nMitigations: {}\nFile: {} (ext: {}, lines {}-{})\nCode: {}\nRule hints: {:?}\nREADME: {:?}",
                    prompt.technique_id,
                    prompt.severity,
                    prompt.summary,
                    prompt.mitigations.iter().map(|m| &m.id).cloned().collect::<Vec<_>>().join(","),
                    file,
                    if ext.is_empty() { "none" } else { ext },
                    prompt.code_chunk.start_line,
                    prompt.code_chunk.end_line,
                    prompt.code_chunk.code,
                    prompt.code_chunk.rule_hints.iter().map(|h| &h.snippet).cloned().collect::<Vec<_>>(),
                    prompt.readme_excerpt.as_deref().unwrap_or("")
                )}
            ]
        });

        let url = format!("{}/chat/completions", self.base_url.trim_end_matches('/'));
        let resp = self
            .client
            .post(&url)
            .bearer_auth(&self.api_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| CodeModelError::CallFailed(e.to_string()))?;
        eprintln!(
            "[openai] request: model={} chunk_id={} file={} start={} end={}",
            self.model_name,
            prompt.code_chunk.id,
            prompt.code_chunk.file,
            prompt.code_chunk.start_line,
            prompt.code_chunk.end_line
        );

        if !resp.status().is_success() {
            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();
            return Err(CodeModelError::CallFailed(format!(
                "status {} body {} request {{model: {}, temperature: 0.0, response_format: json_object, messages: system+user}}",
                status,
                body_text,
                self.model_name
            )));
        }

        let parsed: ChatCompletionResponse = resp
            .json()
            .await
            .map_err(|e| CodeModelError::CallFailed(e.to_string()))?;
        let content = parsed
            .choices
            .get(0)
            .and_then(|c| c.message.content.clone())
            .ok_or_else(|| {
                CodeModelError::CallFailed(OpenAIAdapterError::MissingContent.to_string())
            })?;

        let findings = parse_findings(&content, prompt, &self.model_name)
            .map_err(|e| CodeModelError::CallFailed(e.to_string()))?;
        eprintln!(
            "[openai] response: model={} status=ok findings={}",
            self.model_name,
            findings.len()
        );
        Ok(findings)
    }
}

#[derive(Debug, Deserialize)]
struct ChatCompletionResponse {
    choices: Vec<Choice>,
}

#[derive(Debug, Deserialize)]
struct Choice {
    message: Message,
}

#[derive(Debug, Deserialize)]
struct Message {
    content: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ModelFindingsEnvelope {
    findings: Vec<ModelFindingPayload>,
}

#[derive(Debug, Deserialize)]
struct ModelFindingPayload {
    severity: String,
    observation: String,
    evidence: String,
    #[serde(default)]
    unknown_mitigations: Vec<String>,
}

fn parse_findings(
    content: &str,
    prompt: &PromptPayload,
    model_name: &str,
) -> Result<Vec<ModelFinding>, OpenAIAdapterError> {
    // Attempt to extract JSON if the model included extra text
    let json_str = if let (Some(start), Some(end)) = (content.find('{'), content.rfind('}')) {
        &content[start..=end]
    } else {
        content
    };

    let envelope: ModelFindingsEnvelope =
        serde_json::from_str(json_str).map_err(|e| OpenAIAdapterError::Parse(e.to_string()))?;
    let mut out = Vec::new();
    for f in envelope.findings {
        let parsed_evidence = parse_evidence(&f.evidence);
        let (path, start, end) = parsed_evidence
            .as_ref()
            .map(|p| (p.path.clone(), p.start, p.end))
            .unwrap_or_else(|| {
                (
                    prompt.code_chunk.file.clone(),
                    prompt.code_chunk.start_line,
                    prompt.code_chunk.end_line,
                )
            });
        let evidence_text = parsed_evidence
            .and_then(|p| {
                if p.snippet.trim().is_empty() {
                    None
                } else {
                    Some(p.snippet)
                }
            })
            .unwrap_or_else(|| f.evidence.clone());
        let evidence_text = if evidence_text.trim().is_empty() {
            default_evidence(
                &prompt.code_chunk.file,
                prompt.code_chunk.start_line,
                prompt.code_chunk.end_line,
                &prompt.code_chunk.code,
            )
        } else {
            evidence_text
        };

        // If evidence points to a non-code path, fall back to the chunk path/lines.
        let (path, start, end) = if is_code_file(&path) {
            (path, start, end)
        } else {
            (
                prompt.code_chunk.file.clone(),
                prompt.code_chunk.start_line,
                prompt.code_chunk.end_line,
            )
        };

        out.push(ModelFinding {
            chunk_id: prompt.code_chunk.id.clone(),
            file: path,
            start_line: start,
            end_line: end,
            severity: f.severity,
            observation: f.observation,
            evidence: evidence_text,
            unknown_mitigations: f.unknown_mitigations,
            model_name: model_name.to_string(),
        });
    }
    Ok(out)
}

#[derive(Debug)]
struct ParsedEvidence {
    path: String,
    start: usize,
    end: usize,
    snippet: String,
}

fn parse_evidence(raw: &str) -> Option<ParsedEvidence> {
    // Expected shape: "<path>:<start>-<end><ws><snippet>"
    let trimmed = raw.trim();
    let mut iter = trimmed.splitn(2, |c: char| c.is_whitespace());
    let loc = iter.next()?;
    let snippet = iter.next().unwrap_or("").to_string();
    let (path, range) = loc.split_once(':')?;
    let (start, end) = range.split_once('-')?;
    let start_num = start.parse().ok()?;
    let end_num = end.parse().ok()?;
    Some(ParsedEvidence {
        path: path.to_string(),
        start: start_num,
        end: end_num,
        snippet,
    })
}

fn is_code_file(path: &str) -> bool {
    let p = std::path::Path::new(path);
    let file_name = p
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_lowercase();
    if file_name.starts_with("readme") || file_name == "license" {
        return false;
    }
    let ext = p.extension().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
    matches!(
        ext.as_str(),
        "rs" | "py" | "ts" | "tsx" | "js" | "jsx" | "go" | "rb" | "php" | "java" | "kt"
            | "c" | "cpp" | "cc" | "cs" | "swift" | "m" | "mm" | "scala" | "lua" | "sh"
            | "ps1" | "bash" | "zsh"
    )
}

fn default_evidence(file: &str, start: usize, end: usize, code: &str) -> String {
    let snippet = code.lines().take(3).collect::<Vec<_>>().join("\\n");
    format!("{file}:{start}-{end} {snippet}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk::{ChunkKind, RuleHint};
    use crate::{CodeSignal, Heuristic, Mitigation, OutputSchema, Technique};

    fn sample_payload() -> PromptPayload {
        let tech = Technique {
            id: "T1001".into(),
            name: "Tech".into(),
            severity: "P1".into(),
            summary: "Summary".into(),
            description: "Desc".into(),
            mitigations: vec![Mitigation {
                id: "M1".into(),
                description: "Mit".into(),
            }],
            code_signals: vec![CodeSignal {
                id: "S1".into(),
                description: "Sig".into(),
                heuristics: vec![Heuristic {
                    pattern: Some("foo".into()),
                    regex: None,
                    flags: None,
                }],
            }],
            languages: vec!["rust".into()],
            output_schema: OutputSchema {
                requires_mitigations: false,
                allowed_status_values: vec!["pass".into(), "fail".into()],
            },
        };
        let chunk = crate::chunk::CodeChunk {
            id: "file:1-2".into(),
            file: "src/main.rs".into(),
            start_line: 1,
            end_line: 2,
            kind: ChunkKind::WholeFile,
            code: "fn main() {}".into(),
            rule_hints: vec![RuleHint {
                signal_id: "S1".into(),
                line: 1,
                snippet: "fn main() {}".into(),
            }],
        };
        crate::prompt::build_prompt_payload(&tech, &chunk, Some("README".into()))
    }

    #[test]
    fn parses_findings_payload() {
        let payload = sample_payload();
        let json = r#"{"findings":[{"severity":"high","observation":"issue","evidence":"src/main.rs:1-2 snippet","unknown_mitigations":["M1"]}]}"#;
        let res = parse_findings(json, &payload, "model").unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].severity, "high");
        assert_eq!(res[0].model_name, "model");
        assert_eq!(res[0].start_line, 1);
        assert_eq!(res[0].end_line, 2);
        assert_eq!(res[0].file, "src/main.rs");
    }

    #[test]
    fn fails_on_empty_findings() {
        let payload = sample_payload();
        let json = r#"{"findings":[]}"#;
        let res = parse_findings(json, &payload, "model").unwrap();
        assert!(res.is_empty());
    }

    #[test]
    fn rejects_bad_evidence() {
        let payload = sample_payload();
        let json = r#"{"findings":[{"severity":"high","observation":"issue","evidence":"bad-format","unknown_mitigations":[]}]} "#;
        let res = parse_findings(json, &payload, "model").unwrap();
        // Falls back to chunk metadata when evidence is malformed.
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].file, payload.code_chunk.file);
    }

    #[test]
    fn fills_missing_evidence() {
        let payload = sample_payload();
        let json = r#"{"findings":[{"severity":"info","observation":"issue","evidence":"","unknown_mitigations":[]}]} "#;
        let res = parse_findings(json, &payload, "model").unwrap();
        assert_eq!(res.len(), 1);
        assert!(res[0].evidence.contains("src/main.rs:1-2"));
    }
}
