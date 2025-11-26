use crate::codemodel::{CodeModel, CodeModelError, ModelFinding};
use crate::prompt::PromptPayload;
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;
use thiserror::Error;

#[derive(Clone)]
pub struct AnthropicModel {
    client: reqwest::Client,
    model_name: String,
    api_key: String,
}

#[derive(Debug, Error)]
pub enum AnthropicAdapterError {
    #[error("http error: {0}")]
    Http(String),
    #[error("response missing content")]
    MissingContent,
    #[error("failed to parse model findings: {0}")]
    Parse(String),
}

impl AnthropicModel {
    pub fn new(model_name: String, api_key: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            model_name,
            api_key,
        }
    }
}

#[async_trait]
impl CodeModel for AnthropicModel {
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
            "max_tokens": 256,
            "messages": [
                {"role": "user", "content": [{
                    "type": "text",
                    "text": format!(
                        "Technique: {} (severity {})\nSummary: {}\nMitigations: {}\nFile: {} (ext: {}, lines {}-{})\nCode: {}\nRule hints: {:?}\nREADME: {:?}\nRespond ONLY with JSON: {{\"findings\":[{{\"severity\":\"high|medium|low|info\",\"observation\":\"...\",\"evidence\":\"<path>:<start>-<end> <snippet>\",\"unknown_mitigations\":[\"...\"]}}]}}",
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
                    )
                }]}
            ]
        });

        let resp = self
            .client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .json(&body)
            .send()
            .await
            .map_err(|e| CodeModelError::CallFailed(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(CodeModelError::CallFailed(format!(
                "status {}",
                resp.status()
            )));
        }

        let parsed: AnthropicResponse = resp
            .json()
            .await
            .map_err(|e| CodeModelError::CallFailed(e.to_string()))?;

        let content = parsed
            .content
            .get(0)
            .and_then(|c| c.text.clone())
            .ok_or_else(|| {
                CodeModelError::CallFailed(AnthropicAdapterError::MissingContent.to_string())
            })?;

        let findings = parse_findings(&content, prompt, &self.model_name)
            .map_err(|e| CodeModelError::CallFailed(e.to_string()))?;
        Ok(findings)
    }
}

#[derive(Debug, Deserialize)]
struct AnthropicResponse {
    content: Vec<ContentBlock>,
}

#[derive(Debug, Deserialize)]
struct ContentBlock {
    text: Option<String>,
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
) -> Result<Vec<ModelFinding>, AnthropicAdapterError> {
    let envelope: ModelFindingsEnvelope =
        serde_json::from_str(content).map_err(|e| AnthropicAdapterError::Parse(e.to_string()))?;
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
        assert_eq!(res[0].file, "src/main.rs");
        assert_eq!(res[0].start_line, 1);
        assert_eq!(res[0].end_line, 2);
    }

    #[test]
    fn allows_empty_findings() {
        let payload = sample_payload();
        let json = r#"{"findings":[]}"#;
        let res = parse_findings(json, &payload, "model").unwrap();
        assert!(res.is_empty());
    }

    #[test]
    fn rejects_bad_evidence() {
        let payload = sample_payload();
        let json = r#"{"findings":[{"severity":"high","observation":"issue","evidence":"bad","unknown_mitigations":[]}]} "#;
        let res = parse_findings(json, &payload, "model").unwrap();
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
