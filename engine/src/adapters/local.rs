use crate::codemodel::{CodeModel, CodeModelError, ModelFinding};
use crate::prompt::PromptPayload;
use async_trait::async_trait;

/// Local model adapter that emits findings for rule hints without network calls.
#[derive(Clone, Default)]
pub struct LocalModel {
    pub name: String,
    /// Optional minimum severity to emit for rule-hint findings (info/low/medium/high).
    pub severity: Option<String>,
}

#[async_trait]
impl CodeModel for LocalModel {
    fn name(&self) -> &str {
        if self.name.is_empty() {
            "local"
        } else {
            &self.name
        }
    }

    async fn analyze_chunk(
        &self,
        prompt: &PromptPayload,
    ) -> Result<Vec<ModelFinding>, CodeModelError> {
        if prompt.code_chunk.rule_hints.is_empty() {
            return Ok(Vec::new());
        }
        let sev = self
            .severity
            .as_deref()
            .unwrap_or("info")
            .to_lowercase();
        let findings = prompt
            .code_chunk
            .rule_hints
            .iter()
            .map(|hint| ModelFinding {
                chunk_id: prompt.code_chunk.id.clone(),
                file: prompt.code_chunk.file.clone(),
                start_line: hint.line,
                end_line: hint.line,
                severity: sev.clone(),
                observation: format!("Rule hint matched: {}", hint.signal_id),
                evidence: hint.snippet.clone(),
                unknown_mitigations: Vec::new(),
                model_name: self.name().to_string(),
            })
            .collect();
        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prompt::{CodeChunkPrompt, MitigationPrompt, PromptPayload, RuleHintPrompt};

    fn sample_payload() -> PromptPayload {
        let chunk = CodeChunkPrompt {
            id: "src/lib.rs:1-3".into(),
            file: "src/lib.rs".into(),
            start_line: 1,
            end_line: 3,
            code: "let token = get_token();".into(),
            rule_hints: vec![RuleHintPrompt {
                signal_id: "S1".into(),
                line: 2,
                snippet: "let token = get_token();".into(),
            }],
        };
        PromptPayload {
            technique_id: "T1000".into(),
            technique_name: "Test".into(),
            severity: "P1".into(),
            summary: "".into(),
            description: "".into(),
            mitigations: vec![MitigationPrompt {
                id: "M1".into(),
                description: "".into(),
            }],
            code_chunk: chunk,
            readme_excerpt: None,
        }
    }

    #[tokio::test]
    async fn emits_findings_for_rule_hints() {
        let model = LocalModel::default();
        let payload = sample_payload();
        let findings = model.analyze_chunk(&payload).await.unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].file, "src/lib.rs");
        assert_eq!(findings[0].start_line, 2);
        assert_eq!(findings[0].severity, "info");
        assert_eq!(findings[0].evidence, "let token = get_token();");
    }

    #[tokio::test]
    async fn honors_custom_severity() {
        let model = LocalModel {
            name: String::new(),
            severity: Some("low".into()),
        };
        let payload = sample_payload();
        let findings = model.analyze_chunk(&payload).await.unwrap();
        assert_eq!(findings[0].severity, "low");
    }

    #[tokio::test]
    async fn returns_empty_without_rule_hints() {
        let model = LocalModel::default();
        let mut payload = sample_payload();
        payload.code_chunk.rule_hints.clear();
        let findings = model.analyze_chunk(&payload).await.unwrap();
        assert!(findings.is_empty());
    }
}
