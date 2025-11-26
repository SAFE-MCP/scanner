use crate::{chunk::CodeChunk, Technique};

#[derive(Debug, Clone)]
pub struct PromptPayload {
    pub technique_id: String,
    pub technique_name: String,
    pub severity: String,
    pub summary: String,
    pub description: String,
    pub mitigations: Vec<MitigationPrompt>,
    pub code_chunk: CodeChunkPrompt,
    pub readme_excerpt: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MitigationPrompt {
    pub id: String,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct CodeChunkPrompt {
    pub id: String,
    pub file: String,
    pub start_line: usize,
    pub end_line: usize,
    pub code: String,
    pub rule_hints: Vec<RuleHintPrompt>,
}

#[derive(Debug, Clone)]
pub struct RuleHintPrompt {
    pub signal_id: String,
    pub line: usize,
    pub snippet: String,
}

pub fn build_prompt_payload(
    technique: &Technique,
    chunk: &CodeChunk,
    readme_excerpt: Option<String>,
) -> PromptPayload {
    PromptPayload {
        technique_id: technique.id.clone(),
        technique_name: technique.name.clone(),
        severity: technique.severity.clone(),
        summary: technique.summary.clone(),
        description: technique.description.clone(),
        mitigations: technique
            .mitigations
            .iter()
            .map(|m| MitigationPrompt {
                id: m.id.clone(),
                description: m.description.clone(),
            })
            .collect(),
        code_chunk: CodeChunkPrompt {
            id: chunk.id.clone(),
            file: chunk.file.to_string_lossy().to_string(),
            start_line: chunk.start_line,
            end_line: chunk.end_line,
            code: chunk.code.clone(),
            rule_hints: chunk
                .rule_hints
                .iter()
                .map(|h| RuleHintPrompt {
                    signal_id: h.signal_id.clone(),
                    line: h.line,
                    snippet: h.snippet.clone(),
                })
                .collect(),
        },
        readme_excerpt,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chunk::{ChunkKind, RuleHint},
        CodeSignal, Heuristic, Mitigation, OutputSchema,
    };

    fn sample_technique() -> Technique {
        Technique {
            id: "T1000".into(),
            name: "Test Technique".into(),
            severity: "P1".into(),
            summary: "Summary".into(),
            description: "Description".into(),
            mitigations: vec![Mitigation {
                id: "M1".into(),
                description: "Mitigation desc".into(),
            }],
            code_signals: vec![CodeSignal {
                id: "S1".into(),
                description: "Signal".into(),
                heuristics: vec![Heuristic {
                    pattern: Some("TOKEN".into()),
                    regex: None,
                    flags: None,
                }],
            }],
            languages: vec!["rust".into()],
            output_schema: OutputSchema {
                requires_mitigations: true,
                allowed_status_values: vec!["pass".into(), "fail".into()],
            },
        }
    }

    fn sample_chunk() -> CodeChunk {
        CodeChunk {
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
        }
    }

    #[test]
    fn builds_payload_with_readme_and_hints() {
        let payload = build_prompt_payload(
            &sample_technique(),
            &sample_chunk(),
            Some("README text".into()),
        );
        assert_eq!(payload.technique_id, "T1000");
        assert_eq!(payload.mitigations.len(), 1);
        assert_eq!(payload.code_chunk.file, "src/main.rs");
        assert_eq!(payload.code_chunk.rule_hints.len(), 1);
        assert_eq!(payload.readme_excerpt.as_deref(), Some("README text"));
    }
}
