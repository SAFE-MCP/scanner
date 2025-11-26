use crate::{
    chunk::CodeChunk,
    codemodel::{CodeModel, CodeModelError, ModelFinding},
    prompt::build_prompt_payload,
    rule_hints::apply_rule_hints,
    Technique,
};
use futures::stream::{self, StreamExt};

/// Analyze a set of chunks with a CodeModel, returning aggregated ModelFindings.
/// Rule hints are applied before prompting. The readme_excerpt is included in each prompt.
pub async fn analyze_chunks<M: CodeModel>(
    model: &M,
    technique: &Technique,
    chunks: &mut [CodeChunk],
    readme_excerpt: Option<String>,
) -> Result<Vec<ModelFinding>, CodeModelError> {
    apply_rule_hints(technique, chunks);
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(4));
    let readme_shared = readme_excerpt.clone();
    let results = stream::iter(chunks.iter().cloned())
        .map(|chunk| {
            let permit = semaphore.clone();
            let readme_excerpt = readme_shared.clone();
            async move {
                let _p = permit.acquire_owned().await.unwrap();
                let payload = build_prompt_payload(technique, &chunk, readme_excerpt.clone());
                model.analyze_chunk(&payload).await
            }
        })
        .buffer_unordered(4)
        .collect::<Vec<_>>()
        .await;
    let mut findings = Vec::new();
    for res in results {
        let mut r = res?;
        findings.append(&mut r);
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chunk::{ChunkKind, RuleHint},
        CodeSignal, Heuristic, Mitigation, OutputSchema,
    };
    use async_trait::async_trait;

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
            code: "let token = \"TOKEN\";".into(),
            rule_hints: vec![RuleHint {
                signal_id: "S1".into(),
                line: 1,
                snippet: "let token = \"TOKEN\";".into(),
            }],
        }
    }

    struct StubModel;

    #[async_trait]
    impl CodeModel for StubModel {
        fn name(&self) -> &str {
            "stub"
        }

        async fn analyze_chunk(
            &self,
            prompt: &crate::prompt::PromptPayload,
        ) -> Result<Vec<ModelFinding>, CodeModelError> {
            Ok(vec![ModelFinding {
                chunk_id: prompt.code_chunk.id.clone(),
                file: prompt.code_chunk.file.clone(),
                start_line: prompt.code_chunk.start_line,
                end_line: prompt.code_chunk.end_line,
                severity: "info".into(),
                observation: "ok".into(),
                evidence: prompt.code_chunk.code.clone(),
                unknown_mitigations: vec![],
                model_name: self.name().into(),
            }])
        }
    }

    #[tokio::test]
    async fn runs_model_across_chunks() {
        let tech = sample_technique();
        let mut chunks = vec![sample_chunk()];
        let findings = analyze_chunks(&StubModel, &tech, &mut chunks, Some("readme".into()))
            .await
            .unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].chunk_id, "file:1-2");
        assert_eq!(findings[0].model_name, "stub");
    }
}
