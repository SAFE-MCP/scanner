use crate::codemodel::{CodeModel, CodeModelError, ModelFinding};
use crate::prompt::PromptPayload;
use async_trait::async_trait;
use std::time::Duration;
use tokio::time::{sleep, timeout};

#[derive(Clone)]
pub struct RetryModel<M: CodeModel + Clone> {
    inner: M,
    max_retries: usize,
    delay: Duration,
    timeout: Option<Duration>,
}

impl<M: CodeModel + Clone> RetryModel<M> {
    pub fn new(inner: M, max_retries: usize, delay: Duration, timeout: Option<Duration>) -> Self {
        Self {
            inner,
            max_retries,
            delay,
            timeout,
        }
    }
}

#[async_trait]
impl<M: CodeModel + Clone> CodeModel for RetryModel<M> {
    fn name(&self) -> &str {
        self.inner.name()
    }

    async fn analyze_chunk(
        &self,
        prompt: &PromptPayload,
    ) -> Result<Vec<ModelFinding>, CodeModelError> {
        let mut attempt = 0;
        loop {
            attempt += 1;
            let res = if let Some(to) = self.timeout {
                match timeout(to, self.inner.analyze_chunk(prompt)).await {
                    Ok(inner) => inner,
                    Err(_) => Err(CodeModelError::CallFailed(format!(
                        "timeout after {}ms",
                        to.as_millis()
                    ))),
                }
            } else {
                self.inner.analyze_chunk(prompt).await
            };

            match res {
                Ok(res) => return Ok(res),
                Err(err) => {
                    if attempt > self.max_retries {
                        return Err(err);
                    }
                    sleep(self.delay).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codemodel::{CodeModel, CodeModelError, ModelFinding};
    use crate::prompt::PromptPayload;
    use crate::{
        chunk::{ChunkKind, CodeChunk, RuleHint},
        CodeSignal, Heuristic, Mitigation, OutputSchema, Technique,
    };
    use async_trait::async_trait;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct Flaky {
        calls: Arc<Mutex<usize>>,
        fail_until: usize,
    }

    #[async_trait]
    impl CodeModel for Flaky {
        fn name(&self) -> &str {
            "flaky"
        }

        async fn analyze_chunk(
            &self,
            _prompt: &PromptPayload,
        ) -> Result<Vec<ModelFinding>, CodeModelError> {
            let mut guard = self.calls.lock().unwrap();
            *guard += 1;
            if *guard <= self.fail_until {
                return Err(CodeModelError::CallFailed("fail".into()));
            }
            Ok(vec![])
        }
    }

    #[tokio::test]
    async fn retries_and_succeeds() {
        let model = Flaky {
            calls: Arc::new(Mutex::new(0)),
            fail_until: 1,
        };
        let retry = RetryModel::new(model.clone(), 2, Duration::from_millis(1), None);
        let prompt = sample_payload();
        let res = retry.analyze_chunk(&prompt).await.unwrap();
        assert!(res.is_empty());
        assert_eq!(*model.calls.lock().unwrap(), 2);
    }

    #[tokio::test]
    async fn times_out_and_retries() {
        #[derive(Clone)]
        struct Slow;
        #[async_trait]
        impl CodeModel for Slow {
            fn name(&self) -> &str {
                "slow"
            }
            async fn analyze_chunk(
                &self,
                _prompt: &PromptPayload,
            ) -> Result<Vec<ModelFinding>, CodeModelError> {
                sleep(Duration::from_millis(20)).await;
                Ok(vec![])
            }
        }

        let retry = RetryModel::new(
            Slow,
            1,
            Duration::from_millis(1),
            Some(Duration::from_millis(5)),
        );
        let prompt = sample_payload();
        let err = retry.analyze_chunk(&prompt).await.unwrap_err();
        assert!(format!("{err}").contains("timeout"));
    }

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
        let chunk = CodeChunk {
            id: "c".into(),
            file: "f".into(),
            start_line: 1,
            end_line: 1,
            kind: ChunkKind::WholeFile,
            code: "".into(),
            rule_hints: vec![RuleHint {
                signal_id: "S1".into(),
                line: 1,
                snippet: "".into(),
            }],
        };
        crate::prompt::build_prompt_payload(&tech, &chunk, None)
    }
}
