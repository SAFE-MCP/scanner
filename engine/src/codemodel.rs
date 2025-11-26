use crate::prompt::PromptPayload;
use async_trait::async_trait;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct ModelFinding {
    pub chunk_id: String,
    pub file: String,
    pub start_line: usize,
    pub end_line: usize,
    pub severity: String,
    pub observation: String,
    pub evidence: String,
    pub unknown_mitigations: Vec<String>,
    pub model_name: String,
}

#[derive(Debug, Error)]
pub enum CodeModelError {
    #[error("model call failed: {0}")]
    CallFailed(String),
}

#[async_trait]
pub trait CodeModel: Send + Sync {
    fn name(&self) -> &str;
    async fn analyze_chunk(
        &self,
        prompt: &PromptPayload,
    ) -> Result<Vec<ModelFinding>, CodeModelError>;
}
