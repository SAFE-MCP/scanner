use crate::codemodel::ModelFinding;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub chunk_id: String,
    pub file: String,
    pub start_line: usize,
    pub end_line: usize,
    pub severity: String,
    pub observation: String,
    pub evidence: String,
    pub model_support: Vec<String>, // model names that reported this
    pub unknown_mitigations: Vec<String>,
}

/// Aggregate model findings. For now this performs a simple merge by (file, start_line, end_line, observation).
pub fn aggregate_findings(findings: Vec<ModelFinding>) -> Vec<Finding> {
    let mut merged: Vec<Finding> = Vec::new();
    for f in findings {
        if let Some(existing) = merged.iter_mut().find(|m| {
            m.file == f.file
                && m.start_line == f.start_line
                && m.end_line == f.end_line
                && m.observation == f.observation
        }) {
            if !existing.model_support.contains(&f.model_name) {
                existing.model_support.push(f.model_name);
            }
            for um in f.unknown_mitigations {
                if !existing.unknown_mitigations.contains(&um) {
                    existing.unknown_mitigations.push(um);
                }
            }
            if severity_rank(&f.severity) > severity_rank(&existing.severity) {
                existing.severity = f.severity;
            }
        } else {
            merged.push(Finding {
                chunk_id: f.chunk_id,
                file: f.file,
                start_line: f.start_line,
                end_line: f.end_line,
                severity: f.severity,
                observation: f.observation,
                evidence: f.evidence,
                model_support: vec![f.model_name],
                unknown_mitigations: f.unknown_mitigations,
            });
        }
    }
    merged.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.start_line.cmp(&b.start_line))
            .then(a.end_line.cmp(&b.end_line))
    });
    merged
}

fn severity_rank(sev: &str) -> u8 {
    match sev.to_lowercase().as_str() {
        "p0" | "critical" | "high" => 3,
        "p1" | "medium" => 2,
        "p2" | "low" => 1,
        "info" | "informational" => 0,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codemodel::ModelFinding;

    #[test]
    fn merges_overlapping_same_observation() {
        let f1 = ModelFinding {
            chunk_id: "c1".into(),
            file: "a.rs".into(),
            start_line: 1,
            end_line: 2,
            severity: "high".into(),
            observation: "obs".into(),
            evidence: "e1".into(),
            unknown_mitigations: vec!["UM1".into()],
            model_name: "m1".into(),
        };
        let f2 = ModelFinding {
            chunk_id: "c1".into(),
            file: "a.rs".into(),
            start_line: 1,
            end_line: 2,
            severity: "high".into(),
            observation: "obs".into(),
            evidence: "e1".into(),
            unknown_mitigations: vec!["UM2".into()],
            model_name: "m2".into(),
        };

        let merged = aggregate_findings(vec![f1, f2]);
        assert_eq!(merged.len(), 1);
        assert!(merged[0].model_support.contains(&"m1".into()));
        assert!(merged[0].model_support.contains(&"m2".into()));
        assert!(merged[0].unknown_mitigations.contains(&"UM1".into()));
        assert!(merged[0].unknown_mitigations.contains(&"UM2".into()));
    }

    #[test]
    fn takes_max_severity() {
        let f1 = ModelFinding {
            chunk_id: "c1".into(),
            file: "a.rs".into(),
            start_line: 1,
            end_line: 2,
            severity: "info".into(),
            observation: "obs".into(),
            evidence: "e1".into(),
            unknown_mitigations: vec![],
            model_name: "m1".into(),
        };
        let f2 = ModelFinding {
            chunk_id: "c1".into(),
            file: "a.rs".into(),
            start_line: 1,
            end_line: 2,
            severity: "high".into(),
            observation: "obs".into(),
            evidence: "e1".into(),
            unknown_mitigations: vec![],
            model_name: "m2".into(),
        };
        let merged = aggregate_findings(vec![f1, f2]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].severity.to_lowercase(), "high");
    }
}
