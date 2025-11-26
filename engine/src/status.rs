use crate::aggregation::Finding;

#[derive(Debug, Clone)]
pub enum AnalysisStatus {
    Pass,
    Fail,
    Partial,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct AnalysisResult {
    pub status: AnalysisStatus,
    pub findings: Vec<Finding>,
    pub summary: String,
    pub model_support: Vec<String>,
    pub meta: AnalysisMeta,
}

#[derive(Debug, Clone)]
pub struct AnalysisMeta {
    pub scanned_at_utc: String,
    pub files_scanned: usize,
    pub chunks_analyzed: usize,
}

pub fn compute_status(findings: &[Finding]) -> AnalysisStatus {
    if findings.is_empty() {
        return AnalysisStatus::Pass;
    }
    let mut has_fail = false;
    for f in findings {
        let sev = f.severity.to_lowercase();
        if sev == "high" || sev == "medium" || sev == "low" {
            has_fail = true;
            break;
        }
    }
    if has_fail {
        AnalysisStatus::Fail
    } else {
        AnalysisStatus::Pass
    }
}

pub fn summarize(technique_id: &str, status: &AnalysisStatus, findings: &[Finding]) -> String {
    match status {
        AnalysisStatus::Pass => {
            if findings.is_empty() {
                format!("{}: no issues found.", technique_id)
            } else {
                format!(
                    "{}: informational findings detected ({} items).",
                    technique_id,
                    findings.len()
                )
            }
        }
        AnalysisStatus::Fail => format!(
            "{}: failing findings detected ({} items).",
            technique_id,
            findings.len()
        ),
        AnalysisStatus::Partial => format!(
            "{}: informational findings detected ({} items).",
            technique_id,
            findings.len()
        ),
        AnalysisStatus::Unknown => format!("{}: status unknown.", technique_id),
    }
}

pub fn build_analysis_result(
    technique_id: &str,
    findings: Vec<Finding>,
    files_scanned: usize,
    chunks_analyzed: usize,
) -> Result<AnalysisResult, String> {
    ensure_evidence(&findings)?;
    let status = compute_status(&findings);
    let summary = summarize(technique_id, &status, &findings);
    let mut support = Vec::new();
    for f in &findings {
        for m in &f.model_support {
            if !support.contains(m) {
                support.push(m.clone());
            }
        }
    }
    Ok(AnalysisResult {
        status,
        findings,
        summary,
        model_support: support,
        meta: AnalysisMeta {
            scanned_at_utc: chrono::Utc::now().to_rfc3339(),
            files_scanned,
            chunks_analyzed,
        },
    })
}

fn ensure_evidence(findings: &[Finding]) -> Result<(), String> {
    if let Some(f) = findings.iter().find(|f| f.evidence.trim().is_empty()) {
        return Err(format!(
            "finding missing evidence for {}:{}-{}",
            f.file, f.start_line, f.end_line
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aggregation::Finding;

    fn mk_finding(severity: &str) -> Finding {
        Finding {
            chunk_id: "c1".into(),
            file: "a.rs".into(),
            start_line: 1,
            end_line: 1,
            severity: severity.into(),
            observation: "obs".into(),
            evidence: "ev".into(),
            model_support: vec!["m1".into()],
            unknown_mitigations: vec![],
        }
    }

    #[test]
    fn pass_on_no_findings() {
        assert!(matches!(compute_status(&[]), AnalysisStatus::Pass));
    }

    #[test]
    fn fail_on_high_severity() {
        let status = compute_status(&[mk_finding("high")]);
        assert!(matches!(status, AnalysisStatus::Fail));
    }

    #[test]
    fn partial_on_info_only() {
        let status = compute_status(&[mk_finding("info"), mk_finding("informational")]);
        assert!(matches!(status, AnalysisStatus::Pass));
    }

    #[test]
    fn summary_reflects_status() {
        let findings = vec![mk_finding("info")];
        let result = build_analysis_result("T1000", findings, 1, 1).unwrap();
        assert!(result.summary.contains("T1000"));
    }

    #[test]
    fn errors_on_missing_evidence() {
        let mut f = mk_finding("info");
        f.evidence = "   ".into();
        let result = build_analysis_result("T1000", vec![f], 1, 1);
        assert!(result.is_err());
    }
}
