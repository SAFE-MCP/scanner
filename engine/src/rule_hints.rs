use crate::{
    chunk::{CodeChunk, RuleHint},
    Technique,
};
use regex::RegexBuilder;

/// Apply rule hints from a Technique to the provided chunks, mutating them in place.
/// Matches are recorded with signal id and line number within the original file.
pub fn apply_rule_hints(technique: &Technique, chunks: &mut [CodeChunk]) {
    for chunk in chunks.iter_mut() {
        let mut hints = Vec::new();
        for signal in &technique.code_signals {
            for heuristic in &signal.heuristics {
                let pattern = match (&heuristic.pattern, &heuristic.regex) {
                    (Some(p), _) => HeuristicMatcher::Substring(p.to_string()),
                    (_, Some(r)) => match RegexBuilder::new(r)
                        .case_insensitive(
                            heuristic
                                .flags
                                .as_deref()
                                .map(|f| f.contains('i'))
                                .unwrap_or(false),
                        )
                        .build()
                    {
                        Ok(re) => HeuristicMatcher::Regex(re),
                        Err(_) => continue,
                    },
                    _ => continue,
                };
                if let Some(matcher) = pattern.to_option() {
                    for (idx, line) in chunk.code.lines().enumerate() {
                        let line_no = chunk.start_line + idx;
                        if matcher.matches(line) {
                            hints.push(RuleHint {
                                signal_id: signal.id.clone(),
                                line: line_no,
                                snippet: line.to_string(),
                            });
                        }
                    }
                }
            }
        }
        chunk.rule_hints = hints;
    }
}

enum HeuristicMatcher {
    Substring(String),
    Regex(regex::Regex),
}

impl HeuristicMatcher {
    fn matches(&self, line: &str) -> bool {
        match self {
            HeuristicMatcher::Substring(p) => line.contains(p),
            HeuristicMatcher::Regex(r) => r.is_match(line),
        }
    }

    fn to_option(self) -> Option<Self> {
        Some(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk::ChunkKind;
    use crate::{CodeSignal, Heuristic, Mitigation, OutputSchema, Technique};

    fn make_chunk(code: &str, start: usize) -> CodeChunk {
        CodeChunk {
            id: "file:1-".into(),
            file: "file.rs".into(),
            start_line: start,
            end_line: start + code.lines().count() - 1,
            kind: ChunkKind::WholeFile,
            code: code.to_string(),
            rule_hints: Vec::new(),
        }
    }

    fn technique_with_signal(
        pattern: Option<&str>,
        regex: Option<&str>,
        flags: Option<&str>,
    ) -> Technique {
        Technique {
            id: "T1000".into(),
            name: "Test".into(),
            severity: "P1".into(),
            summary: "summary".into(),
            description: "desc".into(),
            mitigations: vec![Mitigation {
                id: "M1".into(),
                description: "mit".into(),
            }],
            code_signals: vec![CodeSignal {
                id: "S1".into(),
                description: "sig".into(),
                heuristics: vec![Heuristic {
                    pattern: pattern.map(|s| s.to_string()),
                    regex: regex.map(|s| s.to_string()),
                    flags: flags.map(|s| s.to_string()),
                }],
            }],
            languages: vec!["rust".into()],
            output_schema: OutputSchema {
                requires_mitigations: true,
                allowed_status_values: vec!["pass".into()],
            },
        }
    }

    #[test]
    fn finds_substring_matches() {
        let mut chunk = make_chunk("let token = env!(\"API_TOKEN\");", 10);
        let technique = technique_with_signal(Some("TOKEN"), None, None);
        apply_rule_hints(&technique, std::slice::from_mut(&mut chunk));
        assert_eq!(chunk.rule_hints.len(), 1);
        assert_eq!(chunk.rule_hints[0].signal_id, "S1");
        assert_eq!(chunk.rule_hints[0].line, 10);
    }

    #[test]
    fn finds_regex_matches_with_flags() {
        let mut chunk = make_chunk("let secret = \"api_key\";", 5);
        let technique = technique_with_signal(None, Some("api_key"), Some("i"));
        apply_rule_hints(&technique, std::slice::from_mut(&mut chunk));
        assert_eq!(chunk.rule_hints.len(), 1);
        assert_eq!(chunk.rule_hints[0].line, 5);
    }
}
