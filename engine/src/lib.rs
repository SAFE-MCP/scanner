use jsonschema::JSONSchema;
use serde::Deserialize;
use serde_json::Value as JsonValue;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::io::Read;
use std::path::{Path, PathBuf};
use thiserror::Error;

pub mod aggregation;
pub mod analysis;
pub mod chunk;
pub mod codemodel;
pub mod config;
pub mod entrypoint;
pub mod mitigations;
pub mod prioritized;
pub mod prompt;
pub mod readme;
pub mod rule_hints;
pub mod status;
pub mod adapters {
    pub mod anthropic;
    pub mod local;
    pub mod openai;
    pub mod retry;
}

/// Technique specification loaded from YAML/JSON.
#[derive(Debug, Deserialize)]
pub struct Technique {
    pub id: String,
    pub name: String,
    pub severity: String,
    pub summary: String,
    pub description: String,
    pub mitigations: Vec<Mitigation>,
    pub code_signals: Vec<CodeSignal>,
    pub languages: Vec<String>,
    pub output_schema: OutputSchema,
}

#[derive(Debug, Deserialize)]
pub struct Mitigation {
    pub id: String,
    pub description: String,
}

#[derive(Debug, Deserialize)]
pub struct CodeSignal {
    pub id: String,
    pub description: String,
    pub heuristics: Vec<Heuristic>,
}

#[derive(Debug, Deserialize)]
pub struct Heuristic {
    #[serde(default)]
    pub pattern: Option<String>,
    #[serde(default)]
    pub regex: Option<String>,
    #[serde(default)]
    pub flags: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OutputSchema {
    pub requires_mitigations: bool,
    pub allowed_status_values: Vec<String>,
}

#[derive(Debug)]
pub struct TechniqueLoadOutcome {
    pub techniques: Vec<Technique>,
    pub errors: Vec<TechniqueLoadError>,
}

#[derive(Debug, Error)]
pub enum TechniqueLoadError {
    #[error("failed to read file {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: ParseError,
    },
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Yaml(#[from] serde_yaml::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[derive(Debug)]
pub struct TechniqueValidationOutcome {
    pub techniques: Vec<Technique>,
    pub errors: Vec<FileValidationError>,
}

#[derive(Debug, Clone)]
pub struct TechniqueRef {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct TechniqueMetadata {
    pub id: String,
    pub name: String,
    pub severity: String,
    pub summary: String,
}

#[derive(Debug)]
pub struct TechniqueCache {
    by_id: HashMap<String, Technique>,
    metadata: Vec<TechniqueMetadata>,
}

impl TechniqueCache {
    pub fn new(techniques: Vec<Technique>) -> Self {
        let mut by_id = HashMap::new();
        let mut metadata = Vec::new();
        for t in techniques {
            metadata.push(TechniqueMetadata {
                id: t.id.clone(),
                name: t.name.clone(),
                severity: t.severity.clone(),
                summary: t.summary.clone(),
            });
            by_id.insert(t.id.clone(), t);
        }
        metadata.sort_by(|a, b| a.id.cmp(&b.id));
        TechniqueCache { by_id, metadata }
    }

    pub fn get(&self, id: &str) -> Option<&Technique> {
        self.by_id.get(id)
    }

    pub fn metadata(&self) -> &[TechniqueMetadata] {
        &self.metadata
    }

    /// Group technique metadata by severity. Severities are sorted lexicographically;
    /// metadata within each severity is sorted by technique id.
    pub fn by_severity(&self) -> BTreeMap<String, Vec<TechniqueMetadata>> {
        let mut map: BTreeMap<String, Vec<TechniqueMetadata>> = BTreeMap::new();
        for meta in &self.metadata {
            map.entry(meta.severity.clone())
                .or_default()
                .push(meta.clone());
        }
        map
    }
}

#[derive(Debug)]
pub struct FileValidationError {
    pub path: PathBuf,
    pub messages: Vec<String>,
}

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("failed to read schema {path}: {source}")]
    SchemaIo {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to parse schema {path}: {source}")]
    SchemaParse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("invalid schema {path}: {message}")]
    SchemaInvalid { path: PathBuf, message: String },
}

/// Validate technique files against the JSON schema and deserialize into Technique structs.
/// Returns successfully validated techniques and a list of per-file validation errors.
pub fn validate_techniques<P: AsRef<Path>, Q: AsRef<Path>>(
    dir: P,
    schema_path: Q,
) -> Result<TechniqueValidationOutcome, ValidationError> {
    let schema = load_schema(schema_path.as_ref())?;
    let mut techniques = Vec::new();
    let mut errors = Vec::new();

    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(err) => {
            errors.push(FileValidationError {
                path: dir.as_ref().to_path_buf(),
                messages: vec![format!("failed to read directory: {err}")],
            });
            return Ok(TechniqueValidationOutcome { techniques, errors });
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(err) => {
                errors.push(FileValidationError {
                    path: dir.as_ref().to_path_buf(),
                    messages: vec![format!("failed to read directory entry: {err}")],
                });
                continue;
            }
        };

        let path = entry.path();
        if path.is_dir() {
            continue;
        }
        let ext = path.extension().and_then(OsStr::to_str).unwrap_or_default();
        let is_yaml = matches!(ext, "yaml" | "yml");
        let is_json = ext == "json";
        if !is_yaml && !is_json {
            continue;
        }

        match read_to_value(&path, is_yaml) {
            Ok(value) => {
                if let Err(iter) = schema.validate(&value) {
                    let messages = iter.map(|e| e.to_string()).collect();
                    errors.push(FileValidationError { path, messages });
                    continue;
                }
                match serde_json::from_value(value) {
                    Ok(t) => techniques.push(t),
                    Err(err) => errors.push(FileValidationError {
                        path: path.clone(),
                        messages: vec![format!("failed to deserialize: {err}")],
                    }),
                }
            }
            Err(err) => errors.push(FileValidationError {
                path,
                messages: vec![format!("failed to read/parse file: {err}")],
            }),
        }
    }

    techniques.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(TechniqueValidationOutcome { techniques, errors })
}

fn load_schema(path: &Path) -> Result<JSONSchema, ValidationError> {
    let schema_str = fs::read_to_string(path).map_err(|source| ValidationError::SchemaIo {
        path: path.to_path_buf(),
        source,
    })?;
    let schema_json: JsonValue =
        serde_json::from_str(&schema_str).map_err(|source| ValidationError::SchemaParse {
            path: path.to_path_buf(),
            source,
        })?;
    JSONSchema::compile(&schema_json).map_err(|source| ValidationError::SchemaInvalid {
        path: path.to_path_buf(),
        message: source.to_string(),
    })
}

fn read_to_value(path: &Path, is_yaml: bool) -> Result<JsonValue, ParseError> {
    let mut file = fs::File::open(path)?;
    let mut buf = String::new();
    file.read_to_string(&mut buf)?;
    if is_yaml {
        let yaml: serde_yaml::Value = serde_yaml::from_str(&buf)?;
        Ok(serde_json::to_value(yaml)?)
    } else {
        let json: JsonValue = serde_json::from_str(&buf)?;
        Ok(json)
    }
}

/// Enumerate and parse technique specs from a directory.
/// - Reads YAML/YML/JSON files directly under `dir`.
/// - Skips non-matching files and subdirectories.
/// - Returns successfully parsed techniques and any per-file errors.
pub fn load_techniques<P: AsRef<Path>>(dir: P) -> TechniqueLoadOutcome {
    let mut techniques = Vec::new();
    let mut errors = Vec::new();

    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(err) => {
            errors.push(TechniqueLoadError::Io {
                path: dir.as_ref().to_path_buf(),
                source: err,
            });
            return TechniqueLoadOutcome { techniques, errors };
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(err) => {
                errors.push(TechniqueLoadError::Io {
                    path: dir.as_ref().to_path_buf(),
                    source: err,
                });
                continue;
            }
        };
        let path = entry.path();
        if path.is_dir() {
            continue;
        }

        let ext = path.extension().and_then(OsStr::to_str).unwrap_or_default();
        let is_yaml = matches!(ext, "yaml" | "yml");
        let is_json = ext == "json";
        if !is_yaml && !is_json {
            continue;
        }

        match parse_file(&path, is_yaml) {
            Ok(technique) => techniques.push(technique),
            Err(source) => errors.push(TechniqueLoadError::Parse { path, source }),
        }
    }

    techniques.sort_by(|a, b| a.id.cmp(&b.id));
    TechniqueLoadOutcome { techniques, errors }
}

fn parse_file(path: &Path, is_yaml: bool) -> Result<Technique, ParseError> {
    let mut file = fs::File::open(path)?;
    let mut buf = String::new();
    file.read_to_string(&mut buf)?;
    if is_yaml {
        serde_yaml::from_str(&buf).map_err(ParseError::from)
    } else {
        serde_json::from_str(&buf).map_err(ParseError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::fs::File;
    use std::io::Write;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn write_file(dir: &Path, name: &str, contents: &str) {
        let path = dir.join(name);
        let mut file = File::create(path).expect("create file");
        file.write_all(contents.as_bytes()).expect("write file");
    }

    fn schema_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../schemas/technique.schema.json")
    }

    #[test]
    fn loads_yaml_and_json_and_sorts() {
        let dir = tempdir().unwrap();
        write_file(
            dir.path(),
            "T2000.yaml",
            r#"id: T2000
name: "Test"
severity: P2
summary: "Summary"
description: "Desc"
mitigations:
  - id: M1
    description: "Mit"
code_signals:
  - id: S1
    description: "Sig"
    heuristics:
      - pattern: "foo"
languages: ["rust"]
output_schema:
  requires_mitigations: true
  allowed_status_values: ["pass", "fail", "partial", "unknown"]
"#,
        );
        write_file(
            dir.path(),
            "T1000.json",
            r#"{
  "id": "T1000",
  "name": "Json Test",
  "severity": "P1",
  "summary": "Summary",
  "description": "Desc",
  "mitigations": [{"id": "M1", "description": "Mit"}],
  "code_signals": [{
    "id": "S1",
    "description": "Sig",
    "heuristics": [{"pattern": "bar"}]
  }],
  "languages": ["rust"],
  "output_schema": {
    "requires_mitigations": true,
    "allowed_status_values": ["pass","fail","partial","unknown"]
  }
}"#,
        );

        // Non-matching file should be ignored
        write_file(dir.path(), "README.md", "# ignore me");

        let outcome = load_techniques(dir.path());
        assert!(
            outcome.errors.is_empty(),
            "unexpected errors: {:?}",
            outcome.errors
        );
        let ids: Vec<_> = outcome.techniques.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(ids, vec!["T1000", "T2000"]);
    }

    #[test]
    fn reports_parse_errors_per_file() {
        let dir = tempdir().unwrap();
        write_file(
            dir.path(),
            "T9999.yaml",
            "id: T9999\nname: bad\n", // missing required fields
        );

        let outcome = load_techniques(dir.path());
        assert!(outcome.techniques.is_empty());
        assert_eq!(outcome.errors.len(), 1);
        match &outcome.errors[0] {
            TechniqueLoadError::Parse { path, .. } => {
                assert!(path.ends_with("T9999.yaml"));
            }
            _ => panic!("expected parse error"),
        }
    }

    #[test]
    fn validates_against_schema() {
        let dir = tempdir().unwrap();
        write_file(
            dir.path(),
            "T1000.yaml",
            r#"id: T1000
name: "Valid"
severity: P1
summary: "Summary"
description: "Desc"
mitigations:
  - id: M1
    description: "Mit"
code_signals:
  - id: S1
    description: "Sig"
    heuristics:
      - pattern: "foo"
languages: ["rust"]
output_schema:
  requires_mitigations: true
  allowed_status_values: ["pass", "fail", "partial", "unknown"]
"#,
        );

        write_file(
            dir.path(),
            "T2000.yaml",
            r#"id: T2000
name: "Invalid missing description"
severity: P1
summary: "Summary"
mitigations:
  - id: M1
    description: "Mit"
code_signals:
  - id: S1
    description: "Sig"
    heuristics:
      - pattern: "foo"
languages: ["rust"]
output_schema:
  requires_mitigations: true
  allowed_status_values: ["pass", "fail", "partial", "unknown"]
"#,
        );

        let outcome = validate_techniques(dir.path(), schema_path()).expect("schema load");
        let ids: Vec<_> = outcome.techniques.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(ids, vec!["T1000"]);
        assert_eq!(outcome.errors.len(), 1);
        assert!(outcome.errors[0].path.ends_with("T2000.yaml"));
        assert!(
            outcome.errors[0]
                .messages
                .iter()
                .any(|m| m.contains("description")),
            "expected description error, got {:?}",
            outcome.errors[0].messages
        );
    }

    #[test]
    fn caches_and_lists_metadata() {
        let techniques = vec![
            Technique {
                id: "T2000".into(),
                name: "B".into(),
                severity: "P2".into(),
                summary: "summary-b".into(),
                description: "desc".into(),
                mitigations: vec![],
                code_signals: vec![],
                languages: vec!["rust".into()],
                output_schema: OutputSchema {
                    requires_mitigations: true,
                    allowed_status_values: vec!["pass".into()],
                },
            },
            Technique {
                id: "T1000".into(),
                name: "A".into(),
                severity: "P1".into(),
                summary: "summary-a".into(),
                description: "desc".into(),
                mitigations: vec![],
                code_signals: vec![],
                languages: vec!["rust".into()],
                output_schema: OutputSchema {
                    requires_mitigations: true,
                    allowed_status_values: vec!["pass".into()],
                },
            },
        ];

        let cache = TechniqueCache::new(techniques);
        let ids: Vec<_> = cache.metadata().iter().map(|m| m.id.as_str()).collect();
        assert_eq!(ids, vec!["T1000", "T2000"]);

        let meta_set: HashSet<_> = cache.metadata().iter().map(|m| m.id.as_str()).collect();
        assert!(meta_set.contains("T1000"));
        assert!(meta_set.contains("T2000"));

        let t = cache.get("T1000").expect("id present");
        assert_eq!(t.name, "A");
        assert!(cache.get("missing").is_none());
    }

    #[test]
    fn groups_by_severity() {
        let techniques = vec![
            Technique {
                id: "T2000".into(),
                name: "B".into(),
                severity: "P2".into(),
                summary: "summary-b".into(),
                description: "desc".into(),
                mitigations: vec![],
                code_signals: vec![],
                languages: vec!["rust".into()],
                output_schema: OutputSchema {
                    requires_mitigations: true,
                    allowed_status_values: vec!["pass".into()],
                },
            },
            Technique {
                id: "T1000".into(),
                name: "A".into(),
                severity: "P1".into(),
                summary: "summary-a".into(),
                description: "desc".into(),
                mitigations: vec![],
                code_signals: vec![],
                languages: vec!["rust".into()],
                output_schema: OutputSchema {
                    requires_mitigations: true,
                    allowed_status_values: vec!["pass".into()],
                },
            },
        ];

        let cache = TechniqueCache::new(techniques);
        let by_sev = cache.by_severity();
        let p1 = by_sev.get("P1").expect("P1 exists");
        let p2 = by_sev.get("P2").expect("P2 exists");
        assert_eq!(p1.len(), 1);
        assert_eq!(p1[0].id, "T1000");
        assert_eq!(p2.len(), 1);
        assert_eq!(p2[0].id, "T2000");
        assert!(by_sev.get("P3").is_none());
    }
}
