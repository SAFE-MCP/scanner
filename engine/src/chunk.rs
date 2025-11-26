use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeKind {
    FullRepo,
    File {
        file: PathBuf,
    },
    Selection {
        file: PathBuf,
        start_line: usize,
        end_line: usize,
    },
    GitDiff {
        base_ref: String,
    },
}

#[derive(Debug, Clone)]
pub struct CodeChunk {
    pub id: String,
    pub file: PathBuf,
    pub start_line: usize,
    pub end_line: usize,
    pub kind: ChunkKind,
    pub code: String,
    pub rule_hints: Vec<RuleHint>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkKind {
    SlidingWindow,
    WholeFile,
    Selection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleHint {
    pub signal_id: String,
    pub line: usize,
    pub snippet: String,
}

#[derive(Debug, Error)]
pub enum ChunkError {
    #[error("failed to read file {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to diff repository: {0}")]
    Git(String),
    #[error("invalid selection range for file {path}: start {start}, end {end}")]
    InvalidSelection {
        path: PathBuf,
        start: usize,
        end: usize,
    },
    #[error("file excluded by filters: {path}")]
    Excluded { path: PathBuf },
}

/// Walk repository and build chunks according to scope and size heuristics.
pub fn build_chunks(
    repo_path: &Path,
    scope: &ScopeKind,
    max_lines_per_chunk: usize,
    filters: Option<PathFilters>,
) -> Result<Vec<CodeChunk>, ChunkError> {
    let filters = filters.unwrap_or_default();
    match scope {
        ScopeKind::FullRepo => chunk_repo(repo_path, max_lines_per_chunk, &filters),
        ScopeKind::File { file } => chunk_file(repo_path, file, max_lines_per_chunk, &filters),
        ScopeKind::Selection {
            file,
            start_line,
            end_line,
        } => chunk_selection(repo_path, file, *start_line, *end_line),
        ScopeKind::GitDiff { .. } => {
            chunk_git_diff(repo_path, max_lines_per_chunk, &filters, scope)
        }
    }
}

fn chunk_repo(
    repo_path: &Path,
    max_lines_per_chunk: usize,
    filters: &PathFilters,
) -> Result<Vec<CodeChunk>, ChunkError> {
    let mut chunks = Vec::new();
    collect_files(
        repo_path,
        repo_path,
        &mut chunks,
        max_lines_per_chunk,
        filters,
    )?;
    Ok(chunks)
}

fn chunk_git_diff(
    repo_path: &Path,
    max_lines_per_chunk: usize,
    filters: &PathFilters,
    scope: &ScopeKind,
) -> Result<Vec<CodeChunk>, ChunkError> {
    let base = match scope {
        ScopeKind::GitDiff { base_ref } => base_ref,
        _ => unreachable!(),
    };
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(repo_path)
        .arg("diff")
        .arg("--name-only")
        .arg("--diff-filter=AMRC") // skip deletions
        .arg(base)
        .output()
        .map_err(|e| ChunkError::Git(format!("failed to run git diff: {e}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ChunkError::Git(format!(
            "git diff --name-only {base} failed: {stderr}"
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut chunks = Vec::new();
    for line in stdout.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let path = PathBuf::from(line.trim());
        let abs = repo_path.join(&path);
        if !abs.exists() {
            continue;
        }
        if filters.is_allowed(&path, repo_path) {
            chunks.extend(chunk_file(repo_path, &path, max_lines_per_chunk, filters)?);
        }
    }
    Ok(chunks)
}

fn collect_files(
    root: &Path,
    dir: &Path,
    out: &mut Vec<CodeChunk>,
    max_lines_per_chunk: usize,
    filters: &PathFilters,
) -> Result<(), ChunkError> {
    for entry in fs::read_dir(dir).map_err(|source| ChunkError::Io {
        path: dir.to_path_buf(),
        source,
    })? {
        let entry = entry.map_err(|source| ChunkError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') {
            continue;
        }
        if path.is_dir() {
            collect_files(root, &path, out, max_lines_per_chunk, filters)?;
        } else if path.is_file() {
            let rel = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
            if filters.is_allowed(&rel, root) {
                out.extend(chunk_file(root, &rel, max_lines_per_chunk, filters)?);
            }
        }
    }
    Ok(())
}

fn chunk_file(
    repo_path: &Path,
    file: &Path,
    max_lines_per_chunk: usize,
    filters: &PathFilters,
) -> Result<Vec<CodeChunk>, ChunkError> {
    if !filters.is_allowed(file, repo_path) {
        return Err(ChunkError::Excluded {
            path: file.to_path_buf(),
        });
    }
    let abs = repo_path.join(file);
    let content_bytes = std::fs::read(&abs).map_err(|source| ChunkError::Io {
        path: abs.clone(),
        source,
    })?;
    let content = match String::from_utf8(content_bytes) {
        Ok(s) => s,
        Err(_) => {
            // Skip files that are not valid UTF-8 (e.g., binaries like images).
            return Ok(Vec::new());
        }
    };
    let lines: Vec<&str> = content.lines().collect();
    let mut chunks = Vec::new();
    if lines.is_empty() {
        return Ok(chunks);
    }

    if lines.len() <= max_lines_per_chunk {
        chunks.push(CodeChunk {
            id: format!("{}:1-{}", file.display(), lines.len()),
            file: file.to_path_buf(),
            start_line: 1,
            end_line: lines.len(),
            kind: ChunkKind::WholeFile,
            code: content,
            rule_hints: Vec::new(),
        });
        return Ok(chunks);
    }

    let mut start = 0;
    while start < lines.len() {
        let end = usize::min(start + max_lines_per_chunk, lines.len());
        let code = lines[start..end].join("\n");
        chunks.push(CodeChunk {
            id: format!("{}:{}-{}", file.display(), start + 1, end),
            file: file.to_path_buf(),
            start_line: start + 1,
            end_line: end,
            kind: ChunkKind::SlidingWindow,
            code,
            rule_hints: Vec::new(),
        });
        start = end;
    }

    Ok(chunks)
}

fn chunk_selection(
    repo_path: &Path,
    file: &Path,
    start_line: usize,
    end_line: usize,
) -> Result<Vec<CodeChunk>, ChunkError> {
    if start_line == 0 || end_line < start_line {
        return Err(ChunkError::InvalidSelection {
            path: file.to_path_buf(),
            start: start_line,
            end: end_line,
        });
    }
    let abs = repo_path.join(file);
    let content = std::fs::read_to_string(&abs).map_err(|source| ChunkError::Io {
        path: abs.clone(),
        source,
    })?;
    let lines: Vec<&str> = content.lines().collect();
    if end_line > lines.len() {
        return Err(ChunkError::InvalidSelection {
            path: file.to_path_buf(),
            start: start_line,
            end: end_line,
        });
    }
    let code = lines[(start_line - 1)..end_line].join("\n");
    Ok(vec![CodeChunk {
        id: format!("{}:{}-{}", file.display(), start_line, end_line),
        file: file.to_path_buf(),
        start_line,
        end_line,
        kind: ChunkKind::Selection,
        code,
        rule_hints: Vec::new(),
    }])
}

/// File path filters for include/exclude logic.
#[derive(Debug, Clone, Default)]
pub struct PathFilters {
    pub include_extensions: Vec<String>,
    pub exclude_extensions: Vec<String>,
    pub max_file_bytes: Option<u64>,
    pub include_globs: Vec<String>,
    pub exclude_globs: Vec<String>,
    pub exclude_docs: bool,
}

impl PathFilters {
    pub fn is_allowed(&self, path: &Path, root: &Path) -> bool {
        let rel = if path.is_absolute() {
            path.strip_prefix(root).unwrap_or(path)
        } else {
            path
        };
        let rel_str = rel.to_string_lossy();

        if self.exclude_docs {
            if let Some(name) = rel.file_name().and_then(|s| s.to_str()) {
                let lower = name.to_lowercase();
                if lower.starts_with("readme")
                    || lower == "license"
                    || lower.ends_with(".md")
                    || lower.ends_with(".lock")
                    || lower.ends_with(".toml")
                    || lower.ends_with(".txt")
                {
                    return false;
                }
            }
        }

        if !self.include_globs.is_empty()
            && !self.include_globs.iter().any(|g| {
                glob::Pattern::new(g)
                    .map(|p| p.matches(rel_str.as_ref()))
                    .unwrap_or(false)
            })
        {
            return false;
        }
        if self.exclude_globs.iter().any(|g| {
            glob::Pattern::new(g)
                .map(|p| p.matches(rel_str.as_ref()))
                .unwrap_or(false)
        }) {
            return false;
        }

        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .map(|s| s.to_lowercase());
        if let Some(max) = self.max_file_bytes {
            let abs = root.join(path);
            if let Ok(meta) = std::fs::metadata(abs) {
                if meta.len() > max {
                    return false;
                }
            }
        }
        if let Some(ex) = ext.as_ref() {
            if self
                .exclude_extensions
                .iter()
                .any(|x| x.to_lowercase() == *ex)
            {
                return false;
            }
            if !self.include_extensions.is_empty()
                && !self
                    .include_extensions
                    .iter()
                    .any(|x| x.to_lowercase() == *ex)
            {
                return false;
            }
        } else if !self.include_extensions.is_empty() {
            // No extension and includes specified => exclude.
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    fn write_file(root: &Path, rel: &str, contents: &str) {
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let mut f = File::create(path).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
    }

    #[test]
    fn chunks_small_file_as_whole() {
        let dir = tempdir().unwrap();
        write_file(dir.path(), "a.rs", "fn main() {}\n");
        let chunks = build_chunks(
            dir.path(),
            &ScopeKind::File {
                file: "a.rs".into(),
            },
            100,
            None,
        )
        .unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].kind, ChunkKind::WholeFile);
        assert_eq!(chunks[0].start_line, 1);
        assert_eq!(chunks[0].end_line, 1);
    }

    #[test]
    fn chunks_large_file_into_windows() {
        let dir = tempdir().unwrap();
        let content = (0..30)
            .map(|i| format!("line {i}"))
            .collect::<Vec<_>>()
            .join("\n");
        write_file(dir.path(), "b.rs", &content);
        let chunks = build_chunks(
            dir.path(),
            &ScopeKind::File {
                file: "b.rs".into(),
            },
            10,
            None,
        )
        .unwrap();
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].start_line, 1);
        assert_eq!(chunks[0].end_line, 10);
        assert_eq!(chunks[1].start_line, 11);
        assert_eq!(chunks[1].end_line, 20);
        assert_eq!(chunks[2].start_line, 21);
        assert_eq!(chunks[2].end_line, 30);
    }

    #[test]
    fn selection_scope_extracts_exact_range() {
        let dir = tempdir().unwrap();
        let content = indoc! {"
            fn main() {
                println!(\"hi\");
                println!(\"bye\");
            }
        "};
        write_file(dir.path(), "c.rs", content);
        let chunks = build_chunks(
            dir.path(),
            &ScopeKind::Selection {
                file: "c.rs".into(),
                start_line: 2,
                end_line: 3,
            },
            50,
            None,
        )
        .unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].kind, ChunkKind::Selection);
        assert_eq!(chunks[0].start_line, 2);
        assert_eq!(chunks[0].end_line, 3);
        assert!(chunks[0].code.contains("println!(\"hi\");"));
    }

    #[test]
    fn repo_scope_walks_files() {
        let dir = tempdir().unwrap();
        write_file(dir.path(), "src/a.rs", "a");
        write_file(dir.path(), "src/b.rs", "b");
        write_file(dir.path(), ".git/ignore", "ignored");
        let chunks = build_chunks(dir.path(), &ScopeKind::FullRepo, 5, None).unwrap();
        // two files, each small, so two chunks
        let files: Vec<_> = chunks
            .iter()
            .map(|c| c.file.to_string_lossy().to_string())
            .collect();
        assert_eq!(files.len(), 2, "expected two files, got {:?}", files);
        assert!(files.contains(&"src/a.rs".to_string()));
        assert!(files.contains(&"src/b.rs".to_string()));
    }

    #[test]
    fn filters_by_extension_and_size() {
        let dir = tempdir().unwrap();
        write_file(dir.path(), "keep.rs", "a");
        write_file(dir.path(), "skip.txt", "a");
        let filters = PathFilters {
            include_extensions: vec!["rs".into()],
            exclude_extensions: vec!["txt".into()],
            max_file_bytes: Some(1),
            include_globs: vec![],
            exclude_globs: vec![],
            exclude_docs: false,
        };
        let chunks = build_chunks(dir.path(), &ScopeKind::FullRepo, 10, Some(filters)).unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].file.to_string_lossy(), "keep.rs");
    }

    #[test]
    fn git_diff_scope_chunks_changed_files() {
        let dir = tempdir().unwrap();
        write_file(dir.path(), "keep.rs", "fn keep() {}\n");
        write_file(dir.path(), "skip.rs", "fn skip() {}\n");

        std::process::Command::new("git")
            .arg("-C")
            .arg(dir.path())
            .arg("init")
            .output()
            .unwrap();
        std::process::Command::new("git")
            .arg("-C")
            .arg(dir.path())
            .arg("add")
            .arg(".")
            .output()
            .unwrap();
        std::process::Command::new("git")
            .arg("-C")
            .arg(dir.path())
            .arg("commit")
            .arg("-m")
            .arg("init")
            .arg("--allow-empty")
            .output()
            .unwrap();

        write_file(dir.path(), "keep.rs", "fn keep() { println!(\"changed\"); }\n");

        let scope = ScopeKind::GitDiff {
            base_ref: "HEAD".into(),
        };
        let filters = PathFilters {
            include_extensions: vec!["rs".into()],
            ..Default::default()
        };
        let chunks = build_chunks(dir.path(), &scope, 200, Some(filters)).unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].file.to_string_lossy(), "keep.rs");
    }
}
