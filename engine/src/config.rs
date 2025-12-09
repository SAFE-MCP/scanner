use serde::Deserialize;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub allow_remote_providers: bool,
    #[serde(default)]
    pub allowed_providers: Option<Vec<String>>,
    #[serde(default)]
    pub model_names: Option<Vec<String>>,
    #[serde(default)]
    pub openai_api_key: Option<String>,
    #[serde(default)]
    pub openai_base_url: Option<String>,
    #[serde(default)]
    pub anthropic_api_key: Option<String>,
    #[serde(default)]
    pub retry_max_retries: Option<usize>,
    #[serde(default)]
    pub retry_delay_ms: Option<u64>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub include_extensions: Option<Vec<String>>,
    #[serde(default)]
    pub exclude_extensions: Option<Vec<String>>,
    #[serde(default)]
    pub include_globs: Option<Vec<String>>,
    #[serde(default)]
    pub exclude_globs: Option<Vec<String>>,
    #[serde(default)]
    pub max_file_bytes: Option<u64>,
}

/// Load configuration from YAML/JSON file with environment overrides.
/// Env vars:
/// - ALLOW_REMOTE_PROVIDERS=true|false
/// - ALLOWED_PROVIDERS=comma,list
/// - MODEL_NAMES=comma,list
/// - OPENAI_API_KEY
/// - ANTHROPIC_API_KEY
pub fn load_config(path: Option<&Path>) -> Result<Config, String> {
    let mut cfg = if let Some(p) = path {
        let contents = fs::read_to_string(p)
            .map_err(|e| format!("failed to read config {}: {e}", p.display()))?;
        if p.extension().and_then(|s| s.to_str()) == Some("json") {
            serde_json::from_str(&contents)
                .map_err(|e| format!("failed to parse json config {}: {e}", p.display()))?
        } else {
            serde_yaml::from_str(&contents)
                .map_err(|e| format!("failed to parse yaml config {}: {e}", p.display()))?
        }
    } else {
        Config {
            allow_remote_providers: false,
            allowed_providers: None,
            model_names: None,
            openai_api_key: None,
            openai_base_url: None,
            anthropic_api_key: None,
            retry_max_retries: None,
            retry_delay_ms: None,
            timeout_ms: None,
            include_extensions: None,
            exclude_extensions: None,
            include_globs: None,
            exclude_globs: None,
            max_file_bytes: None,
        }
    };

    // Env overrides
    if let Ok(val) = std::env::var("ALLOW_REMOTE_PROVIDERS") {
        cfg.allow_remote_providers = matches!(val.to_lowercase().as_str(), "1" | "true" | "yes");
    }
    if let Ok(val) = std::env::var("ALLOWED_PROVIDERS") {
        let providers: Vec<String> = val
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        if !providers.is_empty() {
            cfg.allowed_providers = Some(providers);
        }
    }
    if let Ok(val) = std::env::var("MODEL_NAMES") {
        let names: Vec<String> = val
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        if !names.is_empty() {
            cfg.model_names = Some(names);
        }
    }
    if let Ok(val) = std::env::var("OPENAI_API_KEY") {
        if !val.is_empty() {
            cfg.openai_api_key = Some(val);
        }
    }
    if let Ok(val) = std::env::var("OPENAI_BASE_URL") {
        if !val.is_empty() {
            cfg.openai_base_url = Some(val);
        }
    }
    if let Ok(val) = std::env::var("ANTHROPIC_API_KEY") {
        if !val.is_empty() {
            cfg.anthropic_api_key = Some(val);
        }
    }
    if let Ok(val) = std::env::var("RETRY_MAX_RETRIES") {
        if let Ok(v) = val.parse::<usize>() {
            cfg.retry_max_retries = Some(v);
        }
    }
    if let Ok(val) = std::env::var("RETRY_DELAY_MS") {
        if let Ok(v) = val.parse::<u64>() {
            cfg.retry_delay_ms = Some(v);
        }
    }
    if let Ok(val) = std::env::var("TIMEOUT_MS") {
        if let Ok(v) = val.parse::<u64>() {
            cfg.timeout_ms = Some(v);
        }
    }
    if let Ok(val) = std::env::var("INCLUDE_EXTENSIONS") {
        let list = split_list(&val);
        if !list.is_empty() {
            cfg.include_extensions = Some(list);
        }
    }
    if let Ok(val) = std::env::var("EXCLUDE_EXTENSIONS") {
        let list = split_list(&val);
        if !list.is_empty() {
            cfg.exclude_extensions = Some(list);
        }
    }
    if let Ok(val) = std::env::var("INCLUDE_GLOBS") {
        let list = split_list(&val);
        if !list.is_empty() {
            cfg.include_globs = Some(list);
        }
    }
    if let Ok(val) = std::env::var("EXCLUDE_GLOBS") {
        let list = split_list(&val);
        if !list.is_empty() {
            cfg.exclude_globs = Some(list);
        }
    }
    if let Ok(val) = std::env::var("MAX_FILE_BYTES") {
        if let Ok(v) = val.parse::<u64>() {
            cfg.max_file_bytes = Some(v);
        }
    }

    Ok(cfg)
}

fn split_list(val: &str) -> Vec<String> {
    val.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Ensure requested provider is allowed given config.
pub fn enforce_provider_allowlist(cfg: &Config, provider: &str) -> Result<(), String> {
    if provider.eq_ignore_ascii_case("local") {
        return Ok(());
    }
    if !cfg.allow_remote_providers {
        return Err(format!(
            "provider {} disallowed: allow_remote_providers=false",
            provider
        ));
    }
    if let Some(list) = &cfg.allowed_providers {
        let set: HashSet<String> = list.iter().map(|s| s.to_lowercase()).collect();
        if !set.contains(&provider.to_lowercase()) {
            return Err(format!("provider {} not in allowed_providers", provider));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::{Mutex, OnceLock};
    use tempfile::tempdir;

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    #[test]
    fn loads_yaml_and_overrides_env() {
        let _guard = env_lock();
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        let yaml = r#"
allow_remote_providers: false
allowed_providers: ["openai"]
model_names: ["gpt-4o"]
"#;
        std::fs::write(&path, yaml).unwrap();

        std::env::set_var("ALLOW_REMOTE_PROVIDERS", "true");
        std::env::set_var("ALLOWED_PROVIDERS", "openai,anthropic");
        std::env::set_var("MODEL_NAMES", "gpt-4o-mini");
        std::env::set_var("OPENAI_API_KEY", "k1");

        let cfg = load_config(Some(&path)).unwrap();
        assert!(cfg.allow_remote_providers);
        assert_eq!(
            cfg.allowed_providers.unwrap(),
            vec!["openai".to_string(), "anthropic".to_string()]
        );
        assert_eq!(cfg.model_names.unwrap(), vec!["gpt-4o-mini".to_string()]);
        assert_eq!(cfg.openai_api_key.as_deref(), Some("k1"));
        assert_eq!(cfg.retry_max_retries, None);
        assert_eq!(cfg.retry_delay_ms, None);
        assert_eq!(cfg.timeout_ms, None);

        std::env::remove_var("ALLOW_REMOTE_PROVIDERS");
        std::env::remove_var("ALLOWED_PROVIDERS");
        std::env::remove_var("MODEL_NAMES");
        std::env::remove_var("OPENAI_API_KEY");
        std::env::remove_var("ANTHROPIC_API_KEY");
    }

    #[test]
    fn enforces_allowlist() {
        let _guard = env_lock();
        let cfg = Config {
            allow_remote_providers: false,
            allowed_providers: Some(vec!["openai".into()]),
            model_names: None,
            openai_api_key: None,
            openai_base_url: None,
            anthropic_api_key: None,
            retry_max_retries: None,
            retry_delay_ms: None,
            timeout_ms: None,
            include_extensions: None,
            exclude_extensions: None,
            include_globs: None,
            exclude_globs: None,
            max_file_bytes: None,
        };
        assert!(enforce_provider_allowlist(&cfg, "local").is_ok());
        assert!(enforce_provider_allowlist(&cfg, "openai").is_err()); // disallowed because remote

        let cfg2 = Config {
            allow_remote_providers: true,
            allowed_providers: Some(vec!["openai".into()]),
            model_names: None,
            openai_api_key: None,
            openai_base_url: None,
            anthropic_api_key: None,
            retry_max_retries: None,
            retry_delay_ms: None,
            timeout_ms: None,
            include_extensions: None,
            exclude_extensions: None,
            include_globs: None,
            exclude_globs: None,
            max_file_bytes: None,
        };
        assert!(enforce_provider_allowlist(&cfg2, "openai").is_ok());
        assert!(enforce_provider_allowlist(&cfg2, "anthropic").is_err());
    }

    #[test]
    fn loads_json_config() {
        let _guard = env_lock();
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.json");
        let json = r#"
{
  "allow_remote_providers": true,
  "allowed_providers": ["local"],
  "model_names": ["local"]
}
"#;
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(json.as_bytes()).unwrap();

        // Clear any env overrides to avoid leakage from other tests.
        std::env::remove_var("ALLOW_REMOTE_PROVIDERS");
        std::env::remove_var("ALLOWED_PROVIDERS");
        std::env::remove_var("MODEL_NAMES");
        let cfg = load_config(Some(&path)).unwrap();
        assert!(cfg.allow_remote_providers);
        assert_eq!(cfg.allowed_providers.unwrap(), vec!["local".to_string()]);
    }
}
