# SAFE-MCP Scanner

Rust workspace that scans repositories for SAFE-MCP techniques. It ships a CLI (`safe-mcp-scan`) and an MCP server (`safe-mcp-analyzer`) that call the shared engine.

## Quick Start
- Prereqs: Rust stable, provider key in config or env (OpenAI/Anthropic), and `schemas/technique.schema.json` path if running outside the repo root.
- CLI example:  
  ```bash
  cargo run -p cli -- --provider openai --model-name gpt-4o-mini \
    T1001 --repo /path/to/repo \
    --schema $(pwd)/schemas/technique.schema.json \
    --json [--llm-review]
  ```
- MCP server: `cargo run -p server --bin safe-mcp-analyzer` (configure providers/filters in YAML/JSON).
- Batch scans: `./run_scans.sh` runs all specs under `techniques/`, continues on failures, writes `scan_outputs/*.json`.

## Data & Inputs
- Specs: active techniques in `techniques/` (top set), additional specs in `techniques_backup/`.
- SAFE-MCP corpus (gitignored): `safe-mcp/README.md`, `safe-mcp/techniques/<ID>/README.md`, `safe-mcp/techniques/prioritized-techniques.md`, mitigations under `safe-mcp/mitigations/`.
- Schema: `schemas/technique.schema.json` (pass `--schema` when running outside repo root).

## Behavior Highlights
- Prompts include file path/extension/line range, README excerpt, rule hints; temperature pinned to 0.
- Path filters: include/exclude globs/exts and `max_file_bytes` (0 disables); docs/manifests allowed by default.
- Optional `--llm-review` post-filters findings; non-fatal on failure; reuses configured OpenAI model/key.
- Evidence is mandatory (file, lines, snippet) for every finding; info-only findings do not fail the scan.

## Contributing
- See `AGENTS.md` for contributor workflow, commands to run, and coding/testing conventions.
- License: Apache 2.0 (see `LICENSE`). Don't commit changes to `safe-mcp/` corpus.
