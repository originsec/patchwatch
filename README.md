# PatchWatch

A local tool for ingesting Windows Patch Tuesday CVEs, diffing patched binaries with [Ghidra](https://ghidra-sre.org/) (via [ghidriff](https://github.com/clearbluejar/ghidriff)), and surfacing LLM-generated security analysis through a browser UI.

PatchWatch wires together a few public data sources and an LLM into a single workflow:

- **[Microsoft Security Update Guide](https://msrc.microsoft.com/update-guide/)** (SUG) — CVE metadata, affected products, CVSS, exploited status.
- **Microsoft Support pages + Update Catalog** — enumerate which files a given KB ships.
- **[Winbindex](https://winbindex.m417z.com/)** — locate pre-patch and post-patch binary versions.
- **[ghidriff](https://github.com/clearbluejar/ghidriff)** (Ghidra under the hood) — produce structured function-level diffs.
- **Anthropic API** — triage, synthesize, and deep-analyze the diff in three LLM stages.

It is designed to run **locally** against your own data store. Nothing is uploaded except prompts sent to the LLM provider you configure.

## Prerequisites

You'll need three things installed:

1. **Rust toolchain** (stable, 2024 edition).
   - Install via [rustup.rs](https://rustup.rs/).
   - On Windows you also need the **MSVC build tools / Windows SDK** so `rustc` can link. The simplest option is to install Visual Studio 2022 Community with the *Desktop development with C++* workload, which pulls in the Windows 11 SDK and `link.exe`. The [`rustup-init` installer](https://rustup.rs/) will prompt you for this on first run if it's missing.

2. **Docker Desktop** with the **WSL 2 backend** enabled.
   - Used to run ghidriff in a container so you don't have to install Ghidra/Java/Python locally.
   - Make sure `docker run hello-world` succeeds from PowerShell before continuing.
   - If you'd rather run ghidriff natively, see the *Local ghidriff* section below.

3. **ghidriff** — a Ghidra-based binary differ.
   - Project page and setup instructions: <https://github.com/clearbluejar/ghidriff>
   - For the Docker workflow, see the *Build the ghidriff image* step in the quickstart.

4. **An Anthropic API key.** PatchWatch is currently hardcoded to the Anthropic Messages API. Set the model in `config.yaml`.

## Quickstart

```powershell
# 1. Clone and enter the project
git clone https://github.com/originsec/patchwatch.git
cd patchwatch

# 2. Build the local ghidriff Docker image.
#    The upstream :latest image ships Ghidra 11.3.1 but pyghidra 3.x requires
#    Ghidra 12.0+. The Dockerfile here pins pyghidra to the last 11.3-compatible
#    release. See https://github.com/clearbluejar/ghidriff/issues/134
docker build -f Dockerfile.ghidriff -t ghidriff-fixed:latest .

# 3. Copy and edit the env file. Set your Anthropic API key and a random CSRF
#    secret (any reasonably long random string).
copy .env.example .env
notepad .env

# 4. (Optional) Copy and edit the config file. Defaults are fine for a first run.
copy crates\patchwatch\config.example.yaml crates\patchwatch\config.yaml

# 5. Build
cargo build --release

# 6. Ingest the most recent Patch Tuesday release. No LLM calls happen here
#    unless a CVE has CVSS >= 9.0 or is marked exploited.
.\target\release\patchwatch.exe --config crates\patchwatch\config.yaml poll --n 1

# 7. Start the local web UI at http://127.0.0.1:8765
.\target\release\patchwatch.exe --config crates\patchwatch\config.yaml web
```

`cargo run` works too if you'd rather not build a release binary up front:

```powershell
cargo run --release -- --config crates\patchwatch\config.yaml poll --n 1
cargo run --release -- --config crates\patchwatch\config.yaml web
```

From the web UI, click any ingested CVE and hit **Analyze** to run the full diff + LLM pipeline. Results render inline as soon as each stage completes.

You can also run the pipeline from the CLI:

```powershell
# Ingest a specific release instead of the most recent
patchwatch poll --release 2025-Apr

# Run the full analysis pipeline on an already-ingested CVE
patchwatch analyze CVE-2025-26633

# Force a specific binary instead of using triage rankings
patchwatch analyze CVE-2025-26633 --binary mscms.dll
```

## Configuration

`crates/patchwatch/config.example.yaml` is the canonical example. The fields most worth knowing about:

```yaml
llm:
  model_primary: "claude-sonnet-4-6"
  model_fallback: "claude-haiku-4-5-20251001"
  api_key_env: "ANTHROPIC_API_KEY"   # env var name that holds the key
  triage_top_n: 5
  max_diff_candidates: 5

diff_engine:
  mode: docker
  image: "ghidriff-fixed:latest"
  volume_root: "~/patchwatch/ghidriff"

storage:
  base_dir: "~/patchwatch"          # SQLite DB, binary cache, reports

web:
  bind_addr: "127.0.0.1:8765"
  csrf_secret_env: "PATCHWATCH_CSRF_SECRET"
  allow_non_loopback: false         # set true only behind a reverse proxy
```

Tildes (`~`) in paths are expanded to `%USERPROFILE%` on Windows.

### Local ghidriff (no Docker)

If you'd rather install ghidriff and Ghidra locally, swap the `diff_engine` block for:

```yaml
diff_engine:
  mode: local
  ghidriff_bin: "ghidriff"                    # or absolute path
  ghidra_install_dir: "C:/path/to/ghidra"     # used as GHIDRA_INSTALL_DIR
  output_dir: "~/patchwatch/ghidriff"
```

Follow the ghidriff [installation instructions](https://github.com/clearbluejar/ghidriff#installation) to get `ghidriff` on `PATH` and a working Ghidra install.

## Data Flow

See [docs/dataflow.md](docs/dataflow.md) for the full Mermaid diagram.

## How It Works

### KB Enumeration

Before any LLM work, PatchWatch enumerates which files the patch touches. Two tiers are tried in order:

**Tier 1 — Support page CSV** (`support.microsoft.com/help/<KB>`)

The KB article page is fetched and scraped for a "file information" download link (anchor text must contain `"file information"`, excluding SSU and hash links). The link is a `go.microsoft.com/fwlink/` redirector that resolves to a CSV on `download.microsoft.com`. The CSV is a multi-section file: each section is preceded by a banner row encoding the architecture (`x64-based`, `arm64-based`, `x86-based`), followed by a header row and data rows. Each data row becomes a `KbFile { filename, version, arch, file_size, date_stamp }`.

**Tier 2 — Update Catalog MSU** (fallback when no CSV link exists)

The Microsoft Update Catalog is searched for the KB number. The x64 result is selected, its `.msu` URL is resolved via `DownloadDialog.aspx`, and the MSU is downloaded and expanded in two passes with `expand.exe` (MSU -> CAB -> extracted files). `.manifest` XML files inside the CAB are parsed for `<assemblyIdentity>` (version + arch) and `<file name>` entries. Only the x64 MSU is fetched, so arm64 entries are absent. Results are deduplicated by `(filename, arch, version)`.

The file list is stored in the DB after first enumeration and reused on subsequent ingests of the same KB.

### LLM Analysis Pipeline

#### Stage 1 — Triage

**Trigger:** Poll ingest, gated on `CVSS base_score >= 9.0 OR exploited == "yes"`. Below that threshold the KB file list is still stored but no LLM call is made. When `analyze` is run directly on a CVE with no existing triage in the DB, triage runs on-demand regardless of score.

**Input:** CVE title, description, CWE + the full list of changed binaries from KB enumeration (filename, architectures, version).

**Output:** `Vec<Ranking>` — every file in the patch ranked by probability of containing the CVE fix, with a confidence score (0–1) and reasoning string. Stored in DB. Used to prioritize which binaries get downloaded and diffed; candidates are sorted descending by confidence and capped at `llm.max_diff_candidates`.

Triage is idempotent: if the CVE's SUG revision number hasn't changed since the last ingest, existing rankings are reused.

#### Interlude — Winbindex + ghidriff

For each top-ranked binary, the orchestrator fetches Winbindex to locate pre-patch and post-patch versions matching the KB, downloads both, and runs **ghidriff**. The resulting JSON is parsed into two representations:

- **`DiffSummary`** — compact, name-only view: lists of added/deleted/modified function names, per-function similarity ratios (`0.0` = completely rewritten, `1.0` = identical), whether changes are code-level vs. address-relocation-only, and added/deleted strings. Passed to Stage 2.
- **`DiffIndex`** — full code view: pre-patch and post-patch decompiled C code for every modified function. Passed to Stage 3.

#### Stage 2 — Synthesis

**Trigger:** User-initiated analyze job, after ghidriff completes.

**Input:** CVE metadata + all diffed binaries, each with its Stage 1 confidence/reasoning and its `DiffSummary` (function names, ratios, change types). No decompiled code.

**Output:** `SynthesisResult`
- `per_binary` — per-binary security relevance assessment with confidence and reasoning
- `primary_binaries` — the subset of binaries that contain security-relevant changes; these proceed to Stage 3
- `ranked_functions` — up to 50 functions most likely to contain the fix (code-changed only, ordered by score), tagged with the binary they belong to
- `overall_summary` — consolidated narrative of what the patch does

#### Stage 3 — Deep Analysis

**Trigger:** Runs for each binary in `primary_binaries` from Stage 2.

**Function selection:** Takes the top-N functions from Stage 2's `ranked_functions` for this binary. Remaining slots are filled with any code-changed functions not already selected, sorted ascending by ratio (most heavily modified first). Functions with only address/refcount changes are excluded from the fallback pool.

**Input:** CVE metadata + before/after decompiled C code for each selected function (from `DiffIndex`).

**Output:** `DeepAnalysisResult`
- `findings` — one `FunctionFinding` per function: relevance score, explanation of what changed and why it relates to the CVE, key changed lines as `old_snippet` / `new_snippet`
- `patch_summary` — consolidated description of what this binary's patch does in the context of the CVE

Results are stored in the DB and rendered in the web UI report view. The orchestrator also writes `report.md` and `report.json` to `<storage_dir>/reports/<cve_id>/`.

### LLM Calls Summary

| Stage | Trigger | Input | Output |
|---|---|---|---|
| **Triage** | Poll ingest (score >= 9 or exploited), or on-demand via analyze | CVE description + all KB file names with arch/version | `Vec<Ranking>`: confidence + reasoning per file |
| **Synthesis** | User-triggered analyze, after ghidriff | CVE + diff summaries (function names, ratios, change types) for all diffed binaries | Primary binaries, ranked functions (top 50, code-changed only), overall summary |
| **Deep analysis** | After synthesis, per primary binary | CVE + full decompiled before/after code for selected functions | Per-function: relevance score, change explanation, old/new snippets; patch summary |

## Architecture Notes

- **Idempotent poll**: KB file enumeration is cached in the DB. CVEs are skipped at triage if the SUG revision number hasn't changed.
- **Serial analysis jobs**: `AnalyzeService` processes one job at a time via a channel. Ghidra analysis is CPU-heavy, so parallelism isn't a win.
- **Binary download cache**: Winbindex downloads are stored on disk by SHA256 hash. Re-running analyze on the same CVE skips downloads.
- **CSRF**: Double-submit cookie (HMAC-SHA256). Set `PATCHWATCH_CSRF_SECRET` before `patchwatch web`.
- **Non-loopback bind**: Blocked by default. Set `web.allow_non_loopback: true` in config to expose on LAN (do this only behind a reverse proxy that adds auth).

## Troubleshooting / Setup Verification

When the full pipeline misbehaves, `patchwatch validate` exposes each external
dependency as a standalone smoke test so you can isolate which stage is broken
without polluting the real DB:

| Subcommand | What it verifies |
|---|---|
| `validate sug` | SUG API is reachable. Lists 2026 releases. |
| `validate kb-csv <KB>` | Tier 1 KB enumeration: support page scrape + CSV download + parser. Example: `patchwatch validate kb-csv KB5036893`. |
| `validate kb-msu <KB> --cache-dir <dir>` | Tier 2 KB enumeration: Update Catalog scrape + MSU download + `expand.exe` extraction + manifest parser. Needs `expand.exe` on `PATH` (it ships with Windows). |
| `validate winbindex <filename> <KB>` | Winbindex query + patched/previous pair selection + binary download to the on-disk cache. Example: `patchwatch validate winbindex mscms.dll KB5036893`. |
| `validate ghidra <binary>` | Runs ghidriff on the binary against itself. Verifies the Docker image (or local install) is wired up correctly and exits 0. |
| `validate dry-run <CVE>` | Full ingest + analyze end-to-end against an **in-memory** SQLite DB. Useful for exercising the complete pipeline without touching `patchwatch.db`. |

All `validate` subcommands honor the same `--config` flag as the top-level CLI.

## Security and Privacy Notes

- PatchWatch sends CVE descriptions, file names, and (in Stage 3) decompiled function bodies to whatever LLM endpoint is configured via `api_key_env`. All decompiled code originates from Microsoft-shipped Windows binaries that are already publicly downloadable, but be aware of where the prompts are going.
- The Anthropic API key and CSRF secret are loaded from environment variables (or a local `.env` file, which is gitignored). Never commit either.
- The web UI binds to loopback by default and uses CSRF double-submit cookies. It has no authentication — don't expose it to a network you don't control.

## Contributing

Issues and PRs welcome. This is a research tool, not a product — expect rough edges and breaking changes between versions.

---

## License

Apache 2.0 — see [LICENSE](./LICENSE) and [NOTICE](./NOTICE)

Built by [Origin](https://originhq.com) for security research and red team operations.
