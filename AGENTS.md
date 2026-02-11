# Agent Notes (robots_txt_tester)

This repository is a single Bash CLI script: `robots_sitemap_check.sh`.
It fetches a `robots.txt`, discovers `Sitemap:` entries, samples URLs from those sitemap(s), and checks whether the sampled URLs are allowed for a given user-agent.

## Quickstart

- Help: `./robots_sitemap_check.sh --help`
- Run against a site: `./robots_sitemap_check.sh https://example.com/robots.txt`
- Change robots matching UA (rules selection): `./robots_sitemap_check.sh -a 'MyBot' https://example.com/robots.txt`
- Increase sample size: `./robots_sitemap_check.sh -n 50 https://example.com/robots.txt`
- Debug logs: `./robots_sitemap_check.sh --debug https://example.com/robots.txt`

## Dependencies / Runtime Assumptions

- Bash: uses associative arrays (`declare -A`) and strict mode; requires Bash 4+.
  - macOS default `/bin/bash` is often 3.2; use Homebrew bash (`brew install bash`) and run with that.
- External commands (checked at runtime): `curl`, `awk`, `grep`, `wc`, `sed`, `tr`, plus `shuf` for sampling.
- Optional: `gzip` if a sitemap URL ends with `.gz`.

## Build / Lint / Test

There is no build step (plain Bash script).

### Lint

- Syntax check: `bash -n robots_sitemap_check.sh`
- ShellCheck (recommended): `shellcheck robots_sitemap_check.sh`
  - Only add `# shellcheck disable=...` when you cannot refactor; keep the disable as narrow as possible and near the offending line.

### Format

- shfmt (recommended):
  - `shfmt -i 2 -bn -ci -sr -w robots_sitemap_check.sh`

### Tests

There is currently no automated test suite in the repo.

- Manual smoke test (fast, real network):
  - `./robots_sitemap_check.sh --debug -n 5 https://www.example.com/robots.txt`

If you add tests, prefer one of these:

- `bats-core` (recommended for Bash):
  - Run all tests: `bats tests`
  - Run a single test file: `bats tests/robots_sitemap_check.bats`
  - Run a single test by name/regex: `bats -f 'extract_sitemaps_from_robots' tests/robots_sitemap_check.bats`
- `shellspec` (alternative):
  - Run all tests: `shellspec`
  - Run a single spec file: `shellspec spec/robots_sitemap_check_spec.sh`
  - Run a single example (regex): `shellspec --example 'robots_check_allowed'`

When writing tests, avoid flaky network calls:

- Stub `curl` (put a stub earlier in `PATH`) or refactor to allow injecting fixtures.
- Use temporary directories via `mktemp -d` and ensure cleanup.

## Cursor / Copilot Rules

- No Cursor rules found (`.cursor/rules/` or `.cursorrules` do not exist in this repo).
- No Copilot instructions found (`.github/copilot-instructions.md` does not exist in this repo).

## Code Style Guidelines (Bash)

### General

- Keep strict mode at the top:
  - `set -Eeuo pipefail`
  - `IFS=$'\n\t'`
- Prefer small, pure functions that communicate via stdout/exit codes.
- Use `local` for function variables; avoid accidental globals.
- Keep logs on stderr; avoid writing non-essential output to stdout.

### Naming

- Constants / configuration: `UPPER_SNAKE_CASE` (e.g. `TIMEOUT_SECS`).
- Functions: `lower_snake_case` verbs (e.g. `curl_fetch_to_file`, `extract_urls_from_sitemap_file`).
- Locals: `lower_snake_case` (e.g. `robots_origin_val`).
- Avoid single-letter variable names except for tight loops and conventional cases.

### Imports / Sourcing

- Do not introduce implicit `source` dependencies.
- If the script grows into multiple files, prefer `lib/*.sh` with explicit `source` and a single entrypoint, but keep it optional and well-documented.

### Quoting / Word Splitting

- Always quote parameter expansions unless you explicitly want splitting/globbing.
  - Prefer `"${var}"` over `$var`.
- Use `[[ ... ]]` for tests; avoid `[` where possible.
- Use arrays when representing lists; avoid `for x in $(cmd)` patterns.

### Conditionals / Loops

- Prefer arithmetic contexts for integers: `(( ... ))`.
- Prefer `case` for option parsing and discrete branching.
- Prefer `while IFS= read -r line; do ...; done` to preserve backslashes and whitespace.
- If using process substitution (`done < <(cmd)`), ensure the body does not rely on pipeline subshell semantics.

### Error Handling

- Centralize fatal errors via `die "message" [exit_code]`.
- Validate inputs early (URL shape, numeric flags, invariants).
- Use `need_cmd` before relying on external tools.
- Use `trap cleanup EXIT` for temp dir removal; keep cleanup idempotent.

### Logging

- Use `log LEVEL message...` and honor `LOG_LEVEL`.
- Do not log secrets (none are currently used); treat URLs as potentially sensitive.
- Keep log messages stable; they are useful for debugging and may be parsed externally.

### Networking (curl)

- Keep curl calls:
  - `-f` fail on HTTP errors, `-sS` quiet but show errors, `-L` follow redirects.
  - timeouts: `--max-time` and `--connect-timeout`.
  - set UA: `-A "$FETCH_UA"`.
- Avoid adding retries by default; if added, ensure bounded retries and good logging.

### Text Processing

- Prefer `awk` for line-oriented parsing and lightweight extraction.
- When parsing robots.txt:
  - Strip `\r` and comments; trim whitespace.
  - Keep behavior close to common robots parsing expectations.
- When extracting sitemap URLs:
  - Current XML parsing is heuristic; keep changes conservative and covered by tests.

### Types / Data Model

- Treat these as the core “types” in the script:
  - URLs: absolute `http(s)://...` strings.
  - Origin: `scheme://host` (no path).
  - path+query: the third field from `url_parse`.
  - Rules: TSV `type<TAB>pattern<TAB>length`.
- Maintain invariants:
  - `ROBOTS_URL` must be absolute http(s).
  - Collected sitemap URLs and sampled URLs must resolve to the same host as `ROBOTS_URL`.

### Performance

- Keep memory bounded:
  - `MAX_URLS`, `MAX_SITEMAPS`, `MAX_DEPTH` are safety rails; preserve them.
- Avoid O(n^2) parsing when `MAX_URLS` is large.

## Making Changes Safely

- Prefer small refactors with behavior-preserving commits.
- If you change robots rule matching semantics (`parse_robots_rules_for_ua`, `robots_check_allowed`), add focused tests.
- If you change URL parsing/resolution (`url_parse`, `resolve_url`), test tricky inputs:
  - fragments, empty path, protocol-relative URLs, relative sitemap paths, query strings.
- Keep CLI flags backward compatible; update `usage()` examples when adding options.
