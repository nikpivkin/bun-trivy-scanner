# bun-trivy-scanner

This package implements the [Security Scanner API](https://bun.com/docs/pm/security-scanner-api) for Bun.

The scanner integrates with Bun's package manager security workflow and uses
[Trivy](https://github.com/aquasecurity/trivy) for vulnerability detection.
It runs automatically during dependency installation, addition, or when executing `bun pm scan`.

## Features

- Native integration with Bun
- No npm dependencies, only the Trivy CLI is required
- Thin wrapper around Trivy
- Supports the full Trivy feature set

## Installation

```bash
bun add --dev @nikpivkin/bun-trivy-scanner
```

## Configuration

### Bun configuration

```toml
[install.security]
scanner = "@nikpivkin/bun-trivy-scanner"
```

### Scanner behavior

You can control which vulnerability severity aborts installation by setting an
**environment variable**:

```bash
export BUN_TRIVY_SCANNER_FATAL_SEVERITY=CRITICAL
```

Valid values are: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.

If a vulnerability with this severity or higher is detected, the installation
will fail. Otherwise, advisories are reported as warnings and the user can
choose whether to continue.

Additionally, you can specify a custom path to save the Trivy JSON report
for manual inspection:

```bash
export BUN_TRIVY_SCANNER_REPORT_PATH=/path/to/report.json
```

If this variable is not set, the scanner will store the report in a temporary
directory (default behavior).

### Trivy configuration (optional)

You can configure Trivy by creating a `trivy.yaml` file in the project root directory
(the directory where Bun is executed).

Example configuration:

```yaml
# yaml-language-server: $schema=https://github.com/aquasecurity/trivy/raw/refs/tags/v0.69.3/schema/trivy-config.json

server:
  addr: http://0.0.0.0:10000

severity:
  - MEDIUM
  - HIGH
  - CRITICAL
```

If the configuration file exists in the project root, it will be automatically loaded during scanning.

Alternatively, Trivy can be configured using environment variables supported by Trivy
(for example `TRIVY_SEVERITY` or `TRIVY_SERVER_ADDR`).

See the Trivy documentation for more details:

- Config file: https://trivy.dev/docs/latest/guide/references/configuration/config-file/
- Environment variables: https://trivy.dev/docs/latest/guide/configuration/#environment-variables

### Trivy logs

The scanner runs Trivy in quiet mode, so only Trivy errors are shown. On the
first run Trivy downloads its vulnerability database (about 100 MB), which may
take a while. To see Trivy logs and download progress, set:

```bash
export TRIVY_QUIET=false
```

## Usage

The scanner will automatically run during dependency installation and addition.

You can also run it manually:

```bash
bun pm scan
```

## Scanner in action

```
❯ bun add lodash@4.17.20
bun add v1.3.10 (30e609e0)

  WARNING: lodash
    via  › lodash
    nodejs-lodash: command injection via template
    https://avd.aquasec.com/nvd/cve-2021-23337

  WARNING: lodash
    via  › lodash
    nodejs-lodash: ReDoS via the toNumber, trim and trimEnd functions
    https://avd.aquasec.com/nvd/cve-2020-28500

  WARNING: lodash
    via  › lodash
    lodash: prototype pollution in _.unset and _.omit functions
    https://avd.aquasec.com/nvd/cve-2025-13465

3 advisories (3 warnings)

Security warnings found. Continue anyway? [y/N]
```

## Development

End-to-end tests run `bun add` in the `test` directory with the local scanner.
They require Trivy in `PATH` and network access to the npm registry.

```bash
bun install
bun run test
```

Instead of downloading the full Trivy database, the tests use a minimal one
from `test/testdata/trivy-cache/db`, which contains advisories only for the
packages used in the tests. To rebuild it, for example after adding a package
to the tests, run `trivy image --download-db-only` to get the full database
and pass it with the package list (on Linux the database is in `~/.cache/trivy/db`):

```bash
cd test/testdata/trivy-cache
go run . ~/Library/Caches/trivy/db/trivy.db lodash is-number
```
