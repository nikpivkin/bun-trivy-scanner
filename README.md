# bun-trivy-scanner

This package implements the [Security Scanner API](https://bun.com/docs/pm/security-scanner-api) for Bun.

The scanner integrates with Bun's package manager security workflow and uses
[Trivy](https://github.com/aquasecurity/trivy) for vulnerability detection.
It runs automatically during dependency installation, addition, or when executing `bun pm scan`.

## Features

- Native integration with Bun
- Small codebase with minimal external dependencies — easier to audit and maintain
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
2026-03-07T16:53:48+06:00       INFO    Loaded  file_path="trivy.yaml"
2026-03-07T16:53:48+06:00       INFO    [vuln] Vulnerability scanning is enabled
2026-03-07T16:53:48+06:00       INFO    Detected SBOM format    format="cyclonedx-json"
2026-03-07T16:53:48+06:00       WARN    Third-party SBOM may lead to inaccurate vulnerability detection
2026-03-07T16:53:48+06:00       WARN    Recommend using Trivy to generate SBOMs
2026-03-07T16:53:48+06:00       INFO    Number of language-specific files       num=1
2026-03-07T16:53:48+06:00       INFO    [node-pkg] Detecting vulnerabilities...

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
