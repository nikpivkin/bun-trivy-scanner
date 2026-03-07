# bun-trivy-scanner

This package implements the [Security Scanner API](https://bun.com/docs/pm/security-scanner-api) for Bun.

The scanner integrates with Bun's package manager security workflow and automatically invoked during
dependency installation, addition, or when running `bun pm scan`.

## Usage

1. Install the scanner:

```bash
bun add --dev @nikpivkin/bun-trivy-scanner
```

2. Add the scanner to your Bun project configuration:

```toml
[install.security]
scanner = "@nikpivkin/bun-trivy-scanner"
```

3. Trivy configuration (optional)

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

If the configuration file exists in the project root, Trivy will automatically load it during scanning.

4. Run scanner

The scanner will automatically run during dependency installation and addition.

You can also run it manually:

```bash
bun pm scan
```
