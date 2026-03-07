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

3. The scanner will automatically run during dependency installation and addition.

You can also run it manually:

```bash
bun pm scan
```
