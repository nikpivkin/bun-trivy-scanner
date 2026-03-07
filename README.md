# bun-trivy-scanner

This package implements the [Security Scanner API](https://bun.com/docs/pm/security-scanner-api) for Bun.

The scanner integrates with Bun's package manager security workflow and automatically invoked during
dependency installation, addition, or when running `bun pm scan`.

## Usage

1. Add the scanner to your Bun project configuration:

```toml
[install.security]
scanner = "@nikpivkin/bun-trivy-scanner"
```

2. Run the security scanner manually (or it will run automatically during install/add):

```bash
bun pm scan
```
