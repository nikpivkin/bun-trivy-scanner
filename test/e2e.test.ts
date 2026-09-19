import { expect, setDefaultTimeout, test } from 'bun:test';
import { mkdtemp, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

setDefaultTimeout(60_000);

const cwd = import.meta.dir;

// Use the minimal Trivy DB from testdata instead of downloading the full one.
// See testdata/trivy-cache/main.go for how to rebuild it.
const baseEnv = {
  ...Object.fromEntries(
    Object.entries(process.env).filter(
      ([key]) => !key.startsWith('BUN_TRIVY_SCANNER_') && !key.startsWith('TRIVY_'),
    ),
  ),
  TRIVY_CACHE_DIR: join(cwd, 'testdata/trivy-cache'),
  TRIVY_SKIP_DB_UPDATE: 'true',
};

async function bunAdd(pkg: string, env: Record<string, string> = {}) {
  const proc = Bun.spawn([process.execPath, 'add', '--no-save', pkg], {
    cwd,
    env: { ...baseEnv, ...env },
    stdin: 'ignore',
    stdout: 'pipe',
    stderr: 'pipe',
  });
  const [stdout, stderr, exitCode] = await Promise.all([
    proc.stdout.text(),
    proc.stderr.text(),
    proc.exited,
  ]);
  return { output: stdout + stderr, exitCode };
}

async function tempDir() {
  return mkdtemp(join(tmpdir(), 'bun-trivy-scanner-e2e-'));
}

test('warns about a vulnerable package and cancels install without a TTY', async () => {
  const { output, exitCode } = await bunAdd('lodash@4.17.20');

  expect(exitCode).toBe(1);
  expect(output).toContain('WARNING: lodash');
  expect(output).not.toContain('FATAL: lodash');
  expect(output).toContain('(HIGH) CVE-2021-23337: nodejs-lodash: command injection via template');
  expect(output).toContain('https://avd.aquasec.com/nvd/cve-2021-23337');
  // Only the title is shown, not the full description
  expect(output).not.toContain('Lodash versions prior to 4.17.21');
  expect(await Bun.file(join(cwd, 'node_modules/lodash/package.json')).exists()).toBe(false);
});

test('reports fatal advisories at or above BUN_TRIVY_SCANNER_FATAL_SEVERITY', async () => {
  const { output, exitCode } = await bunAdd('lodash@4.17.20', {
    BUN_TRIVY_SCANNER_FATAL_SEVERITY: 'HIGH',
  });

  expect(exitCode).toBe(1);
  expect(output).toMatch(/FATAL: lodash\s+via\s+› lodash\s+\(HIGH\)/);
  expect(output).toMatch(/WARNING: lodash\s+via\s+› lodash\s+\(MEDIUM\)/);
});

test('fails on an invalid BUN_TRIVY_SCANNER_FATAL_SEVERITY', async () => {
  const { output, exitCode } = await bunAdd('lodash@4.17.20', {
    BUN_TRIVY_SCANNER_FATAL_SEVERITY: 'CRTICAL',
  });

  expect(exitCode).toBe(1);
  expect(output).toContain('Invalid BUN_TRIVY_SCANNER_FATAL_SEVERITY value "CRTICAL"');
});

test('removes the temporary SBOM file', async () => {
  const dir = await tempDir();

  try {
    const { output } = await bunAdd('lodash@4.17.20', { TMPDIR: dir });

    expect(output).toContain('WARNING: lodash');
    const leftovers = (await readdir(dir)).filter((name) => name.startsWith('bun-trivy-'));
    expect(leftovers).toEqual([]);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('installs a package without vulnerabilities', async () => {
  const { output, exitCode } = await bunAdd('is-number@7.0.0');

  expect(output).toContain('installed is-number@7.0.0');
  expect(exitCode).toBe(0);
});

test('saves the Trivy report to BUN_TRIVY_SCANNER_REPORT_PATH', async () => {
  const dir = await tempDir();
  const reportPath = join(dir, 'report.json');

  try {
    await bunAdd('lodash@4.17.20', { BUN_TRIVY_SCANNER_REPORT_PATH: reportPath });

    const report = await Bun.file(reportPath).json();
    const pkgNames = report.Results.flatMap((r: any) => r.Vulnerabilities ?? []).map(
      (v: any) => v.PkgName,
    );
    expect(pkgNames).toContain('lodash');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('fails when Trivy is not in PATH', async () => {
  const dir = await tempDir();

  try {
    const { output, exitCode } = await bunAdd('lodash@4.17.20', { PATH: dir });

    expect(exitCode).toBe(1);
    expect(output).toContain('Trivy CLI not found in PATH');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('fails when Trivy exits with an error', async () => {
  const dir = await tempDir();

  try {
    const { output, exitCode } = await bunAdd('lodash@4.17.20', {
      TRIVY_CACHE_DIR: dir,
      TRIVY_SKIP_DB_UPDATE: 'false',
      TRIVY_DB_REPOSITORY: 'invalid.invalid/trivy-db',
    });

    expect(exitCode).toBe(1);
    expect(output).toContain('failed to download vulnerability DB');
    expect(output).toContain('Trivy exited with code 1');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
