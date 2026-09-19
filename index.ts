import { rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const reportPath = process.env.BUN_TRIVY_SCANNER_REPORT_PATH;

export const scanner: Bun.Security.Scanner = {
  version: '1',
  async scan(info: { packages: Bun.Security.Package[] }): Promise<Bun.Security.Advisory[]> {
    const trivyPath = Bun.which('trivy');
    if (!trivyPath) {
      throw new Error(
        'Trivy CLI not found in PATH. Please install Trivy to use this security scanner.',
      );
    }

    if (fatalSeverity && !SEVERITY_ORDER.includes(fatalSeverity)) {
      throw new Error(
        `Invalid BUN_TRIVY_SCANNER_FATAL_SEVERITY value "${fatalSeverity}". ` +
          `Valid values are: ${SEVERITY_ORDER.join(', ')}.`,
      );
    }

    const sbom = buildBom(info.packages);

    const file = join(tmpdir(), `bun-trivy-${crypto.randomUUID()}.json`);
    await Bun.write(file, sbom);

    let output: string;
    try {
      const proc = Bun.spawn([trivyPath, 'sbom', '--format', 'json', file], {
        env: { TRIVY_QUIET: 'true', ...process.env },
      });

      let exitCode: number;
      [output, exitCode] = await Promise.all([proc.stdout.text(), proc.exited]);
      if (exitCode !== 0) {
        throw new Error(`Trivy exited with code ${exitCode}`);
      }
    } finally {
      await rm(file, { force: true });
    }

    const result = JSON.parse(output);
    if (reportPath) {
      await Bun.write(reportPath, JSON.stringify(result, null, 2));
    }
    return convert(result);
  },
};

// Builds a minimal CycloneDX 1.6 SBOM with a library component per package
function buildBom(packages: Bun.Security.Package[]): string {
  const components = new Map<string, object>();

  for (const p of packages) {
    const purl = `pkg:npm/${p.name}@${p.version}`;
    components.set(purl, {
      type: 'library',
      name: p.name,
      version: p.version,
      'bom-ref': purl,
      purl,
    });
  }

  return JSON.stringify({
    $schema: 'http://cyclonedx.org/schema/bom-1.6.schema.json',
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    version: 1,
    components: [...components.values()],
    dependencies: [...components.keys()].map((ref) => ({ ref })),
  });
}

const fatalSeverity = process.env.BUN_TRIVY_SCANNER_FATAL_SEVERITY?.toUpperCase();
const SEVERITY_ORDER = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

function severityToLevel(sev: string): 'fatal' | 'warn' {
  if (!fatalSeverity) {
    return 'warn';
  }

  if (SEVERITY_ORDER.indexOf(sev.toUpperCase()) >= SEVERITY_ORDER.indexOf(fatalSeverity)) {
    return 'fatal';
  }

  return 'warn';
}

function convert(result: TrivyOutput): Bun.Security.Advisory[] {
  const advisories: Bun.Security.Advisory[] = [];

  for (const r of result.Results ?? []) {
    for (const v of r.Vulnerabilities ?? []) {
      advisories.push({
        level: severityToLevel(v.Severity),
        package: v.PkgName,
        url: v.PrimaryURL ?? null,
        description: formatDescription(v),
      });
    }
  }

  return advisories;
}

// Trivy omits empty Title and Description fields
function formatDescription(v: TrivyVulnerability): string {
  let description = `(${v.Severity}) ${v.VulnerabilityID}`;
  if (v.Title) {
    description += `: ${v.Title}`;
  }
  if (v.Description) {
    description += `\n\n  ${v.Description}`;
  }
  return description;
}

interface TrivyVulnerability {
  VulnerabilityID: string;
  PkgName: string;
  Severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  Title?: string;
  Description?: string;
  PrimaryURL?: string;
}

interface TrivyResult {
  Target: string;
  Type?: string;
  Vulnerabilities?: TrivyVulnerability[];
}

interface TrivyOutput {
  Results?: TrivyResult[];
}
