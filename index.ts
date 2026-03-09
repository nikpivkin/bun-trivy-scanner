import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { Models, Enums, Serialize, Spec } from '@cyclonedx/cyclonedx-library';

export const scanner: Bun.Security.Scanner = {
  version: '1',
  async scan(info: { packages: Bun.Security.Package[] }): Promise<Bun.Security.Advisory[]> {
    const trivyPath = Bun.which('trivy');
    if (!trivyPath) {
      throw new Error(
        'Trivy CLI not found in PATH. Please install Trivy to use this security scanner.',
      );
    }

    const sbom = buildBom(info.packages);

    const file = join(tmpdir(), `bun-trivy-${crypto.randomUUID()}.json`);
    await Bun.write(file, sbom);

    const proc = Bun.spawn([trivyPath, 'sbom', '--format', 'json', file]);

    const result = await proc.stdout.json();
    return convert(result);
  },
};

function buildBom(packages: Bun.Security.Package[]) {
  const bom = new Models.Bom();

  for (const p of packages) {
    const component = new Models.Component(Enums.ComponentType.Library, p.name, {
      version: p.version,
      purl: `pkg:npm/${p.name}@${p.version}`,
    });
    bom.components.add(component);
  }

  const spec = Spec.Spec1dot6;
  const normalizerFactory = new Serialize.JSON.Normalize.Factory(spec);
  const serializer = new Serialize.JsonSerializer(normalizerFactory);
  return serializer.serialize(bom);
}

const fatalSeverity = process.env.BUN_TRIVY_SCANNER_FATAL_SEVERITY;
const SEVERITY_ORDER = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

function severityToLevel(sev: string): 'fatal' | 'warn' {
  if (!fatalSeverity) {
    return 'warn';
  }

  if (SEVERITY_ORDER.indexOf(sev) >= SEVERITY_ORDER.indexOf(fatalSeverity)) {
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
        description: v.Title ?? null,
      });
    }
  }

  return advisories;
}

interface TrivyVulnerability {
  PkgName: string;
  InstalledVersion?: string;
  VulnerabilityID?: string;
  Severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  Title?: string;
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
