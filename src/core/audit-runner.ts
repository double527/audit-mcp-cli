import { execa } from 'execa';
import { t } from './i18n.js';
import type { PackageManager } from '../types.js';

export interface AuditRawOutput {
  rawJson: string;
  source: PackageManager;
}

/**
 * Execute the appropriate audit command based on package manager
 */
export async function runAudit(
  projectPath: string,
  pkgManager: PackageManager,
): Promise<AuditRawOutput> {
  if (pkgManager === 'pnpm') {
    return runPnpmAudit(projectPath);
  }
  // npm and yarn (yarn falls back to npm) both use npm audit
  return runNpmAudit(projectPath);
}

async function runPnpmAudit(projectPath: string): Promise<AuditRawOutput> {
  const result = await execa('pnpm', ['audit', '--json'], {
    cwd: projectPath,
    reject: false,
    timeout: 120_000,
  });

  if (result.timedOut) {
    throw new Error(t('error.pnpmAuditTimeout'));
  }

  if (result.failed && !result.stdout) {
    throw new Error(t('error.pnpmAuditFailed', { stderr: result.stderr }));
  }

  if (!result.stdout) {
    throw new Error(t('error.pnpmAuditNoOutput'));
  }

  // pnpm may output plain text instead of JSON when no vulnerabilities found
  const firstBrace = result.stdout.indexOf('{');
  if (firstBrace === -1) {
    const output = result.stdout.trim().toLowerCase();
    if (output.includes('no known vulnerabilities') || output.includes('no vulnerabilities')) {
      return {
        rawJson: JSON.stringify({
          actions: [],
          advisories: {},
          muted: [],
          metadata: { vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 0 }, dependencies: 0, devDependencies: 0, optionalDependencies: 0, totalDependencies: 0 },
        }),
        source: 'pnpm',
      };
    }
    throw new Error(t('error.pnpmAuditBadFormat'));
  }

  return {
    rawJson: result.stdout.slice(firstBrace).trim(),
    source: 'pnpm',
  };
}

async function runNpmAudit(projectPath: string): Promise<AuditRawOutput> {
  const result = await execa('npm', ['audit', '--json'], {
    cwd: projectPath,
    reject: false,
    timeout: 60_000,
  });

  if (result.timedOut) {
    throw new Error(t('error.npmAuditTimeout'));
  }

  if (result.failed && !result.stdout) {
    throw new Error(t('error.npmAuditFailed', { stderr: result.stderr }));
  }

  if (!result.stdout) {
    throw new Error(t('error.npmAuditNoOutput'));
  }

  const firstBrace = result.stdout.indexOf('{');
  if (firstBrace === -1) {
    throw new Error(t('error.npmAuditBadFormat'));
  }

  const cleaned = result.stdout.slice(firstBrace).trim();
  if (!cleaned.startsWith('{')) {
    throw new Error(t('error.npmAuditBadFormat'));
  }

  return {
    rawJson: cleaned,
    source: 'npm',
  };
}
