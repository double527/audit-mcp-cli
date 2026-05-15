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
  // 检测 pnpm 版本，< 11 时提示升级（旧端点将于 2026-07-15 关闭）
  try {
    const verResult = await execa('pnpm', ['--version'], { reject: false });
    const major = parseInt(verResult.stdout.split('.')[0], 10);
    if (major < 11) {
      console.warn(
        '⚠ 您的 pnpm 版本过低，pnpm audit 旧端点即将于 2026-07-15 关闭，届时 pnpm audit 将不可用。建议升级: pnpm add -g pnpm@latest',
      );
    }
  } catch {
    // 版本检测失败不影响主流程
  }

  const result = await execa('pnpm', ['audit', '--json'], {
    cwd: projectPath,
    reject: false,
    timeout: 120_000,
    env: { npm_config_registry: 'https://registry.npmjs.org/' },
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
    env: { npm_config_registry: 'https://registry.npmjs.org/' },
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

  // npm audit 在 registry 不支持 audit API 或网络错误时，
  // 输出错误 JSON（无 auditReportVersion），需要在此拦截
  try {
    const peek = JSON.parse(cleaned);
    if (peek.auditReportVersion === undefined) {
      const msg = peek.message || '';
      const code = peek.statusCode || '';
      if (msg || code) {
        throw new Error(t('error.npmAuditEndpointError', { message: msg, statusCode: code }));
      }
      throw new Error(t('error.npmAuditNotReport'));
    }
  } catch (e) {
    if (e instanceof Error && e.message.startsWith('npm audit')) {
      throw e;
    }
    // JSON.parse 本身失败，继续走 parser 层处理
  }

  return {
    rawJson: cleaned,
    source: 'npm',
  };
}
