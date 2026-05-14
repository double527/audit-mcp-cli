import { execa } from 'execa';
import type { PackageManager } from '../types.js';

export interface AuditRawOutput {
  rawJson: string;
  source: PackageManager;
}

/**
 * 根据包管理器执行对应的 audit 命令
 */
export async function runAudit(
  projectPath: string,
  pkgManager: PackageManager,
): Promise<AuditRawOutput> {
  if (pkgManager === 'pnpm') {
    return runPnpmAudit(projectPath);
  }
  // npm 和 yarn（yarn 走 npm 兜底）都使用 npm audit
  return runNpmAudit(projectPath);
}

async function runPnpmAudit(projectPath: string): Promise<AuditRawOutput> {
  const result = await execa('pnpm', ['audit', '--json'], {
    cwd: projectPath,
    reject: false,
    timeout: 120_000,
  });

  if (result.timedOut) {
    throw new Error('pnpm audit 执行超时（>120s），请检查网络或 registry 配置');
  }

  if (result.failed && !result.stdout) {
    throw new Error(`pnpm audit 执行失败: ${result.stderr}`);
  }

  if (!result.stdout) {
    throw new Error('pnpm audit 未返回有效输出');
  }

  // pnpm 无漏洞时可能输出纯文本而非 JSON
  const firstBrace = result.stdout.indexOf('{');
  if (firstBrace === -1) {
    // 没有 JSON，判断是否为"无漏洞"提示
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
    throw new Error('pnpm audit 输出格式异常，无法解析为 JSON');
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
    throw new Error('npm audit 执行超时（>60s），请检查网络或 registry 配置');
  }

  if (result.failed && !result.stdout) {
    throw new Error(`npm audit 执行失败: ${result.stderr}`);
  }

  if (!result.stdout) {
    throw new Error('npm audit 未返回有效输出，请确认 npm 版本 >= 7');
  }

  const firstBrace = result.stdout.indexOf('{');
  if (firstBrace === -1) {
    throw new Error('npm audit 输出格式异常，无法解析为 JSON。请确认 npm 版本 >= 7');
  }

  const cleaned = result.stdout.slice(firstBrace).trim();
  if (!cleaned.startsWith('{')) {
    throw new Error('npm audit 输出格式异常，无法解析为 JSON。请确认 npm 版本 >= 7');
  }

  return {
    rawJson: cleaned,
    source: 'npm',
  };
}
