import { resolve } from 'node:path';
import { checkNpmEnvironment, detectPackageManager, ensureLockfile, ensurePnpmLockfile } from './core/lockfile-manager.js';
import { runAudit } from './core/audit-runner.js';
import { parseNpmAudit } from './core/parsers/npm-parser.js';
import { parsePnpmAudit } from './core/parsers/pnpm-parser.js';
import { generateReport } from './core/report-generator.js';
import { fetchRemoteFiles, cleanupTempDir, parseRemoteRepo } from './core/remote-fetcher.js';
import { loadIgnoreFile, partitionVulnerabilities } from './core/ignore-loader.js';
import { SEVERITY_RANK } from './types.js';
import type { AuditOptions, AuditResult, Severity, Vulnerability, VulnerabilitySummary } from './types.js';

// ─── 简易 Spinner（无第三方依赖） ───

const SPINNER_FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
const SPINNER_INTERVAL = 80; // ms

let spinnerTimer: ReturnType<typeof setInterval> | null = null;
let spinnerStartTime = 0;
let silent = false;

function startSpinner(message: string): void {
  if (silent) return;
  stopSpinner();
  spinnerStartTime = Date.now();
  let frameIdx = 0;
  process.stdout.write(`  ${SPINNER_FRAMES[0]} ${message}`);
  spinnerTimer = setInterval(() => {
    frameIdx = (frameIdx + 1) % SPINNER_FRAMES.length;
    const elapsed = ((Date.now() - spinnerStartTime) / 1000).toFixed(0);
    process.stdout.write(`\r  ${SPINNER_FRAMES[frameIdx]} ${message} (${elapsed}s)`);
  }, SPINNER_INTERVAL);
}

function stopSpinner(): void {
  if (spinnerTimer) {
    clearInterval(spinnerTimer);
    spinnerTimer = null;
    process.stdout.write('\r' + ' '.repeat(60) + '\r');
  }
}

function stepOk(message: string): void {
  if (silent) return;
  stopSpinner();
  console.log(`  ✔ ${message}`);
}

function stepWarn(message: string): void {
  if (silent) return;
  stopSpinner();
  console.log(`  ⚠ ${message}`);
}

/**
 * 核心审计函数：串联 环境检查 → 锁文件 → audit → 解析 → 报告
 *
 * 本地模式：projectPath → 环境检测 → 锁文件 → audit → 解析 → 报告
 * 远程模式：先拉文件到临时目录，再走本地流程，最后清理
 */
export async function auditProject(options: AuditOptions = {}): Promise<AuditResult> {
  const {
    remoteRepo,
    ref = 'main',
    token,
    format = 'md',
    output,
  } = options;

  // MCP 模式静默，不输出 spinner
  silent = !!process.env.AUDIT_SILENT;

  if (!silent) console.log('\n🔍 audit-mcp-cli 开始审计...\n');

  // 1. npm 环境检查（本地/远程都需要）
  startSpinner('检查 npm 环境...');
  const { npmVersion } = await checkNpmEnvironment();
  stepOk(`npm v${npmVersion}`);

  let resolvedPath: string;
  let tempDir: string | null = null;
  let lockfileGenerated = false;

  if (remoteRepo) {
    // ── 远程模式 ──
    const { platform, owner, repo } = parseRemoteRepo(remoteRepo);
    if (platform !== 'github') {
      throw new Error(`暂不支持平台：${platform}，仅支持 GitHub`);
    }

    startSpinner(`拉取远程仓库 ${owner}/${repo} (${ref})...`);
    const remote = await fetchRemoteFiles(owner, repo, ref, token);
    tempDir = remote.tempDir;
    resolvedPath = tempDir;
    lockfileGenerated = remote.packageLockJson === null && remote.pnpmLockYaml === null;
    stepOk(`远程仓库文件已就绪`);
  } else {
    // ── 本地模式 ──
    resolvedPath = resolve(options.projectPath ?? process.cwd());
  }

  try {
    // 2. 包管理器检测
    const pkgManager = detectPackageManager(resolvedPath);
    stepOk(`包管理器: ${pkgManager}`);

    // 3. 确保锁文件存在
    if (pkgManager === 'pnpm') {
      // pnpm 项目：确保 pnpm-lock.yaml 存在
      try {
        startSpinner('生成/检查 pnpm-lock.yaml...');
        const lockResult = await ensurePnpmLockfile(resolvedPath);
        if (remoteRepo) {
          lockfileGenerated = lockResult.generated;
        }
        stepOk('锁文件就绪');
      } catch (e) {
        throw new Error(`无法生成 pnpm-lock.yaml：${(e as Error).message}`);
      }
    } else {
      // npm / yarn 项目：确保 package-lock.json 存在
      let lockResult: { generated: boolean };
      try {
        startSpinner('生成/检查 package-lock.json...');
        lockResult = await ensureLockfile(resolvedPath);
        stepOk('锁文件就绪');
      } catch (e) {
        const hint = pkgManager === 'yarn'
          ? `当前项目使用 yarn，已尝试用 npm 生成 lockfile。请手动执行：npm install --package-lock-only --legacy-peer-deps`
          : (e as Error).message;
        throw new Error(`无法生成 package-lock.json：${hint}`);
      }
      if (remoteRepo) {
        lockfileGenerated = lockResult.generated;
      }
    }

    // 4. 执行 audit（根据包管理器分发）
    startSpinner(`执行 ${pkgManager} audit...`);
    const { rawJson, source } = await runAudit(resolvedPath, pkgManager);
    stepOk(`审计完成 (${source})`);

    // 5. 读取项目名
    const projectName = await readProjectName(resolvedPath);

    // 6. 解析（根据 audit 来源路由到对应 parser）
    startSpinner('解析审计结果...');
    let result: AuditResult;
    if (source === 'pnpm') {
      result = await parsePnpmAudit(rawJson, projectName);
    } else {
      result = await parseNpmAudit(rawJson, resolvedPath, projectName);
      result.auditSource = 'npm';
    }
    result.lockfileGenerated = lockfileGenerated;
    result.npmVersion = npmVersion;
    stepOk(`解析完成，发现 ${result.vulnerabilities.length} 个漏洞`);

    // 7. 加载忽略规则，分离漏洞
    const ignoreRules = await loadIgnoreFile(resolvedPath);
    const { active, ignored } = partitionVulnerabilities(result.vulnerabilities, ignoreRules);
    result.vulnerabilities = active;
    result.ignoredVulnerabilities = ignored.map(({ vuln, rule }) => ({
      vuln,
      reason: rule.reason,
      expiresAt: rule.expiresAt,
    }));

    // 8. severity 过滤
    if (options.severity) {
      result.vulnerabilities = filterBySeverity(result.vulnerabilities, options.severity);
    }

    // 9. summary 与实际漏洞列表对齐（metadata 原始计数可能与 parser 去重后不一致）
    result.summary = recalculateSummary(result.vulnerabilities);

    // 10. 生成报告文件
    startSpinner('生成报告...');
    const reportPath = await generateReport({
      auditResult: result,
      format,
      outputPath: output,
    });
    result.reportFilePath = reportPath;
    result.reportFormat = format;
    stepOk(`报告已保存: ${reportPath}`);

    return result;
  } finally {
    stopSpinner();
    // 远程模式：清理临时目录
    if (tempDir) {
      await cleanupTempDir(tempDir);
    }
  }
}

async function readProjectName(projectPath: string): Promise<string> {
  try {
    const { readFile } = await import('node:fs/promises');
    const raw = await readFile(resolve(projectPath, 'package.json'), 'utf-8');
    const pkg = JSON.parse(raw);
    return pkg.name || projectPath.split(/[/\\]/).pop() || 'unknown';
  } catch {
    return projectPath.split(/[/\\]/).pop() || 'unknown';
  }
}

function filterBySeverity(vulns: AuditResult['vulnerabilities'], min: Severity) {
  const threshold = SEVERITY_RANK[min];
  return vulns.filter((v) => SEVERITY_RANK[v.severity] >= threshold);
}

function recalculateSummary(vulns: Vulnerability[]): VulnerabilitySummary {
  const summary: VulnerabilitySummary = { total: 0, critical: 0, high: 0, moderate: 0, low: 0 };
  for (const v of vulns) {
    summary.total++;
    summary[v.severity]++;
  }
  return summary;
}
