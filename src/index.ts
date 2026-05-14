import { resolve } from 'node:path';
import { checkNpmEnvironment, detectPackageManager, ensureLockfile, ensurePnpmLockfile } from './core/lockfile-manager.js';
import { runAudit } from './core/audit-runner.js';
import { parseNpmAudit } from './core/parsers/npm-parser.js';
import { parsePnpmAudit } from './core/parsers/pnpm-parser.js';
import { generateReport } from './core/report-generator.js';
import { fetchRemoteFiles, cleanupTempDir, parseRemoteRepo } from './core/remote-fetcher.js';
import { loadIgnoreFile, partitionVulnerabilities } from './core/ignore-loader.js';
import { SEVERITY_RANK } from './types.js';
import { t } from './core/i18n.js';
import type { AuditOptions, AuditResult, Severity, Vulnerability, VulnerabilitySummary } from './types.js';

// ─── Simple Spinner (no third-party deps) ───

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
 * Core audit function: environment check → lockfile → audit → parse → report
 *
 * Local mode: projectPath → environment → lockfile → audit → parse → report
 * Remote mode: fetch files to temp dir, then local flow, cleanup at end
 */
export async function auditProject(options: AuditOptions = {}): Promise<AuditResult> {
  const {
    remoteRepo,
    ref = 'main',
    token,
    format = 'md',
    output,
  } = options;

  // MCP mode: silence spinner
  silent = !!process.env.AUDIT_SILENT;

  if (!silent) console.log(t('audit.starting'));

  // 1. npm environment check (local/remote both need)
  startSpinner(t('audit.checkingNpm'));
  const { npmVersion } = await checkNpmEnvironment();
  stepOk(`npm v${npmVersion}`);

  let resolvedPath: string;
  let tempDir: string | null = null;
  let lockfileGenerated = false;

  if (remoteRepo) {
    // ── Remote mode ──
    const { platform, owner, repo } = parseRemoteRepo(remoteRepo);
    if (platform !== 'github') {
      throw new Error(t('audit.unsupportedPlatform', { platform }));
    }

    startSpinner(t('audit.fetchingRemote', { owner, repo, ref }));
    const remote = await fetchRemoteFiles(owner, repo, ref, token);
    tempDir = remote.tempDir;
    resolvedPath = tempDir;
    lockfileGenerated = remote.packageLockJson === null && remote.pnpmLockYaml === null;
    stepOk(t('audit.remoteReady'));
  } else {
    // ── Local mode ──
    resolvedPath = resolve(options.projectPath ?? process.cwd());
  }

  try {
    // 2. Package manager detection
    const pkgManager = detectPackageManager(resolvedPath);
    stepOk(t('audit.pkgManager', { manager: pkgManager }));

    // 3. Ensure lockfile exists
    if (pkgManager === 'pnpm') {
      try {
        startSpinner(t('audit.generatingPnpmLockfile'));
        const lockResult = await ensurePnpmLockfile(resolvedPath);
        if (remoteRepo) {
          lockfileGenerated = lockResult.generated;
        }
        stepOk(t('audit.lockfileReady'));
      } catch (e) {
        throw new Error(t('audit.cannotGeneratePnpmLockfile', { message: (e as Error).message }));
      }
    } else {
      let lockResult: { generated: boolean };
      try {
        startSpinner(t('audit.generatingNpmLockfile'));
        lockResult = await ensureLockfile(resolvedPath);
        stepOk(t('audit.lockfileReady'));
      } catch (e) {
        const hint = pkgManager === 'yarn'
          ? t('audit.yarnLockfileHint')
          : (e as Error).message;
        throw new Error(t('audit.cannotGenerateNpmLockfile', { hint }));
      }
      if (remoteRepo) {
        lockfileGenerated = lockResult.generated;
      }
    }

    // 4. Execute audit (route by package manager)
    startSpinner(t('audit.runningAudit', { manager: pkgManager }));
    const { rawJson, source } = await runAudit(resolvedPath, pkgManager);
    stepOk(t('audit.auditDone', { source }));

    // 5. Read project name
    const projectName = await readProjectName(resolvedPath);

    // 6. Parse (route to corresponding parser by audit source)
    startSpinner(t('audit.parsing'));
    let result: AuditResult;
    if (source === 'pnpm') {
      result = await parsePnpmAudit(rawJson, projectName);
    } else {
      result = await parseNpmAudit(rawJson, resolvedPath, projectName);
      result.auditSource = 'npm';
    }
    result.lockfileGenerated = lockfileGenerated;
    result.npmVersion = npmVersion;
    stepOk(t('audit.parseDone', { count: result.vulnerabilities.length }));

    // 7. Load ignore rules, partition vulnerabilities
    const ignoreRules = await loadIgnoreFile(resolvedPath);
    const { active, ignored } = partitionVulnerabilities(result.vulnerabilities, ignoreRules);
    result.vulnerabilities = active;
    result.ignoredVulnerabilities = ignored.map(({ vuln, rule }) => ({
      vuln,
      reason: rule.reason,
      expiresAt: rule.expiresAt,
    }));

    // 8. Severity filter
    if (options.severity) {
      result.vulnerabilities = filterBySeverity(result.vulnerabilities, options.severity);
    }

    // 9. Realign summary with actual vulnerability list
    result.summary = recalculateSummary(result.vulnerabilities);

    // 10. Generate report file
    startSpinner(t('audit.generatingReport'));
    const reportPath = await generateReport({
      auditResult: result,
      format,
      outputPath: output,
    });
    result.reportFilePath = reportPath;
    result.reportFormat = format;
    stepOk(t('audit.reportSaved', { path: reportPath }));

    return result;
  } finally {
    stopSpinner();
    // Remote mode: cleanup temp directory
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
