import { Command } from 'commander';
import { createRequire } from 'node:module';
import { auditProject } from './index.js';
import { startMcpServer } from './mcp-server.js';
import { SEVERITY_RANK, type Severity } from './types.js';
import { initLocale, t } from './core/i18n.js';

const require = createRequire(import.meta.url);
const pkg = require('../package.json');

const program = new Command();

program
  .name('audit-mcp-cli')
  .description(t('cli.description'))
  .version(pkg.version)
  .option('--path <path>', t('cli.opt.path'))
  .option('--remote <repo>', t('cli.opt.remote'))
  .option('--ref <ref>', t('cli.opt.ref'), 'main')
  .option('--token <token>', t('cli.opt.token'))
  .option('--format <format>', t('cli.opt.format'), 'md')
  .option('--output <path>', t('cli.opt.output'))
  .option('--severity <level>', t('cli.opt.severity'), 'low')
  .option('--fail-on <level>', t('cli.opt.failOn'))
  .option('--lang <lang>', t('cli.opt.lang'))
  .option('--mcp', t('cli.opt.mcp'))
  .action(async (opts) => {
    // Initialize locale (must be before any localized output)
    initLocale(opts.lang);

    if (opts.mcp) {
      await startMcpServer();
      return;
    }

    // 互斥校验：--path 和 --remote 不能同时使用
    if (opts.path && opts.remote) {
      console.error(t('cli.error.pathRemoteExclusive'));
      process.exit(1);
    }

    // --token 只能与 --remote 配合
    if (opts.token && !opts.remote) {
      console.error(t('cli.error.tokenNeedsRemote'));
      process.exit(1);
    }

    // --ref 只能与 --remote 配合
    if (opts.ref !== 'main' && !opts.remote) {
      console.error(t('cli.error.refNeedsRemote'));
      process.exit(1);
    }

    // 校验枚举值
    const validSeverities: Severity[] = ['low', 'moderate', 'high', 'critical'];
    if (!validSeverities.includes(opts.severity)) {
      console.error(t('cli.error.invalidSeverity', { value: opts.severity ?? '', options: validSeverities.join('/') }));
      process.exit(1);
    }
    if (opts.failOn && !validSeverities.includes(opts.failOn)) {
      console.error(t('cli.error.invalidFailOn', { value: opts.failOn, options: validSeverities.join('/') }));
      process.exit(1);
    }
    if (opts.format !== 'md' && opts.format !== 'html') {
      console.error(t('cli.error.invalidFormat', { value: opts.format }));
      process.exit(1);
    }

    try {
      const result = await auditProject({
        projectPath: opts.path,
        remoteRepo: opts.remote,
        ref: opts.ref,
        token: opts.token,
        format: opts.format,
        output: opts.output,
        severity: opts.severity as Severity,
        failOn: opts.failOn as Severity | undefined,
      });

      console.log(t('cli.auditComplete', { name: result.projectName }));
      const activeCount = result.vulnerabilities.length;
      const ignoredCount = result.ignoredVulnerabilities?.length ?? 0;
      console.log(t('cli.vulnCount', { count: activeCount, critical: result.summary.critical, high: result.summary.high, moderate: result.summary.moderate, low: result.summary.low }));
      if (ignoredCount > 0) {
        console.log(t('cli.ignoredCount', { count: ignoredCount }));
      }
      console.log(t('cli.reportPath', { path: result.reportFilePath ?? '' }));

      // --fail-on 退出码
      if (opts.failOn) {
        const threshold = SEVERITY_RANK[opts.failOn as Severity];
        const hasFailing = result.vulnerabilities.some(
          (v) => SEVERITY_RANK[v.severity] >= threshold,
        );
        if (hasFailing) {
          console.error(t('cli.ciFailed', { level: opts.failOn }));
          process.exit(1);
        }
      }
    } catch (e) {
      console.error(t('cli.auditFailed', { message: (e as Error).message }));
      process.exit(1);
    }
  });

program.parse();
