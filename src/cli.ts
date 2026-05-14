import { Command } from 'commander';
import { auditProject } from './index.js';
import { startMcpServer } from './mcp-server.js';
import { SEVERITY_RANK, type Severity } from './types.js';

const program = new Command();

program
  .name('audit-mcp-cli')
  .description('轻量级依赖漏洞审计工具')
  .version('1.0.0')
  .option('--path <path>', '本地项目路径')
  .option('--remote <repo>', '远程仓库标识（github:owner/repo 或 https://github.com/owner/repo）')
  .option('--ref <ref>', '远程引用（分支名 / Tag / SHA）', 'main')
  .option('--token <token>', 'GitHub 访问令牌')
  .option('--format <format>', '报告格式（md 或 html）', 'md')
  .option('--output <path>', '输出文件路径')
  .option('--severity <level>', '最低显示级别（low / moderate / high / critical）', 'low')
  .option('--fail-on <level>', 'CI 失败阈值（low / moderate / high / critical）')
  .option('--mcp', '以 MCP Server 模式启动')
  .action(async (opts) => {
    if (opts.mcp) {
      await startMcpServer();
      return;
    }

    // 互斥校验：--path 和 --remote 不能同时使用
    if (opts.path && opts.remote) {
      console.error('错误：--path 和 --remote 不能同时使用');
      process.exit(1);
    }

    // --token 只能与 --remote 配合
    if (opts.token && !opts.remote) {
      console.error('错误：--token 只能与 --remote 配合使用');
      process.exit(1);
    }

    // --ref 只能与 --remote 配合
    if (opts.ref !== 'main' && !opts.remote) {
      console.error('错误：--ref 只能与 --remote 配合使用');
      process.exit(1);
    }

    // 校验枚举值
    const validSeverities: Severity[] = ['low', 'moderate', 'high', 'critical'];
    if (!validSeverities.includes(opts.severity)) {
      console.error(`错误：--severity 值无效（${opts.severity}），可选：${validSeverities.join('/')}`);
      process.exit(1);
    }
    if (opts.failOn && !validSeverities.includes(opts.failOn)) {
      console.error(`错误：--fail-on 值无效（${opts.failOn}），可选：${validSeverities.join('/')}`);
      process.exit(1);
    }
    if (opts.format !== 'md' && opts.format !== 'html') {
      console.error(`错误：--format 值无效（${opts.format}），可选：md/html`);
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

      console.log(`\n✅ 审计完成 — ${result.projectName}`);
      const activeCount = result.vulnerabilities.length;
      const ignoredCount = result.ignoredVulnerabilities?.length ?? 0;
      console.log(`   漏洞：${activeCount} 个（${result.summary.critical} critical, ${result.summary.high} high, ${result.summary.moderate} moderate, ${result.summary.low} low）`);
      if (ignoredCount > 0) {
        console.log(`   已忽略：${ignoredCount} 个`);
      }
      console.log(`   报告：${result.reportFilePath}`);

      // --fail-on 退出码
      if (opts.failOn) {
        const threshold = SEVERITY_RANK[opts.failOn as Severity];
        const hasFailing = result.vulnerabilities.some(
          (v) => SEVERITY_RANK[v.severity] >= threshold,
        );
        if (hasFailing) {
          console.error(`\n❌ 发现 ${opts.failOn} 及以上级别漏洞，CI 检查未通过`);
          process.exit(1);
        }
      }
    } catch (e) {
      console.error(`\n❌ 审计失败：${(e as Error).message}`);
      process.exit(1);
    }
  });

program.parse();
