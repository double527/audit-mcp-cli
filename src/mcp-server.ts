import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { auditProject } from './index.js';
import type { AuditResult } from './types.js';

const AuditInputSchema = z.object({
  projectPath: z.string().optional().describe('本地项目路径'),
  remoteRepo: z.string().optional().describe('远程仓库标识，格式 github:owner/repo'),
  ref: z.string().optional().describe('远程引用（分支名 / Tag / Commit SHA），默认 main'),
  token: z.string().optional().describe('GitHub 访问令牌（私有仓库需要），也可通过 GITHUB_TOKEN 环境变量设置'),
  severity: z.enum(['low', 'moderate', 'high', 'critical']).optional().describe('最低显示级别，默认 low'),
  format: z.enum(['md', 'html']).optional().describe('报告格式，默认 md'),
  outputPath: z.string().optional().describe('报告输出文件路径'),
});

export async function startMcpServer(): Promise<void> {
  // MCP 模式静默 spinner，避免干扰 stdio 协议
  process.env.AUDIT_SILENT = '1';

  const server = new Server(
    { name: 'audit-mcp-cli', version: '1.0.0' },
    { capabilities: { tools: {} } },
  );

  // 注册工具列表
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: 'audit_dependencies',
        description:
          '审计 Node.js 项目的依赖安全漏洞。支持 npm 和 pnpm 项目，可审计本地项目或 GitHub 远程仓库。' +
          '返回每个漏洞的详细信息（严重级别、CVSS 分数、依赖链、修复方案），并生成 Markdown 或 HTML 报告文件。',
        inputSchema: {
          type: 'object',
          properties: {
            projectPath: { type: 'string', description: '本地项目路径' },
            remoteRepo: { type: 'string', description: '远程仓库标识，格式：github:owner/repo 或 https://github.com/owner/repo' },
            ref: { type: 'string', description: '远程引用（分支名 / Tag / Commit SHA），默认 main' },
            token: { type: 'string', description: 'GitHub 访问令牌（审计私有仓库需要），也可通过 GITHUB_TOKEN 环境变量设置' },
            severity: { type: 'string', enum: ['low', 'moderate', 'high', 'critical'], description: '最低显示级别，默认 low' },
            format: { type: 'string', enum: ['md', 'html'], description: '报告格式，默认 md' },
            outputPath: { type: 'string', description: '报告输出文件路径' },
          },
        },
      },
    ],
  }));

  // 处理工具调用
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    if (request.params.name !== 'audit_dependencies') {
      return {
        content: [{ type: 'text', text: `未知工具：${request.params.name}` }],
        isError: true,
      };
    }

    const raw = request.params.arguments ?? {};
    const parsed = AuditInputSchema.safeParse(raw);
    if (!parsed.success) {
      return {
        content: [{ type: 'text', text: `参数校验失败：${parsed.error.message}` }],
        isError: true,
      };
    }

    const args = parsed.data;
    const token = args.token || process.env.GITHUB_TOKEN;
    const defaultFormat = (process.env.DEP_AUDIT_FORMAT as 'md' | 'html') || args.format || 'md';

    try {
      const result = await auditProject({
        projectPath: args.projectPath,
        remoteRepo: args.remoteRepo,
        ref: args.ref,
        token,
        format: defaultFormat,
        output: args.outputPath,
        severity: args.severity,
      });

      const summary = formatAuditResult(result);
      return {
        content: [
          { type: 'text', text: `报告已生成：${result.reportFilePath}\n\n${summary}` },
        ],
      };
    } catch (e) {
      return {
        content: [{ type: 'text', text: `审计失败：${(e as Error).message}` }],
        isError: true,
      };
    }
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);
}

function formatAuditResult(result: AuditResult): string {
  const lines: string[] = [];

  // 项目元信息
  lines.push(`项目：${result.projectName}`);
  lines.push(`来源：${result.auditSource === 'pnpm' ? 'pnpm audit' : 'npm audit'} (npm v${result.npmVersion})`);
  if (result.lockfileGenerated) {
    lines.push('⚠️ 此审计基于自动生成的锁文件，可能与项目实际依赖树有差异');
  }
  lines.push('');
  lines.push(`漏洞总数：${result.summary.total}（Critical: ${result.summary.critical}, High: ${result.summary.high}, Moderate: ${result.summary.moderate}, Low: ${result.summary.low}）`);

  if (result.vulnerabilities.length === 0) {
    lines.push('', '✅ 未发现已知漏洞。');
    return lines.join('\n');
  }

  lines.push('');
  const maxShow = 30;
  const vulns = result.vulnerabilities.slice(0, maxShow);

  vulns.forEach((v, i) => {
    const badge = v.severity.toUpperCase();
    const suffix = !v.isDirect && v.affectedBy ? `（漏洞源于 ${v.affectedBy}）` : '';
    lines.push(`### ${i + 1}. [${badge}] ${v.packageName} — ${v.title}${suffix}`);

    if (!v.isDirect && v.affectedBy) {
      lines.push(`- 漏洞包：${v.affectedBy} ${v.installedVersion}`);
    } else {
      lines.push(`- 安装版本：${v.installedVersion}`);
    }

    if (v.cvss) {
      lines.push(`- CVSS：${v.cvss.score}（${v.cvss.vectorString}）`);
    }
    if (v.url) {
      lines.push(`- Advisory：${v.url}`);
    }
    if (v.fixAvailable) {
      lines.push(`- 修复方案：${v.fixAvailable.fixCommand}${v.fixAvailable.targetVersion ? `（升级到 ${v.fixAvailable.targetVersion}）` : ''}`);
    } else {
      lines.push('- 修复方案：暂无可用修复');
    }

    if (v.dependencyChains.length > 0) {
      const chainStrs = v.dependencyChains.map((c, ci) => {
        if (c.path.length === 1) return `  ${ci + 1}. ${c.path[0]} — 直接依赖`;
        return `  ${ci + 1}. ${c.path[0]} → ${c.path.slice(1).join(' → ')}`;
      });
      lines.push(`- 依赖链：`, ...chainStrs);
    }

    lines.push('');
  });

  if (result.vulnerabilities.length > maxShow) {
    lines.push(`... 还有 ${result.vulnerabilities.length - maxShow} 个漏洞，完整报告见 ${result.reportFilePath}`);
  }

  // 已忽略的漏洞
  if (result.ignoredVulnerabilities && result.ignoredVulnerabilities.length > 0) {
    lines.push('', '### 已忽略的漏洞');
    for (const item of result.ignoredVulnerabilities) {
      const badge = item.vuln.severity.toUpperCase();
      const reason = item.reason ? `（${item.reason}）` : '';
      const expiry = item.expiresAt ? `，到期 ${item.expiresAt}` : '';
      lines.push(`- [${badge}] ${item.vuln.packageName}: ${item.vuln.title}${reason}${expiry}`);
    }
  }

  return lines.join('\n');
}
