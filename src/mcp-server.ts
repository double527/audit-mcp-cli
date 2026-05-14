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
  severity: z.enum(['low', 'moderate', 'high', 'critical']).optional().describe('最低显示级别，默认 low'),
  format: z.enum(['md', 'html']).optional().describe('报告格式，默认 md'),
  outputPath: z.string().optional().describe('报告输出文件路径'),
});

export async function startMcpServer(): Promise<void> {
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
          '审计项目的依赖漏洞。支持本地项目路径或 GitHub 远程仓库。返回结构化漏洞信息和报告文件路径。',
        inputSchema: {
          type: 'object',
          properties: {
            projectPath: { type: 'string', description: '本地项目路径' },
            remoteRepo: { type: 'string', description: '远程仓库标识，格式 github:owner/repo' },
            ref: { type: 'string', description: '远程引用（分支名 / Tag / Commit SHA），默认 main' },
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
    const token = process.env.GITHUB_TOKEN;
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

      // 返回：报告文件路径 + 结构化 JSON 元数据
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
  const lines: string[] = [
    `## 审计结果 — ${result.projectName}`,
    '',
    `漏洞总数：${result.summary.total}`,
    `- Critical: ${result.summary.critical}`,
    `- High: ${result.summary.high}`,
    `- Moderate: ${result.summary.moderate}`,
    `- Low: ${result.summary.low}`,
  ];

  if (result.vulnerabilities.length > 0) {
    lines.push('');
    for (const v of result.vulnerabilities.slice(0, 20)) {
      const badge = v.severity.toUpperCase();
      const direct = v.isDirect ? '' : ` (受影响: ${v.affectedBy})`;
      lines.push(`- [${badge}] ${v.packageName}: ${v.title}${direct}`);
    }
    if (result.vulnerabilities.length > 20) {
      lines.push(`... 还有 ${result.vulnerabilities.length - 20} 个漏洞`);
    }
  }

  return lines.join('\n');
}
