import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { auditProject } from './index.js';
import { initLocale, t } from './core/i18n.js';
import type { AuditResult } from './types.js';

const AuditInputSchema = z.object({
  projectPath: z.string().optional().describe('Local project path'),
  remoteRepo: z.string().optional().describe('Remote repo identifier, format: github:owner/repo'),
  ref: z.string().optional().describe('Remote ref (branch / tag / commit SHA), default: main'),
  token: z.string().optional().describe('GitHub personal access token (required for private repos), or use GITHUB_TOKEN env var'),
  severity: z.enum(['low', 'moderate', 'high', 'critical']).optional().describe('Minimum severity level, default: low'),
  format: z.enum(['md', 'html']).optional().describe('Report format, default: md'),
  outputPath: z.string().optional().describe('Report output file path'),
});

export async function startMcpServer(): Promise<void> {
  // Initialize locale for MCP mode (uses env/system detection, no --lang)
  initLocale();

  // Silence spinner in MCP mode to avoid interfering with stdio protocol
  process.env.AUDIT_SILENT = '1';

  const server = new Server(
    { name: 'audit-mcp-cli', version: '1.0.0' },
    { capabilities: { tools: {} } },
  );

  // Register tool list
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: 'audit_dependencies',
        description:
          'Audit Node.js project dependencies for security vulnerabilities. Supports npm and pnpm projects, local or GitHub remote repos. ' +
          'Returns detailed vulnerability info (severity, CVSS score, dependency chains, fix suggestions) and generates Markdown/HTML report.',
        inputSchema: {
          type: 'object',
          properties: {
            projectPath: { type: 'string', description: 'Local project path' },
            remoteRepo: { type: 'string', description: 'Remote repo: github:owner/repo or https://github.com/owner/repo' },
            ref: { type: 'string', description: 'Remote ref (branch / tag / commit SHA), default: main' },
            token: { type: 'string', description: 'GitHub token (for private repos), or use GITHUB_TOKEN env var' },
            severity: { type: 'string', enum: ['low', 'moderate', 'high', 'critical'], description: 'Minimum severity level, default: low' },
            format: { type: 'string', enum: ['md', 'html'], description: 'Report format, default: md' },
            outputPath: { type: 'string', description: 'Report output file path' },
          },
        },
      },
    ],
  }));

  // Handle tool calls
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    if (request.params.name !== 'audit_dependencies') {
      return {
        content: [{ type: 'text', text: t('mcp.unknownTool', { name: request.params.name }) }],
        isError: true,
      };
    }

    const raw = request.params.arguments ?? {};
    const parsed = AuditInputSchema.safeParse(raw);
    if (!parsed.success) {
      return {
        content: [{ type: 'text', text: t('mcp.validationFailed', { message: parsed.error.message ?? 'Unknown error' }) }],
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
          { type: 'text', text: `${t('mcp.reportGenerated', { path: result.reportFilePath ?? '' })}\n\n${summary}` },
        ],
      };
    } catch (e) {
      return {
        content: [{ type: 'text', text: t('mcp.auditFailed', { message: (e as Error).message }) }],
        isError: true,
      };
    }
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);
}

function formatAuditResult(result: AuditResult): string {
  const lines: string[] = [];

  // Project metadata
  lines.push(t('mcp.project', { name: result.projectName }));
  const sourceLabel = result.auditSource === 'pnpm' ? 'pnpm audit' : 'npm audit';
  lines.push(t('mcp.source', { source: sourceLabel, version: result.npmVersion }));
  if (result.lockfileGenerated) {
    lines.push(t('report.lockfileWarning'));
  }
  lines.push('');
  lines.push(t('mcp.totalVulns', { total: result.summary.total, critical: result.summary.critical, high: result.summary.high, moderate: result.summary.moderate, low: result.summary.low }));

  if (result.vulnerabilities.length === 0) {
    lines.push('', `✅ ${t('report.noVulns')}`);
    return lines.join('\n');
  }

  lines.push('');
  const maxShow = 30;
  const vulns = result.vulnerabilities.slice(0, maxShow);

  vulns.forEach((v, i) => {
    const badge = v.severity.toUpperCase();
    const suffix = !v.isDirect && v.affectedBy ? `（${t('report.vulnFrom')} ${v.affectedBy}）` : '';
    lines.push(`### ${i + 1}. [${badge}] ${v.packageName} — ${v.title}${suffix}`);

    if (!v.isDirect && v.affectedBy) {
      lines.push(`- ${t('report.vulnPackage')}：${v.affectedBy} ${v.installedVersion}`);
    } else {
      lines.push(`- ${t('report.installedVersion')}：${v.installedVersion}`);
    }

    if (v.cvss) {
      lines.push(`- CVSS：${v.cvss.score}（${v.cvss.vectorString}）`);
    }
    if (v.url) {
      lines.push(`- Advisory：${v.url}`);
    }
    if (v.fixAvailable) {
      lines.push(`- ${t('report.fix')}：${v.fixAvailable.fixCommand}${v.fixAvailable.targetVersion ? `（${t('report.upgradeTo')} ${v.fixAvailable.targetVersion}）` : ''}`);
    } else {
      lines.push(`- ${t('report.fix')}：${t('report.noFix')}`);
    }

    if (v.dependencyChains.length > 0) {
      const chainStrs = v.dependencyChains.map((c, ci) => {
        if (c.path.length === 1) return `  ${ci + 1}. ${c.path[0]} — ${t('report.directDep')}`;
        return `  ${ci + 1}. ${c.path[0]} → ${c.path.slice(1).join(' → ')}`;
      });
      lines.push(`- ${t('report.depChain')}：`, ...chainStrs);
    }

    lines.push('');
  });

  if (result.vulnerabilities.length > maxShow) {
    lines.push(t('mcp.moreVulns', { count: result.vulnerabilities.length - maxShow, path: result.reportFilePath ?? '' }));
  }

  // Ignored vulnerabilities
  if (result.ignoredVulnerabilities && result.ignoredVulnerabilities.length > 0) {
    lines.push('', `### ${t('report.ignored')}`);
    for (const item of result.ignoredVulnerabilities) {
      const badge = item.vuln.severity.toUpperCase();
      const reason = item.reason ? `（${item.reason}）` : '';
      const expiry = item.expiresAt ? t('mcp.expiryLabel', { date: item.expiresAt }) : '';
      lines.push(`- [${badge}] ${item.vuln.packageName}: ${item.vuln.title}${reason}${expiry}`);
    }
  }

  return lines.join('\n');
}
