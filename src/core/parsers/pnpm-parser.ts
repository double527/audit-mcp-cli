import { SEVERITY_RANK } from '../../types.js';
import type {
  AuditResult,
  DependencyChain,
  FixInfo,
  Severity,
  Vulnerability,
  VulnerabilitySummary,
  PnpmAuditJson,
  PnpmAdvisory,
} from '../../types.js';

function formatAuditTime(): string {
  return new Intl.DateTimeFormat('sv-SE', {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    hour12: false,
  }).format(new Date());
}

/**
 * 从 pnpm audit --json 原始输出构建统一内部模型
 */
export async function parsePnpmAudit(
  rawJson: string,
  projectName: string,
): Promise<AuditResult> {
  let parsed: PnpmAuditJson;
  try {
    parsed = JSON.parse(rawJson);
  } catch (e) {
    throw new Error(`pnpm audit 输出解析失败: ${(e as Error).message}`);
  }

  const meta = parsed.metadata.vulnerabilities;
  const summary: VulnerabilitySummary = {
    total: meta.info + meta.low + meta.moderate + meta.high + meta.critical,
    critical: meta.critical,
    high: meta.high,
    moderate: meta.moderate,
    low: meta.low,
  };

  const advisories = Object.values(parsed.advisories);
  if (advisories.length === 0) {
    return {
      projectName,
      auditTime: formatAuditTime(),
      lockfileGenerated: false,
      npmVersion: '',
      auditSource: 'pnpm',
      vulnerabilities: [],
      summary,
    };
  }

  const vulnerabilities = advisories
    .map((adv) => parseAdvisory(adv))
    .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);

  return {
    projectName,
    auditTime: formatAuditTime(),
    lockfileGenerated: false,
    npmVersion: '',
    auditSource: 'pnpm',
    vulnerabilities,
    summary,
  };
}

function parseAdvisory(adv: PnpmAdvisory): Vulnerability {
  const chains = extractChains(adv);

  // 修复建议：优先用 advisory 自带的 recommendation + patched_versions
  let fixAvailable: FixInfo | null = null;
  if (adv.patched_versions && adv.recommendation) {
    // patched_versions 格式: ">=1.15.1" 或 ""（无补丁）
    const target = adv.patched_versions.replace(/^>=?\s*/, '');
    fixAvailable = {
      isFixable: true,
      fixCommand: `pnpm update ${adv.module_name}`,
      targetVersion: target || adv.recommendation.replace(/.*to version\s*/i, ''),
      isSemVerMajor: false, // pnpm 不提供此信息
    };
  }

  return {
    packageName: adv.module_name,
    severity: adv.severity as Severity,
    title: adv.title,
    url: adv.url,
    advisorySource: adv.id,
    cwe: adv.cwe,
    cvss: adv.cvss,
    installedVersion: adv.vulnerable_versions,
    isDirect: true, // pnpm 的每个 advisory 都是直接漏洞
    affectedBy: null,
    dependencyChains: chains,
    fixAvailable,
  };
}

/**
 * 从 findings[].paths 提取依赖链
 * pnpm 格式: "apps\\web > element-plus > lodash-es" 或 "apps\\server > prisma@7.6.0 > hono@4.12.9"
 */
function extractChains(adv: PnpmAdvisory): DependencyChain[] {
  const seen = new Set<string>();
  const chains: DependencyChain[] = [];

  for (const finding of adv.findings) {
    for (const rawPath of finding.paths) {
      // "apps\\web > element-plus > lodash-es" → ["apps/web", "element-plus", "lodash-es"]
      // 或者 "apps\\server > @prisma/client@7.6.0 > prisma@7.6.0 > hono@4.12.9"
      const parts = rawPath
        .split(/\s*>\s*/)
        .map((s) => s.replace(/\\/, '/'))
        .map((s) => s.replace(/@[\d.]+$/, '')) // 去掉版本号: "hono@4.12.9" → "hono"
        .filter(Boolean);

      if (parts.length === 0) continue;

      // 去掉根项目前缀（如 "apps/web"），保留源头依赖到漏洞包的路径
      // pnpm monorepo 路径: ["apps/web", "element-plus", "lodash-es"]
      // 非monorepo路径: ["axios@1.13.6"] 或 ["lodash-es"]
      const sourceIdx = parts.length > 1 ? 1 : 0;
      const chain = parts.slice(sourceIdx);

      if (chain.length === 0) continue;

      const key = chain.join('→');
      if (!seen.has(key)) {
        seen.add(key);
        chains.push({
          path: chain,
          hasCycle: false,
          cycleAt: null,
        });
      }
    }
  }

  // 按长度排序（最短在前）
  chains.sort((a, b) => a.path.length - b.path.length);
  return chains;
}
