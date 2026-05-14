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
    .flatMap((adv) => parseAdvisory(adv))
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

/**
 * 解析单个 advisory，按直接依赖分组返回一条或多条漏洞记录
 *
 * 例如 lodash 被 element-plus 和 echarts 同时依赖，
 * 会返回两条记录分别报告 element-plus 和 echarts
 */
function parseAdvisory(adv: PnpmAdvisory): Vulnerability[] {
  const chains = extractChains(adv);

  // 判断是否为直接依赖漏洞：链条只有 1 层（链头就是漏洞包本身）
  const isDirectVuln = chains.length === 0 || chains.every(c => c.path.length <= 1);

  if (isDirectVuln) {
    // 直接依赖漏洞：直接一条记录
    return [buildVulnerability(adv, chains, true, adv.module_name, null)];
  }

  // 传递性漏洞：按链条的第一个包（直接依赖）分组
  const groups = new Map<string, DependencyChain[]>();
  for (const chain of chains) {
    const directPkg = chain.path[0];
    if (!directPkg) continue;
    if (!groups.has(directPkg)) {
      groups.set(directPkg, []);
    }
    groups.get(directPkg)!.push(chain);
  }

  const results: Vulnerability[] = [];
  for (const [directPkg, groupChains] of groups) {
    results.push(buildVulnerability(adv, groupChains, false, directPkg, adv.module_name));
  }
  return results;
}

function buildVulnerability(
  adv: PnpmAdvisory,
  chains: DependencyChain[],
  isDirectVuln: boolean,
  packageName: string,
  affectedBy: string | null,
): Vulnerability {
  // 修复建议：优先用 advisory 自带的 recommendation + patched_versions
  let fixAvailable: FixInfo | null = null;
  if (adv.patched_versions && adv.recommendation) {
    // patched_versions 格式: ">=1.15.1" 或 ""（无补丁）
    const target = adv.patched_versions.replace(/^>=?\s*/, '');
    // 如果是传递性漏洞，修复命令应该是升级直接依赖，而不是底层包
    const fixPkg = isDirectVuln ? adv.module_name : packageName;
    fixAvailable = {
      isFixable: true,
      fixCommand: `pnpm update ${fixPkg}`,
      targetVersion: target || adv.recommendation.replace(/.*to version\s*/i, ''),
      isSemVerMajor: false, // pnpm 不提供此信息
    };
  }

  return {
    packageName,
    severity: adv.severity as Severity,
    title: adv.title,
    url: adv.url,
    advisorySource: adv.id,
    cwe: adv.cwe,
    cvss: adv.cvss,
    installedVersion: adv.vulnerable_versions,
    isDirect: isDirectVuln,
    affectedBy,
    dependencyChains: chains,
    fixAvailable,
  };
}

/**
 * 从 findings[].paths 提取依赖链
 * pnpm 格式: "apps\\web > element-plus > lodash-es" 或 "apps\\server > prisma@7.6.0 > hono@4.12.9"
 *
 * 返回的链条：去掉根项目前缀（如 "apps/web"），保留 "直接依赖 → ... → 漏洞包" 的路径
 * 例如: ["element-plus", "lodash-es"]，其中 element-plus 是源头直接依赖，lodash-es 是有漏洞的底层包
 */
function extractChains(adv: PnpmAdvisory): DependencyChain[] {
  const seen = new Set<string>();
  const chains: DependencyChain[] = [];

  for (const finding of adv.findings) {
    for (const rawPath of finding.paths) {
      // "apps\\web > element-plus > lodash-es" → ["apps/web", "element-plus", "lodash-es"]
      const parts = rawPath
        .split(/\s*>\s*/)
        .map((s) => s.replace(/\\/g, '/'))
        .map((s) => s.replace(/@[\d.]+$/, '')) // 去掉版本号: "hono@4.12.9" → "hono"
        .filter(Boolean);

      if (parts.length === 0) continue;

      // 去掉根项目前缀（如 "apps/web" 或项目名），保留源头依赖到漏洞包的路径
      // pnpm monorepo 路径: ["apps/web", "element-plus", "lodash-es"] → ["element-plus", "lodash-es"]
      // 非monorepo路径: ["lodash-es"] → ["lodash-es"]（直接依赖）
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
