import semver from 'semver';
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
    // pnpm 11.x 移除了 actions 和 muted 字段，补默认值以兼容
    parsed.actions ??= [];
    parsed.muted ??= [];
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

  // 每个 advisory 产出一条 Vulnerability（以漏洞包为中心）
  const rawVulns = advisories.map((adv) => parseAdvisory(adv));

  // 按 (affectedBy/packageName, advisorySources) 合并同漏洞包跨直接依赖的条目
  const vulnerabilities = mergeVulnerabilities(rawVulns);

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
 * 解析单个 advisory，以漏洞包为中心产出一条记录
 *
 * 不再按直接依赖拆分。所有依赖链、受影响的直接依赖都收拢到同一条记录中。
 */
function parseAdvisory(adv: PnpmAdvisory): Vulnerability {
  const chains = extractChains(adv);

  // 判断是否为直接依赖漏洞：链条只有 1 层（链头就是漏洞包本身）
  const isDirectVuln = chains.length === 0 || chains.every(c => c.path.length <= 1);

  if (isDirectVuln) {
    // 直接依赖漏洞：packageName = 漏洞包本身
    return buildVulnerability(adv, chains, true, adv.module_name, null, []);
  }

  // 传递性漏洞：收集所有受影响的直接依赖
  const directDeps = [...new Set(chains.map(c => c.path[0]).filter(Boolean))];
  return buildVulnerability(adv, chains, false, adv.module_name, adv.module_name, directDeps);
}

function buildVulnerability(
  adv: PnpmAdvisory,
  chains: DependencyChain[],
  isDirectVuln: boolean,
  packageName: string,
  affectedBy: string | null,
  affectedDirectDeps: string[],
): Vulnerability {
  // 获取当前安装版本（从 findings 中取第一个）
  const currentVersion = adv.findings[0]?.version || '';

  // 修复建议：基于 patched_versions（recommendation 在 pnpm 11 已移除）
  let fixAvailable: FixInfo | null = null;
  if (adv.patched_versions) {
    // 使用 semver.minVersion() 获取满足条件的最小版本
    const minVer = semver.minVersion(adv.patched_versions);
    const target = minVer?.version || '';

    if (target) {
      // 判断是否 major 升级
      const isSemVerMajor = currentVersion
        ? semver.diff(currentVersion, target) === 'major'
        : false;

      if (isDirectVuln) {
        // 直接漏洞：升级该包本身
        fixAvailable = {
          isFixable: true,
          fixCommand: `pnpm update ${adv.module_name}`,
          targetVersion: target,
          isSemVerMajor,
        };
      } else {
        // 传递性漏洞：推荐升级直接依赖，备选使用 pnpm.overrides
        const directDepsCmd = affectedDirectDeps.length > 0
          ? `pnpm update ${affectedDirectDeps.join(' ')}`
          : `pnpm update ${adv.module_name}`;

        fixAvailable = {
          isFixable: true,
          fixCommand: directDepsCmd,
          targetVersion: '', // 传递性漏洞：直接依赖的版本无法确定，不显示
          isSemVerMajor,
          alternativeFix: {
            description: `或使用 pnpm.overrides 强制指定 ${adv.module_name} 版本（需 >= ${target}）`,
            command: `"pnpm": { "overrides": { "${adv.module_name}": ">=${target}" } }`,
          },
        };
      }
    }
  }

  // cwe 兼容：pnpm 10.x 为 string[]，11.x 为逗号分隔字符串
  const normalizedCwe: string[] = typeof adv.cwe === 'string'
    ? adv.cwe.split(',').map((s) => s.trim()).filter(Boolean)
    : adv.cwe;

  return {
    packageName,
    severity: adv.severity as Severity,
    title: adv.title,
    url: adv.url,
    advisoryUrls: [adv.url],
    advisorySource: adv.id,
    advisorySources: [adv.id],
    cwe: normalizedCwe,
    cvss: adv.cvss ?? null,
    installedVersion: adv.vulnerable_versions,
    isDirect: isDirectVuln,
    affectedBy,
    affectedDirectDeps,
    dependencyChains: chains,
    fixAvailable,
    mergedCount: 1,
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

/**
 * 按 (漏洞包名) 分组合并
 *
 * 传递漏洞：key = affectedBy
 * 直接漏洞：key = packageName
 *
 * 同一漏洞包的不同 advisory 全部合并到一起，实现：
 * - postcss（10 个直接依赖）→ 1 条（包含所有 advisory 和所有依赖链）
 * - hono（11 个 advisory + 2 个直接依赖）→ 1 条
 * - axios（15 个 advisory）→ 1 条
 *
 * 合并规则：
 * - severity → 取最高级别
 * - advisorySource → 保留最高级别的那个（向后兼容）
 * - advisorySources → 合并所有
 * - advisoryUrls → 合并去重
 * - title → 最高级别 advisory 的标题
 * - cwe → 合并去重
 * - cvss → 取 score 最高的
 * - dependencyChains → 合并去重
 * - affectedDirectDeps → 合并去重
 * - fixAvailable → 取最高级别 advisory 的
 * - mergedCount → 合并了几条
 */
function mergeVulnerabilities(vulns: Vulnerability[]): Vulnerability[] {
  const groups = new Map<string, Vulnerability[]>();

  for (const v of vulns) {
    // 以漏洞包名作为合并 key（不包含 advisorySource）
    const vulnPkg = v.isDirect ? v.packageName : (v.affectedBy ?? v.packageName);
    const key = vulnPkg;

    let group = groups.get(key);
    if (!group) {
      group = [];
      groups.set(key, group);
    }
    group.push(v);
  }

  const merged: Vulnerability[] = [];
  for (const group of groups.values()) {
    if (group.length === 1) {
      // 单条无需合并，但确保新字段有值
      const v = group[0];
      merged.push({
        ...v,
        advisorySources: v.advisorySources ?? [v.advisorySource],
        advisoryUrls: v.advisoryUrls ?? [v.url],
        affectedDirectDeps: v.affectedDirectDeps ?? [],
        mergedCount: v.mergedCount ?? 1,
      });
      continue;
    }

    // 按 severity 降序排列，取最高级别的作为 primary
    group.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);
    const primary = group[0];

    // 合并 advisorySources
    const advisorySources = [...new Set(group.flatMap((v) => v.advisorySources))];

    // 合并 advisoryUrls（去重）
    const advisoryUrls = [...new Set(group.flatMap((v) => v.advisoryUrls).filter(Boolean))];

    // 合并 cwe（去重）
    const cwe = [...new Set(group.flatMap((v) => v.cwe))];

    // 合并 cvss：取 score 最高的
    const cvssCandidates = group.map((v) => v.cvss).filter((c): c is NonNullable<typeof c> => c !== null);
    const cvss = cvssCandidates.length > 0
      ? cvssCandidates.reduce((best, c) => c.score > best.score ? c : best)
      : null;

    // 合并 dependencyChains（按 path key 去重）
    const chainMap = new Map<string, DependencyChain>();
    for (const v of group) {
      for (const chain of v.dependencyChains) {
        const key = chain.path.join('→');
        if (!chainMap.has(key)) {
          chainMap.set(key, chain);
        }
      }
    }
    const dependencyChains = [...chainMap.values()]
      .sort((a, b) => a.path.length - b.path.length);

    // 合并 affectedDirectDeps（去重）
    const affectedDirectDeps = [...new Set(group.flatMap((v) => v.affectedDirectDeps))];

    // 选择最佳 fixAvailable：优先选有 targetVersion 的
    const fixCandidate = group.find(v => v.fixAvailable?.targetVersion) ?? primary;

    merged.push({
      packageName: primary.packageName,
      severity: primary.severity,
      title: primary.title,
      url: primary.url,
      advisoryUrls,
      advisorySource: primary.advisorySource,
      advisorySources,
      cwe,
      cvss,
      installedVersion: primary.installedVersion,
      isDirect: primary.isDirect,
      affectedBy: primary.affectedBy,
      affectedDirectDeps,
      dependencyChains,
      fixAvailable: fixCandidate.fixAvailable,
      mergedCount: group.reduce((sum, v) => sum + v.mergedCount, 1),
    });
  }

  // 按 severity 降序排序
  merged.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);
  return merged;
}
