import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

function formatAuditTime(): string {
  return new Intl.DateTimeFormat('sv-SE', {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    hour12: false,
  }).format(new Date());
}
import { SEVERITY_RANK } from '../../types.js';
import type {
  AuditResult,
  Vulnerability,
  DependencyChain,
  FixInfo,
  Severity,
  VulnerabilitySummary,
  NpmAuditJson,
  NpmVulnerabilityEntry,
  NpmAdvisory,
  PackageLockJson,
} from '../../types.js';

/**
 * 从 npm audit v7+ 原始 JSON 构建统一内部模型
 */
export async function parseNpmAudit(
  rawJson: string,
  projectPath: string,
  projectName: string,
): Promise<AuditResult> {
  let parsed: NpmAuditJson;
  try {
    parsed = JSON.parse(rawJson);
  } catch (e) {
    throw new Error(`npm audit 输出解析失败: ${(e as Error).message}`);
  }

  if (parsed.auditReportVersion !== 2) {
    throw new Error(
      `不支持的 npm audit 版本（auditReportVersion=${parsed.auditReportVersion}），需要 v7+ (auditReportVersion 2)`,
    );
  }

  const meta = parsed.metadata.vulnerabilities;
  const summary: VulnerabilitySummary = {
    total: meta.total,
    critical: meta.critical,
    high: meta.high,
    moderate: meta.moderate,
    low: meta.low,
  };

  const entries = Object.values(parsed.vulnerabilities);
  if (entries.length === 0) {
    return {
      projectName,
      auditTime: formatAuditTime(),
      lockfileGenerated: false,
      npmVersion: '',
      vulnerabilities: [],
      summary,
    };
  }

  // 构建依赖树（用于生成 dependency chains）
  const depTree = await buildDependencyTree(projectPath, projectName);

  const vulnerabilities = entries
    .map((entry) => parseVulnerabilityEntry(entry, depTree, projectName))
    .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);

  return {
    projectName,
    auditTime: formatAuditTime(),
    lockfileGenerated: false,
    npmVersion: '',
    vulnerabilities,
    summary,
  };
}

/**
 * 解析单个漏洞条目
 */
function parseVulnerabilityEntry(
  entry: NpmVulnerabilityEntry,
  depTree: DependencyTree | null,
  projectName: string,
): Vulnerability {
  const advisoryItems = entry.via.filter((v): v is NpmAdvisory => typeof v === 'object');
  const stringItems = entry.via.filter((v): v is string => typeof v === 'string');

  // 判断是否为直接漏洞
  const hasOwnAdvisory = advisoryItems.some((a) => a.name === entry.name);
  const isDirect = hasOwnAdvisory;
  const affectedBy = !isDirect && stringItems.length > 0 ? stringItems[0] : null;

  // 从 advisory 对象提取漏洞详情
  const advisory = advisoryItems[0];
  const title = advisory?.title ?? entry.name;
  const url = advisory?.url ?? '';
  const advisorySource = advisory?.source ?? 0;
  const cwe = advisory?.cwe ?? [];
  const cvss = advisory?.cvss ?? null;
  const installedVersion = entry.range;

  // 构建 dependency chains
  const chains = depTree
    ? findDependencyChains(depTree, entry.name, projectName)
    : [];

  // 处理 fixAvailable 三种形态
  const fixAvailable = normalizeFixAvailable(entry.fixAvailable, entry.name);

  return {
    packageName: entry.name,
    severity: entry.severity,
    title,
    url,
    advisorySource,
    cwe,
    cvss,
    installedVersion,
    isDirect,
    affectedBy,
    dependencyChains: chains,
    fixAvailable,
  };
}

/**
 * fixAvailable 三种形态统一转换
 */
function normalizeFixAvailable(
  raw: NpmVulnerabilityEntry['fixAvailable'],
  packageName: string,
): FixInfo | null {
  if (raw === false || raw === undefined) return null;
  if (raw === true) {
    return {
      isFixable: true,
      fixCommand: `npm update ${packageName}`,
      targetVersion: 'latest',
      isSemVerMajor: false,
    };
  }
  return {
    isFixable: true,
    fixCommand: `npm update ${raw.name}`,
    targetVersion: raw.version,
    isSemVerMajor: raw.isSemVerMajor,
  };
}

// ─── 依赖树构建 ───

interface DependencyTree {
  /** 包名 → 直接依赖的包名列表 */
  children: Map<string, Set<string>>;
  /** 根项目名 */
  rootName: string;
}

/**
 * 从 package-lock.json 的 packages 树构建依赖树
 *
 * packages 键格式：
 *   ""                                          → 根项目
 *   "node_modules/A"                            → 顶层依赖 A
 *   "node_modules/A/node_modules/B"             → A 的依赖 B
 *   "node_modules/A/node_modules/B/node_modules/C" → B 的依赖 C
 */
async function buildDependencyTree(
  projectPath: string,
  projectName: string,
): Promise<DependencyTree | null> {
  let raw: string;
  try {
    raw = await readFile(join(projectPath, 'package-lock.json'), 'utf-8');
  } catch {
    return null;
  }

  let lockfile: PackageLockJson;
  try {
    lockfile = JSON.parse(raw);
  } catch {
    return null;
  }

  if (!lockfile.packages || typeof lockfile.packages !== 'object') {
    return null;
  }

  const children = new Map<string, Set<string>>();
  children.set(projectName, new Set());

  // 解析 packages 树，提取每对 父包→子包 关系
  for (const [pkgPath, pkgInfo] of Object.entries(lockfile.packages)) {
    if (pkgPath === '') continue; // 根项目，后面单独处理

    // 从 "node_modules/A/node_modules/B" 提取各段
    // 去掉 "node_modules/" 前缀，按 "/node_modules/" 拆分
    const segments = parseNodeModulesPath(pkgPath);
    if (segments.length === 0) continue;

    const ownName = segments[segments.length - 1];

    // 确保 ownName 在 children map 中有条目
    if (!children.has(ownName)) {
      children.set(ownName, new Set());
    }

    // 父节点：如果只有一段 (e.g. ["jest"])，父节点是根项目
    // 如果有多段 (e.g. ["jest", "jest-cli"])，父节点是倒数第二个段
    const parentName =
      segments.length === 1 ? projectName : segments[segments.length - 2];

    if (!children.has(parentName)) {
      children.set(parentName, new Set());
    }
    children.get(parentName)!.add(ownName);
  }

  // 处理根项目的 dependencies（packages[""].dependencies）
  const rootPkg = lockfile.packages[''];
  if (rootPkg?.dependencies) {
    for (const depName of Object.keys(rootPkg.dependencies)) {
      children.get(projectName)!.add(depName);
      if (!children.has(depName)) {
        children.set(depName, new Set());
      }
    }
  }

  // 处理各包的 dependencies 字段（优先于从路径推断的关系）
  for (const [pkgPath, pkgInfo] of Object.entries(lockfile.packages)) {
    if (pkgPath === '') continue;
    const segments = parseNodeModulesPath(pkgPath);
    if (segments.length === 0) continue;
    const ownName = segments[segments.length - 1];

    // packages 中的 dependencies 字段提供更准确的依赖关系
    const deps = pkgInfo.dependencies ?? pkgInfo.requires;
    if (deps) {
      const childSet = children.get(ownName);
      if (childSet) {
        for (const depName of Object.keys(deps)) {
          childSet.add(depName);
        }
      }
    }
  }

  return { children, rootName: projectName };
}

/**
 * 将 "node_modules/A/node_modules/B/node_modules/C" 解析为 ["A", "B", "C"]
 */
function parseNodeModulesPath(pkgPath: string): string[] {
  if (!pkgPath.startsWith('node_modules/')) return [];
  // "node_modules/A/node_modules/B" → "A/node_modules/B"
  const rest = pkgPath.slice('node_modules/'.length);
  // 按 "/node_modules/" 拆分
  return rest.split('/node_modules/');
}

/**
 * DFS 从根项目出发查找所有到目标包的依赖链
 * 返回结果按源头依赖（package.json 中的直接依赖）去重，每个源头只保留最短路径
 */
function findDependencyChains(
  tree: DependencyTree,
  targetPkg: string,
  projectName: string,
): DependencyChain[] {
  // 收集所有链（含根项目名）
  const allChains: DependencyChain[] = [];

  function dfs(current: string, path: string[], visited: Set<string>): void {
    if (current === targetPkg && path.length > 1) {
      allChains.push({
        path: [...path],
        hasCycle: false,
        cycleAt: null,
      });
      return;
    }

    const deps = tree.children.get(current);
    if (!deps) return;

    for (const dep of deps) {
      if (visited.has(dep)) continue;
      visited.add(dep);
      path.push(dep);
      dfs(dep, path, visited);
      path.pop();
      visited.delete(dep);
    }
  }

  const rootDeps = tree.children.get(projectName);
  if (!rootDeps) return [];

  const visited = new Set<string>([projectName]);
  for (const dep of rootDeps) {
    visited.add(dep);
    dfs(dep, [projectName, dep], visited);
    visited.delete(dep);
  }

  // 按源头依赖去重：path[1] 是源头（package.json 中的直接依赖）
  // 每个源头只保留最短路径
  const bestBySource = new Map<string, DependencyChain>();
  for (const chain of allChains) {
    const source = chain.path[1]; // 根项目之后的第一个包
    const existing = bestBySource.get(source);
    if (!existing || chain.path.length < existing.path.length) {
      bestBySource.set(source, chain);
    }
  }

  // 去掉根项目名前缀，按路径长度排序（最短的在前）
  const result: DependencyChain[] = [];
  for (const chain of bestBySource.values()) {
    result.push({
      path: chain.path.slice(1), // 去掉根项目名
      hasCycle: false,
      cycleAt: null,
    });
  }
  result.sort((a, b) => a.path.length - b.path.length);

  return result;
}
