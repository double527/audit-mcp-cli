/**
 * audit-mcp-cli 统一内部模型 — 所有 parser 输出相同类型
 */

/** 严重级别，按严重程度降序 */
export type Severity = 'critical' | 'high' | 'moderate' | 'low';

/** 严重级别数值映射（用于比较） */
export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  moderate: 2,
  low: 1,
};

/** 包管理器类型 */
export type PackageManager = 'npm' | 'pnpm' | 'yarn';

/** 依赖链（环已拆解） */
export interface DependencyChain {
  /** 包名路径，如 ["my-project", "jest", "minimist"] */
  path: string[];
  /** 路径上是否存在环 */
  hasCycle: boolean;
  /** 环出现的包名，如 "B" */
  cycleAt: string | null;
}

/** 修复信息 */
export interface FixInfo {
  isFixable: boolean;
  /** 修复命令，如 "npm update minimist" */
  fixCommand: string;
  /** 目标版本，如 "1.2.6" */
  targetVersion: string;
  /** 是否涉及大版本升级 */
  isSemVerMajor: boolean;
}

/** CVSS 评分 */
export interface CvssInfo {
  /** 分数，如 8.1 */
  score: number;
  /** 向量字符串 */
  vectorString: string;
}

/** 漏洞数据（统一内部模型） */
export interface Vulnerability {
  /** 漏洞所在包名（直接漏洞=该包本身；传递漏洞=底层漏洞包，即 affectedBy） */
  packageName: string;
  /** 严重级别（多个 advisory 合并后取最高） */
  severity: Severity;
  /** 漏洞标题（取最高级别 advisory 的标题） */
  title: string;
  /** advisory 详情链接（含 GHSA ID，最高级别 advisory 的链接） */
  url: string;
  /** 所有 advisory 详情链接 */
  advisoryUrls: string[];
  /** advisory 内部编号（最高级别 advisory 的 ID） */
  advisorySource: number;
  /** 所有 advisory 内部编号 */
  advisorySources: number[];
  /** CWE 编号，如 ["CWE-502"]，可能为空数组（已合并去重） */
  cwe: string[];
  /** CVSS 评分，可能为 null（取最高分） */
  cvss: CvssInfo | null;
  /** 安装版本范围，如 "<=1.2.5" */
  installedVersion: string;
  /** 漏洞是否直接在该包中（vs 传递性漏洞） */
  isDirect: boolean;
  /** 传递性漏洞：实际有漏洞的包名；直接漏洞为 null */
  affectedBy: string | null;
  /** 传递性漏洞受影响的直接依赖列表（去重）；直接漏洞为空数组 */
  affectedDirectDeps: string[];
  /** 完整依赖路径（环已拆解，已合并去重） */
  dependencyChains: DependencyChain[];
  /** 修复信息，不可修复时为 null */
  fixAvailable: FixInfo | null;
  /** 合并的 advisory 数量（1 表示未合并） */
  mergedCount: number;
}

/** 漏洞摘要统计 */
export interface VulnerabilitySummary {
  total: number;
  critical: number;
  high: number;
  moderate: number;
  low: number;
}

/** 审计结果 */
export interface AuditResult {
  /** 项目名（取自 package.json name 字段） */
  projectName: string;
  /** 审计时间 ISO 字符串 */
  auditTime: string;
  /** 是否为自动生成的锁文件 */
  lockfileGenerated: boolean;
  /** npm 版本 */
  npmVersion: string;
  /** 审计数据来源：'npm' | 'pnpm' */
  auditSource?: string;
  /** 报告文件绝对路径（生成后才有） */
  reportFilePath?: string;
  /** 报告格式 */
  reportFormat?: 'md' | 'html';
  /** 漏洞列表（按严重级别降序，不含被忽略的） */
  vulnerabilities: Vulnerability[];
  /** 被忽略的漏洞列表 */
  ignoredVulnerabilities?: Array<{
    vuln: Vulnerability;
    reason?: string;
    expiresAt?: string;
  }>;
  /** 摘要统计 */
  summary: VulnerabilitySummary;
}

/** 审计选项（传入核心函数的参数） */
export interface AuditOptions {
  /** 本地项目路径 */
  projectPath?: string;
  /** 远程仓库标识，如 "github:owner/repo" */
  remoteRepo?: string;
  /** 远程引用（分支名 / Tag / SHA） */
  ref?: string;
  /** GitHub Token */
  token?: string;
  /** 最低显示级别 */
  severity?: Severity;
  /** 报告格式 */
  format?: 'md' | 'html';
  /** 输出文件路径 */
  output?: string;
  /** CI 失败阈值 */
  failOn?: Severity;
}

// ─── npm audit v7+ 原始 JSON 类型 ───

/** npm audit via 中的 advisory 对象 */
export interface NpmAdvisory {
  source: number;
  name: string;
  dependency: string;
  title: string;
  url: string;
  severity: Severity;
  cwe: string[];
  cvss: {
    score: number;
    vectorString: string;
  } | null;
  range: string;
}

/** npm audit vulnerabilities 中单个条目 */
export interface NpmVulnerabilityEntry {
  name: string;
  severity: Severity;
  isDirect: boolean;
  via: (NpmAdvisory | string)[];
  effects: string[];
  range: string;
  nodes: string[];
  fixAvailable: { name: string; version: string; isSemVerMajor: boolean } | boolean;
}

/** npm audit v7+ JSON 顶层结构 */
export interface NpmAuditJson {
  auditReportVersion: number;
  vulnerabilities: Record<string, NpmVulnerabilityEntry>;
  metadata: {
    vulnerabilities: {
      info: number;
      low: number;
      moderate: number;
      high: number;
      critical: number;
      total: number;
    };
    dependencies: {
      prod: number;
      dev: number;
      optional: number;
      peer: number;
      peerOptional: number;
      total: number;
    };
  };
}

// ─── package-lock.json 类型 ───

/** package-lock.json v2/v3 结构 */
export interface PackageLockJson {
  name: string;
  lockfileVersion: 2 | 3;
  packages: Record<string, {
    name?: string;
    version?: string;
    dependencies?: Record<string, string>;
    requires?: Record<string, string>;
  }>;
}

// ─── pnpm audit JSON 类型 ───

/** pnpm audit advisory 中的 findings */
export interface PnpmFinding {
  version: string;
  paths: string[];
}

/** pnpm audit advisories 中单个条目（兼容 pnpm 10.x / 11.x） */
export interface PnpmAdvisory {
  findings: PnpmFinding[];
  title: string;
  severity: Severity;
  module_name: string;
  vulnerable_versions: string;
  /** pnpm 10.x 有此字段，11.x 已移除 */
  recommendation?: string;
  patched_versions: string;
  /** pnpm 10.x 有此字段，11.x 已移除 */
  cves?: string[];
  github_advisory_id: string;
  /** pnpm 10.x 有此字段，11.x 已移除 */
  cvss?: { score: number; vectorString: string } | null;
  /** pnpm 10.x 为 string[]，11.x 为逗号分隔字符串 */
  cwe: string[] | string;
  url: string;
  id: number;
}

/** pnpm audit actions 中单个条目 */
export interface PnpmAction {
  action: string;
  module: string;
  target: string;
  depth: number;
  resolves: Array<{
    id: number;
    path: string;
    dev: boolean;
    optional: boolean;
    bundled: boolean;
  }>;
}

/** pnpm audit --json 顶层结构 */
export interface PnpmAuditJson {
  actions: PnpmAction[];
  advisories: Record<string, PnpmAdvisory>;
  muted: unknown[];
  metadata: {
    vulnerabilities: {
      info: number;
      low: number;
      moderate: number;
      high: number;
      critical: number;
    };
    dependencies: number;
    devDependencies: number;
    optionalDependencies: number;
    totalDependencies: number;
  };
}
