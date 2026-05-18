export type Locale = 'en' | 'zh-CN';

type MessageMap = Record<string, string>;

const en: MessageMap = {
  // CLI descriptions
  'cli.description': 'Lightweight dependency vulnerability audit tool',
  'cli.opt.path': 'Local project path',
  'cli.opt.remote': 'Remote repo (github:owner/repo or https://github.com/owner/repo)',
  'cli.opt.ref': 'Remote ref (branch / tag / SHA)',
  'cli.opt.token': 'GitHub personal access token',
  'cli.opt.format': 'Report format (md or html)',
  'cli.opt.output': 'Output file path',
  'cli.opt.severity': 'Minimum severity (low / moderate / high / critical)',
  'cli.opt.failOn': 'CI fail threshold (low / moderate / high / critical)',
  'cli.opt.mcp': 'Start as MCP Server',
  'cli.opt.lang': 'Language (en or zh-CN)',

  // CLI errors
  'cli.error.pathRemoteExclusive': 'Error: --path and --remote cannot be used together',
  'cli.error.tokenNeedsRemote': 'Error: --token can only be used with --remote',
  'cli.error.refNeedsRemote': 'Error: --ref can only be used with --remote',
  'cli.error.invalidSeverity': 'Error: invalid --severity value ({value}), options: {options}',
  'cli.error.invalidFailOn': 'Error: invalid --fail-on value ({value}), options: {options}',
  'cli.error.invalidFormat': 'Error: invalid --format value ({value}), options: md/html',

  // CLI output
  'cli.auditComplete': 'Audit complete — {name}',
  'cli.vulnCount': '   Vulnerabilities: {count} ({critical} critical, {high} high, {moderate} moderate, {low} low)',
  'cli.ignoredCount': '   Ignored: {count}',
  'cli.reportPath': '   Report: {path}',
  'cli.ciFailed': '\n❌ Found {level}+ severity vulnerabilities, CI check failed',
  'cli.auditFailed': '\n❌ Audit failed: {message}',

  // Audit process
  'audit.starting': '\n🔍 audit-mcp-cli starting audit...\n',
  'audit.checkingNpm': 'Checking npm environment...',
  'audit.fetchingRemote': 'Fetching remote repo {owner}/{repo} ({ref})...',
  'audit.remoteReady': 'Remote repo files ready',
  'audit.generatingPnpmLockfile': 'Generating/checking pnpm-lock.yaml...',
  'audit.generatingNpmLockfile': 'Generating/checking package-lock.json...',
  'audit.lockfileReady': 'Lockfile ready',
  'audit.runningAudit': 'Running {manager} audit...',
  'audit.auditDone': 'Audit done ({source})',
  'audit.parsing': 'Parsing audit results...',
  'audit.parseDone': 'Parse done, found {count} vulnerabilities',
  'audit.generatingReport': 'Generating report...',
  'audit.reportSaved': 'Report saved: {path}',
  'audit.pkgManager': 'Package manager: {manager}',
  'audit.unsupportedPlatform': 'Unsupported platform: {platform}, only GitHub is supported',
  'audit.cannotGeneratePnpmLockfile': 'Cannot generate pnpm-lock.yaml: {message}',
  'audit.cannotGenerateNpmLockfile': 'Cannot generate package-lock.json: {hint}',
  'audit.yarnLockfileHint': 'This project uses yarn. Attempted npm lockfile generation. Please run manually: npm install --package-lock-only --legacy-peer-deps',

  // Core errors
  'error.pnpmNotFound': 'pnpm not found. Please install: npm install -g pnpm',
  'error.npmNotFound': 'npm not found. Please install Node.js >= 18',
  'error.npmVersionLow': 'npm version too low (current {version}, need >= 7). Please upgrade Node.js',
  'error.pnpmAuditTimeout': 'pnpm audit timed out (>120s). Check network or registry config',
  'error.pnpmAuditFailed': 'pnpm audit failed: {stderr}',
  'error.pnpmAuditNoOutput': 'pnpm audit returned no output',
  'error.pnpmAuditBadFormat': 'pnpm audit output format error, cannot parse as JSON',
  'error.npmAuditTimeout': 'npm audit timed out (>60s). Check network or registry config',
  'error.npmAuditFailed': 'npm audit failed: {stderr}',
  'error.npmAuditNoOutput': 'npm audit returned no output. Please confirm npm >= 7',
  'error.npmAuditBadFormat': 'npm audit output format error, cannot parse as JSON. Please confirm npm >= 7',
  'error.npmAuditEndpointError': 'npm audit request failed: {message} (HTTP {statusCode}). Check registry config or network',
  'error.npmAuditNotReport': 'npm audit did not return a valid report. Check network or whether registry supports audit API',
  'error.remoteParseFailed': 'Cannot parse remote repo identifier: {remote}. Supported formats: github:owner/repo or https://github.com/owner/repo',
  'error.githubFileNotFound': 'File not found: {path} (repo {owner}/{repo}, ref {ref}). May be no access or wrong path',
  'error.githubRateLimited': 'GitHub API rate limited. Use --token or try again later',
  'error.githubAuthFailed': 'GitHub authentication failed. Please check --token',
  'error.githubApiError': 'GitHub API error: {status} {text}',
  'error.githubTreeApiError': 'GitHub Tree API error: {status}',
  'error.githubFileNotInTree': 'File not found in Tree API: {path}',
  'error.githubBlobApiError': 'GitHub Blob API error: {status}',

  // Report labels
  'report.title': 'Dependency Audit Report',
  'report.auditTime': 'Audit time',
  'report.dataSource': 'Data source',
  'report.lockfileWarning': '⚠️ This audit is based on an auto-generated lockfile, which may differ from the actual dependency tree',
  'report.summary': 'Summary',
  'report.severity': 'Severity',
  'report.count': 'Count',
  'report.total': 'Total',
  'report.noVulns': 'No known vulnerabilities found.',
  'report.installedVersion': 'Installed version',
  'report.vulnPackage': 'Vulnerable package',
  'report.fix': 'Fix',
  'report.noFix': 'No fix available',
  'report.depChain': 'Dependency chain',
  'report.directDep': 'direct dependency',
  'report.vulnFrom': 'vulnerability from',
  'report.majorUpgrade': '⚠️ Major version upgrade — ',
  'report.upgradeTo': 'upgrade to',
  'report.ignored': 'Ignored',
  'report.severityLevel': 'Severity level',
  'report.ignoreReason': 'Ignore reason',
  'report.notSpecified': 'Not specified',
  'report.ignoreExpiry': 'Ignore expires',
  'report.moreAdvisories': '(+{count} other advisories)',
  'report.advisories': 'Advisories',
  'report.affectedDirectDeps': 'Affected direct dependencies',
  'report._htmlLang': 'en',

  // MCP
  'mcp.reportGenerated': 'Report generated: {path}',
  'mcp.auditFailed': 'Audit failed: {message}',
  'mcp.unknownTool': 'Unknown tool: {name}',
  'mcp.validationFailed': 'Validation failed: {message}',
  'mcp.project': 'Project: {name}',
  'mcp.source': 'Source: {source} (npm v{version})',
  'mcp.totalVulns': 'Total vulnerabilities: {total} (Critical: {critical}, High: {high}, Moderate: {moderate}, Low: {low})',
  'mcp.noVulns': 'No known vulnerabilities found.',
  'mcp.moreVulns': '... and {count} more vulnerabilities. See full report: {path}',
  'mcp.ignoredSection': 'Ignored vulnerabilities',
  'mcp.expiryLabel': ', expires {date}',
};

const zhCN: MessageMap = {
  // CLI descriptions
  'cli.description': '轻量级依赖漏洞审计工具',
  'cli.opt.path': '本地项目路径',
  'cli.opt.remote': '远程仓库标识（github:owner/repo 或 https://github.com/owner/repo）',
  'cli.opt.ref': '远程引用（分支名 / Tag / SHA）',
  'cli.opt.token': 'GitHub 访问令牌',
  'cli.opt.format': '报告格式（md 或 html）',
  'cli.opt.output': '输出文件路径',
  'cli.opt.severity': '最低显示级别（low / moderate / high / critical）',
  'cli.opt.failOn': 'CI 失败阈值（low / moderate / high / critical）',
  'cli.opt.mcp': '以 MCP Server 模式启动',
  'cli.opt.lang': '语言（en 或 zh-CN）',

  // CLI errors
  'cli.error.pathRemoteExclusive': '错误：--path 和 --remote 不能同时使用',
  'cli.error.tokenNeedsRemote': '错误：--token 只能与 --remote 配合使用',
  'cli.error.refNeedsRemote': '错误：--ref 只能与 --remote 配合使用',
  'cli.error.invalidSeverity': '错误：--severity 值无效（{value}），可选：{options}',
  'cli.error.invalidFailOn': '错误：--fail-on 值无效（{value}），可选：{options}',
  'cli.error.invalidFormat': '错误：--format 值无效（{value}），可选：md/html',

  // CLI output
  'cli.auditComplete': '审计完成 — {name}',
  'cli.vulnCount': '   漏洞：{count} 个（{critical} critical, {high} high, {moderate} moderate, {low} low）',
  'cli.ignoredCount': '   已忽略：{count} 个',
  'cli.reportPath': '   报告：{path}',
  'cli.ciFailed': '\n❌ 发现 {level} 及以上级别漏洞，CI 检查未通过',
  'cli.auditFailed': '\n❌ 审计失败：{message}',

  // Audit process
  'audit.starting': '\n🔍 audit-mcp-cli 开始审计...\n',
  'audit.checkingNpm': '检查 npm 环境...',
  'audit.fetchingRemote': '拉取远程仓库 {owner}/{repo} ({ref})...',
  'audit.remoteReady': '远程仓库文件已就绪',
  'audit.generatingPnpmLockfile': '生成/检查 pnpm-lock.yaml...',
  'audit.generatingNpmLockfile': '生成/检查 package-lock.json...',
  'audit.lockfileReady': '锁文件就绪',
  'audit.runningAudit': '执行 {manager} audit...',
  'audit.auditDone': '审计完成 ({source})',
  'audit.parsing': '解析审计结果...',
  'audit.parseDone': '解析完成，发现 {count} 个漏洞',
  'audit.generatingReport': '生成报告...',
  'audit.reportSaved': '报告已保存: {path}',
  'audit.pkgManager': '包管理器: {manager}',
  'audit.unsupportedPlatform': '暂不支持平台：{platform}，仅支持 GitHub',
  'audit.cannotGeneratePnpmLockfile': '无法生成 pnpm-lock.yaml：{message}',
  'audit.cannotGenerateNpmLockfile': '无法生成 package-lock.json：{hint}',
  'audit.yarnLockfileHint': '当前项目使用 yarn，已尝试用 npm 生成 lockfile。请手动执行：npm install --package-lock-only --legacy-peer-deps',

  // Core errors
  'error.pnpmNotFound': '未检测到 pnpm，请先安装：npm install -g pnpm',
  'error.npmNotFound': '未检测到 npm，请安装 Node.js >= 18',
  'error.npmVersionLow': 'npm 版本过低（当前 {version}），需要 >= 7，请升级 Node.js',
  'error.pnpmAuditTimeout': 'pnpm audit 执行超时（>120s），请检查网络或 registry 配置',
  'error.pnpmAuditFailed': 'pnpm audit 执行失败: {stderr}',
  'error.pnpmAuditNoOutput': 'pnpm audit 未返回有效输出',
  'error.pnpmAuditBadFormat': 'pnpm audit 输出格式异常，无法解析为 JSON',
  'error.npmAuditTimeout': 'npm audit 执行超时（>60s），请检查网络或 registry 配置',
  'error.npmAuditFailed': 'npm audit 执行失败: {stderr}',
  'error.npmAuditNoOutput': 'npm audit 未返回有效输出，请确认 npm 版本 >= 7',
  'error.npmAuditBadFormat': 'npm audit 输出格式异常，无法解析为 JSON。请确认 npm 版本 >= 7',
  'error.npmAuditEndpointError': 'npm audit 请求失败: {message} (HTTP {statusCode})，请检查 registry 配置或网络',
  'error.npmAuditNotReport': 'npm audit 未返回有效审计报告，请检查网络连接或 registry 是否支持 audit API',
  'error.remoteParseFailed': '无法解析远程仓库标识：{remote}。支持格式：github:owner/repo 或 https://github.com/owner/repo',
  'error.githubFileNotFound': '文件不存在：{path}（仓库 {owner}/{repo}，引用 {ref}）。可能无权限或路径错误',
  'error.githubRateLimited': 'GitHub API 限流，请使用 --token 参数或稍后重试',
  'error.githubAuthFailed': 'GitHub 认证失败，请检查 --token 参数',
  'error.githubApiError': 'GitHub API 错误：{status} {text}',
  'error.githubTreeApiError': 'GitHub Tree API 错误：{status}',
  'error.githubFileNotInTree': 'Tree API 中未找到文件：{path}',
  'error.githubBlobApiError': 'GitHub Blob API 错误：{status}',

  // Report labels
  'report.title': '依赖审计报告',
  'report.auditTime': '审计时间',
  'report.dataSource': '数据来源',
  'report.lockfileWarning': '⚠️ 此审计基于自动生成的锁文件，可能与项目实际依赖树有差异',
  'report.summary': '摘要',
  'report.severity': '严重程度',
  'report.count': '数量',
  'report.total': '合计',
  'report.noVulns': '未发现已知漏洞。',
  'report.installedVersion': '安装版本',
  'report.vulnPackage': '漏洞包',
  'report.fix': '修复方案',
  'report.noFix': '暂无可用修复',
  'report.depChain': '依赖链',
  'report.directDep': '直接依赖',
  'report.vulnFrom': '漏洞源于',
  'report.majorUpgrade': '⚠️ 涉及大版本升级 — ',
  'report.upgradeTo': '升级到',
  'report.ignored': '已忽略',
  'report.severityLevel': '严重级别',
  'report.ignoreReason': '忽略原因',
  'report.notSpecified': '未注明',
  'report.ignoreExpiry': '忽略到期',
  'report.moreAdvisories': '（另有 {count} 个 advisory）',
  'report.advisories': 'Advisory 列表',
  'report.affectedDirectDeps': '受影响的直接依赖',
  'report._htmlLang': 'zh-CN',

  // MCP
  'mcp.reportGenerated': '报告已生成：{path}',
  'mcp.auditFailed': '审计失败：{message}',
  'mcp.unknownTool': '未知工具：{name}',
  'mcp.validationFailed': '参数校验失败：{message}',
  'mcp.project': '项目：{name}',
  'mcp.source': '来源：{source} (npm v{version})',
  'mcp.totalVulns': '漏洞总数：{total}（Critical: {critical}, High: {high}, Moderate: {moderate}, Low: {low}）',
  'mcp.noVulns': '未发现已知漏洞。',
  'mcp.moreVulns': '... 还有 {count} 个漏洞，完整报告见 {path}',
  'mcp.ignoredSection': '已忽略的漏洞',
  'mcp.expiryLabel': '，到期 {date}',
};

const messages: Record<Locale, MessageMap> = { en, 'zh-CN': zhCN };

let currentLocale: Locale = 'en';

export function initLocale(lang?: string): void {
  if (lang) {
    currentLocale = (lang === 'zh' || lang === 'zh-CN') ? 'zh-CN' : 'en';
    return;
  }
  const envLang = process.env.AUDIT_LANG;
  if (envLang) {
    currentLocale = (envLang === 'zh' || envLang === 'zh-CN') ? 'zh-CN' : 'en';
    return;
  }
  try {
    const sysLocale = Intl.DateTimeFormat().resolvedOptions().locale;
    currentLocale = sysLocale.startsWith('zh') ? 'zh-CN' : 'en';
  } catch {
    currentLocale = 'en';
  }
}

/**
 * Get a localized message by key, with optional {placeholder} replacement.
 * Falls back to English if key not found in current locale.
 */
export function t(key: string, params?: Record<string, string | number>): string {
  let msg = messages[currentLocale]?.[key] || messages['en'][key] || key;
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      msg = msg.replace(new RegExp(`\\{${k}\\}`, 'g'), String(v));
    }
  }
  return msg;
}

export function getLocale(): Locale {
  return currentLocale;
}

/** For report templates: returns all messages for current locale (merged with en fallback) */
export function getLabels(): MessageMap & Record<string, string> {
  return { ...messages['en'], ...messages[currentLocale] };
}
