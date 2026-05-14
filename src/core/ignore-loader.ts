import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import type { Vulnerability } from '../types.js';

export interface IgnoreRule {
  packageName: string;
  advisorySource?: number;
  reason?: string;
  expiresAt?: string;
}

interface IgnoreFile {
  ignore: IgnoreRule[];
}

/**
 * 加载 .dep-audit-ignore.json（如果存在）
 */
export async function loadIgnoreFile(projectPath: string): Promise<IgnoreRule[]> {
  try {
    const raw = await readFile(resolve(projectPath, '.dep-audit-ignore.json'), 'utf-8');
    const data: IgnoreFile = JSON.parse(raw);
    return data.ignore ?? [];
  } catch {
    return [];
  }
}

/**
 * 判断漏洞是否被忽略规则匹配
 *
 * 匹配规则：
 * - 有 advisorySource → packageName + advisorySource 精确匹配
 * - 无 advisorySource → 仅按 packageName 匹配（忽略该包所有 advisory）
 * - expiresAt 过期则不再匹配
 */
export function isIgnored(vuln: Vulnerability, rules: IgnoreRule[]): IgnoreRule | null {
  const now = new Date();
  for (const rule of rules) {
    // 包名不匹配，跳过
    if (rule.packageName !== vuln.packageName) continue;

    // 有 advisorySource → 精确匹配
    if (rule.advisorySource !== undefined) {
      if (rule.advisorySource !== vuln.advisorySource) continue;
    }

    // 检查过期
    if (rule.expiresAt) {
      const expiry = new Date(rule.expiresAt);
      if (now > expiry) continue;
    }

    return rule;
  }
  return null;
}

/**
 * 将漏洞分为两组：正常漏洞和被忽略的漏洞
 */
export function partitionVulnerabilities(
  vulns: Vulnerability[],
  rules: IgnoreRule[],
): { active: Vulnerability[]; ignored: Array<{ vuln: Vulnerability; rule: IgnoreRule }> } {
  const active: Vulnerability[] = [];
  const ignored: Array<{ vuln: Vulnerability; rule: IgnoreRule }> = [];

  for (const vuln of vulns) {
    const rule = isIgnored(vuln, rules);
    if (rule) {
      ignored.push({ vuln, rule });
    } else {
      active.push(vuln);
    }
  }

  return { active, ignored };
}
