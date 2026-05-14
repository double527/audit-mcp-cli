import { readFile, writeFile } from 'node:fs/promises';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Eta } from 'eta';
import type { AuditResult } from '../types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
// 编译后 __dirname = dist/core/，模板在 dist/templates/（由 build 脚本复制）
const templatesDir = join(__dirname, '..', 'templates');

const eta = new Eta({ autoEscape: false, autoTrim: [false, false] });

export interface GenerateReportOptions {
  auditResult: AuditResult;
  format: 'md' | 'html';
  outputPath?: string;
}

async function readTemplate(name: string): Promise<string> {
  return readFile(join(templatesDir, name), 'utf-8');
}

/**
 * 从 AuditResult 生成 Markdown 或 HTML 报告文件
 */
export async function generateReport(
  options: GenerateReportOptions,
): Promise<string> {
  const { auditResult, format, outputPath } = options;

  const templateFile = format === 'html' ? 'report.html.eta' : 'report.md.eta';
  const templateStr = await readTemplate(templateFile);
  const content = eta.renderString(templateStr, auditResult);

  const defaultFilename = format === 'html' ? 'audit-report.html' : 'audit-report.md';
  const targetPath = resolve(outputPath ?? defaultFilename);

  await writeFile(targetPath, content, 'utf-8');
  return targetPath;
}
