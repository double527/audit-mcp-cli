import { readFile, writeFile } from 'node:fs/promises';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Eta } from 'eta';
import { getLabels } from './i18n.js';
import type { AuditResult } from '../types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
// After compilation __dirname = dist/core/, templates in dist/templates/ (copied by build script)
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
 * Generate a Markdown or HTML report file from AuditResult
 */
export async function generateReport(
  options: GenerateReportOptions,
): Promise<string> {
  const { auditResult, format, outputPath } = options;

  const templateFile = format === 'html' ? 'report.html.eta' : 'report.md.eta';
  const templateStr = await readTemplate(templateFile);
  const labels = getLabels();
  const content = eta.renderString(templateStr, { ...auditResult, labels });

  const defaultFilename = format === 'html' ? 'audit-report.html' : 'audit-report.md';
  const targetPath = resolve(outputPath ?? defaultFilename);

  await writeFile(targetPath, content, 'utf-8');
  return targetPath;
}
