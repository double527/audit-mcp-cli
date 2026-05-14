import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { execa } from 'execa';
import { t } from './i18n.js';
import type { PackageManager } from '../types.js';

const LOCKFILE_PRIORITY: Array<{ file: string; manager: PackageManager }> = [
  { file: 'pnpm-lock.yaml', manager: 'pnpm' },
  { file: 'package-lock.json', manager: 'npm' },
  { file: 'yarn.lock', manager: 'npm' }, // yarn falls back to npm
];

export function detectPackageManager(projectPath: string): PackageManager {
  for (const { file, manager } of LOCKFILE_PRIORITY) {
    if (existsSync(join(projectPath, file))) {
      return manager;
    }
  }
  return 'npm';
}

export async function ensureLockfile(
  projectPath: string,
): Promise<{ generated: boolean }> {
  const lockfilePath = join(projectPath, 'package-lock.json');
  if (existsSync(lockfilePath)) {
    return { generated: false };
  }

  await execa(
    'npm',
    ['install', '--package-lock-only', '--ignore-scripts', '--legacy-peer-deps'],
    { cwd: projectPath, timeout: 600_000, reject: true },
  );

  return { generated: true };
}

/**
 * Ensure pnpm-lock.yaml exists for pnpm projects.
 * Similar to npm's --package-lock-only, pnpm uses --lockfile-only.
 */
export async function ensurePnpmLockfile(
  projectPath: string,
): Promise<{ generated: boolean }> {
  const lockfilePath = join(projectPath, 'pnpm-lock.yaml');
  if (existsSync(lockfilePath)) {
    return { generated: false };
  }

  // Check if pnpm is available
  try {
    await execa('pnpm', ['--version'], { reject: true });
  } catch {
    throw new Error(t('error.pnpmNotFound'));
  }

  await execa(
    'pnpm',
    ['install', '--lockfile-only', '--ignore-scripts'],
    { cwd: projectPath, timeout: 600_000, reject: true },
  );

  return { generated: true };
}

export async function checkNpmEnvironment(): Promise<{ npmVersion: string }> {
  let stdout: string;
  try {
    const result = await execa('npm', ['--version'], { reject: true });
    stdout = result.stdout;
  } catch {
    throw new Error(t('error.npmNotFound'));
  }

  const trimmed = stdout.trim();
  const major = Number(trimmed.split('.')[0]);
  if (Number.isNaN(major) || major < 7) {
    throw new Error(t('error.npmVersionLow', { version: trimmed }));
  }

  return { npmVersion: trimmed };
}
