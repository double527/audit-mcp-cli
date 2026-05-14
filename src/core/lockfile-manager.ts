import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { execa } from 'execa';
import type { PackageManager } from '../types.js';

const LOCKFILE_PRIORITY: Array<{ file: string; manager: PackageManager }> = [
  { file: 'pnpm-lock.yaml', manager: 'pnpm' },
  { file: 'yarn.lock', manager: 'yarn' },
  { file: 'package-lock.json', manager: 'npm' },
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
 * 为 pnpm 项目确保 pnpm-lock.yaml 存在
 * 类似 npm 的 --package-lock-only，pnpm 用 --lockfile-only
 */
export async function ensurePnpmLockfile(
  projectPath: string,
): Promise<{ generated: boolean }> {
  const lockfilePath = join(projectPath, 'pnpm-lock.yaml');
  if (existsSync(lockfilePath)) {
    return { generated: false };
  }

  // 先检查 pnpm 是否可用
  try {
    await execa('pnpm', ['--version'], { reject: true });
  } catch {
    throw new Error('未检测到 pnpm，请先安装：npm install -g pnpm');
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
    throw new Error('未检测到 npm，请安装 Node.js >= 18');
  }

  const trimmed = stdout.trim();
  const major = Number(trimmed.split('.')[0]);
  if (Number.isNaN(major) || major < 7) {
    throw new Error(
      `npm 版本过低（当前 ${trimmed}），需要 >= 7，请升级 Node.js`,
    );
  }

  return { npmVersion: trimmed };
}
