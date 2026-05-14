import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const GITHUB_API = 'https://api.github.com';

export interface RemoteFiles {
  tempDir: string;
  packageJson: string;
  packageLockJson: string | null;
  pnpmLockYaml: string | null;
}

/**
 * 从 GitHub 远程仓库拉取 package.json 和 package-lock.json 到临时目录
 */
export async function fetchRemoteFiles(
  owner: string,
  repo: string,
  ref: string,
  token?: string,
): Promise<RemoteFiles> {
  const headers: Record<string, string> = {
    'User-Agent': 'audit-mcp-cli',
    Accept: 'application/vnd.github.v3+json',
  };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  // 创建临时目录
  const tempDir = await mkdtemp(join(tmpdir(), 'audit-mcp-cli-'));

  // 注册清理钩子
  const cleanup = () => {
    rm(tempDir, { recursive: true, force: true }).catch(() => {});
  };
  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);

  try {
    // 拉取 package.json
    const pkgJsonContent = await fetchGitHubFile(owner, repo, 'package.json', ref, headers);
    await writeFile(join(tempDir, 'package.json'), pkgJsonContent, 'utf-8');

    // 拉取 package-lock.json（可选）
    let packageLockJson: string | null = null;
    try {
      packageLockJson = await fetchGitHubFile(owner, repo, 'package-lock.json', ref, headers);
      await writeFile(join(tempDir, 'package-lock.json'), packageLockJson, 'utf-8');
    } catch {
      // 锁文件不存在，后续会自动生成
    }

    // 拉取 pnpm-lock.yaml（可选）
    let pnpmLockYaml: string | null = null;
    try {
      pnpmLockYaml = await fetchGitHubFile(owner, repo, 'pnpm-lock.yaml', ref, headers);
      await writeFile(join(tempDir, 'pnpm-lock.yaml'), pnpmLockYaml, 'utf-8');
    } catch {
      // 锁文件不存在，后续会自动生成
    }

    return { tempDir, packageJson: pkgJsonContent, packageLockJson, pnpmLockYaml };
  } catch (e) {
    // 拉取失败时清理临时目录
    await rm(tempDir, { recursive: true, force: true }).catch(() => {});
    throw e;
  }
}

/**
 * 清理临时目录
 */
export async function cleanupTempDir(tempDir: string): Promise<void> {
  await rm(tempDir, { recursive: true, force: true });
}

/**
 * 解析远程仓库标识
 * 支持格式：
 *   github:owner/repo
 *   https://github.com/owner/repo
 *   https://github.com/owner/repo.git
 */
export function parseRemoteRepo(remote: string): { platform: string; owner: string; repo: string } {
  // github:owner/repo
  const shortMatch = remote.match(/^github:([^/]+)\/(.+)$/);
  if (shortMatch) {
    return { platform: 'github', owner: shortMatch[1], repo: shortMatch[2] };
  }

  // https://github.com/owner/repo(.git)?
  const urlMatch = remote.match(/^https?:\/\/github\.com\/([^/]+)\/([^/.]+?)(?:\.git)?$/);
  if (urlMatch) {
    return { platform: 'github', owner: urlMatch[1], repo: urlMatch[2] };
  }

  throw new Error(`无法解析远程仓库标识：${remote}。支持格式：github:owner/repo 或 https://github.com/owner/repo`);
}

// ─── GitHub API 调用 ───

async function fetchGitHubFile(
  owner: string,
  repo: string,
  path: string,
  ref: string,
  headers: Record<string, string>,
): Promise<string> {
  // 1. 先尝试 Contents API
  const contentsUrl = `${GITHUB_API}/repos/${owner}/${repo}/contents/${path}?ref=${encodeURIComponent(ref)}`;
  const contentsResp = await githubFetch(contentsUrl, headers);

  if (contentsResp.ok) {
    const data = await contentsResp.json();
    return decodeBase64(data.content);
  }

  // 2. 如果是 403 且因为文件太大，fallback 到 Blob API
  if (contentsResp.status === 403) {
    const body = await contentsResp.text();
    if (body.includes('1 MB') || body.includes('too large')) {
      return await fetchViaBlobApi(owner, repo, path, ref, headers);
    }
  }

  // 3. 404 = 文件不存在
  if (contentsResp.status === 404) {
    throw new Error(`文件不存在：${path}（仓库 ${owner}/${repo}，引用 ${ref}）。可能无权限或路径错误`);
  }

  // 4. 403 = 限流
  if (contentsResp.status === 403) {
    throw new Error('GitHub API 限流，请使用 --token 参数或稍后重试');
  }

  // 5. 401 = 认证失败
  if (contentsResp.status === 401) {
    throw new Error('GitHub 认证失败，请检查 --token 参数');
  }

  throw new Error(`GitHub API 错误：${contentsResp.status} ${contentsResp.statusText}`);
}

async function fetchViaBlobApi(
  owner: string,
  repo: string,
  path: string,
  ref: string,
  headers: Record<string, string>,
): Promise<string> {
  // 1. 通过 Tree API 获取文件 SHA
  const treeUrl = `${GITHUB_API}/repos/${owner}/${repo}/git/trees/${encodeURIComponent(ref)}?recursive=1`;
  const treeResp = await githubFetch(treeUrl, headers);
  if (!treeResp.ok) {
    throw new Error(`GitHub Tree API 错误：${treeResp.status}`);
  }

  const treeData = await treeResp.json();
  const fileEntry = treeData.tree?.find((entry: { path: string; sha: string }) => entry.path === path);
  if (!fileEntry) {
    throw new Error(`Tree API 中未找到文件：${path}`);
  }

  // 2. 通过 Blob API 获取文件内容
  const blobUrl = `${GITHUB_API}/repos/${owner}/${repo}/git/blobs/${fileEntry.sha}`;
  const blobResp = await githubFetch(blobUrl, headers);
  if (!blobResp.ok) {
    throw new Error(`GitHub Blob API 错误：${blobResp.status}`);
  }

  const blobData = await blobResp.json();
  return decodeBase64(blobData.content);
}

async function githubFetch(url: string, headers: Record<string, string>): Promise<Response> {
  const resp = await fetch(url, { headers });
  return resp as Response;
}

function decodeBase64(encoded: string): string {
  // GitHub API 返回的 Base64 可能含换行符
  const cleaned = encoded.replace(/\n/g, '');
  return Buffer.from(cleaned, 'base64').toString('utf-8');
}
