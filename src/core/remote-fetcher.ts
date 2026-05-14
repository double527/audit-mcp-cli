import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { t } from './i18n.js';

const GITHUB_API = 'https://api.github.com';

export interface RemoteFiles {
  tempDir: string;
  packageJson: string;
  packageLockJson: string | null;
  pnpmLockYaml: string | null;
}

/**
 * Fetch package.json and package-lock.json from a GitHub remote repo to a temp directory
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

  // Create temp directory
  const tempDir = await mkdtemp(join(tmpdir(), 'audit-mcp-cli-'));

  // Register cleanup hooks
  const cleanup = () => {
    rm(tempDir, { recursive: true, force: true }).catch(() => {});
  };
  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);

  try {
    // Fetch package.json
    const pkgJsonContent = await fetchGitHubFile(owner, repo, 'package.json', ref, headers);
    await writeFile(join(tempDir, 'package.json'), pkgJsonContent, 'utf-8');

    // Fetch package-lock.json (optional)
    let packageLockJson: string | null = null;
    try {
      packageLockJson = await fetchGitHubFile(owner, repo, 'package-lock.json', ref, headers);
      await writeFile(join(tempDir, 'package-lock.json'), packageLockJson, 'utf-8');
    } catch {
      // Lockfile not found, will be auto-generated later
    }

    // Fetch pnpm-lock.yaml (optional)
    let pnpmLockYaml: string | null = null;
    try {
      pnpmLockYaml = await fetchGitHubFile(owner, repo, 'pnpm-lock.yaml', ref, headers);
      await writeFile(join(tempDir, 'pnpm-lock.yaml'), pnpmLockYaml, 'utf-8');
    } catch {
      // Lockfile not found, will be auto-generated later
    }

    return { tempDir, packageJson: pkgJsonContent, packageLockJson, pnpmLockYaml };
  } catch (e) {
    // Cleanup temp dir on fetch failure
    await rm(tempDir, { recursive: true, force: true }).catch(() => {});
    throw e;
  }
}

/**
 * Cleanup temp directory
 */
export async function cleanupTempDir(tempDir: string): Promise<void> {
  await rm(tempDir, { recursive: true, force: true });
}

/**
 * Parse remote repo identifier.
 * Supported formats:
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

  throw new Error(t('error.remoteParseFailed', { remote }));
}

// ─── GitHub API calls ───

async function fetchGitHubFile(
  owner: string,
  repo: string,
  path: string,
  ref: string,
  headers: Record<string, string>,
): Promise<string> {
  // 1. Try Contents API first
  const contentsUrl = `${GITHUB_API}/repos/${owner}/${repo}/contents/${path}?ref=${encodeURIComponent(ref)}`;
  const contentsResp = await githubFetch(contentsUrl, headers);

  if (contentsResp.ok) {
    const data = await contentsResp.json();
    return decodeBase64(data.content);
  }

  // 2. If 403 and file too large, fallback to Blob API
  if (contentsResp.status === 403) {
    const body = await contentsResp.text();
    if (body.includes('1 MB') || body.includes('too large')) {
      return await fetchViaBlobApi(owner, repo, path, ref, headers);
    }
  }

  // 3. 404 = file not found
  if (contentsResp.status === 404) {
    throw new Error(t('error.githubFileNotFound', { path, owner, repo, ref }));
  }

  // 4. 403 = rate limited
  if (contentsResp.status === 403) {
    throw new Error(t('error.githubRateLimited'));
  }

  // 5. 401 = auth failed
  if (contentsResp.status === 401) {
    throw new Error(t('error.githubAuthFailed'));
  }

  throw new Error(t('error.githubApiError', { status: String(contentsResp.status), text: contentsResp.statusText }));
}

async function fetchViaBlobApi(
  owner: string,
  repo: string,
  path: string,
  ref: string,
  headers: Record<string, string>,
): Promise<string> {
  // 1. Get file SHA via Tree API
  const treeUrl = `${GITHUB_API}/repos/${owner}/${repo}/git/trees/${encodeURIComponent(ref)}?recursive=1`;
  const treeResp = await githubFetch(treeUrl, headers);
  if (!treeResp.ok) {
    throw new Error(t('error.githubTreeApiError', { status: String(treeResp.status) }));
  }

  const treeData = await treeResp.json();
  const fileEntry = treeData.tree?.find((entry: { path: string; sha: string }) => entry.path === path);
  if (!fileEntry) {
    throw new Error(t('error.githubFileNotInTree', { path }));
  }

  // 2. Get file content via Blob API
  const blobUrl = `${GITHUB_API}/repos/${owner}/${repo}/git/blobs/${fileEntry.sha}`;
  const blobResp = await githubFetch(blobUrl, headers);
  if (!blobResp.ok) {
    throw new Error(t('error.githubBlobApiError', { status: String(blobResp.status) }));
  }

  const blobData = await blobResp.json();
  return decodeBase64(blobData.content);
}

async function githubFetch(url: string, headers: Record<string, string>): Promise<Response> {
  const resp = await fetch(url, { headers });
  return resp as Response;
}

function decodeBase64(encoded: string): string {
  // GitHub API returns Base64 that may contain newlines
  const cleaned = encoded.replace(/\n/g, '');
  return Buffer.from(cleaned, 'base64').toString('utf-8');
}
