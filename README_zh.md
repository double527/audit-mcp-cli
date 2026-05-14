# audit-mcp-cli

[English](./README.md) | **中文**

轻量级 Node.js 依赖漏洞审计工具。支持 CLI 和 MCP Server 两种模式，覆盖 npm 和 pnpm 项目，生成带有完整依赖链的 Markdown / HTML 结构化报告。

## 功能特性

- **完整依赖链追踪** — 从 package.json 根依赖到漏洞包的完整路径
- **npm + pnpm 支持** — 自动检测包管理器类型
- **远程 GitHub 审计** — 无需克隆即可审计公开或私有仓库
- **MCP Server** — 集成到 AI 编码助手（Claude、Cursor 等）
- **Markdown / HTML 报告** — 按严重程度降序排列的清晰报告
- **CI 门禁** — `--fail-on` 退出码，适配 CI/CD 流水线
- **忽略机制** — 按包名或 advisory ID 忽略已确认的漏洞，支持过期时间
- **严重程度过滤** — 只显示指定级别以上的漏洞

## 安装

```bash
# 直接运行
npx audit-mcp-cli

# 或全局安装
npm install -g audit-mcp-cli
```

要求 Node.js >= 18。

## 使用方式

```bash
# 审计当前目录
audit-mcp-cli

# 指定项目路径
audit-mcp-cli --path /path/to/project

# 远程 GitHub 仓库（分支）
audit-mcp-cli --remote github:facebook/react --ref main

# 远程 GitHub 仓库（Tag）
audit-mcp-cli --remote github:facebook/react --ref v18.2.0

# 远程 GitHub 仓库（Commit SHA）
audit-mcp-cli --remote github:facebook/react --ref abc123def

# 生成 HTML 报告
audit-mcp-cli --format html --output report.html

# CI：发现 high 及以上漏洞时失败
audit-mcp-cli --fail-on high

# 严重程度过滤（只显示 high 和 critical）
audit-mcp-cli --severity high
```

## CLI 参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--path <path>` | 本地项目路径 | `process.cwd()` |
| `--remote <repo>` | 远程仓库：`github:owner/repo` 或 `https://github.com/owner/repo` | — |
| `--ref <ref>` | Git 引用（分支名 / Tag / Commit SHA） | `main` |
| `--token <token>` | GitHub Personal Access Token（私有仓库需要） | `GITHUB_TOKEN` 环境变量 |
| `--format <fmt>` | 报告格式：`md` 或 `html` | `md` |
| `--output <path>` | 输出文件路径 | `audit-report.md` 或 `.html` |
| `--severity <level>` | 最低显示级别：`low` / `moderate` / `high` / `critical` | `low` |
| `--fail-on <level>` | CI 失败阈值 — 存在该级别及以上漏洞时 exit 1 | — |
| `--mcp` | 以 MCP Server 模式启动 | — |

### `--fail-on` 退出码规则

| 值 | 触发 exit 1 的条件 |
|----|-------------------|
| `critical` | 存在 critical 漏洞 |
| `high` | 存在 high 或 critical 漏洞 |
| `moderate` | 存在 moderate 及以上漏洞 |
| `low` | 存在任何漏洞 |
| *(不传)* | 永远 exit 0 |

## MCP Server

作为 MCP stdio 服务运行，供 AI 助手调用：

```bash
audit-mcp-cli --mcp
```

### Claude Desktop

```json
{
  "mcpServers": {
    "audit-mcp-cli": {
      "command": "npx",
      "args": ["-y", "audit-mcp-cli", "--mcp"],
      "env": {
        "GITHUB_TOKEN": "ghp_xxxx"
      }
    }
  }
}
```

### Cursor

添加到 `.cursor/mcp.json`：

```json
{
  "mcpServers": {
    "audit-mcp-cli": {
      "command": "npx",
      "args": ["-y", "audit-mcp-cli", "--mcp"],
      "env": {
        "GITHUB_TOKEN": "ghp_xxxx"
      }
    }
  }
}
```

### 工具：`audit_dependencies`

MCP Server 注册了一个 `audit_dependencies` 工具，支持本地和远程审计：

| 参数 | 说明 |
|------|------|
| `projectPath` | 本地项目路径 |
| `remoteRepo` | 远程仓库：`github:owner/repo` |
| `ref` | Git 引用（分支 / Tag / SHA） |
| `format` | `md` 或 `html` |
| `severity` | 最低严重级别过滤 |
| `outputPath` | 自定义输出文件路径 |

返回值：报告文件路径 + 结构化漏洞摘要（最多显示 20 条）。

## 忽略机制

在项目根目录创建 `.dep-audit-ignore.json` 来忽略已确认接受的漏洞：

```json
{
  "ignore": [
    {
      "packageName": "minimist",
      "advisorySource": 1179,
      "reason": "已确认风险，影响范围有限，暂不修复",
      "expiresAt": "2025-12-31T00:00:00Z"
    }
  ]
}
```

- `packageName` — 忽略该包的所有 advisory；配合 `advisorySource` 可精确匹配单条
- `expiresAt` — 可选，到期后忽略自动失效
- 被忽略的漏洞在报告中单独列出，不计入 `--fail-on` 判断

## CI 集成

```yaml
# GitHub Actions 示例
- name: Security Audit
  run: npx audit-mcp-cli --fail-on high
```

```bash
# 通用 CI
npx audit-mcp-cli --fail-on high && echo "pass" || echo "fail"
```

## 许可证

[MIT](./LICENSE)
