# Cloudflare Workers 编辑器

一个基于 Cloudflare Workers 的 Web 管理工具，提供完整的 Workers 开发和管理界面。支持在线编辑、部署、KV 存储管理、日志查询、资源绑定等功能。不同于 Cloudflare Dashboard，此编辑器对浏览器版本的要求更低，大部分现代浏览器都能正常运行。

## 目录

- [功能特性](#功能特性)
- [快速开始](#快速开始)
- [安装部署](#安装部署)
- [配置说明](#配置说明)
- [使用指南](#使用指南)
- [API 接口](#api-接口)
- [安全特性](#安全特性)
- [技术栈](#技术栈)
- [贡献指南](#贡献指南)
- [许可证](#许可证)

## 功能特性

### 核心功能

- **在线编辑与部署** - 创建、编辑、保存 Workers 脚本，支持语法检查（JSHint）
- **KV 命名空间管理** - 管理命名空间和键值对，支持批量操作与过期时间设置
- **Worker 调用日志** - 实时查询调用记录，按状态、路径、国家等条件过滤
- **资源绑定配置** - 绑定 KV、R2、D1、Secret、Durable Objects 等 Cloudflare 资源
- **部署历史与回滚** - 查看部署记录，一键回滚到任意历史版本
- **域名路由配置** - 为 Worker 绑定域名路由，支持模式匹配
- **cURL 代理工具** - 直接执行 Cloudflare API 的 cURL 命令
- **GraphQL 支持** - 使用 GraphQL 查询 Cloudflare 账户信息

### 界面特性

- 响应式设计，支持桌面和移动端
- 暗色/亮色主题自动切换
- 键盘快捷键支持（Ctrl+S 保存、Ctrl+L 加载等）
- Toast 通知系统
- 代码语法检查与错误提示

## 快速开始

### 前置要求

- Cloudflare 账户
- Cloudflare API Token（需要 Workers 编辑权限）
- 已部署的 Cloudflare Worker（用于托管此编辑器）

### 获取 API Token

1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com/profile/api-tokens)
2. 创建 API Token，选择以下权限：
   - Account - Cloudflare Workers - Edit
   - Account - Cloudflare D1 - Edit（如需使用 D1）
   - Account - Cloudflare R2 - Edit（如需使用 R2）
   - Account - Cloudflare KV - Edit（如需使用 KV）

## 安装部署

### 方法一：通过 Wrangler CLI 部署

```bash
# 安装 Wrangler
npm install -g wrangler

# 登录 Cloudflare
wrangler login

# 克隆项目
git clone <repository-url>
cd worker/editor

# 部署到 Cloudflare Workers
wrangler deploy
```

### 方法二：通过 Cloudflare Dashboard 部署

1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com)
2. 进入 Workers & Pages
3. 创建新的 Worker
4. 将 `worker.js` 文件内容复制到编辑器
5. 保存并部署

### 配置环境变量

在 Cloudflare Dashboard 中设置以下环境变量（可选）：

- `SCRIPT_ID` - 自定义服务器 ID，用于加密数据（不设置则使用代码中的默认值）

## 配置说明

### 核心配置参数

在 `worker.js` 文件顶部可以修改以下配置：

```javascript
// 服务器 ID，用于加密数据（强烈建议修改为随机字符串）
const scriptId = '21f68f42-9bc6-45e9-84a3-9fde721cbf81';

// Token 免密钥登录期限（秒），默认 3 天
const loginPeriod = 3*60*60*24;

// 登录时间偏差窗口（秒），用于防止时钟不同步问题
const CLOCK_SKEW = 10;

// 自动续期配置
const renewal = {
    threshold: 0.4,              // 续期阈值（40% 剩余时间时触发）
    maxPeriod: 30*24*60*60,      // 续期最大期限（30 天）
    minInterval: 30*60           // 自动请求续期间隔（30 分钟）
};

// 调试模式（生产环境务必设为 false）
const DEBUG = false;
```

### 安全配置建议

1. **修改 scriptId** - 使用随机生成的 UUID 或字符串
2. **关闭 DEBUG 模式** - 生产环境必须设为 `false`
3. **启用 HTTPS** - 系统会自动强制 HTTPS 跳转
4. **定期更新 API Token** - 建议每 90 天更换一次

## 使用指南

### 登录

1. 访问部署后的 Worker URL
2. 点击"登录"按钮
3. 输入 Cloudflare Account ID 和 API Token
4. 选择登录方式：
   - **导入登录** - 直接使用 API Token
   - **LocalStorage 登录** - 加密存储在浏览器本地
   - **Cookie 登录** - 使用 Cookie 存储（支持自动续期）

### 管理 Workers

#### 查看 Worker 列表

访问 `/list` 页面查看所有 Workers，支持：
- 搜索和过滤
- 快速进入编辑、绑定、设置等页面

#### 编辑 Worker

访问 `/edit?worker=<worker-name>` 页面：
- 加载当前脚本内容
- 在线编辑代码
- 使用 JSHint 检查语法错误
- 保存并部署修改

**快捷键：**
- `Ctrl+S` - 保存脚本
- `Ctrl+L` - 加载脚本
- `Ctrl+K` - 检查代码
- `Ctrl+D` - 清空编辑器
- `Ctrl+E` - 下载脚本

#### 创建 Worker

访问 `/create` 页面：
- 输入 Worker 名称
- 自动创建 Hello World 示例脚本

#### 管理绑定

访问 `/binding?worker=<worker-name>` 页面：
- 查看当前绑定配置
- 添加新的绑定（KV、R2、D1、Secret 等）
- 删除现有绑定
- 管理 Secret 环境变量

#### 查看部署历史

访问 `/deployment?worker=<worker-name>` 页面：
- 查看所有部署版本
- 查看每个版本的详细信息
- 一键回滚到历史版本

#### 配置路由

访问 `/routes?worker=<worker-name>` 页面：
- 查看当前路由配置
- 添加自定义域名路由
- 配置路由模式匹配规则

#### 管理设置

访问 `/setting?worker=<worker-name>` 页面：
- 开启/关闭日志记录
- 删除 Worker
- 查看 Worker 详细信息

### KV 存储管理

#### 命名空间管理

访问 `/kv` 页面：
- 查看所有 KV 命名空间
- 创建新的命名空间
- 删除命名空间

#### 键值对管理

点击命名空间进入键值管理页面：
- 查看、编辑、删除键值对
- 设置键的过期时间（TTL 或绝对时间）
- 添加元数据（JSON 格式）
- 上传文件（支持二进制文件）
- 批量导入/导出

#### 批量操作

访问 `/kv/bulk?ns=<namespace-id>` 页面：
- 批量添加多个键值对
- 支持文本和文件上传
- 为每个键值对设置独立的元数据和过期时间

### 日志查询

访问 `/wtc?worker=<worker-name>` 页面：
- 查看 Worker 调用日志
- 按时间范围、状态码、路径、国家等过滤
- 查看请求详情（Headers、Body、响应等）

### cURL 代理

访问 `/curl` 页面：
- 输入 cURL 命令
- 自动解析并执行
- 支持附加当前 API Token
- 仅限代理 `api.cloudflare.com` 域名

### GraphQL 查询

访问 `/graphql` 页面：
- 使用 GraphQL 查询 Cloudflare 账户信息
- 支持自定义查询语句
- 查看查询结果

## API 接口

### 认证机制

所有 API 接口需要认证，支持以下方式：

1. **Cookie 认证** - 登录后自动设置
2. **Bearer Token** - 在请求头中添加 `Authorization: Bearer <token>`

### 页面路由

| 路径 | 方法 | 说明 |
|------|------|------|
| `/` | GET | 首页 |
| `/login` | GET/POST | 登录页面/登录接口 |
| `/logout` | GET | 登出 |
| `/list` | GET | Worker 列表 |
| `/edit` | GET | 编辑 Worker |
| `/kv` | GET | KV 命名空间管理 |
| `/kv/bulk` | GET | KV 批量操作 |
| `/wtc` | GET | 日志查询 |
| `/binding` | GET | 绑定管理 |
| `/deployment` | GET | 部署历史 |
| `/routes` | GET | 路由配置 |
| `/setting` | GET | Worker 设置 |
| `/create` | GET | 创建 Worker |
| `/curl` | GET | cURL 代理 |
| `/graphql` | GET | GraphQL 查询 |

### API 路由

所有 API 路由以 `/api` 开头，返回 JSON 格式。

#### Workers 管理

```http
GET /api/workers
```

获取当前账户下所有 Workers 列表。

#### 脚本管理

```http
GET /api/script/{workerName}
PUT /api/script/{workerName}
```

获取或更新 Worker 脚本内容。

#### KV 命名空间

```http
GET /api/kv/namespaces
POST /api/kv/namespaces
DELETE /api/kv/namespaces/{namespaceId}
```

管理 KV 命名空间。

#### KV 键值对

```http
GET /api/kv/{namespaceId}/keys
GET /api/kv/{namespaceId}/values/{key}
PUT /api/kv/{namespaceId}/values/{key}
DELETE /api/kv/{namespaceId}/values/{key}
GET /api/kv/{namespaceId}/metadata/{key}
```

管理 KV 键值对。

#### 绑定管理

```http
GET /api/bindings/{workerName}
PATCH /api/bindings/{workerName}
POST /api/bindings/{workerName}/secret
DELETE /api/bindings/{workerName}/secret/{secretName}
```

管理 Worker 绑定和 Secret。

#### 部署管理

```http
GET /api/deployment/{workerName}
POST /api/deployment/{workerName}/rollback/{versionId}
```

查看部署历史和回滚。

#### 路由管理

```http
GET /api/routes/{workerName}
PUT /api/routes/{workerName}
```

管理 Worker 路由配置。

#### 设置管理

```http
POST /api/setting/create
DELETE /api/setting/delete/{workerName}
PATCH /api/setting/logs/{workerName}
```

创建、删除 Worker 和管理日志设置。

#### cURL 代理

```http
POST /api/curl
POST /api/curl/raw
```

执行 cURL 命令（仅限 `api.cloudflare.com`）。

#### GraphQL

```http
POST /api/graphql
```

执行 GraphQL 查询。

### 响应格式

成功响应：
```json
{
  "success": true,
  "result": { ... },
  "errors": [],
  "messages": []
}
```

错误响应：
```json
{
  "success": false,
  "error": "错误描述"
}
```

## 安全特性

### 认证安全

- **Token 加密存储** - API Token 使用 AES-256-GCM 加密后存储
- **自动续期机制** - Cookie 支持自动续期，避免频繁登录
- **时间窗口校验** - 防止时钟不同步导致的安全问题
- **IP 绑定验证** - 续期 Token 绑定客户端 IP

### 传输安全

- **HTTPS 强制跳转** - 所有 HTTP 请求自动跳转到 HTTPS
- **HttpOnly Cookie** - 敏感 Cookie 设置 HttpOnly 标志
- **SameSite 策略** - 防止 CSRF 攻击
- **Secure 标志** - Cookie 仅通过 HTTPS 传输

### 应用安全

- **XSS 防护** - 所有用户输入经过转义处理
- **CORS 控制** - API 支持跨域请求配置
- **输入验证** - 所有 API 接口进行参数验证
- **错误处理** - 统一错误处理，不泄露敏感信息

### 调试模式

`DEBUG` 模式提供以下调试功能：
- 详细的错误信息输出
- Cookie 状态查询接口（`/get/cookie`、`/get/cookie/status`）

**警告：** 生产环境务必关闭 DEBUG 模式，否则可能泄露敏感数据。

## 技术栈

- **运行时** - Cloudflare Workers (V8 Isolates)
- **加密** - Web Crypto API (AES-256-GCM)
- **前端** - 原生 HTML/CSS/JavaScript
- **代码检查** - JSHint
- **API** - Cloudflare API v4

## 贡献指南

欢迎贡献代码、报告问题或提出建议！

### 开发流程

1. Fork 本仓库
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 提交 Pull Request

### 代码规范

- 使用 ES6+ 语法
- 保持代码简洁清晰
- 添加必要的注释
- 遵循现有代码风格

### 报告问题

提交 Issue 时请包含：
- 问题描述
- 复现步骤
- 预期行为
- 实际行为
- 环境信息（浏览器、操作系统等）

## 许可证

本项目采用 MIT 许可证。详情请见 [LICENSE](LICENSE) 文件。

## 免责声明

本工具仅作为 Cloudflare 资源管理界面，不存储任何用户数据。所有 API Token 和敏感信息均加密存储在客户端浏览器中。

使用本工具时请确保：
- 妥善保管 API Token
- 定期更换 Token
- 不要在公共设备上使用
- 生产环境关闭 DEBUG 模式

## 联系方式

如有问题或建议，请通过以下方式联系：
- 提交 GitHub Issue
- 发送邮件至项目维护者

---

**注意：** 本项目与 Cloudflare 官方无关，是独立的第三方工具。
