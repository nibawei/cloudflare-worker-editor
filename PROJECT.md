# Cloudflare Workers 编辑器 - 项目架构文档

## 1. 项目概述

本项目是一个基于 **Cloudflare Workers** 构建的轻量级 Web 管理工具，提供完整的 Cloudflare 资源管理界面。与官方 Cloudflare Dashboard 不同，本编辑器对浏览器版本要求更低，且可部署在自己的 Worker 账户中独立使用。

**一句话定位**：单文件自托管的 Cloudflare 资源管理面板，支持 Workers 编辑、KV 管理、日志查询、资源绑定等全部核心功能。

### 设计特点

| 特点           | 说明                                                                                              |
| ------------ | ----------------------------------------------------------------------------------------------- |
| **单文件架构**    | 全部逻辑集中在 [index.js](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js)，便于部署和维护 |
| **零数据库依赖**   | 所有用户数据加密存储在客户端，服务端无状态                                                                           |
| **全栈纯 JS**   | 前后端均为原生 JavaScript，无构建步骤                                                                        |
| **API 代理模式** | Worker 作为中间层代理所有 Cloudflare API 请求                                                              |

***

## 2. 项目文件结构

```
editor/
├── src/
│   └── index.js              # 核心代码（所有模块，~11000 行）
├── .dev.vars.example         # 开发环境变量示例
├── .gitignore
├── LICENSE
├── README.md                 # 用户使用文档
├── package.json              # 项目配置与脚本
├── wrangler.toml             # Wrangler 部署配置
└── PROJECT.md                # 本文档（架构说明）
```

### 关键配置文件说明

#### [package.json](file:///d:/niwei/Documents/trae_projects/worker/editor/package.json)

- 名称：`worker-editor` v1.0.0
- 唯一依赖：`wrangler ^3.0.0`（Cloudflare 官方 CLI）
- 脚本：
  - `npm run dev` → 本地开发
  - `npm run deploy` → 部署到 Cloudflare

#### [wrangler.toml](file:///d:/niwei/Documents/trae_projects/worker/editor/wrangler.toml)

- 入口：`src/index.js`
- 兼容日期：`2025-01-01`（确保使用最新 Workers 运行时 API）
- 可观测性：已启用 Tail Workers 日志采集

***

## 3. 核心架构总览

```
                    ┌─────────────────────────┐
                    │    用户浏览器 (Client)   │
                    │  - HTML UI 渲染         │
                    │  - JS 交互逻辑          │
                    │  - 加密存储 Token       │
                    └────────────┬────────────┘
                                 │ HTTPS
                    ┌────────────▼────────────┐
                    │   Cloudflare Worker     │
                    │  (本项目 index.js)      │
                    │                         │
                    │  ┌───────────────────┐  │
                    │  │  1. 路由分发层     │  │
                    │  │  2. 认证鉴权层     │  │
                    │  │  3. API 代理层     │  │
                    │  │  4. 页面渲染层     │  │
                    │  │  5. 加密工具层     │  │
                    │  └───────────────────┘  │
                    └────────────┬────────────┘
                                 │ HTTPS
                    ┌────────────▼────────────┐
                    │  Cloudflare API v4      │
                    │  - Workers API          │
                    │  - KV API               │
                    │  - GraphQL API          │
                    │  - R2 / D1 API          │
                    └─────────────────────────┘
```

### 请求处理主流程

入口函数位于 [handleRequest](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L26-L207)，采用**线性路由匹配 + 责任链**模式：

1. **静态资源处理**（L43-L54）：`/robots.txt`、`/sitemap.xml`、`/static/style.css`、`/favicon.svg`
2. **HTTPS 强制跳转**（L57-L70）：非调试模式下 HTTP 自动跳转 HTTPS
3. **公开路由**（L73-L78）：`/login`（登录页）、`/logout`（登出）
4. **调试路由**（L81-L100）：`/get/cookie`、`/get/cookie/status`（仅 DEBUG 模式）
5. **登录处理**（L103-L105）：`/login*`、`/api/cookie*` 走专门的认证流程
6. **API 路由**（L108-L110）：`/api/*` 统一走 API 代理层
7. **页面路由**（L124-L163）：需要鉴权后返回 HTML 页面
8. **兜底 404**（L166-L172）

***

## 4. 五大核心模块详解

### 模块 1：路由分发层

**入口**：[handleRequest](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L26-L207)、[handleApiRequest](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L219-L300)

#### 页面路由表（15 个界面）

| 路径            | 处理函数                                                                                                    | 功能            |
| ------------- | ------------------------------------------------------------------------------------------------------- | ------------- |
| `/`           | [handleStartPage](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L364-L516)        | 首页（功能介绍、登录入口） |
| `/list`       | [handleListPage](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L3763-L4230)       | Worker 列表页    |
| `/edit`       | [handleEditPage](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L4231-L4926)       | Worker 编辑器页   |
| `/create`     | [handleCreatePage](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L10411-L10512)   | 创建 Worker 页   |
| `/kv`         | [handleKVHtml](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L5583-L6351)         | KV 命名空间管理     |
| `/kv/bulk`    | [handleKVBulkHtml](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L6352-L6711)     | KV 批量操作页      |
| `/wtc`        | [handleWtcPage](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L7031-L7786)        | Worker 调用日志页  |
| `/binding`    | [handleBindingsPage](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L8111-L8647)   | 资源绑定配置页       |
| `/deployment` | [handleDeploymentPage](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L8990-L9202) | 部署历史与回滚页      |
| `/routes`     | [handleRoutesPage](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L9477-L9795)     | 域名路由配置页       |
| `/setting`    | [handleSettingPage](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L10040-L10410)  | Worker 设置页    |
| `/curl`       | [handleCurlPage](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L10779-L10980)     | cURL 代理工具页    |
| `/graphql`    | [handleGraphQLPage](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L11192-L...)    | GraphQL 查询页   |
| `/login`      | [showLoginPage](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L2543-L3299)        | 登录页           |
| 未匹配           | [handle404Page](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L518-L569)          | 404 页面        |

#### API 路由表（10 组接口）

| 路径前缀                        | 处理函数                                                                                                   | 代理的 Cloudflare API 资源            |
| --------------------------- | ------------------------------------------------------------------------------------------------------ | -------------------------------- |
| `/api/workers`              | [handleWorkersAPI](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L3743-L3762)    | Worker Script 列表                 |
| `/api/script`               | [handleEditorRequest](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L3439-L3731) | Worker Script 内容（读写）             |
| `/api/kv`、`/api/namespaces` | [handleKvNamespace](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L4927-L5037)   | KV 命名空间 + 键值对                    |
| `/api/wtc`                  | [handleWtc](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L6712-L6805)           | Worker 调用日志（GraphQL）             |
| `/api/bindings`             | [handleBindings](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L7787-L8110)      | 资源绑定配置                           |
| `/api/deployment`           | [handleDeployment](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L8831-L8989)    | 部署版本 / 回滚                        |
| `/api/routes`               | [handleRoutes](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L9203-L9476)        | 域名路由                             |
| `/api/setting`              | [handleSetting](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L9796-L10039)      | 创建 / 删除 Worker、日志开关              |
| `/api/curl`                 | [handleCurl](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L10513-L10684)        | 自定义 cURL（仅允许 api.cloudflare.com） |
| `/api/graphql`              | [handleGraphQL](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L10981-L11180)     | Cloudflare GraphQL API           |

***

### 模块 2：认证鉴权层

**核心文件位置**：L1898-L2542

#### 三种登录存储模式

用户在登录页可选择以下任意一种方式存储 API Token：

| 模式                  | 存储位置             | 加密方式                                     | 自动续期 | 账户名称支持 | 适用场景                    |
| ------------------- | ---------------- | ---------------------------------------- | ---- | ------ | ----------------------- |
| **导入登录**            | 内存（JS 变量）        | 无（会话级）,后续进行**localStorage**加密存储和cookie登录 | ✅    | ✅      | 用于首次登录时导入并设置密码,以便后续快速登录 |
| **LocalStorage 登录** | 浏览器 localStorage | AES-256-GCM,后续进入cookie登录流程               | ✅    | ✅      | 个人设备,长期保存,输入密码即可快速进入    |
| **Cookie 登录**       | HttpOnly Cookie  | AES-256-GCM + 时间戳签名                      | ✅    | ✅      | 主要用于会话管理,自动续期会话         |

> **账户名称支持**：登录成功后会自动调用 Cloudflare `/accounts/:id` 接口拉取账户名（name/EMAIL），通过两种方式持久化以便页面展示：
>
> 1. 服务端使用**Token SHA-256 哈希派生密钥 XOR 加密**后写入 `account_name` HttpOnly Cookie（安全性要求不高，可快速还原用于导航栏/欢迎语展示）；
> 2. 登录响应 JSON 附带明文字段 `account_name`，前端存入独立的 `cf_accounts_meta` localStorage key，用于登录页「本地账户列表」优先显示名称而非 ID。

#### Token 加密体系

所有加密操作均使用 **Web Crypto API**（SubtleCrypto），核心函数：

| 函数                                                                                                            | 位置    | 作用                                                              |
| ------------------------------------------------------------------------------------------------------------- | ----- | --------------------------------------------------------------- |
| [deriveKey](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L1917-L1932)                  | L1917 | 基于 PBKDF2 派生 AES 密钥（使用 scriptId + accountId）                    |
| [encrypt](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L1933-L1954)                    | L1933 | AES-256-GCM 加密（随机 IV，输出 Base64）                                 |
| [decrypt](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L1955-L1976)                    | L1955 | AES-256-GCM 解密                                                  |
| [encryptForCookie](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L1985-L1991)           | L1985 | Cookie 专用加密（附加过期时间 + renewToken）                                |
| [decryptForCookie](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L1992-L2021)           | L1992 | Cookie 专用解密（校验过期时间）                                             |
| [simpleEncryptWithTokenHash](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L2046-L2059) | L2046 | 账户名称轻量加密：使用 `SHA-256(token)` 32B 密钥循环 XOR，Base64 输出             |
| [simpleDecryptWithTokenHash](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L2061-L2074) | L2061 | 对应解密函数，仅持有原始 token 时可还原账户名                                      |
| [fetchCloudflareAccountName](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L2022-L2044) | L2022 | 调用 Cloudflare `GET /accounts/:id` 获取账户名（name/EMAIL），失败静默返回 null |

#### 账户名称获取、存储与显示链路

```
登录验证通过（verifyApiToken）
        ↓
fetchCloudflareAccountName → 拿到账户名 rawAccountName
        ↓
┌─────────────┬──────────────────────────────────────────────────────────────┐
│ 服务端写入 Cookie  │  simpleEncryptWithTokenHash(raw, token) → Base64       │
│                   │  写入 Set-Cookie: account_name=<Base64>                │
│                   │  所有页面：getValidToken 拿到 token 后解密 → displayAccount │
│                   │  导航栏、欢迎语、各页面顶部优先使用 displayAccount 显示         │
├─────────────┼──────────────────────────────────────────────────────────────┤
│ 前端 localStorage │  createLoginResponse / API 响应 JSON 带 account_name       │
│                   │  （明文，用于本地列表展示；安全性要求不高）                       │
│                   │  前端写入 cf_accounts_meta[accountId].account_name         │
│                   │  登录页 renderAccountList 优先显示名称，缺少则回退显示 accountId   │
└─────────────┴──────────────────────────────────────────────────────────────┘
```

**向后兼容策略**：

- `cf_accounts` 原有 token 存储结构**未做任何改动**，老客户端数据直接可用；
- 账户名称使用**独立 localStorage key** `cf_accounts_meta`（结构：`{ [accountId]: { account_name: string } }`），缺失时 UI 自动回退显示 ID；
- 登录响应 JSON 新增字段 `account_name` 为**可选字段**，旧前端忽略即可；
- `account_name` Cookie、续期、登出清除逻辑均为**新增可选项**，无值时不写入，不影响旧会话。

#### 客户端本地存储结构（localStorage）

| Key                | 结构                                                                     | 作用                        | 新增/原有 |
| ------------------ | ---------------------------------------------------------------------- | ------------------------- | ----- |
| `cf_accounts`      | `{ [accountId: string]: string }`（AES-256-GCM + PBKDF2 双重加密 token 字符串） | 保存账户的加密 API Token（原有结构未变） | 原有    |
| `cf_accounts_meta` | `{ [accountId: string]: { account_name?: string } }`                   | 账户名、备注等可扩展元信息（不侵入旧结构）     | 新增    |

#### Token 有效性验证

在 [getValidToken](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L2050-L2096) 中统一实现，按以下优先级获取凭证：

```
1. Authorization: Bearer <token> 头
2. Cookie 中的 cf_api + account_id
3. LocalStorage 中的加密数据（通过请求头传递）
```

验证通过后调用 [verifyApiToken](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L2022-L2049) 实际访问 Cloudflare API 确认 Token 有效。

#### 自动续期机制（Cookie 模式）

核心函数 [checkAndRenewCookie](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L2395-L2542)：

1. **续期触发条件**：剩余时间 < `loginPeriod * 40%`（默认 3 天 × 0.4 = 1.2 天）
2. **续期间隔限制**：最短 30 分钟（`renewal.minInterval`）
3. **续期最大期限**：登录超过 30 天不再续期，需重新登录
4. **IP 绑定**：续期 Token 包含客户端 IP 哈希，防止 Token 被盗用
5. **客户端发起**：前端公共脚本（buildHtmlResponse 注入）定时请求 `/login/renew`

***

### 模块 3：API 代理层

所有 Cloudflare API 请求通过 [apiRequest](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L5050-L5078) 发出：

```javascript
async function apiRequest(path, method, body, token, extraHeaders) {
  // 自动拼接：https://api.cloudflare.com/client/v4 + path
  // 自动注入：Authorization: Bearer <token>
  // 自动注入：Content-Type: application/json
  // 统一错误处理：返回 Cloudflare 格式的 JSON 响应
}
```

#### API 分组封装

| 封装模块           | 函数                                                                                                                                                                                                                                                                                                          | Cloudflare API 端点                            |
| -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------- |
| **Workers 列表** | [listWorkers](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L3732-L3742)                                                                                                                                                                                                              | `GET accounts/:id/workers/scripts`           |
| **脚本管理**       | [handleEditorRequest](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L3439-L3731)                                                                                                                                                                                                      | `GET/PUT accounts/:id/workers/scripts/:name` |
| **KV 命名空间**    | [createNamespace](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L5079-L5094) / [listNamespaces](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L5095-L5127) / [deleteNamespace](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L5128-L5146) | `/storage/kv/namespaces` CRUD                |
| **KV 键值对**     | [writeKey](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L5278-L5348) / [readKey](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L5147-L5182) / [deleteKey](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L5183-L5240)                     | `/namespaces/:ns/values/:key` CRUD           |
| **KV 批量写入**    | [bulkWriteKeys](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L5322-L5348)                                                                                                                                                                                                            | `/namespaces/:ns/bulk`                       |
| **绑定管理**       | [handleGetBindings](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L8009-L8060) / [handleUpdateBindings](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L8061-L8110)                                                                                              | Worker bindings + content-type multipart     |
| **Secret 管理**  | [handleSecretOperation](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L7827-L7879) / [handleDeleteSecret](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L7880-L7925)                                                                                            | Worker secrets CRUD                          |
| **部署管理**       | [handleGetVersions](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L8875-L8906) / [handleRollback](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L8907-L8957)                                                                                                    | `/deployments/versions` + rollback           |
| **日志（WTC）**    | [queryTelemetryAPI](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L6806-L6818)                                                                                                                                                                                                        | `POST /graphql`（Worker Invocation 事件）        |

***

### 模块 4：页面渲染层

#### SSR 渲染模型

项目采用**服务端模板字符串拼接**的 SSR 模式，无前端框架。核心工具函数：

**[buildHtmlResponse](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L749-L1219)** 是所有页面的公共渲染器，负责：

1. **导航栏注入**：根据登录状态选择完整导航栏（FULL\_NAV）或精简导航栏（SMALL\_NAV）
2. **公共脚本注入**：主题切换 + 响应式适配 + Cookie 自动续期 + 401 覆盖层
3. **错误覆盖层**：可选的动态错误页叠加层
4. **响应头设置**：Content-Type、自定义 headers

#### 主题系统

通过 CSS 变量实现亮/暗双主题，切换按钮由公共脚本统一管理：

```css
:root {                    /* 亮色模式（默认） */
  --primary-color: #2563eb;
  --bg-color: #ffffff;
  ...
}
[data-theme="dark"] {      /* 深色模式 */
  --primary-color: #3b82f6;
  --bg-color: #0f172a;
  ...
}
```

#### 编辑器页面（handleEditPage）特殊机制

- **代码检查**：前端通过 CDN 加载 JSHint 进行语法检查
- **快捷键**：Ctrl+S（保存）、Ctrl+L（加载）、Ctrl+K（检查）、Ctrl+D（清空）、Ctrl+E（下载）
- **Module 模式**：支持 Service Worker 格式 与 ES Module 格式自动检测

***

### 模块 5：工具与安全层

#### 通用工具函数

| 函数                                                                                                    | 位置     | 作用                    |
| ----------------------------------------------------------------------------------------------------- | ------ | --------------------- |
| [parseCookies](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L302-L308)         | L302   | Cookie 字符串解析为对象       |
| [jsonResponse](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L310-L319)         | L310   | 统一 JSON 响应封装（格式化 + 头） |
| [escapeHtml](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L739-L747)           | L739   | HTML 转义（防 XSS）        |
| [errorResponse](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L5038-L5049)      | L5038  | 标准化 Cloudflare 错误响应   |
| [parseCurlCommand](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L10685-L10778) | L10685 | cURL 命令行解析器（支持常用参数）   |

#### 安全防护措施

1. **HTTPS 强制**（L57）：非调试模式所有 HTTP 跳转 HTTPS
2. **XSS 防护**：所有用户输入经 `escapeHtml` 转义后再拼接 HTML
3. **HttpOnly Cookie**：所有关键 Cookie 设置 HttpOnly + Secure + SameSite
4. **CORS 控制**（L222）：API 响应带 `Access-Control-Allow-Origin` 头
5. **cURL 白名单**（L10513）：仅允许代理 `api.cloudflare.com`，防止 SSRF

***

## 5. 核心配置参数

全部位于 [index.js](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L1-L24) 文件顶部：

```javascript
// ============ 生产部署前务必修改 ============
const scriptId    = '...';    // 加密盐值，改为随机 UUID 或任意字符串
const DEBUG       = false;    // 生产环境必须为 false！

// ============ 可根据需要调整 ============
const loginPeriod = 3*60*60*24;  // Token 免密登录期限（默认 3 天）
const CLOCK_SKEW  = 10;          // 时钟偏差容忍窗口（秒）
const renewal = {
    threshold:   0.4,            // 剩余时间 40% 时触发续期
    maxPeriod:   30*24*60*60,    // 超过 30 天强制重新登录
    minInterval: 30*60           // 续期最短间隔 30 分钟
};
```

| 参数                | 重要性   | 说明                                 |
| ----------------- | ----- | ---------------------------------- |
| `scriptId`        | ⭐⭐⭐⭐⭐ | 加密密钥派生基础，**必须修改为随机值**，否则所有部署使用相同密钥 |
| `DEBUG`           | ⭐⭐⭐⭐⭐ | 生产必须 false，开启后可查看 Cookie 明文        |
| `loginPeriod`     | ⭐⭐⭐   | 有效期太短频繁登录，太长不安全                    |
| `SCRIPT_ID` (env) | ⭐⭐⭐⭐  | 通过环境变量覆盖 scriptId，优先级高于代码内硬编码      |

***

## 6. 数据流示例：编辑 Worker 全流程

```
1. 浏览器访问 /edit?worker=my-script
   ↓
2. handleRequest → 鉴权 getValidToken
   ↓
3. handleEditPage(acc, logined=true)
   ↓ 渲染编辑器 HTML（包含加载/保存按钮）
4. 用户点击「加载」→ 前端 fetch('/api/script/my-script')
   ↓
5. handleApiRequest → handleEditorRequest GET
   ↓
6. apiRequest() → GET api.cloudflare.com/.../scripts/my-script
   ↓ 返回 script 内容
7. 前端填充 textarea
   ↓
8. 用户编辑后 Ctrl+S → PUT /api/script/my-script
   ↓
9. handleEditorRequest PUT → 构造 multipart/form-data
   ↓    (包含 script content + bindings metadata)
10. PUT api.cloudflare.com/.../scripts/my-script
    ↓
11. 返回部署结果 → Toast 提示
```

***

## 7. 开发与部署

### 本地开发

```bash
# 1. 安装依赖
npm install

# 2. 登录 Cloudflare（首次）
npx wrangler login

# 3. 启动本地开发服务器
npm run dev
# → http://localhost:8787
```

### 生产部署

```bash
# 方法一：CLI 部署
npm run deploy

# 方法二：Dashboard 部署
# 直接复制 src/index.js 内容到 Cloudflare Worker 编辑器保存即可
```

### 环境变量配置

在 [wrangler.toml](file:///d:/niwei/Documents/trae_projects/worker/editor/wrangler.toml) `[vars]` 节或 Dashboard 中设置：

```
SCRIPT_ID = "你自己的随机字符串"
```

或复制 `.dev.vars.example` → `.dev.vars` 用于本地开发。

***

## 8. 代码阅读导航建议

由于全部代码集中在单文件中，建议按以下顺序阅读：

| 阅读阶段            | 行号范围                                                                     | 目标                         |
| --------------- | ------------------------------------------------------------------------ | -------------------------- |
| **第一阶段：整体骨架**   | L26-L207                                                                 | handleRequest 主路由流程        |
| **第二阶段：认证逻辑**   | L1898-L2542                                                              | 加密 + 登录 + Token 验证 + 自动续期  |
| **第三阶段：API 分发** | L219-L300、L5050-L5078                                                    | API 路由分发 + apiRequest 统一请求 |
| **第四阶段：核心功能**   | L3439-L4230（Worker管理）L4927-L5582（KV）L6712-L7786（日志）L7787-L9202（绑定/部署/路由） | 各业务模块实现                    |
| **第五阶段：页面渲染**   | L321-L1220、各 handleXXXPage                                               | HTML 生成 + UI 结构            |
| **第六阶段：辅助功能**   | L10513-L11192                                                            | cURL 代理 + GraphQL          |

***

## 9. 架构决策速查表

| 决策点      | 选型                             | 原因                     |
| -------- | ------------------------------ | ---------------------- |
| 运行时      | Cloudflare Workers (ES Module) | 全球边缘、零运维、免费额度充足        |
| 架构模式     | 单文件 SSR + API Proxy            | 便于复制粘贴部署，无构建依赖         |
| 存储模型     | 客户端加密存储                        | 服务端完全无状态，无需数据库         |
| 加密算法     | AES-256-GCM + PBKDF2           | Web Crypto 原生支持，安全强度足够 |
| Token 续期 | 客户端主动轮询 + 服务端验证                | 无 Server-Sent 依赖，兼容性好  |
| 前端方案     | 原生 HTML/CSS/JS（JSHint CDN）     | 兼容性好，低版本浏览器可运行         |
| UI 主题    | CSS 变量 + data-theme 属性         | 零 JS 运行时开销，即时切换        |

***

## 10. 常见修改点索引

| 修改需求      | 查找位置                                                                                                  |
| --------- | ----------------------------------------------------------------------------------------------------- |
| 修改页面标题    | 各 handleXXXPage 函数中的 `<title>` 标签                                                                     |
| 新增 CSS 样式 | [handleCss](file:///d:/niwei/Documents/trae_projects/worker/editor/src/index.js#L1221-L1742)（L1221 起） |
| 修改登录过期时间  | 顶部 `loginPeriod` 常量                                                                                   |
| 新增 API 接口 | handleApiRequest 路由判断 + 新增处理函数                                                                        |
| 新增页面路由    | handleRequest 页面路由段 + 新增 handleXXXPage 函数                                                             |
| 修改加密密钥    | 代码顶部 `scriptId` 或环境变量 `SCRIPT_ID`                                                                     |
| 修改主题色值    | handleCss 中的 CSS 变量定义                                                                                 |

***

*文档生成日期：2026-07-09*
