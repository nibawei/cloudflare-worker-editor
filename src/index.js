//cloudflare worker.js
// @module-type: esm
// 服务器id 用于加密数据
const scriptId = '21f68f42-9bc6-45e9-84a3-9fde721cbf81'; //为保证安全，请替换为随机数
// token免密钥登录期限(s)
const loginPeriod = 3 * 60 * 60 * 24; //3天
// 登录时间偏差窗口(s)
const CLOCK_SKEW = 10;
const renewal = {
    // 续期阈值（百分比）
    threshold: 0.4,
    // 续期最大期限,密码登录超过此时间不能自动续期(s)
    maxPeriod: 30 * 24 * 60 * 60,
    // 自动请求续期间隔(s)
    minInterval: 30 * 60
};
//=========================================

const DEBUG = false; // 仅供调试使用，开启后极有可能会导致敏感数据泄露
export default {
    async fetch(request, env, ctx) {
        return handleRequest(request, env);
    }
};
// 主请求处理
async function handleRequest(request, env) {
    // 在 try 外部声明变量，确保 catch 块中可以访问
    let url, method, pathname, acceptHeader, isApiRequest;

    try {
        // 解析请求基础信息
        url = new URL(request.url);
        method = request.method;
        pathname = url.pathname;
        acceptHeader = request.headers.get('Accept') || '';
        isApiRequest = acceptHeader.includes('application/json') || pathname.startsWith('/api');

        const SCRIPT_ID = env?.SCRIPT_ID;
        const cookies = parseCookies(request.headers.get('Cookie')) || {};
        const serverId = getScriptID(url, SCRIPT_ID);

        // ===== 静态资源处理 =====
        if (pathname === '/robots.txt' && method === 'GET') {
            return handleRobotsTxt(request);
        }
        if (pathname === '/sitemap.xml' && method === 'GET') {
            return handleSitemap(request);
        }
        if (pathname === '/static/style.css' && method === 'GET') {
            return handleCss();
        }
        if ((pathname === '/static/svg/favicon.svg' || pathname === '/favicon.svg') && method === 'GET') {
            return handleFavicon(request, url);
        }

        // ===== HTTPS 强制跳转 =====
        if (url.protocol !== 'https:' && !DEBUG) {
            if (isApiRequest) {
                return new Response(JSON.stringify({ error: 'HTTPS Required' }), {
                    status: 403,
                    headers: { 'Content-Type': 'application/json' }
                });
            } else {
                // 安全生成 HTTPS 链接：使用 URL 对象修改协议
                const httpsUrl = new URL(url.href);
                httpsUrl.protocol = 'https:';
                const redirectUrl = httpsUrl.href;
                return errHtml(403, '请使用安全的网络访问本网站\n(HTTPS Required)', redirectUrl, true);
            }
        }

        // ===== 公开路由 =====
        if (pathname === '/login' && method === 'GET') {
            return showLoginPage(request, url);
        }
        if (pathname === '/logout' && method === 'GET') {
            return handleLogout(request);
        }

        // ===== 调试路由 =====
        if (DEBUG) {
            if (pathname === '/get/cookie') {
                return new Response(JSON.stringify(cookies), {
                    status: 200,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
            if (pathname === '/get/cookie/status') {
                if (!cookies.cf_api || !cookies.account_id) {
                    return new Response(JSON.stringify({ valid: false, remainingSeconds: null }), {
                        status: 200,
                        headers: { 'Content-Type': 'application/json' }
                    });
                }
                return new Response(JSON.stringify(await getCookieStatus(cookies.cf_api, cookies.account_id, serverId)), {
                    status: 200,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
        }

        // ===== 登录相关 =====
        if (pathname.startsWith('/login') || pathname.startsWith('/api/cookie')) {
            return await handleLoginRequest(request, serverId, cookies, method, url);
        }

        // ===== API 路由 =====
        if (pathname.startsWith('/api')) {
            return handleApiRequest(request, cookies, url, method, serverId);
        }

        // ===== 需要认证的路由 =====
        const authHeader = request.headers.get('Authorization');
        let tokenFromHeader = null;
        if (authHeader && authHeader.startsWith('Bearer ')) {
            tokenFromHeader = authHeader.substring(7);
        }
        const accountIdHeader = request.headers.get('accountId') || null;
        const tokenInfo = await getValidToken(request, cookies, serverId, tokenFromHeader, accountIdHeader);
        const logined = tokenInfo.valid;
        const accountId = tokenInfo.accountId || cookies.account_id || '';
        let displayAccount = accountId;
        if (logined && tokenInfo.token && cookies.account_name) {
            try {
                const decryptedName = await simpleDecryptWithTokenHash(decodeURIComponent(cookies.account_name), tokenInfo.token);
                if (decryptedName) {
                    displayAccount = decryptedName;
                }
            } catch (e) {
                console.warn('Failed to decrypt account_name cookie:', e);
                displayAccount = accountId;
            }
        } else {
            console.warn('No account_name cookie found, using accountId:', accountId);
            displayAccount = accountId;
        }

        // 页面路由
        if (pathname === '/' && method === 'GET') {
            return handleStartPage(displayAccount, logined);
        }
        if (pathname === '/list' && method === 'GET') {
            return handleListPage(displayAccount, logined);
        }
        if (pathname === '/edit' && method === 'GET') {
            return handleEditPage(request, displayAccount, logined);
        }
        if (pathname === '/kv' && method === 'GET') {
            return handleKVHtml(displayAccount, logined);
        }
        if (pathname === '/kv/bulk' && method === 'GET') {
            return handleKVBulkHtml(displayAccount, logined);
        }

        if (pathname === '/wtc' && method === 'GET') {
            return handleWtcPage(displayAccount, logined);
        }
        if (pathname === '/binding' && method === 'GET') {
            return handleBindingsPage(displayAccount, logined);
        }
        if (pathname === '/deployment' && method === 'GET') {
            return handleDeploymentPage(displayAccount, logined);
        }
        if (pathname === '/routes' && method === 'GET') {
            return handleRoutesPage(displayAccount, logined);
        }
        if (pathname === '/setting' && method === 'GET') {
            return handleSettingPage(displayAccount, logined);
        }
        if (pathname === '/create' && method === 'GET') {
            return handleCreatePage(displayAccount, logined);
        }
        if (pathname === '/curl' && method === 'GET') {
            return handleCurlPage(displayAccount, logined);
        }
        if (pathname === '/graphql' && method === 'GET') {
            return handleGraphQLPage(displayAccount, logined);
        }

        // 未匹配任何路由
        if (isApiRequest) {
            return new Response(JSON.stringify({ error: 'Not found' }), {
                status: 404,
                headers: { 'Content-Type': 'application/json' }
            });
        }
        return handle404Page();

    } catch (error) {
        // 统一错误处理
        console.error('Request error:', error);

        // 尝试获取请求类型（若出错时 url 未定义，则从 request 重新构造）
        let isJsonResponse = false;
        try {
            if (url) {
                isJsonResponse = isApiRequest;
            } else {
                const tempUrl = new URL(request.url);
                const tempAccept = request.headers.get('Accept') || '';
                isJsonResponse = tempAccept.includes('application/json') || tempUrl.pathname.startsWith('/api');
            }
        } catch (e) {
            // 如果连 URL 都无法解析，默认返回 JSON
            isJsonResponse = true;
        }

        if (isJsonResponse) {
            const errorBody = DEBUG
                ? JSON.stringify({ error: 'Server error: ' + error.message })
                : JSON.stringify({ error: 'Server error, please try again later' });
            return new Response(errorBody, {
                status: 500,
                headers: { 'Content-Type': 'application/json' }
            });
        } else {
            if (DEBUG) return errHtml(500, '服务器错误:' + error.message);
            // 返回 HTML 错误页
            return errHtml(500, '服务器错误，请稍后再试');
        }
    }
}
// 处理登录请求
async function handleLoginRequest(request, serverId, cookies, method, url) {
    if ((url.pathname === '/login' || url.pathname === '/api/login') && method === 'POST') {
        return handleLogin(request, serverId, url, cookies);
    }
    if (url.pathname === '/login/renew' && method === 'GET') {
        return checkAndRenewCookie(cookies, serverId, { requireRenewToken: true, request });
    }
    return new Response("Not Found", { status: 404 });
}
// 处理api请求
async function handleApiRequest(request, cookies, url, method, serverId) {
    try {
        // 处理CORS预检请求
        if (method === 'OPTIONS') {
            return new Response(null, {
                headers: {
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Methods': 'GET, PUT, OPTIONS',
                    'Access-Control-Allow-Headers': 'Content-Type, Authorization'
                }
            });
        }
        // 从请求头获取 token（如果存在）
        const authHeader = request.headers.get('Authorization');
        let tokenFromHeader = null;
        if (authHeader && authHeader.startsWith('Bearer ')) {
            tokenFromHeader = authHeader.substring(7);
        }
        // 获取有效的 token
        const tokenInfo = await getValidToken(request, cookies, serverId, tokenFromHeader);
        if (!tokenInfo.valid) {
            return new Response(JSON.stringify({
                success: false,
                error: "Unauthorized"
            }), {
                status: 401,
                headers: {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                }
            });
        }
        const accountId = tokenInfo.accountId;
        const token = tokenInfo.token;
        // API 路由分发
        if (url.pathname === '/api/workers') {
            return handleWorkersAPI(request, accountId, token);
        }
        if (url.pathname.startsWith('/api/script')) {
            return handleEditorRequest(request, accountId, token);
        }
        if (url.pathname.startsWith('/api/kv') || url.pathname.startsWith('/api/namespaces')) {
            return await handleKvNamespace(request, accountId, token, url, method);
        }
        if (url.pathname.startsWith('/api/wtc')) {
            return await handleWtc(request, url.pathname, accountId, token);
        }
        if (url.pathname.startsWith('/api/bindings')) {
            return await handleBindings(request, url, accountId, token);
        }
        if (url.pathname.startsWith('/api/deployment')) {
            return await handleDeployment(request, url, accountId, token);
        }
        if (url.pathname.startsWith('/api/routes')) {
            return await handleRoutes(request, url, accountId, token);
        }
        if (url.pathname.startsWith('/api/setting')) {
            return await handleSetting(request, url, accountId, token);
        }
        if (url.pathname.startsWith('/api/curl')) {
            return await handleCurl(request, token, url);
        }
        if (url.pathname.startsWith('/api/graphql')) {
            return await handleGraphQL(request, url, accountId, token);
        }
        return new Response(JSON.stringify({
            success: false,
            error: "Not Found"
        }), {
            status: 404,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });
    } catch (error) {
        console.error('Error:', error);
        return jsonResponse({
            error: 'Internal server error: ' + error
        }, 500);
    }
}
// 解析Cookie
function parseCookies(cookieHeader) {
    return (cookieHeader || '').split(';').reduce((cookies, item) => {
        const [name, value] = item.split('=').map(i => i.trim())
        cookies[name] = value
        return cookies
    }, {})
}
// 返回JSON响应
function jsonResponse(data, options = {}) {
    const headers = {
        'Content-Type': 'application/json',
        ...(options.headers || {}),
    };
    return new Response(JSON.stringify(data, null, 2), {
        ...options,
        headers,
    });
}
//=================pages===================
//处理网站图标
async function handleFavicon(request, url) {
    // 远程SVG URL
    const remoteSvgUrl = 'https://image.datas.ip-ddns.com/images/c79fbea5-3896-45bf-afe4-9351d8575498';
    try {
        const svgResponse = await fetch(remoteSvgUrl);
        if (svgResponse.ok) {
            const svgData = await svgResponse.text();
            return new Response(svgData, {
                headers: {
                    'Content-Type': 'image/svg+xml',
                    'Cache-Control': 'public, max-age=86400', // 缓存1天
                    'Access-Control-Allow-Origin': '*' // 添加CORS头
                }
            });
        } else {
            // 处理HTTP错误状态码
            return new Response(JSON.stringify({
                success: false,
                error: `Failed to fetch remote favicon: HTTP ${svgResponse.status}`
            }), {
                status: svgResponse.status,
                headers: {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                }
            });
        }
    } catch (error) {
        console.error('Failed to fetch remote favicon:', error);
        return new Response(JSON.stringify({
            success: false,
            error: 'Failed to fetch remote favicon: ' + error.message
        }), {
            status: 500,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });
    }
}
// 首页 / 
function handleStartPage(acc, logined) {
    const welcomeMsg = logined ?
        `<div class="alert alert-success" style="background-color: var(--info-color); color: var(--text-color); padding: 1rem; border-radius: var(--radius); margin-bottom: 1.5rem;">欢迎回来，${escapeHtml(acc)}</div>` :
        `<div class="alert alert-warning" style="background-color: var(--info-color); color: var(--text-color); padding: 1rem; border-radius: var(--radius); margin-bottom: 1.5rem;">点击登录按钮开始体验</div>`;

    const features = [{
        icon: "📝",
        title: "在线编辑与部署 Worker",
        desc: "创建、编辑、保存 Workers 脚本，支持语法检查"
    },
    {
        icon: "🗄️",
        title: "KV 命名空间及键值管理",
        desc: "管理命名空间和键值对，支持批量操作与过期时间"
    },
    {
        icon: "📜",
        title: "Worker 调用日志查询",
        desc: "实时查询调用记录，按状态、路径、国家等过滤"
    },
    {
        icon: "🔗",
        title: "资源绑定配置",
        desc: "绑定 KV、R2、D1、Secret 等 Cloudflare 资源"
    },
    {
        icon: "🔄",
        title: "部署历史与版本回滚",
        desc: "查看部署记录，一键回滚到任意历史版本"
    },
    {
        icon: "🌐",
        title: "域名路由配置",
        desc: "为 Worker 绑定域名路由，支持模式匹配"
    },
    {
        icon: "🧪",
        title: "cURL 代理调试工具",
        desc: "直接执行 Cloudflare API 的 cURL 命令"
    },
    {
        icon: "📊",
        title: "请求统计与性能图表",
        desc: "可视化请求趋势、CPU 时间、地理分布"
    }
    ];

    const featuresHtml = features.map(f => `
        <div class="feature" data-desc="${escapeHtml(f.desc)}">
            <div class="feature-icon">${f.icon}</div>
            <div class="feature-title">${escapeHtml(f.title)}</div>
            <div class="feature-desc">${escapeHtml(f.desc)}</div>
        </div>
    `).join('');

    const html = `
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <link rel="icon" href="/favicon.svg" type="image/svg+xml">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Worker 编辑器|首页</title>
        <link rel="stylesheet" href="/static/style.css">
        <style>
            .hero {
                text-align: center;
                padding: 2rem 1rem;
                background: var(--surface-color);
                border-radius: var(--radius);
                margin-bottom: 2rem;
                border: 1px solid var(--border-color);
            }
            .hero h1 { font-size: 2rem; margin-bottom: 0.5rem; }
            .features {
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
                gap: 1rem;
                margin: 1.5rem 0;
            }
            .feature {
                background: var(--surface-color);
                border: 1px solid var(--border-color);
                border-radius: var(--radius);
                padding: 1rem;
                text-align: center;
                transition: all 0.2s ease;
                cursor: default;
            }
            .feature:hover {
                transform: translateY(-2px);
                box-shadow: var(--shadow);
                border-color: var(--primary-color);
            }
            .feature-icon {
                font-size: 2rem;
                margin-bottom: 0.5rem;
            }
            .feature-title {
                font-weight: 600;
                margin-bottom: 0.5rem;
                color: var(--primary-color);
            }
            .feature-desc {
                font-size: 0.8rem;
                color: var(--text-secondary);
                line-height: 1.4;
                display: none; /* 默认隐藏，悬停时显示 */
            }
            .feature:hover .feature-desc {
                display: block;
            }
            .btn-center {
                text-align: center;
                margin: 1.5rem 0;
            }
            @media (max-width: 640px) {
                .feature-desc { display: block; } /* 移动端始终显示 */
                .feature:hover .feature-desc { display: block; }
            }
        </style>
    </head>
    <body>
        {{NAVBAR}}
        <main class="container">
            ${welcomeMsg}
            <div class="hero">
                <h1>🚀 Cloudflare Workers 编辑器</h1>
                <p>一个简洁的 Web 管理工具，助您轻松管理 Workers、KV、日志、路由等资源。</p>
            </div>
            <div class="btn-center">
                ${logined
            ? `<a href="/list" class="btn">进入控制台</a>`
            : `<a href="/login" class="btn">登录</a>`}
            </div>
            <div class="features">
                ${featuresHtml}
            </div>
            <div class="card" style="margin-top: 1.5rem; text-align: center;">
                <p>🔐 使用 Cloudflare API Token 登录后即可开始管理。</p>
                <small>本工具仅作为管理界面，不存储任何用户数据。</small>
            </div>
        </main>
    </body>
    </html>
    `;
    return buildHtmlResponse(html, logined ? acc : '', {
        littleNav: !logined,
        errorHandler: errHtml,
        homeUrl: '/',
        enableUnauthorizedOverlay: false
    });
}
// 错误界面
function handle404Page() {
    const html = `
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
        <meta charset="UTF-8">
        <link rel="icon" href="/favicon.svg" type="image/svg+xml">
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <title>Worker 编辑器|404</title>
        <link rel="stylesheet" href="/static/style.css">
        <style>
        .error-container {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        min-height: calc(100vh - 120px);
        text-align: center;
        padding: 2rem;
        }
        h1 {
        font-size: 6rem;
        line-height: 1;
        color: var(--primary-color);
        margin-bottom: 1rem;
        }
        .button-group {
        display: flex;
        gap: 1rem;
        margin-top: 2rem;
        flex-wrap: wrap;
        justify-content: center;
        }
        </style>
        </head>
        <body>
        {{NAVBAR}}
        <div class="error-container">
        <h1>404</h1>
        <h2>页面未找到</h2>
        <p>抱歉，您访问的页面不存在或已被移除</p>
        <div class="button-group">
        <a href="/" class="btn">返回首页</a>
        <a href="javascript:history.back()" class="btn btn-secondary">返回上一页</a>
        </div>
        </div>
        </body>
        </html>`;
    return buildHtmlResponse(html, '', {
        littleNav: true
    });
}
function errHtml(code, message, redirectUrl = '/', showCloseOnly = false) {
    const buttonsHtml = showCloseOnly ? `<button onclick="window.close()" class="btn btn-danger">关闭页面</button>` : `<div class="button-group">
        <a href="javascript:history.back()" class="btn btn-secondary">返回上一页</a>
        <a href="${redirectUrl}" class="btn">返回首页</a>
        </div>`;
    const html = `<!DOCTYPE html>
        <html lang="zh-CN">
        <head>
        <meta charset="UTF-8">
        <link rel="icon" href="/favicon.svg" type="image/svg+xml">
        <title>Worker 编辑器|${code}</title>
        <link rel="stylesheet" href="/static/style.css">
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <style>
        .error-container {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        min-height: 70vh;
        text-align: center;
        padding: 2rem;
        }
        .error-code {
        font-size: 4rem;
        line-height: 1;
        color: var(--danger-color);
        margin-bottom: 0.5rem;
        }
        .error-title {
        margin-bottom: 1rem;
        }
        .error-message {
        color: var(--text-secondary);
        margin-bottom: 2rem;
        max-width: 500px;
        }
        .button-group {
        display: flex;
        gap: 1rem;
        flex-wrap: wrap;
        justify-content: center;
        }
        </style>
        </head>
        <body>
        <!-- 导航栏 -->
        <nav class="navbar">
        <!-- 左侧区域 -->
        <div class="d-flex align-center gap-2" style="min-width: 0;">
        <span style="font-weight: 500; white-space: nowrap; flex-shrink: 0;">worker 编辑器</span>
        </div>

        <!-- 右侧区域 -->
        <div class="d-flex align-center gap-2" style="flex-shrink: 0;">
        <!-- 深色模式按钮 -->
        <div class="theme-toggle">
        <button class="theme-toggle-btn" id="themeToggle" aria-label="切换主题">
        <span class="theme-icon">切换主题</span>
        </button>
        </div>
        </div>
        </nav>

        <div class="error-container">
        <h1 class="error-code">${code}</h1>
        <h2 class="error-title">${getErrorTitle(code)}</h2>
        <p class="error-message">${message}</p>
        ${buttonsHtml}
        </div>
        <script>
        // 主题切换功能
        function initThemeToggle() {
        const themeToggle = document.getElementById('themeToggle');
        const htmlElement = document.documentElement;

        // 添加一个用于显示图标的span元素
        const themeIcon = document.createElement('span');
        themeIcon.className = 'theme-icon';
        themeToggle.appendChild(themeIcon);

        // 检查本地存储的主题设置
        const savedTheme = localStorage.getItem('theme');

        // 检查系统主题偏好
        const prefersDarkScheme = window.matchMedia('(prefers-color-scheme: dark)');

        // 设置初始主题
        let currentTheme;
        if (savedTheme) {
        currentTheme = savedTheme;
        htmlElement.setAttribute('data-theme', savedTheme);
        } else if (prefersDarkScheme.matches) {
        currentTheme = 'dark';
        htmlElement.setAttribute('data-theme', 'dark');
        } else {
        currentTheme = 'light';
        }

        // 初始化按钮文字
        updateButtonText(currentTheme);

        // 主题切换逻辑
        themeToggle.addEventListener('click', () => {
        const currentTheme = htmlElement.getAttribute('data-theme');

        if (currentTheme === 'light') {
        htmlElement.setAttribute('data-theme', 'dark');
        localStorage.setItem('theme', 'dark');
        updateButtonText('dark');
        } else if (currentTheme === 'dark') {
        htmlElement.removeAttribute('data-theme');
        localStorage.removeItem('theme');
        updateButtonText('light');
        } else {
        htmlElement.setAttribute('data-theme', 'light');
        localStorage.setItem('theme', 'light');
        updateButtonText('light');
        }
        });

        // 监听系统主题变化
        prefersDarkScheme.addEventListener('change', (e) => {
        if (!localStorage.getItem('theme')) {
        if (e.matches) {
        htmlElement.setAttribute('data-theme', 'dark');
        updateButtonText('dark');
        } else {
        htmlElement.removeAttribute('data-theme');
        updateButtonText('light');
        }
        }
        });

        // 更新按钮文字的函数
        function updateButtonText(theme) {
        const icon = theme === 'dark' ? '🌙' : '☀';
        themeIcon.textContent = icon;
        themeToggle.setAttribute('aria-label',
        theme === 'dark' ? '切换到浅色模式' : '切换到深色模式');
        }
        }

        // 在页面加载完成后初始化主题切换
        document.addEventListener('DOMContentLoaded', initThemeToggle);
        </script>
        </body>
        </html>`;
    return new Response(html, {
        status: code,
        headers: {
            'Content-Type': 'text/html;charset=UTF-8'
        }
    });
}
// 根据错误代码获取标题
function getErrorTitle(code) {
    const titles = {
        400: '请求错误',
        401: '未授权',
        403: '禁止访问',
        404: '页面未找到',
        500: '服务器错误',
        502: '网关错误',
        503: '服务不可用'
    };
    return titles[code] || '发生错误';
}
// 转义html
function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/[&<>]/g, function (m) {
        if (m === '&') return '&amp;';
        if (m === '<') return '&lt;';
        if (m === '>') return '&gt;';
        return m;
    });
}
// html处理
function buildHtmlResponse(html, account, options = {}) {
    /**
     * 处理 HTML 响应，注入导航栏、公共脚本及可选的错误覆盖层
     * @param {string} html - 原始 HTML 字符串
     * @param {string} account - 账户名（显示在完整导航栏中间）
     * @param {Object} options - 配置选项
     * @param {boolean} options.littleNav - 是否使用简化导航栏（无返回/主页/退出按钮）
     * @param {Function} options.errorHandler - 错误处理函数，接收 (statusCode, message) 并返回 Response
     * @param {string} options.homeUrl - 主页按钮链接，默认 '/list'
     * @param {Object} options.errorOverlay - 配置，包含 code, message, redirectUrl, showCloseOnly, homeOnly, directlyReturn
     * @param {Object} options.headers - 自定义响应头，会与默认的 { 'Content-Type': 'text/html' } 合并（相同键将覆盖默认值）
     * @param {boolean} options.directlyReturn - 是否直接返回 HTML 字符串而非 Response 对象
     * @param {boolean} options.autoRenew - 是否自动请求 /login/renew，默认 true（仅在无错误覆盖层时生效）
     * @param {string} options.renewUrl - 续期请求地址，默认 '/login/renew'
     * @param {string} options.loginUrl - 登录页面地址，默认 '/login'
     * @param {boolean} options.enableUnauthorizedOverlay - 是否在 401 时显示未登录错误页面，默认 true
     * @returns {Response|string} HTML 响应或字符串
     */
    const {
        littleNav = false,
        errorHandler = null,
        homeUrl = '/list',
        errorOverlay = null,
        headers: customHeaders = {},
        directlyReturn = false,
        autoRenew = true,
        renewUrl = '/login/renew',
        loginUrl = '/login',
        enableUnauthorizedOverlay = true
    } = options;

    // ---------- 辅助函数：转义 HTML 与 JS 字符串 ----------
    const escapeHtml = (str) => {
        if (!str) return '';
        return str.replace(/[&<>]/g, function (m) {
            if (m === '&') return '&amp;';
            if (m === '<') return '&lt;';
            if (m === '>') return '&gt;';
            return m;
        }).replace(/[\uD800-\uDBFF][\uDC00-\uDFFF]/g, function (c) {
            return c;
        });
    };

    const escapeJsString = (str) => {
        if (!str) return '';
        return str.replace(/[\\'"]/g, function (m) {
            if (m === '\\') return '\\\\';
            if (m === "'") return "\\'";
            if (m === '"') return '\\"';
            return m;
        }).replace(/\n/g, '\\n').replace(/\r/g, '\\r');
    };

    // ---------- 模板定义 ----------
    const THEME_TOGGLE_BTN = `
    <div class="theme-toggle">
      <button class="theme-toggle-btn" id="themeToggle" aria-label="切换主题">
        <span class="theme-icon"></span>
      </button>
    </div>
  `;

    const FULL_NAV = `
    <nav class="navbar">
      <div class="d-flex align-center gap-2" style="min-width: 0;">
        <a href="javascript:history.back()" class="btn btn-secondary d-flex align-center gap-1" style="flex-shrink: 0;">
          <svg width="16" height="16" fill="currentColor" viewBox="0 0 16 16">
            <path fill-rule="evenodd" d="M15 8a.5.5 0 0 0-.5-.5H2.707l3.147-3.146a.5.5 0 1 0-.708-.708l-4 4a.5.5 0 0 0 0 .708l4 4a.5.5 0 0 0 .708-.708L2.707 8.5H14.5A.5.5 0 0 0 15 8z"/>
          </svg>
          返回
        </a>
        <div style="width: 1px; height: 24px; background-color: var(--border-color); flex-shrink: 0;"></div>
        <span style="font-weight: 500; white-space: nowrap; flex-shrink: 0;">worker 编辑器</span>
      </div>
      <div style="flex: 1; min-width: 0; margin: 0 1rem; display: flex; align-items: center; justify-content: center;">
        <div class="account-display" style="max-width: 100%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; padding: 0 0.5rem; text-align: center; font-weight: 500; color: var(--text-color);" title="${escapeHtml(account)}">
          ${escapeHtml(account)}
        </div>
      </div>
      <div class="d-flex align-center gap-2" style="flex-shrink: 0;">
        ${THEME_TOGGLE_BTN}
        <a href="${escapeHtml(homeUrl)}" class="btn btn-outline d-flex align-center gap-1" title="返回主页">
          <svg width="16" height="16" fill="currentColor" viewBox="0 0 16 16">
            <path d="M8.354 1.146a.5.5 0 0 0-.708 0l-6 6A.5.5 0 0 0 1.5 7.5v7a.5.5 0 0 0 .5.5h4.5a.5.5 0 0 0 .5-.5v-4h2v4a.5.5 0 0 0 .5.5H14a.5.5 0 0 0 .5-.5v-7a.5.5 0 0 0-.146-.354L13 5.793V2.5a.5.5 0 0 0-.5-.5h-1a.5.5 0 0 0-.5.5v1.293L8.354 1.146zM2.5 14V7.707l5.5-5.5 5.5 5.5V14H10v-4a.5.5 0 0 0-.5-.5h-3a.5.5 0 0 0-.5.5v4H2.5z"/>
          </svg>
          <span class="d-none d-md-inline">主页</span>
        </a>
        <a href="/logout" class="btn btn-danger d-flex align-center gap-1" title="退出登录">
          <svg width="16" height="16" fill="currentColor" viewBox="0 0 16 16">
            <path fill-rule="evenodd" d="M10 12.5a.5.5 0 0 1-.5.5h-8a.5.5 0 0 1-.5-.5v-9a.5.5 0 0 1 .5-.5h8a.5.5 0 0 1 .5.5v2a.5.5 0 0 0 1 0v-2A1.5 1.5 0 0 0 9.5 2h-8A1.5 1.5 0 0 0 0 3.5v9A1.5 1.5 0 0 0 1.5 14h8a1.5 1.5 0 0 0 1.5-1.5v-2a.5.5 0 0 0-1 0v2z"/>
            <path fill-rule="evenodd" d="M15.854 8.354a.5.5 0 0 0 0-.708l-3-3a.5.5 0 0 0-.708.708L14.293 7.5H5.5a.5.5 0 0 0 0 1h8.793l-2.147 2.146a.5.5 0 0 0 .708.708l3-3z"/>
          </svg>
          <span class="d-none d-md-inline">退出</span>
        </a>
      </div>
    </nav>
  `;

    const SMALL_NAV = `
    <nav class="navbar">
      <div class="d-flex align-center gap-2" style="min-width: 0;">
        <span style="font-weight: 500; white-space: nowrap; flex-shrink: 0;">worker 编辑器</span>
      </div>
      <div class="d-flex align-center gap-2" style="flex-shrink: 0;">
        ${THEME_TOGGLE_BTN}
      </div>
    </nav>
  `;

    // ---------- 动态生成公共脚本（包含自动续期及 401 处理）----------
    const generateCommonScript = (autoRenew, renewUrl, loginUrl, enableUnauthorizedOverlay) => {
        const minInterval = (renewal?.minInterval || 30 * 60) * 1000;
        // 注入配置对象（安全转义）
        const configJson = JSON.stringify({
            autoRenew,
            renewUrl,
            loginUrl,
            enableUnauthorizedOverlay,
            minInterval
        });

        return `
    <script>
      (function() {
        // 续期配置（由服务端注入）
        var renewConfig = ${configJson};

        // ---------- 主题管理（统一入口） ----------
        function getEffectiveTheme() {
          var html = document.documentElement;
          var attr = html.getAttribute('data-theme');
          if (attr === 'dark' || attr === 'light') return attr;
          return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
        }

        function updateAllThemeIcons() {
          var theme = getEffectiveTheme();
          var icon = theme === 'dark' ? '\\uD83C\\uDF19' : '\\u2600';   // 🌙 和 ☀
          var label = theme === 'dark' ? '切换到浅色模式' : '切换到深色模式';
          var icons = document.querySelectorAll('.theme-toggle-btn .theme-icon');
          for (var i = 0; i < icons.length; i++) {
            icons[i].textContent = icon;
            icons[i].parentNode.setAttribute('aria-label', label);
          }
        }

        function toggleTheme() {
          var html = document.documentElement;
          var current = html.getAttribute('data-theme');
          var newTheme;
          if (current === 'dark') {
            newTheme = null;            // 移除属性，表示跟随系统
          } else if (current === 'light') {
            newTheme = 'dark';
          } else {
            newTheme = 'light';
          }
          if (newTheme) {
            html.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);
          } else {
            html.removeAttribute('data-theme');
            localStorage.removeItem('theme');
          }
          updateAllThemeIcons();
        }

        function initThemeToggle(buttonId) {
        // 恢复用户保存的主题
  var savedTheme = localStorage.getItem('theme');
  if (savedTheme === 'dark' || savedTheme === 'light') {
    document.documentElement.setAttribute('data-theme', savedTheme);
  } else {
    document.documentElement.removeAttribute('data-theme');
  }
          var btn = document.getElementById(buttonId);
          if (!btn) return;
          if (!btn.querySelector('.theme-icon')) {
            var iconSpan = document.createElement('span');
            iconSpan.className = 'theme-icon';
            btn.appendChild(iconSpan);
          }
          btn.onclick = toggleTheme;
          updateAllThemeIcons();
        }

        // 系统主题变化监听
        var prefersDark = window.matchMedia('(prefers-color-scheme: dark)');
        prefersDark.addEventListener('change', function() {
          if (!document.documentElement.getAttribute('data-theme')) {
            updateAllThemeIcons();
          }
        });

        // ---------- 响应式辅助 ----------
        function handleResponsive() {
          var spans = document.querySelectorAll('.btn span.d-none');
          var hide = window.innerWidth < 768;
          for (var i = 0; i < spans.length; i++) {
            if (hide) {
              spans[i].classList.add('d-none');
            } else {
              spans[i].classList.remove('d-none');
            }
          }
        }

        // ---------- 未登录覆盖层（动态 DOM 创建，避免 XSS） ----------
        function showUnauthorizedOverlay(loginUrl) {
          if (document.getElementById('unauthorizedOverlay')) return;

          // 创建覆盖层容器
          var overlay = document.createElement('div');
          overlay.id = 'unauthorizedOverlay';
          overlay.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;background-color:var(--bg-color);z-index:10000;overflow-y:auto;display:flex;flex-direction:column;';

          // 导航栏
          var nav = document.createElement('nav');
          nav.className = 'navbar';
          nav.style.justifyContent = 'space-between';
          var leftDiv = document.createElement('div');
          leftDiv.className = 'd-flex align-center gap-2';
          leftDiv.innerHTML = '<span style="font-weight:500;">worker 编辑器</span>';
          var rightDiv = document.createElement('div');
          rightDiv.className = 'd-flex align-center gap-2';
          var themeToggleWrap = document.createElement('div');
          themeToggleWrap.className = 'theme-toggle';
          var themeBtn = document.createElement('button');
          themeBtn.className = 'theme-toggle-btn';
          themeBtn.id = 'unauthThemeToggle';
          themeBtn.setAttribute('aria-label', '切换主题');
          themeToggleWrap.appendChild(themeBtn);
          rightDiv.appendChild(themeToggleWrap);
          nav.appendChild(leftDiv);
          nav.appendChild(rightDiv);

          // 内容区域
          var content = document.createElement('div');
          content.style.cssText = 'display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:calc(100vh - 60px);text-align:center;padding:2rem;';
          content.innerHTML = '<h1 style="font-size:4rem;color:var(--danger-color);margin-bottom:0.5rem;">401</h1>' +
            '<h2 style="margin-bottom:1rem;">未授权</h2>' +
            '<p style="color:var(--text-secondary);margin-bottom:2rem;max-width:500px;">未登录或登录已过期，请重新登录</p>';
          var loginLink = document.createElement('a');
          loginLink.href = loginUrl;
          loginLink.className = 'btn';
          loginLink.textContent = '去登录';
          content.appendChild(loginLink);

          overlay.appendChild(nav);
          overlay.appendChild(content);
          document.body.appendChild(overlay);

          // 初始化覆盖层内的主题按钮（复用相同逻辑）
          initThemeToggle('unauthThemeToggle');
        }

        // ---------- Cookie 辅助 ----------
        function getCookie(name) {
          var value = '; ' + document.cookie;
          var parts = value.split('; ' + name + '=');
          if (parts.length === 2) return parts.pop().split(';').shift();
          return null;
        }

        function shouldRenewImmediately() {
          return getCookie('cookie_available') !== 'true';
        }

        // ---------- 自动续期逻辑 ----------
        function scheduleRenewIfNeeded() {
          if (!renewConfig.autoRenew) return;
          // 如果已显示未授权覆盖层，不再尝试续期
          if (document.getElementById('unauthorizedOverlay')) return;

          var STORAGE_KEY = 'lastRenewTimestamp';
          var MIN_INTERVAL_MS = renewConfig.minInterval || 30 * 60 * 1000;
          var now = Date.now();

          if (shouldRenewImmediately()) {
            performRenewRequest();
            return;
          }

          var lastTimestamp = null;
          try {
            lastTimestamp = parseInt(localStorage.getItem(STORAGE_KEY), 10);
          } catch (e) {}

          if (lastTimestamp && (now - lastTimestamp) < MIN_INTERVAL_MS) return;

          // 使用空闲回调，降级为 setTimeout
          if (window.requestIdleCallback) {
            requestIdleCallback(performRenewRequest, { timeout: 5000 });
          } else {
            setTimeout(performRenewRequest, 1000);
          }
        }

        function performRenewRequest() {
          fetch(renewConfig.renewUrl, {
            method: 'GET',
            credentials: 'same-origin',
            headers: { 'Accept': 'application/json' }
          }).then(function(response) {
            if (response.status === 401 && renewConfig.enableUnauthorizedOverlay) {
              showUnauthorizedOverlay(renewConfig.loginUrl);
            }
          }).catch(function(err) {
            console.warn('Auto renew request failed:', err);
          }).finally(function() {
            try {
              localStorage.setItem('lastRenewTimestamp', Date.now().toString());
            } catch (e) {}
          });
        }

        // 页面可见性变化
        function handleVisibilityChange() {
          if (document.visibilityState === 'visible') {
            scheduleRenewIfNeeded();
          }
        }

        // ---------- 统一初始化入口 ----------
        document.addEventListener('DOMContentLoaded', function() {
          initThemeToggle('themeToggle');
          handleResponsive();
          window.addEventListener('resize', handleResponsive);

          scheduleRenewIfNeeded();
          document.addEventListener('visibilitychange', handleVisibilityChange);
        });
      })();
    </script>
  `;
    };

    // ---------- 错误覆盖层生成器（支持只显示返回）----------
    function generateErrorOverlay(code, message, redirectUrl = '/', showCloseOnly = false, homeOnly = false) {
        const errorTitles = {
            400: '请求错误',
            401: '未授权',
            403: '禁止访问',
            404: '页面未找到',
            500: '服务器错误',
            502: '网关错误',
            503: '服务不可用'
        };
        const title = errorTitles[code] || '发生错误';

        // 按钮逻辑：homeOnly 优先 -> 只显示返回
        let buttonsHtml = '';
        if (homeOnly) {
            buttonsHtml = `<a href="${escapeHtml(redirectUrl)}" class="btn">返回</a>`;
        } else if (showCloseOnly) {
            buttonsHtml = `<button onclick="this.closest('#errorOverlay').remove()" class="btn btn-danger">关闭</button>`;
        } else {
            buttonsHtml = `<div class="button-group">
                       <button onclick="this.closest('#errorOverlay').remove()" class="btn btn-secondary">关闭</button>
                       <a href="${escapeHtml(redirectUrl)}" class="btn">返回首页</a>
                     </div>`;
        }

        return `
      <div id="errorOverlay" style="position: fixed; top:0; left:0; right:0; bottom:0; background-color: var(--bg-color); z-index:9999; overflow-y:auto; display:flex; flex-direction:column;">
        <nav class="navbar">
          <div class="d-flex align-center gap-2"><span style="font-weight:500;">worker 编辑器</span></div>
          <div class="d-flex align-center gap-2">
            <div class="theme-toggle">
              <button class="theme-toggle-btn" id="errorThemeToggle" aria-label="切换主题"><span class="theme-icon"></span></button>
            </div>
          </div>
        </nav>
        <div style="display:flex; flex-direction:column; align-items:center; justify-content:center; min-height:calc(100vh - 60px); text-align:center; padding:2rem;">
          <h1 style="font-size:4rem; color:var(--danger-color); margin-bottom:0.5rem;">${code}</h1>
          <h2 style="margin-bottom:1rem;">${escapeHtml(title)}</h2>
          <p style="color:var(--text-secondary); margin-bottom:2rem; max-width:500px;">${escapeHtml(message)}</p>
          ${buttonsHtml}
        </div>
        <script>
          (function() {
            function initErrorTheme() {
              const toggle = document.getElementById('errorThemeToggle');
              if (!toggle) return;
              const html = document.documentElement;
              const iconSpan = document.createElement('span');
              iconSpan.className = 'theme-icon';
              toggle.appendChild(iconSpan);
              const saved = localStorage.getItem('theme');
              const prefersDark = window.matchMedia('(prefers-color-scheme: dark)');
              let theme = saved || (prefersDark.matches ? 'dark' : 'light');
              html.setAttribute('data-theme', theme);
              const update = (t) => {
                iconSpan.textContent = t === 'dark' ? '🌙' : '☀';
                toggle.setAttribute('aria-label', t === 'dark' ? '切换到浅色模式' : '切换到深色模式');
              };
              update(theme);
              toggle.addEventListener('click', () => {
                const cur = html.getAttribute('data-theme');
                const newTheme = cur === 'light' ? 'dark' : (cur === 'dark' ? null : 'light');
                if (newTheme === null) {
                  html.removeAttribute('data-theme');
                  localStorage.removeItem('theme');
                  update('light');
                } else {
                  html.setAttribute('data-theme', newTheme);
                  localStorage.setItem('theme', newTheme);
                  update(newTheme);
                }
              });
              prefersDark.addEventListener('change', (e) => {
                if (!localStorage.getItem('theme')) {
                  const newTheme = e.matches ? 'dark' : 'light';
                  html.setAttribute('data-theme', newTheme);
                  update(newTheme);
                }
              });
            }
            document.addEventListener('DOMContentLoaded', initErrorTheme);
          })();
        </script>
      </div>
    `;
    }

    // ---------- 主逻辑 ----------
    try {
        const navHtml = littleNav ? SMALL_NAV : FULL_NAV;
        const commonScript = generateCommonScript(autoRenew, renewUrl, loginUrl, enableUnauthorizedOverlay);
        let finalHtml = html.replace('{{NAVBAR}}', navHtml + commonScript);

        if (errorOverlay && typeof errorOverlay === 'object') {
            const {
                code,
                message,
                redirectUrl = '/',
                showCloseOnly = false,
                homeOnly = false
            } = errorOverlay;
            const overlayHtml = generateErrorOverlay(code, message, redirectUrl, showCloseOnly, homeOnly);
            finalHtml = finalHtml.replace('</body>', overlayHtml + '</body>');
        }

        if (directlyReturn) {
            // 直接返回 HTML 字符串（不附加响应头）
            return finalHtml;
        }

        // 合并自定义响应头
        const responseHeaders = {
            'Content-Type': 'text/html',
            ...customHeaders
        };

        return new Response(finalHtml, {
            headers: responseHeaders
        });
    } catch (err) {
        if (typeof errorHandler === 'function') {
            return errorHandler(500, err.message);
        }
        // 兜底错误响应
        return new Response(`<h1>500 内部错误</h1><p>${escapeHtml(err.message)}</p>`, {
            status: 500,
            headers: {
                'Content-Type': 'text/html'
            }
        });
    }
}
// css内容
function handleCss() {
    const css = `
        /* /static/style.css */
        :root {
        /* 白天模式变量 */
        --primary-color: #2563eb;
        --primary-light: #dbeafe;
        --primary-dark: #1d4ed8;
        --bg-color: #ffffff;
        --surface-color: #f8fafc;
        --text-color: #1e293b;
        --text-secondary: #64748b;
        --border-color: #e2e8f0;
        --success-color: #10b981;
        --warning-color: #f59e0b;
        --danger-color: #ef4444;
        --info-color: #3b82f6;
        --success-text: #065f46;
        --warning-text: #92400e;
        --danger-text: #991b1b;
        --info-text: #1e40af;
        --shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        --radius: 0.375rem;
        --transition: all 0.25s cubic-bezier(0.2, 0.9, 0.4, 1.1);
        }

        [data-theme="dark"] {
        /* 深色模式变量 */
        --primary-color: #3b82f6;
        --primary-light: #1e3a8a;
        --primary-dark: #60a5fa;
        --bg-color: #0f172a;
        --surface-color: #1e293b;
        --text-color: #f1f5f9;
        --text-secondary: #94a3b8;
        --border-color: #334155;
        --success-text: #a7f3d0;
        --warning-text: #fde68a;
        --danger-text: #fecaca;
        --info-text: #bfdbfe;
        --success-text: #065f46;
        --warning-text: #92400e;
        --danger-text: #991b1b;
        --info-text: #1e40af;
        --shadow: 0 1px 3px rgba(0, 0, 0, 0.3);
        }

        /* 基础重置 */
        * {
        box-sizing: border-box;
        margin: 0;
        padding: 0;
        }

        body {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
        background-color: var(--bg-color);
        color: var(--text-color);
        line-height: 1.5;
        transition: var(--transition);
        padding: 20px;
        max-width: 1200px;
        margin: 0 auto;
        min-height: 100vh;
        }
        
        /*变换动画*/
        button,.btn,a,input,select,textarea,tr,.card {
        transition: var(--transition);
        }
        button:active,
        .btn:active {
        transform: scale(0.97);
        }

        /* 标题样式 */
        h1, h2, h3, h4, h5, h6 {
        color: var(--text-color);
        margin-bottom: 1rem;
        font-weight: 600;
        }

        h1 { font-size: 2rem; margin-top: 1.5rem; }
        h2 { font-size: 1.5rem; margin-top: 1.25rem; }
        h3 { font-size: 1.25rem; margin-top: 1rem; }

        /* 段落和文字 */
        p {
        margin-bottom: 1rem;
        color: var(--text-secondary);
        }

        a {
        color: var(--primary-color);
        text-decoration: none;
        transition: var(--transition);
        }

        a:hover {
        color: var(--primary-dark);
        text-decoration: underline;
        }

        /* 按钮样式 */
        button, .btn {
        display: inline-block;
        padding: 0.5rem 1rem;
        background-color: var(--primary-color);
        color: white;
        border: none;
        border-radius: var(--radius);
        cursor: pointer;
        font-size: 0.875rem;
        font-weight: 500;
        transition: var(--transition);
        text-align: center;
        line-height: 1.25rem;
        }

        button:hover, .btn:hover {
        background-color: var(--primary-dark);
        transform: translateY(-1px);
        box-shadow: var(--shadow);
        }

        button:active, .btn:active {
        transform: translateY(0);
        }

        .btn-secondary {
        background-color: var(--surface-color);
        color: var(--text-color);
        border: 1px solid var(--border-color);
        }

        .btn-secondary:hover {
        background-color: var(--border-color);
        }

        .btn-success {
        background-color: var(--success-color);
        }

        .btn-warning {
        background-color: var(--warning-color);
        }

        .btn-danger {
        background-color: var(--danger-color);
        }

        .btn-outline {
        background-color: transparent;
        color: var(--primary-color);
        border: 1px solid var(--primary-color);
        }

        .btn-outline:hover {
        background-color: var(--primary-light);
        }

        /* 按钮禁用状态 */
        button:disabled,
        .btn:disabled,
        .btn.disabled {
        opacity: 0.5;
        cursor: not-allowed;
        pointer-events: none;
        transform: none;
        box-shadow: none;
        }

        button:disabled:hover,
        .btn:disabled:hover,
        .btn.disabled:hover {
        background-color: var(--primary-color);
        transform: none;
        box-shadow: none;
        }

        .btn-outline:disabled,
        .btn-outline.disabled {
        opacity: 0.5;
        cursor: not-allowed;
        pointer-events: none;
        color: var(--text-secondary);
        border-color: var(--border-color);
        }

        .btn-secondary:disabled,
        .btn-secondary.disabled {
        opacity: 0.5;
        cursor: not-allowed;
        pointer-events: none;
        background-color: var(--surface-color);
        color: var(--text-secondary);
        }

        .btn-success:disabled,
        .btn-success.disabled {
        opacity: 0.5;
        cursor: not-allowed;
        pointer-events: none;
        }

        .btn-warning:disabled,
        .btn-warning.disabled {
        opacity: 0.5;
        cursor: not-allowed;
        pointer-events: none;
        }

        .btn-danger:disabled,
        .btn-danger.disabled {
        opacity: 0.5;
        cursor: not-allowed;
        pointer-events: none;
        }

        /* 禁用状态下的聚焦效果移除 */
        button:disabled:focus,
        .btn:disabled:focus,
        input:disabled:focus,
        textarea:disabled:focus,
        select:disabled:focus {
        outline: none;
        box-shadow: none;
        border-color: var(--border-color);
        }

        /* 表单控件 */
        input, textarea, select {
        width: 100%;
        padding: 0.5rem 0.75rem;
        border: 1px solid var(--border-color);
        border-radius: var(--radius);
        background-color: var(--surface-color);
        color: var(--text-color);
        font-size: 0.875rem;
        transition: var(--transition);
        }

        input:focus, textarea:focus, select:focus {
        outline: none;
        border-color: var(--primary-color);
        box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
        }

        label {
        display: block;
        margin-bottom: 0.5rem;
        font-weight: 500;
        color: var(--text-color);
        }

        .form-group {
        margin-bottom: 1rem;
        }

        /* 表格样式 */
        table {
        width: 100%;
        border-collapse: collapse;
        margin-bottom: 1.5rem;
        box-shadow: var(--shadow);
        border-radius: var(--radius);
        overflow: hidden;
        }

        th, td {
        padding: 0.75rem 1rem;
        text-align: left;
        border-bottom: 1px solid var(--border-color);
        }

        th {
        background-color: var(--primary-light);
        color: var(--primary-dark);
        font-weight: 600;
        text-transform: uppercase;
        font-size: 0.75rem;
        letter-spacing: 0.05em;
        }
        
        tbody tr:nth-child(even) {
        background-color: var(--surface-color);
        }

        tr:hover {
        background-color: var(--surface-color);
        transition: var(--transition);
        }

        /* 列表样式 */
        ul, ol {
        margin-bottom: 1rem;
        padding-left: 1.5rem;
        color: var(--text-secondary);
        }

        li {
        margin-bottom: 0.5rem;
        }

        /* 卡片容器 */
        .card {
        background-color: var(--surface-color);
        border-radius: var(--radius);
        padding: 1.5rem;
        box-shadow: var(--shadow);
        margin-bottom: 1.5rem;
        border: 1px solid var(--border-color);
        }

        /* 导航栏 */
        .navbar {
        background-color: var(--surface-color);
        padding: 1rem;
        border-radius: var(--radius);
        margin-bottom: 2rem;
        display: flex;
        justify-content: space-between;
        align-items: center;
        border: 1px solid var(--border-color);
        }

        .nav-links {
        display: flex;
        gap: 1.5rem;
        }

        .nav-links a {
        color: var(--text-color);
        font-weight: 500;
        }

        .nav-links a:hover {
        color: var(--primary-color);
        text-decoration: none;
        }

        /* 代码块 */
        code, pre {
        font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
        background-color: var(--surface-color);
        border-radius: var(--radius);
        padding: 0.2rem 0.4rem;
        font-size: 0.875em;
        }

        pre {
        padding: 1rem;
        overflow-x: auto;
        margin-bottom: 1rem;
        }

        /* 分隔线 */
        hr {
        border: none;
        height: 1px;
        background-color: var(--border-color);
        margin: 1.5rem 0;
        }

        /* 复选框和单选按钮 */
        input[type="checkbox"], input[type="radio"] {
        width: auto;
        margin-right: 0.5rem;
        }

        /* 图片 */
        img {
        max-width: 100%;
        height: auto;
        border-radius: var(--radius);
        }

        /* 容器 */
        .container {
        width: 100%;
        margin: 0 auto;
        padding: 0 1rem;
        }

        /* 辅助类 */
        .text-center { text-align: center; }
        .text-right { text-align: right; }
        .mt-1 { margin-top: 0.25rem; }
        .mt-2 { margin-top: 0.5rem; }
        .mt-3 { margin-top: 1rem; }
        .mt-4 { margin-top: 1.5rem; }
        .mb-1 { margin-bottom: 0.25rem; }
        .mb-2 { margin-bottom: 0.5rem; }
        .mb-3 { margin-bottom: 1rem; }
        .mb-4 { margin-bottom: 1.5rem; }
        .p-1 { padding: 0.25rem; }
        .p-2 { padding: 0.5rem; }
        .p-3 { padding: 1rem; }
        .p-4 { padding: 1.5rem; }
        .d-flex { display: flex; }
        .flex-column { flex-direction: column; }
        .align-center { align-items: center; }
        .justify-between { justify-content: space-between; }
        .gap-1 { gap: 0.5rem; }
        .gap-2 { gap: 1rem; }
        .gap-3 { gap: 1.5rem; }
        .d-none { display: none !important; }
        .d-md-inline { display: inline !important; }

        /* 响应式设计 */
        @media (max-width: 768px) {
  body {
    padding: 10px;
  }

  .navbar {
    flex-direction: column;
    gap: 1rem;
    padding: 0.75rem;
  }

  .nav-links {
    flex-direction: column;
    gap: 0.5rem;
  }

  table {
    display: block;
    overflow-x: auto;
  }

  .account-display {
    font-size: 0.875rem;
    max-width: 150px;
  }

  .btn {
    padding: 0.375rem 0.75rem;
    font-size: 0.8125rem;
  }

  /* 防止按钮被拉宽 */
  .btn,
  button {
    width: auto !important;
    display: inline-block;
    flex-shrink: 0;
  }
}

        @media (max-width: 576px) {
        .account-display {
        max-width: 120px;
        }

        .btn span:not(.d-md-inline) {
        display: none;
        }
        }
        /* 打印优化 */
@media print {
  body {
    background-color: white;
    color: black;
    padding: 0;
  }
  
  .navbar,
  button,
  .btn {
    display: none;
  }
  
  a {
    text-decoration: underline;
    color: black;
  }
  
  .card {
    box-shadow: none;
    border: 1px solid #ddd;
    break-inside: avoid;
  }
}
/* 修复按钮/表单控件被拉伸 */
.d-flex > :is(button, .btn, input:not([type=checkbox]), select),
.grid > :is(button, .btn, input:not([type=checkbox]), select),
[style*=flex] > :is(button, .btn, input:not([type=checkbox]), select) {
  width: auto !important;
  flex: 0 0 auto;
}
.pagination .btn,
.pagination button,
.bottom-bar .btn,
.bottom-bar button {
  width: auto !important;
  flex-shrink: 0;
}
@media (max-width: 768px) {
  .btn, button, input:not([type=checkbox]), select {
    width: auto !important;
    flex: 0 0 auto;
  }
  textarea {
    width: 100% !important;
    flex: 1 1 auto !important;
  }
  [style*="display:flex"] {
    align-items: flex-start !important;
  }
}
        `
    return new Response(css, {
        headers: {
            'Content-Type': 'text/css',
            'Cache-Control': 'public, max-age=86400'
        }
    })
}

// ==============sitemap.xml&robots.txt===============
// 处理 sitemap.xml 请求
async function handleSitemap(request) {
    const url = new URL(request.url);
    const baseUrl = `${url.protocol}//${url.host}`;
    const xml = generateSitemapXml(baseUrl);
    return new Response(xml, {
        headers: {
            'Content-Type': 'application/xml',
            'Cache-Control': 'public, max-age=3600' // 缓存1小时
        }
    });
}
// 处理 robots.txt 请求
async function handleRobotsTxt(request) {
    const url = new URL(request.url);
    const baseUrl = `${url.protocol}//${url.host}`;

    const content = `
        User-agent: *
        Allow: /
        Disallow: /logout
        Disallow: /api/
        Disallow: /get/
        Sitemap: ${baseUrl}/sitemap.xml
        Crawl-delay: 1
        `;

    return new Response(content, {
        headers: {
            'Content-Type': 'text/plain; charset=utf-8',
            'Cache-Control': 'public, max-age=86400'
        }
    });
}
// 生成 sitemap XML 内容
function generateSitemapXml(baseUrl) {
    // 定义所有需要收录的页面路径
    const pages = [{
        path: '/',
        priority: 1.0,
        changefreq: 'monthly'
    },
    {
        path: '/login',
        priority: 0.9,
        changefreq: 'monthly'
    },
    {
        path: '/list',
        priority: 0.9,
        changefreq: 'monthly'
    },
    {
        path: '/edit',
        priority: 0.8,
        changefreq: 'monthly'
    },
    {
        path: '/kv',
        priority: 0.8,
        changefreq: 'monthly'
    },
    {
        path: '/wtc',
        priority: 0.8,
        changefreq: 'monthly'
    },
    {
        path: '/binding',
        priority: 0.8,
        changefreq: 'monthly'
    },
    {
        path: '/deployment',
        priority: 0.7,
        changefreq: 'monthly'
    },
    {
        path: '/routes',
        priority: 0.8,
        changefreq: 'monthly'
    },
    {
        path: '/setting',
        priority: 0.7,
        changefreq: 'monthly'
    },
    {
        path: '/create',
        priority: 0.7,
        changefreq: 'monthly'
    },
    {
        path: '/curl',
        priority: 0.6,
        changefreq: 'monthly'
    },
    {
        path: '/graphql',
        priority: 0.7,
        changefreq: 'monthly'
    }
    ];

    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n';

    for (const page of pages) {
        const fullUrl = `${baseUrl}${page.path}`;
        xml += '  <url>\n';
        xml += `    <loc>${escapeXml(fullUrl)}</loc>\n`;
        xml += `    <priority>${page.priority}</priority>\n`;
        xml += `    <changefreq>${page.changefreq}</changefreq>\n`;
        xml += '  </url>\n';
    }

    xml += '</urlset>';
    return xml;
}
// XML 转义
function escapeXml(str) {
    return str.replace(/[<>&]/g, function (m) {
        if (m === '<') return '&lt;';
        if (m === '>') return '&gt;';
        if (m === '&') return '&amp;';
        return m;
    });
}

//=================login===================
const COOKIE_EXPIRY_WORKER_ID = 'cookie_expiry_binding';
// UTF-8<===>Uint8Array
function encodeText(text) {
    return new TextEncoder().encode(text);
}
function decodeText(buffer) {
    return new TextDecoder().decode(buffer);
}
// arrayBuffer<===>Base64
function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}
function base64ToArrayBuffer(base64) {
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}
// 服务器 ID 生成
function getScriptID(urlStr, SCRIPT_ID) {
    const url = new URL(urlStr);
    const domain = url.hostname;
    const safeEnvironmentId = typeof SCRIPT_ID !== 'undefined' ? SCRIPT_ID : null;
    const safeScriptId = typeof scriptId !== 'undefined' ? scriptId : null;
    const randomId = safeEnvironmentId ?? safeScriptId ?? null;
    if (randomId === null) {
        throw new Error("请先设置 'scriptId' 常量或 'SCRIPT_ID' 环境变量");
    }
    const combinedData = [randomId.substring(0, 50), domain.substring(0, 50)].join('|');
    let hash = 0;
    for (let i = 0; i < combinedData.length; i++) {
        const char = combinedData.charCodeAt(i);
        hash = (hash << 5) - hash + char;
        hash = hash & hash; // 保持在 32 位整数范围内
    }
    return Math.abs(hash).toString(16).padStart(8, '0');
}
// 安全加解密函数
async function deriveKey(serverId, identity) {
    /**
 * 由 serverId 和 identity 派生 AES‑GCM 密钥（128 位）
 * 使用 SHA‑256 压缩并取前 16 字节，保证密钥唯一性且不可逆推原始 ID
 */
    const material = encodeText(`${serverId}|${identity}`);
    const hash = await crypto.subtle.digest('SHA-256', material);
    const keyBytes = new Uint8Array(hash).slice(0, 16); // 128 位
    return crypto.subtle.importKey(
        'raw',
        keyBytes.buffer,
        { name: 'AES-GCM' },
        false,
        ['encrypt', 'decrypt']
    );
}
async function encrypt(plaintext, serverId, identity) {
    /**
 * 安全加密：AES‑GCM，随机 IV
 * @param {string} plaintext   明文
 * @param {string} serverId    服务器标识
 * @param {string} identity    绑定标识（如 accountId 或 COOKIE_EXPIRY_WORKER_ID）
 * @returns {Promise<string>}  Base64 编码的 [12 bytes IV || ciphertext || 16 bytes auth tag]
 */
    const key = await deriveKey(serverId, identity);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const data = encodeText(plaintext);
    const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        data
    );
    // encrypted 是整个 ArrayBuffer（包含密文和认证标签）
    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(encrypted), iv.length);
    return arrayBufferToBase64(combined.buffer);
}
async function decrypt(ciphertextBase64, serverId, identity) {
    /**
 * 安全解密
 * @param {string} ciphertextBase64  Base64 密文（由 encrypt 生成）
 * @param {string} serverId
 * @param {string} identity
 * @returns {Promise<string>} 明文
 */
    const key = await deriveKey(serverId, identity);
    const combined = new Uint8Array(base64ToArrayBuffer(ciphertextBase64));
    const iv = combined.slice(0, 12);
    const ciphertext = combined.slice(12);
    const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        key,
        ciphertext.buffer
    );
    return decodeText(decrypted);
}

// ==================== Token 加密/解密封装 ====================
// 为 API 返回生成加密 token（仅内层，账户绑定）
async function generateEncryptedToken(plainToken, serverId, accountId) {
    return encrypt(plainToken, serverId, accountId);
}
// 解密加密 token（对应前端的 encrypted_token）
async function decryptEncryptedToken(ciphertext, serverId, accountId) {
    return decrypt(ciphertext, serverId, accountId);
}
// Cookie 增强加密：内层(账户绑定) → 拼接过期时间戳 → 外层(cookie 固定 ID)
async function encryptForCookie(plainToken, serverId, accountId, expirySeconds) {
    const inner = await encrypt(plainToken, serverId, accountId);
    const expiryTimestamp = Date.now() + expirySeconds * 1000;
    const payload = `${inner}|${expiryTimestamp}`;
    return encrypt(payload, serverId, COOKIE_EXPIRY_WORKER_ID);
}
// Cookie 增强解密与过期检查
async function decryptForCookie(outerCipher, serverId, accountId) {
    // 尝试新格式
    try {
        const payload = await decrypt(outerCipher, serverId, COOKIE_EXPIRY_WORKER_ID);
        const parts = payload.split('|');
        if (parts.length !== 2) {
            console.warn('Invalid cookie payload format (expected 2 parts)');
            throw new Error('Session validation failed'); // 通用错误，不暴露格式细节
        }
        const innerCipher = parts[0];
        const expiryTimestamp = parseInt(parts[1], 10);
        if (Date.now() > expiryTimestamp + (typeof CLOCK_SKEW !== 'undefined' ? CLOCK_SKEW : 0)) {
            console.warn('Cookie token expired');
            if (DEBUG) throw new Error('Cookie token expired');
            throw new Error('Session expired'); // 通用错误
        }
        return decrypt(innerCipher, serverId, accountId);
    } catch (e) {
        // 回退到旧版单层加密（兼容性）
        console.warn('Falling back to legacy cookie decryption', e);
        try {
            return decrypt(outerCipher, serverId, accountId);
        } catch (legacyErr) {
            console.error('Legacy cookie decryption also failed', legacyErr);
            if (DEBUG) throw new Error('Legacy cookie decryption also failed' + legacyErr);
            throw new Error('Session validation failed');
        }
    }
}
// 从 Cloudflare API 获取账户名称
async function fetchCloudflareAccountName(token, accountId) {
    try {
        const response = await fetch(
            `https://api.cloudflare.com/client/v4/accounts/${accountId}`,
            { headers: { 'Authorization': `Bearer ${token}` } }
        );
        if (!response.ok) {
            console.warn('Failed to fetch account name:', response.status);
            return null;
        }
        const data = await response.json();
        if (data && data.success && data.result) {
            return data.result.name || data.result.EMAIL || null;
        }
        return null;
    } catch (e) {
        console.warn('Error fetching account name:', e.message);
        return null;
    }
}
// 基于 token 哈希的简单加密 (安全性要求不高，使用 token SHA-256 派生密钥 XOR)
async function simpleEncryptWithTokenHash(plaintext, token) {
    if (!plaintext || !token) return null;
    try {
        const tokenHash = new Uint8Array(await crypto.subtle.digest('SHA-256', encodeText(token)));
        const data = encodeText(plaintext);
        const result = new Uint8Array(data.length);
        for (let i = 0; i < data.length; i++) {
            result[i] = data[i] ^ tokenHash[i % tokenHash.length];
        }
        return arrayBufferToBase64(result.buffer);
    } catch (e) {
        console.warn('simpleEncrypt failed:', e);
        return null;
    }
}
// 对应解密函数
async function simpleDecryptWithTokenHash(ciphertextBase64, token) {
    if (!ciphertextBase64 || !token) return null;
    try {
        const tokenHash = new Uint8Array(await crypto.subtle.digest('SHA-256', encodeText(token)));
        const data = new Uint8Array(base64ToArrayBuffer(ciphertextBase64));
        const result = new Uint8Array(data.length);
        for (let i = 0; i < data.length; i++) {
            result[i] = data[i] ^ tokenHash[i % tokenHash.length];
        }
        return decodeText(result.buffer);
    } catch (e) {
        console.warn('simpleDecrypt failed:', e);
        return null;
    }
}
// API Token 验证
async function verifyApiToken(token, accountId) {
    try {
        const response = await fetch(
            `https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts`,
            { headers: { 'Authorization': `Bearer ${token}` } }
        );
        if (!response.ok) {
            // 记录详细错误到日志，但不返回给用户
            let errorDetail = `HTTP ${response.status}: ${response.statusText}`;
            try {
                const errorData = await response.json();
                errorDetail = errorData.errors?.[0]?.message || errorData.message || errorDetail;
            } catch (_) {
                const text = await response.text();
                if (text) errorDetail = text.length > 200 ? text.substring(0, 200) + '...' : text;
            }
            console.error('API token validation failed:', errorDetail);
            if (DEBUG) return { valid: false, error: 'API token validation failed:' + errorDetail };
            return { valid: false, error: 'API token validation failed' };
        }
        return { valid: true };
    } catch (e) {
        console.error('Network error during token validation:', e);
        if (DEBUG) return { valid: false, error: 'Network error during token validation:' + e };
        return { valid: false, error: 'Token validation service error' };
    }
}
// 获取有效Token
async function getValidToken(request, cookies, serverId, tokenFromHeader = null, accountIdHeader = null) {
    let token = tokenFromHeader;
    let accountId = cookies.account_id || accountIdHeader;
    let isEncrypted = false;

    // 1. 优先使用 Authorization 头中的 token
    if (token) {
        // 尝试原始 token
        const verification = await verifyApiToken(token, accountId);
        if (verification.valid) {
            return { valid: true, token, accountId, isEncrypted: false };
        }
        // 尝试解密头中的 token（可能前端传了加密 token）
        try {
            const decrypted = await decryptEncryptedToken(token, serverId, accountId);
            const verification2 = await verifyApiToken(decrypted, accountId);
            if (verification2.valid) {
                return { valid: true, token: decrypted, accountId, isEncrypted: true };
            }
        } catch (e) {
            console.log('Header token decryption failed:', e);
        }
    }

    // 2. 从 Cookie 获取
    if (cookies.cf_api && cookies.account_id) {
        try {
            // 先按增强格式解密（自动校验过期）
            const decryptedToken = await decryptForCookie(cookies.cf_api, serverId, cookies.account_id);
            const verification = await verifyApiToken(decryptedToken, cookies.account_id);
            if (verification.valid) {
                return { valid: true, token: decryptedToken, accountId: cookies.account_id, isEncrypted: true };
            }
        } catch (e) {
            console.log('Cookie enhanced decrypt failed:', e);
        }
        // 尝试原始 token（未加密）
        const verification = await verifyApiToken(cookies.cf_api, cookies.account_id);
        if (verification.valid) {
            return { valid: true, token: cookies.cf_api, accountId: cookies.account_id, isEncrypted: false };
        }
    }

    // 通用错误消息，不暴露缺失原因细节
    return { valid: false, error: 'No valid authentication token found' };
}
// 登录请求处理
async function handleLogin(input, serverId, url = '', cookies = {}) {
    /**
 * 统一的登录处理入口
 * 支持 login_type: import / localstorage / cookie / api / internal
 */
    try {
        let data;
        let inputMode;

        if (input instanceof Request) {
            data = await input.json();
            inputMode = 'request';
        } else if (typeof input === 'object' && input !== null) {
            data = input;
            inputMode = 'data';
            if (!data.url) throw new Error('Url is needed');
        } else {
            throw new Error('Invalid input type');
        }

        let { account_id, login_type } = data;
        if (!account_id || !login_type) {
            throw new Error('Missing required fields: account_id or login_type');
        }

        let originalToken;
        let encryptedApiToken;
        let encryptedCookieToken;

        switch (login_type) {
            case 'import':
                if (!data.api_token) throw new Error('API token is required for import');
                originalToken = data.api_token;
                break;

            case 'localstorage':
                if (!data.encrypted_token) throw new Error('Encrypted token is required for localstorage login');
                // 这里的 encrypted_token 仍是服务器绑定加密，直接解密
                try {
                    originalToken = await decryptEncryptedToken(data.encrypted_token, serverId, account_id);
                } catch (decErr) {
                    throw new Error('Decryption failed in localstorage login:' + decErr);
                }
                break;

            case 'cookie':
                return checkAndRenewCookie(cookies, serverId, {
                    requireRenewToken: true,
                    request: input instanceof Request ? input : null,
                    redirect: input instanceof Request ? 'list' : null,
                });

            case 'api':
                if (!data.token) throw new Error('Token is required for api login');
                originalToken = data.token;
                break;

            case 'internal':
                if (inputMode !== 'data') throw new Error('Internal login type only available for direct data input');
                if (!data.token) throw new Error('Token is required for internal login');
                originalToken = data.token;
                encryptedApiToken = await generateEncryptedToken(originalToken, serverId, account_id);
                return { account_id, encrypted_token: encryptedApiToken };

            default:
                throw new Error('Invalid login type: ' + login_type);
        }

        // 验证原始 token 的有效性（verifyApiToken 内部已做日志，返回通用错误）
        const { valid, error } = await verifyApiToken(originalToken, account_id);
        if (!valid) {
            throw new Error('Token verification failed during login:' + error);
        }

        // 尝试获取账户名称并用 token 哈希加密（安全性要求不高）
        let encryptedAccountName = null;
        let rawAccountName = null;
        try {
            rawAccountName = await fetchCloudflareAccountName(originalToken, account_id);
            if (rawAccountName) {
                encryptedAccountName = await simpleEncryptWithTokenHash(rawAccountName, originalToken);
            }
        } catch (nameErr) {
            console.warn('Failed to process account name during login:', nameErr);
        }

        // 生成各种加密格式
        const expirySeconds = typeof loginPeriod !== 'undefined' ? loginPeriod : 604800; // 默认7天
        encryptedCookieToken = await encryptForCookie(originalToken, serverId, account_id, expirySeconds);
        encryptedApiToken = await generateEncryptedToken(originalToken, serverId, account_id);

        if (inputMode === 'request') {
            if (login_type === 'api') {
                // api 登录只返回加密 token，不写 Cookie
                const body = {
                    success: true,
                    encrypted_token: encryptedApiToken,
                    account_id: account_id
                };
                if (rawAccountName) {
                    body.account_name = rawAccountName;
                }
                return new Response(JSON.stringify(body), {
                    status: 200,
                    headers: {
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*',
                        'Access-Control-Allow-Methods': 'GET, PUT, OPTIONS',
                        'Access-Control-Allow-Headers': 'Content-Type, Authorization'
                    }
                });
            } else {
                let renewToken;
                const clientIp = input.headers.get('CF-Connecting-IP') || '0.0.0.0';
                const deadline = Date.now() + renewal.maxPeriod * 1000; // maxPeriod 单位为秒
                renewToken = await generateRenewToken(account_id, clientIp, deadline, serverId);

                return createLoginResponse(account_id, encryptedApiToken, url, encryptedCookieToken, renewToken, encryptedAccountName, rawAccountName);
            }
        } else {
            // 直接数据调用（internal 已提前返回，这里通常不会走到）
            return { success: true, encrypted_token: encryptedApiToken, account_id: account_id };
        }
    } catch (error) {
        // 捕获所有错误，向客户端返回通用安全消息，详细错误记录到控制台
        console.error('Login processing error:', error);
        if (input instanceof Request) {
            // 根据错误类型给出合适的状态码，但消息保持通用
            let status = 400;
            let userMessage = 'Invalid login request';
            if (error.message.includes('Authentication failed') || error.message.includes('session') || error.message.includes('expired')) {
                status = 401;
                userMessage = 'Authentication failed. Please check your credentials.';
            } else if (error.message.includes('Missing required fields') || error.message.includes('required for')) {
                status = 400;
                userMessage = 'Missing required login parameters.';
            }
            if (DEBUG) {
                userMessage = 'Invalid login request:' + error;
            }
            return new Response(JSON.stringify({ error: userMessage }), {
                status: status,
                headers: { 'Content-Type': 'application/json' }
            });
        } else {
            // 内部调用返回完整错误信息
            throw new Error('Login processing failed' + error);
        }
    }
}
// 登录响应（设置 Cookie）
function createLoginResponse(account_id, encryptedApiToken, requestUrl, encryptedCookieToken, renewToken = null, encryptedAccountName = null, plainAccountName = null) {
    const headers = new Headers();
    headers.set('Content-Type', 'application/json');
    const secureFlag = String(requestUrl ?? '').startsWith('https:') ? '; Secure' : '';
    const maxAge = typeof loginPeriod !== 'undefined' ? loginPeriod : 604800;
    const cookieOptions = `Max-Age=${maxAge}; Path=/; HttpOnly${secureFlag}; SameSite=Strict`;

    headers.append('Set-Cookie', `account_id=${account_id}; ${cookieOptions}`);
    headers.append('Set-Cookie', `cf_api=${encryptedCookieToken}; ${cookieOptions}`);
    headers.append('Set-Cookie', `token_encrypted=true; ${cookieOptions}`);
    if (encryptedAccountName) {
        headers.append('Set-Cookie', `account_name=${encodeURIComponent(encryptedAccountName)}; ${cookieOptions}`);
    }
    // 登录指示
    headers.append('Set-Cookie', `cookie_available=true;Max-Age=${maxAge}; Path=/; SameSite=Lax`);

    if (renewToken) {
        const renewMaxAge = renewal.maxPeriod;
        const renewCookieOptions = `Max-Age=${renewMaxAge}; Path=/; HttpOnly${secureFlag}; SameSite=Strict`;
        headers.append('Set-Cookie', `renew_token=${renewToken}; ${renewCookieOptions}`);
    }

    const body = {
        success: true,
        encrypted_token: encryptedApiToken,
        account_id: account_id
    };
    if (plainAccountName) {
        body.account_name = plainAccountName;
    }
    return new Response(JSON.stringify(body), { status: 200, headers });
}
// ==================== 登录续期====================
// 派生秘密钥
async function deriveAesKey(serverId) {
    /**
 * 从 serverId 派生 AES-256-GCM 密钥（SHA-256 哈希后作为原始密钥）
 */
    const enc = new TextEncoder();
    const hash = await crypto.subtle.digest('SHA-256', enc.encode(serverId));
    return crypto.subtle.importKey('raw', hash, 'AES-GCM', false, ['encrypt', 'decrypt']);
}
// 创建续期令牌
async function generateRenewToken(accountId, clientIp, deadlineTimestamp, serverId) {
    /**
   * 生成加密的 renew_token
   * @param {string} accountId
   * @param {string} clientIp
   * @param {number} deadlineTimestamp - 毫秒时间戳
   * @param {string} serverId
   * @returns {Promise<string>} renew_token (base64)
   */

    const key = await deriveAesKey(serverId);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const payload = `${accountId}|${clientIp}|${deadlineTimestamp}`;
    const enc = new TextEncoder();

    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        enc.encode(payload)
    );

    // 组合 iv + 密文（含 auth tag），转为 base64
    const combined = new Uint8Array(iv.length + ciphertext.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(ciphertext), iv.length);
    return btoa(String.fromCharCode(...combined));
}
// 验证续期令牌
async function verifyRenewToken(renewToken, clientIp, serverId) {
    try {
        /**
   * 验证并解密 renew_token
   * @param {string} renewToken
   * @param {string} clientIp - 当前请求的 IP
   * @param {string} serverId
   * @returns {Promise<{valid: boolean, accountId?: string, reason?: string}>}
   */
        const key = await deriveAesKey(serverId);
        const raw = Uint8Array.from(atob(renewToken), c => c.charCodeAt(0));
        const iv = raw.slice(0, 12);
        const ciphertext = raw.slice(12);

        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            key,
            ciphertext
        );

        const payload = new TextDecoder().decode(decrypted);
        const [accountId, tokIp, deadlineStr] = payload.split('|');
        if (!accountId || !tokIp || !deadlineStr) {
            return { valid: false, reason: 'bad payload' };
        }

        const deadline = parseInt(deadlineStr, 10);
        if (isNaN(deadline)) return { valid: false, reason: 'invalid deadline' };

        // 检查 IP 和有效期
        if (tokIp !== clientIp) return { valid: false, reason: 'ip mismatch' };
        if (Date.now() > deadline) return { valid: false, reason: 'expired' };

        return { valid: true, accountId };
    } catch (e) {
        // 解密失败（篡改、密钥错误等）
        return { valid: false, reason: 'decryption failed' };
    }
}
// 获取cookie状态
async function getCookieStatus(cookieValue, accountId, serverId) {
    /**
 * 获取 Cookie 的状态（是否有效、剩余有效秒数）
 * @param {string} cookieValue - cf_api Cookie 的值
 * @param {string} accountId - 账户 ID
 * @param {string} serverId - 服务器标识（与加密时相同）
 * @returns {Promise<{ valid: boolean, remainingSeconds: number | null }>}
 *   - valid: true 表示 Cookie 有效且（若为增强格式）未过期；false 表示无效/过期
 *   - remainingSeconds: 有效时返回剩余秒数（增强格式），旧版格式返回 null；无效时返回 null
 */
    if (!cookieValue || !accountId || !serverId) {
        return { valid: false, remainingSeconds: null };
    }

    // 定义时钟偏差（与 decryptForCookie 保持一致）
    const CLOCK_SKEW = typeof globalThis.CLOCK_SKEW !== 'undefined' ? globalThis.CLOCK_SKEW : 0;

    try {
        // 尝试按增强格式解析：外层解密得到 "内层密文|过期时间戳"
        const payload = await decrypt(cookieValue, serverId, COOKIE_EXPIRY_WORKER_ID);
        const parts = payload.split('|');
        if (parts.length !== 2) {
            // 格式错误，无效
            return { valid: false, remainingSeconds: null };
        }

        const innerCipher = parts[0];
        const expiryTimestamp = parseInt(parts[1], 10);
        const now = Date.now();

        // 检查是否过期（允许时钟偏差）
        if (now > expiryTimestamp + CLOCK_SKEW) {
            return { valid: false, remainingSeconds: null };
        }

        // 验证内层是否能正确解密（确保 token 未被篡改）
        try {
            await decrypt(innerCipher, serverId, accountId);
        } catch (innerErr) {
            // 内层解密失败 => Cookie 无效
            return { valid: false, remainingSeconds: null };
        }

        // 计算剩余秒数（不小于 0）
        const remainingSeconds = Math.max(0, Math.floor((expiryTimestamp - now) / 1000));
        return { valid: true, remainingSeconds };
    } catch (err) {
        // 增强格式解析失败 -> 尝试兼容旧版单层加密（无过期时间）
        try {
            await decrypt(cookieValue, serverId, accountId);
            // 旧版 Cookie 有效，但无法获取剩余时间
            return { valid: true, remainingSeconds: null };
        } catch (legacyErr) {
            // 两种格式都失败
            return { valid: false, remainingSeconds: null };
        }
    }
}
// 续期cookie
async function checkAndRenewCookie(cookies, serverId, options = {}) {
    /**
     * 核心续期/重新签发 Cookie 逻辑
     * @param {Object} cookies - 已解析的 cookies 对象
     * @param {string} serverId
     * @param {Object} options - { requireRenewToken: boolean, request?: Request, redirect?: string }
     * @returns {Promise<Response>}
     */
    const { requireRenewToken = false, request = null, redirect = null } = options;
    const cookieValue = cookies?.cf_api;
    const accountId = cookies?.account_id;

    // ========== 1. 优先检查认证凭证是否存在 ==========
    if (!cookieValue || !accountId) {
        return new Response(JSON.stringify({ error: 'Missing authentication cookie' }), {
            status: 401,
            headers: { 'Content-Type': 'application/json' }
        });
    }

    const totalExpirySeconds = (typeof loginPeriod !== 'undefined') ? loginPeriod : 604800;
    const RENEW_THRESHOLD = totalExpirySeconds * renewal.threshold;

    // ========== 2. 解密并验证主 Token（cf_api）有效性 ==========
    let needRenew = false;
    let originalToken = null;

    try {
        const payload = await decrypt(cookieValue, serverId, COOKIE_EXPIRY_WORKER_ID);
        const parts = payload.split('|');
        if (parts.length === 2) {
            const expiryTimestamp = parseInt(parts[1], 10);
            const remainingMs = expiryTimestamp - Date.now();
            const remainingSec = Math.max(0, Math.floor(remainingMs / 1000));
            if (remainingSec < RENEW_THRESHOLD) {
                needRenew = true;
            }
            originalToken = await decrypt(parts[0], serverId, accountId);
        } else {
            // 格式错误 -> 401
            return new Response(JSON.stringify({ error: 'Invalid cookie format' }), {
                status: 401,
                headers: { 'Content-Type': 'application/json' }
            });
        }
    } catch (err) {
        // 尝试旧格式解密
        try {
            originalToken = await decrypt(cookieValue, serverId, accountId);
            needRenew = true; // 旧版一律续期
        } catch (legacyErr) {
            return new Response(JSON.stringify({ error: 'Invalid or expired cookie' }), {
                status: 401,
                headers: { 'Content-Type': 'application/json' }
            });
        }
    }

    // 验证 Token 是否仍然有效（与后端核对）
    const { valid } = await verifyApiToken(originalToken, accountId);
    if (!valid) {
        return new Response(JSON.stringify({ error: 'Token invalid, please re-login' }), {
            status: 401,
            headers: { 'Content-Type': 'application/json' }
        });
    }

    // ========== 3. 如果要求续期（自动续期接口），再检查 renew_token（403 场景） ==========
    if (requireRenewToken) {
        const renewToken = cookies?.renew_token;
        if (!renewToken) {
            if (redirect && request) {
                return Response.redirect(new URL(redirect, request.url).toString(), 302);
            }
            return new Response(JSON.stringify({ error: 'Missing renew token' }), {
                status: 403,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        let clientIp = '0.0.0.0';
        if (request) {
            clientIp = request.headers.get('CF-Connecting-IP') || '0.0.0.0';
        }

        const verification = await verifyRenewToken(renewToken, clientIp, serverId);
        if (!verification.valid) {
            if (redirect && request) {
                return Response.redirect(new URL(redirect, request.url).toString(), 302);
            }
            // 吊销 renew_token
            const headers = new Headers({ 'Content-Type': 'application/json' });
            const revokeCookie = 'renew_token=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Strict';
            headers.append('Set-Cookie', revokeCookie);
            return new Response(JSON.stringify({ error: 'Renew token invalid or expired', reason: verification.reason }), {
                status: 403,
                headers
            });
        }

        // 校验 token 中的 accountId 是否匹配
        if (verification.accountId !== accountId) {
            if (redirect && request) {
                return Response.redirect(new URL(redirect, request.url).toString(), 302);
            }
            return new Response(JSON.stringify({ error: 'Account mismatch' }), {
                status: 403,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        // 不需要续期时直接返回（仍然 200，但注明未续期）
        if (!needRenew) {
            if (redirect && request) {
                return Response.redirect(new URL(redirect, request.url).toString(), 302);
            }
            const response = new Response(JSON.stringify({ renewed: false, message: 'No renewal needed' }), {
                status: 200,
                headers: { 'Content-Type': 'application/json' }
            });
            return response;
        }
    }

    // ========== 4. 生成新 Cookie（续期）并返回 200 ==========
    const newEncryptedCookie = await encryptForCookie(originalToken, serverId, accountId, totalExpirySeconds);
    const secureFlag = String(options?.request?.url ?? '').startsWith('https:') ? '; Secure' : '';
    const cookieOptions = `Max-Age=${totalExpirySeconds}; Path=/; HttpOnly${secureFlag}; SameSite=Strict`;

    const responseHeaders = new Headers({ 'Content-Type': 'application/json' });
    responseHeaders.append('Set-Cookie', `account_id=${accountId}; ${cookieOptions}`);
    responseHeaders.append('Set-Cookie', `cf_api=${newEncryptedCookie}; ${cookieOptions}`);
    responseHeaders.append('Set-Cookie', `token_encrypted=true; ${cookieOptions}`);
    // 续期 account_name cookie（使用原有的加密值续期 Max-Age，或重新加密）
    if (cookies?.account_name) {
        responseHeaders.append('Set-Cookie', `account_name=${cookies.account_name}; ${cookieOptions}`);
    } else {
        // 若原 cookie 中不存在则尝试重新获取并加密
        try {
            const rawAccountName = await fetchCloudflareAccountName(originalToken, accountId);
            if (rawAccountName) {
                const encName = await simpleEncryptWithTokenHash(rawAccountName, originalToken);
                if (encName) {
                    responseHeaders.append('Set-Cookie', `account_name=${encodeURIComponent(encName)}; ${cookieOptions}`);
                }
            }
        } catch (e) {
            console.warn('Renewal: failed to re-process account_name:', e);
        }
    }
    // 登录指示
    responseHeaders.append('Set-Cookie', `cookie_available; Max-Age=${totalExpirySeconds}; Path=/; SameSite=Lax`);

    const response = new Response(JSON.stringify({
        success: true,
        renewed: needRenew || !requireRenewToken,
        message: 'Session refreshed'
    }), { status: 200, headers: responseHeaders });

    if (redirect && request) {
        return Response.redirect(new URL(redirect, request.url).toString(), 302);
    }
    return response;
}
// 显示登录页面 /login
async function showLoginPage(request, url) {
    // 从cookie中读取已保存的账户信息
    const cookieHeader = request.headers.get('Cookie') || '';
    const cookies = Object.fromEntries(cookieHeader.split(';').map(c => c.trim().split('=')));
    const hasCookie = cookies.cf_api && cookies.account_id;
    const html = `
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
        <meta charset="UTF-8">
        <link rel="icon" href="/favicon.svg" type="image/svg+xml">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Worker 编辑器|登录</title>
        <link rel="stylesheet" href="/static/style.css">
        <style>
        .container { max-width: 500px; margin: 0 auto; }
        .account-item { border: 1px solid var(--border-color); padding: 1rem; margin: 0.5rem 0; border-radius: var(--radius); background-color: var(--surface-color); }
        .error { color: var(--danger-color); margin: 0.5rem 0; padding: 0.75rem; background-color: #fef2f2; border-radius: var(--radius); border: 1px solid #fecaca; display: none; }
        .loading { text-align: center; margin: 1rem 0; color: var(--primary-color); display: none; }
        .import-section { margin-top: 1.5rem; padding-top: 1.5rem; border-top: 1px solid var(--border-color); }
        /* 密码输入框组样式 */
        .password-wrapper {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .password-wrapper input {
            flex: 1;
        }
        .toggle-password {
            background: none;
            border: none;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            padding: 0;
            color: var(--text-secondary);
            transition: color 0.2s;
        }
        .toggle-password:hover {
            color: var(--primary-color);
        }
        /* 大屏幕布局调整 */
        @media (min-width: 768px) {
        .container { max-width: 1024px; }
        .login-layout {
        display: grid;
        grid-template-columns: 1fr 1fr;
        grid-template-rows: auto auto;
        gap: 2.5rem;
        align-items: start;
        }
        .account-section {
        grid-column: 1;
        grid-row: 1;
        }
        #localStorageLogin {
        grid-column: 1;
        grid-row: 2;
        }
        .import-section {
        grid-column: 2;
        grid-row: 1 / -1;
        margin-top: 0;
        padding-top: 0;
        border-top: none;
        border-left: 1px solid var(--border-color);
        padding-left: 2.5rem;
        }
        .account-item {
        display: grid;
        grid-template-columns: 1fr auto;
        gap: 0.75rem 1rem;
        align-items: center;
        padding: 1.25rem;
        }
        .account-item p { grid-column: 1 / -1; margin-bottom: 0.25rem; }
        .account-item .password-wrapper { width: 100%; }
        .account-item .d-flex { grid-column: 1 / -1; }
        .import-section input[type="text"],
        .import-section input[type="password"] {
        max-width: 380px;
        }
        }
        </style>
        </head>
        <body>
        {{NAVBAR}}
        <div class="container">
        <div class="card">
        <h1>Cloudflare Workers 登录</h1>
        <div id="errorMsg" class="error"></div>
        <div id="loading" class="loading">登录中...</div>

        <div class="login-layout">
        ${hasCookie ? `
        <div class="account-section mb-4">
        <h3>发现已登录账户</h3>
        <p class="mb-3" style="overflow-wrap: break-word;word-wrap: break-word;word-break: break-word;">账户ID: ${cookies.account_id}</p>
        <div class="d-flex gap-2">
        <button onclick="directLogin()" class="btn">继续</button>
        <button onclick="logout('${cookies.account_id}')" class="btn btn-secondary">登出</button>
        </div>
        </div>
        `: ''}

        <div id="localStorageLogin">
        <h3>从本地存储登录</h3>
        <div id="accountList" class="mb-3">
        <p class="text-center text-secondary">加载中...</p>
        </div>
        </div>

        <div id="importAccount" class="import-section">
        <h3>导入新账户</h3>
        <form id="importForm">
        <div class="form-group">
        <input type="text" id="import_account_id" placeholder="Account ID" required>
        </div>
        <div class="form-group">
            <div class="password-wrapper">
                <input type="password" id="import_api_token" placeholder="API Token" required>
                <button type="button" class="toggle-password" data-target="import_api_token">
                    <svg class="eye-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <path d="M1 12C1 12 5 4 12 4C19 4 23 12 23 12C23 12 19 20 12 20C5 20 1 12 1 12Z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                        <circle cx="12" cy="12" r="3" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                </button>
            </div>
        </div>
        <p class="text-secondary" style="font-size:0.8rem;">你的API Token将完全安全的地加密存储到本地，请勿清除浏览器数据</p>
        <div class="form-group">
            <div class="password-wrapper">
                <input type="password" id="import_password" placeholder="设置登录密码 " required>
                <button type="button" class="toggle-password" data-target="import_password">
                    <svg class="eye-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <path d="M1 12C1 12 5 4 12 4C19 4 23 12 23 12C23 12 19 20 12 20C5 20 1 12 1 12Z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                        <circle cx="12" cy="12" r="3" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                </button>
            </div>
            <div id="password_strength" class="password-strength" style="margin-top: 0.5rem; display: none;">
                <div class="strength-bar" style="height: 4px; background-color: #e0e0e0; border-radius: 2px; overflow: hidden;">
                    <div id="strength_fill" style="height: 100%; width: 0%; transition: width 0.3s, background-color 0.3s;"></div>
                </div>
                <p id="strength_text" class="text-secondary" style="font-size: 0.75rem; margin: 0.25rem 0 0 0;"></p>
            </div>
        </div>
        <div class="form-group">
            <div class="password-wrapper">
                <input type="password" id="import_password_confirm" placeholder="确认登录密码" required>
                <button type="button" class="toggle-password" data-target="import_password_confirm">
                    <svg class="eye-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <path d="M1 12C1 12 5 4 12 4C19 4 23 12 23 12C23 12 19 20 12 20C5 20 1 12 1 12Z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                        <circle cx="12" cy="12" r="3" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                </button>
            </div>
            <div id="password_match" class="password-match" style="margin-top: 0.5rem; display: none;">
                <p id="match_text" class="text-secondary" style="font-size: 0.75rem; margin: 0;"></p>
            </div>
        </div>
        <p class="text-secondary" style="font-size:0.8rem; margin-top:-0.5rem;">密码要求：至少 8 位，必须同时包含字母和数字</p>
        <button type="submit" id="importBtn" class="btn">导入并登录</button>
        <div class="token-info mb-3" style="background-color: var(--surface-secondary); padding: 0.75rem; border-radius: var(--radius); border-left: 3px solid var(--primary-color);">
        <p style="margin: 0; font-size: 0.9rem;">
        <strong>如何获取 API Token：</strong>
        访问
        <a href="https://dash.cloudflare.com/?to=/:account/api-tokens" target="_blank" style="color: var(--primary-color); text-decoration: underline;">
        Cloudflare API Tokens
        </a>
        创建一个标准 Worker 编辑令牌即可。
        </p>
        </div>
        </form>
        </div>
        </div>
        </div>
        </div>

        <script>
        // 全局状态控制
        let isLoading = false;
        const errorMsg = document.getElementById('errorMsg');
        const loadingEl = document.getElementById('loading');

        // 显示错误消息
        function showError(message) {
            errorMsg.textContent = message;
            errorMsg.style.display = 'block';
            setTimeout(() => errorMsg.style.display = 'none', 5000);
        }

        function setLoading(state) {
            isLoading = state;
            loadingEl.style.display = state ? 'block' : 'none';
            document.querySelectorAll('button').forEach(btn => btn.disabled = state);
        }

        function loadAccounts() {
            try {
                return JSON.parse(localStorage.getItem('cf_accounts') || '{}');
            } catch (e) {
                console.error('Failed to load accounts from localStorage', e);
                return {};
            }
        }

        // 独立存储账户名称 meta，保证完全向后兼容（不侵入原有 cf_accounts 结构）
        const ACCOUNTS_META_KEY = 'cf_accounts_meta';
        function loadAccountsMeta() {
            try {
                return JSON.parse(localStorage.getItem(ACCOUNTS_META_KEY) || '{}');
            } catch (e) {
                console.error('Failed to load accounts meta from localStorage', e);
                return {};
            }
        }
        function saveAccountNameMeta(accountId, accountName) {
            if (!accountId || !accountName) return;
            try {
                const meta = loadAccountsMeta();
                meta[accountId] = Object.assign({}, meta[accountId] || {}, { account_name: accountName });
                localStorage.setItem(ACCOUNTS_META_KEY, JSON.stringify(meta));
            } catch (e) {
                console.warn('Failed to save account name meta:', e);
            }
        }
        function removeAccountNameMeta(accountId) {
            if (!accountId) return;
            try {
                const meta = loadAccountsMeta();
                if (meta[accountId]) {
                    delete meta[accountId];
                    localStorage.setItem(ACCOUNTS_META_KEY, JSON.stringify(meta));
                }
            } catch (e) {
                console.warn('Failed to remove account name meta:', e);
            }
        }
        function getAccountDisplayName(accountId) {
            const meta = loadAccountsMeta();
            const name = meta[accountId]?.account_name;
            return (name && String(name).trim()) ? String(name).trim() : accountId;
        }

        // 渲染账户列表，每个密码框都带有独立的切换按钮
        function renderAccountList() {
            const accounts = loadAccounts();
            const accountListEl = document.getElementById('accountList');

            if (Object.keys(accounts).length > 0) {
                let html = '';
                for (const [accountId] of Object.entries(accounts)) {
                    const displayName = getAccountDisplayName(accountId);
                    const showName = displayName !== accountId;
                    const pwdId = \`pwd_\${accountId}\`;
                    html += \`
                    <div class="account-item">
                        <p class="mb-2" style="overflow-wrap: break-word;word-wrap: break-word;word-break: break-word;" title="\${showName ? escapeHtml('ID: ' + accountId) : ''}">
                            <strong>\${escapeHtml(displayName)}</strong>
                            \${showName ? \`<br><small style="color: var(--text-secondary); font-weight: 400;">ID: \${escapeHtml(accountId)}</small>\` : ''}
                        </p>
                        <div class="password-wrapper">
                            <input type="password" id="\${pwdId}" placeholder="输入密码" class="mb-2">
                            <button type="button" class="toggle-password" data-target="\${pwdId}">
                                <svg class="eye-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                                    <path d="M1 12C1 12 5 4 12 4C19 4 23 12 23 12C23 12 19 20 12 20C5 20 1 12 1 12Z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                                    <circle cx="12" cy="12" r="3" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                                </svg>
                            </button>
                        </div>
                        <div class="d-flex gap-2">
                            <button onclick="loginFromLocalStorage('\${escapeHtml(accountId)}')" class="btn">登录</button>
                            <button onclick="removeAccount('\${escapeHtml(accountId)}')" class="btn btn-secondary">删除</button>
                        </div>
                    </div>
                    \`;
                }
                accountListEl.innerHTML = html;
            } else {
                accountListEl.innerHTML = '<p class="text-center text-secondary">暂无存储的账户</p>';
            }
        }

        // 简单的防XSS辅助函数
        function escapeHtml(str) {
            return str.replace(/[&<>]/g, function(m) {
                if (m === '&') return '&amp;';
                if (m === '<') return '&lt;';
                if (m === '>') return '&gt;';
                return m;
            }).replace(/[\\uD800-\\uDBFF][\\uDC00-\\uDFFF]/g, function(c) {
                return c;
            });
        }

        // 加解密函数
        async function encryptForStorage(data, password) {
            try {
                const salt = crypto.getRandomValues(new Uint8Array(8));
                const iv = crypto.getRandomValues(new Uint8Array(12));
                const encoder = new TextEncoder();
                const dataBuffer = encoder.encode(data);
                const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
                const key = await crypto.subtle.deriveKey(
                    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
                    keyMaterial,
                    { name: 'AES-GCM', length: 128 },
                    false,
                    ['encrypt']
                );
                const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, dataBuffer);
                
                // 生成 HMAC 密钥用于完整性校验
                const hmacKeyMaterial = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
                const hmacKey = await crypto.subtle.deriveKey(
                    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
                    hmacKeyMaterial,
                    { name: 'HMAC', hash: 'SHA-256' },
                    false,
                    ['sign']
                );
                
                // 对加密数据（salt + iv + ciphertext）计算 HMAC
                const hmacData = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
                hmacData.set(salt, 0);
                hmacData.set(iv, salt.length);
                hmacData.set(new Uint8Array(encrypted), salt.length + iv.length);
                const hmacSignature = await crypto.subtle.sign('HMAC', hmacKey, hmacData);
                
                // 新格式：salt(8) + iv(12) + ciphertext + hmac(32)
                const combined = new Uint8Array(salt.length + iv.length + encrypted.byteLength + hmacSignature.byteLength);
                combined.set(salt, 0);
                combined.set(iv, salt.length);
                combined.set(new Uint8Array(encrypted), salt.length + iv.length);
                combined.set(new Uint8Array(hmacSignature), salt.length + iv.length + encrypted.byteLength);
                
                return btoa(String.fromCharCode(...combined));
            } catch (err) {
                console.error('Encryption error:', err);
                throw new Error('加密失败，请重试');
            }
        }

        async function decryptForStorage(encryptedData, password) {
            try {
                const combined = new Uint8Array(atob(encryptedData).split('').map(c => c.charCodeAt(0)));
                const encoder = new TextEncoder();
                
                // 检测数据格式：新格式包含 HMAC(32 字节)，旧格式不包含
                // 旧格式：salt(8) + iv(12) + ciphertext(至少 16) = 至少 36 字节
                // 新格式：salt(8) + iv(12) + ciphertext(至少 16) + hmac(32) = 至少 68 字节
                const HMAC_LENGTH = 32;
                const MIN_CIPHERTEXT_LENGTH = 16;
                const HEADER_LENGTH = 8 + 12; // salt + iv
                const NEW_FORMAT_MIN_LENGTH = HEADER_LENGTH + MIN_CIPHERTEXT_LENGTH + HMAC_LENGTH;
                
                const isNewFormat = combined.length >= NEW_FORMAT_MIN_LENGTH;
                
                if (isNewFormat) {
                    // 新格式：验证 HMAC 完整性
                    const salt = combined.slice(0, 8);
                    const iv = combined.slice(8, 20);
                    const ciphertext = combined.slice(20, combined.length - HMAC_LENGTH);
                    const storedHmac = combined.slice(combined.length - HMAC_LENGTH);
                    
                    // 生成 HMAC 密钥
                    const hmacKeyMaterial = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
                    const hmacKey = await crypto.subtle.deriveKey(
                        { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
                        hmacKeyMaterial,
                        { name: 'HMAC', hash: 'SHA-256' },
                        false,
                        ['verify']
                    );
                    
                    // 验证 HMAC
                    const hmacData = new Uint8Array(salt.length + iv.length + ciphertext.byteLength);
                    hmacData.set(salt, 0);
                    hmacData.set(iv, salt.length);
                    hmacData.set(new Uint8Array(ciphertext), salt.length + iv.length);
                    const isValid = await crypto.subtle.verify('HMAC', hmacKey, storedHmac, hmacData);
                    
                    if (!isValid) {
                        throw new Error('PASSWORD_ERROR');
                    }
                    
                    // HMAC 验证通过，解密数据
                    const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
                    const key = await crypto.subtle.deriveKey(
                        { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
                        keyMaterial,
                        { name: 'AES-GCM', length: 128 },
                        false,
                        ['decrypt']
                    );
                    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
                    return new TextDecoder().decode(decrypted);
                } else {
                    // 旧格式：向后兼容，直接解密
                    const salt = combined.slice(0, 8);
                    const iv = combined.slice(8, 20);
                    const ciphertext = combined.slice(20);
                    
                    const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
                    const key = await crypto.subtle.deriveKey(
                        { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
                        keyMaterial,
                        { name: 'AES-GCM', length: 128 },
                        false,
                        ['decrypt']
                    );
                    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
                    return new TextDecoder().decode(decrypted);
                }
            } catch (err) {
                console.error('Decryption error:', err);
                // 区分错误类型
                if (err.message === 'PASSWORD_ERROR') {
                    throw new Error('密码错误');
                }
                if (err.name === 'InvalidAccessError' || err.name === 'OperationError') {
                    throw new Error('数据已损坏');
                }
                throw new Error('解密失败，密码错误或数据已损坏');
            }
        }

        // 安全显示 URL 传递的消息（修复 XSS）
        function checkAndShowMessage() {
            const urlParams = new URLSearchParams(window.location.search);
            const message = urlParams.get('message');

            function removeMessageParam() {
                const url = new URL(window.location);
                url.searchParams.delete('message');
                window.history.replaceState({}, '', url);
            }

            if (message) {
                const messageDiv = document.createElement('div');
                messageDiv.className = 'message-notification';
                messageDiv.style.cssText = \`
                    position: fixed;
                    top: 20px;
                    right: 20px;
                    background: var(--surface-color);
                    color: var(--primary-color);
                    padding: 1rem 1.5rem;
                    border-radius: var(--radius);
                    box-shadow: var(--shadow);
                    z-index: 1000;
                    animation: slideIn 0.3s ease;
                    max-width: 400px;
                \`;

                const style = document.createElement('style');
                style.textContent = \`
                    @keyframes slideIn {
                        from { transform: translateX(100%); opacity: 0; }
                        to { transform: translateX(0); opacity: 1; }
                    }
                    @keyframes fadeOut {
                        from { opacity: 1; }
                        to { opacity: 0; }
                    }
                \`;
                document.head.appendChild(style);

                const closeMessage = () => {
                    messageDiv.style.animation = 'fadeOut 0.3s ease';
                    setTimeout(() => {
                        if (messageDiv.parentElement) messageDiv.remove();
                        removeMessageParam();
                    }, 300);
                };

                const messageSpan = document.createElement('span');
                messageSpan.textContent = decodeURIComponent(message);
                const closeBtn = document.createElement('button');
                closeBtn.textContent = '确定';
                closeBtn.addEventListener('click', closeMessage);

                messageDiv.appendChild(messageSpan);
                messageDiv.appendChild(closeBtn);
                document.body.appendChild(messageDiv);

                setTimeout(() => {
                    if (messageDiv.parentElement) closeMessage();
                }, 5000);
            }
        }

        async function directLogin() {
            if (isLoading) return;
            setLoading(true);
            try {
                const response = await fetch('/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        login_type: 'cookie',
                        account_id: '${cookies.account_id}',
                        api_token: ''
                    })
                });
                if (response.ok) {
                    window.location.href = '/list';
                } else {
                    showError('登录失败，请重新登录');
                }
            } catch (error) {
                console.error('Direct login error:', error);
                showError('网络错误，请稍后重试');
            } finally {
                setLoading(false);
            }
        }

        async function loginFromLocalStorage(accountId) {
            if (isLoading) return;
            const password = document.getElementById('pwd_' + accountId).value;
            if (!password) {
                showError('请输入密码');
                return;
            }
            setLoading(true);
            try {
                const accounts = loadAccounts();
                const doubleEncryptedToken = accounts[accountId];
                if (!doubleEncryptedToken) {
                    showError('账户不存在');
                    return;
                }
                let serverEncryptedToken;
                try {
                    serverEncryptedToken = await decryptForStorage(doubleEncryptedToken, password);
                } catch (decErr) {
                    console.error('Decrypt failed in loginFromLocalStorage', decErr);
                    // 根据错误类型提供不同的提示
                    const errMsg = decErr.message || '';
                    if (errMsg === '密码错误') {
                        showError('密码错误，请重新输入');
                    } else if (errMsg === '数据已损坏') {
                        showError('数据已损坏，请重新导入账户');
                    } else {
                        showError('密码错误或数据已损坏');
                    }
                    return;
                }
                const response = await fetch('/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        login_type: 'localstorage',
                        account_id: accountId,
                        encrypted_token: serverEncryptedToken
                    })
                });
                if (response.ok) {
                    const result = await response.json();
                    const newDoubleEncryptedToken = await encryptForStorage(result.encrypted_token, password);
                    accounts[accountId] = newDoubleEncryptedToken;
                    localStorage.setItem('cf_accounts', JSON.stringify(accounts));
                    if (result.account_name) saveAccountNameMeta(accountId, result.account_name);
                    window.location.href = '/list';
                } else {
                    const errorData = await response.json().catch(() => ({}));
                    console.error('Login API error:', errorData);
                    if(${DEBUG}){
                        showError('登录失败:'+ JSON.stringify(errorData));
                    }else{
                    showError('登录失败，请检查密码和账户');
                    }
                }
            } catch (error) {
                console.error('Unexpected error in loginFromLocalStorage:', error);
                if(${DEBUG}){
                        showError('Unexpected error in loginFromLocalStorage:'+ error);
                    }else{
                    showError('登录过程中发生错误，请重试');
                    }
            } finally {
                setLoading(false);
            }
        }

        // 导入表单提交
        document.getElementById('importForm')?.addEventListener('submit', async (e) => {
            e.preventDefault();
            if (isLoading) return;

            const accountId = document.getElementById('import_account_id').value.trim();
            const apiToken = document.getElementById('import_api_token').value.trim();
            const password = document.getElementById('import_password').value;
            const confirmPassword = document.getElementById('import_password_confirm').value;

            if (!accountId || !apiToken || !password || !confirmPassword) {
                showError('请填写所有字段');
                return;
            }
            
            // 密码强度校验（至少 8 位且同时包含字母和数字）
            if (password.length < 8 || !/[a-zA-Z]/.test(password) || !/[0-9]/.test(password)) {
                showError('密码不符合要求：至少 8 位且同时包含字母和数字');
                return;
            }
            
            // 一致性检查
            if (password !== confirmPassword) {
                showError('两次输入的密码不一致');
                return;
            }

            setLoading(true);
            try {
                const response = await fetch('/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        login_type: 'import',
                        account_id: accountId,
                        api_token: apiToken
                    })
                });
                if (response.ok) {
                    const result = await response.json();
                    const doubleEncryptedToken = await encryptForStorage(result.encrypted_token, password);
                    const accounts = loadAccounts();
                    accounts[accountId] = doubleEncryptedToken;
                    localStorage.setItem('cf_accounts', JSON.stringify(accounts));
                    if (result.account_name) saveAccountNameMeta(accountId, result.account_name);
                    window.location.href = '/list';
                } else {
                    let errorMsgText = '导入失败，请检查API Token';
                    try {
                        const errorData = await response.json();
                        console.error('Import API error details:', errorData);
                        if (${DEBUG}) errorMsgText = 'Import API error :' + errorData;
                    } catch (_) {}
                    showError(errorMsgText);
                }
            } catch (error) {
                console.error('Import error:', error);
                if(${DEBUG}){
                        showError('Import error:'+ error);
                    }else{
                showError('导入失败，请检查网络或稍后重试');
                    }
            } finally {
                setLoading(false);
            }
        });

        function removeAccount(accountId) {
            if (isLoading) return;
            if (confirm('确定要删除此账户吗？')) {
                const accounts = loadAccounts();
                delete accounts[accountId];
                localStorage.setItem('cf_accounts', JSON.stringify(accounts));
                removeAccountNameMeta(accountId);
                renderAccountList();
            }
        }

        function logout(accountId) {
            window.location.href = '/logout?account_id=' + encodeURIComponent(accountId);
        }

        // 统一密码显示/隐藏切换（事件委托，支持动态添加的按钮）
        function initPasswordToggles() {
            document.addEventListener('click', function(e) {
                const toggleBtn = e.target.closest('.toggle-password');
                if (!toggleBtn) return;
                e.preventDefault();
                const targetId = toggleBtn.getAttribute('data-target');
                if (!targetId) return;
                const input = document.getElementById(targetId);
                if (!input) return;
                const type = input.getAttribute('type') === 'password' ? 'text' : 'password';
                input.setAttribute('type', type);
                const svg = toggleBtn.querySelector('.eye-icon');
                if (svg) {
                    if (type === 'text') {
                        svg.innerHTML = '<path d="M1 12C1 12 5 4 12 4C19 4 23 12 23 12C23 12 19 20 12 20C5 20 1 12 1 12Z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><circle cx="12" cy="12" r="3" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><line x1="3" y1="3" x2="21" y2="21" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>';
                    } else {
                        svg.innerHTML = '<path d="M1 12C1 12 5 4 12 4C19 4 23 12 23 12C23 12 19 20 12 20C5 20 1 12 1 12Z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><circle cx="12" cy="12" r="3" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>';
                    }
                }
            });
        }

        // 密码强度检查
        function checkPasswordStrength(password) {
            const strengthEl = document.getElementById('password_strength');
            const strengthFill = document.getElementById('strength_fill');
            const strengthText = document.getElementById('strength_text');
            
            if (!password || password.length === 0) {
                strengthEl.style.display = 'none';
                return 0;
            }
            
            strengthEl.style.display = 'block';
            
            let score = 0;
            const checks = [];
            
            // 长度检查
            if (password.length >= 8) score += 25;
            if (password.length >= 12) score += 10;
            if (password.length >= 16) score += 5;
            
            // 字符类型检查
            if (/[a-z]/.test(password)) { score += 10; checks.push('小写字母'); }
            if (/[A-Z]/.test(password)) { score += 15; checks.push('大写字母'); }
            if (/[0-9]/.test(password)) { score += 15; checks.push('数字'); }
            if (/[^a-zA-Z0-9]/.test(password)) { score += 20; checks.push('特殊字符'); }
            
            // 限制最高 100 分
            score = Math.min(score, 100);
            
            // 更新 UI
            strengthFill.style.width = score + '%';
            
            if (score < 40) {
                strengthFill.style.backgroundColor = '#ef4444';
                strengthText.style.color = '#ef4444';
                strengthText.textContent = '强度：弱';
            } else if (score < 70) {
                strengthFill.style.backgroundColor = '#f59e0b';
                strengthText.style.color = '#f59e0b';
                strengthText.textContent = '强度：中等';
            } else if (score < 90) {
                strengthFill.style.backgroundColor = '#3b82f6';
                strengthText.style.color = '#3b82f6';
                strengthText.textContent = '强度：强';
            } else {
                strengthFill.style.backgroundColor = '#22c55e';
                strengthText.style.color = '#22c55e';
                strengthText.textContent = '强度：非常强';
            }
            
            return score;
        }

        // 密码一致性检查
        function checkPasswordMatch(password, confirmPassword) {
            const matchEl = document.getElementById('password_match');
            const matchText = document.getElementById('match_text');
            
            if (!confirmPassword || confirmPassword.length === 0) {
                matchEl.style.display = 'none';
                return;
            }
            
            matchEl.style.display = 'block';
            
            if (password === confirmPassword) {
                matchText.style.color = '#22c55e';
                matchText.innerHTML = '✓ 密码一致';
            } else {
                matchText.style.color = '#ef4444';
                matchText.innerHTML = '✗ 密码不一致';
            }
        }

        // 初始化密码强度和一致性检查
        function initPasswordChecks() {
            const passwordInput = document.getElementById('import_password');
            const confirmInput = document.getElementById('import_password_confirm');
            
            if (passwordInput) {
                passwordInput.addEventListener('input', function() {
                    const strength = checkPasswordStrength(this.value);
                    checkPasswordMatch(this.value, confirmInput ? confirmInput.value : '');
                });
            }
            
            if (confirmInput) {
                confirmInput.addEventListener('input', function() {
                    checkPasswordMatch(passwordInput ? passwordInput.value : '', this.value);
                });
            }
        }

        document.addEventListener('DOMContentLoaded', function() {
            renderAccountList();
            checkAndShowMessage();
            initPasswordToggles(); // 使用事件委托，只需初始化一次
            initPasswordChecks(); // 初始化密码强度与一致性检查
        });
        </script>
        </body>
        </html>
        `;
    return buildHtmlResponse(html, '', {
        littleNav: true,
        enableUnauthorizedOverlay: false
    });
}
// 处理登出请求 /logout
async function handleLogout(request) {
    const headers = new Headers();
    headers.set('Content-Type', 'text/html');

    // 从请求中获取cookie
    const cookieHeader = request.headers.get('Cookie') || '';
    const cookies = Object.fromEntries(cookieHeader.split(';').map(c => {
        const [key, ...vals] = c.trim().split('=');
        return [key, vals.join('=')];
    }));

    // 优先从 URL 参数获取 account_id，其次从 cookie 获取
    const url = new URL(request.url);
    const accountIdFromUrl = url.searchParams.get('account_id');
    const accountId = accountIdFromUrl || cookies.account_id || '';

    // 清除所有cookie
    const secureFlag = request.url.startsWith('https:') ? '; Secure' : '';
    const expireDate = 'Thu, 01 Jan 1970 00:00:00 GMT';
    headers.append('Set-Cookie', `account_id=; Path=/; expires=${expireDate}${secureFlag}; SameSite=Strict`);
    headers.append('Set-Cookie', `cf_api=; Path=/; expires=${expireDate}${secureFlag}; SameSite=Strict`);
    headers.append('Set-Cookie', `token_encrypted=; Path=/; expires=${expireDate}${secureFlag}; SameSite=Strict`);
    headers.append('Set-Cookie', `encrypted_data=; Path=/; expires=${expireDate}${secureFlag}; SameSite=Strict`);
    headers.append('Set-Cookie', `account_name=; Path=/; expires=${expireDate}${secureFlag}; SameSite=Strict`);
    headers.append('Set-Cookie', `renew_token=; Path=/; expires=${expireDate}${secureFlag}; SameSite=Strict`);
    headers.append('Set-Cookie', `cookie_available; Max-Age=${expireDate}; Path=/; SameSite=Lax`);
    const html = `
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
        <meta charset="UTF-8">
        <link rel="icon" href="/favicon.svg" type="image/svg+xml">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Worker 编辑器|登出</title>
        <link rel="stylesheet" href="/static/style.css">
        <style>
        .logout-container {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            min-height: 70vh;
            text-align: center;
            padding: 2rem;
        }
        .logout-icon {
            width: 80px;
            height: 80px;
            background: var(--primary-color);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 24px;
        }
        .logout-icon svg {
            width: 40px;
            height: 40px;
            color: white;
        }
        .choice-buttons {
            display: flex;
            gap: 1rem;
            justify-content: center;
            margin: 1.5rem 0;
            flex-wrap: wrap;
        }
        .choice-buttons .btn {
            min-width: 140px;
        }
        .info-text {
            margin-bottom: 1rem;
            color: var(--text-secondary);
        }
        </style>
        </head>
        <body>
        {{NAVBAR}}
        <div class="logout-container">
            <div class="card" style="max-width: 500px;">
                <div class="logout-icon">
                    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                    </svg>
                </div>
                <h1>登出成功</h1>
                <p class="info-text">您已从当前会话登出</p>
                <p class="info-text">是否删除浏览器中保存的此账户信息？</p>
                <div class="choice-buttons">
                    <button id="deleteAndLogout" class="btn btn-danger">删除本地存储并返回</button>
                    <button id="justLogout" class="btn btn-secondary">仅返回</button>
                </div>
            </div>
        </div>

        <script>
            const accountId = ${JSON.stringify(accountId)};
            
            function redirectToHome() {
                window.location.href = '/';
            }
            
            // 删除本地存储中对应账户的条目
            function deleteLocalStorageAccount() {
                if (!accountId) return;
                try {
                    const accounts = JSON.parse(localStorage.getItem('cf_accounts') || '{}');
                    if (accounts[accountId]) {
                        delete accounts[accountId];
                        localStorage.setItem('cf_accounts', JSON.stringify(accounts));
                        console.log('已删除本地存储账户:', accountId);
                    }
                    // 同步删除账户名称 meta（向后兼容，不存在则忽略）
                    try {
                        const meta = JSON.parse(localStorage.getItem('cf_accounts_meta') || '{}');
                        if (meta[accountId]) {
                            delete meta[accountId];
                            localStorage.setItem('cf_accounts_meta', JSON.stringify(meta));
                        }
                    } catch (_) {}
                } catch(e) {
                    console.warn('删除本地存储失败:', e);
                }
            }
            
            document.getElementById('deleteAndLogout').addEventListener('click', () => {
                deleteLocalStorageAccount();
                redirectToHome();
            });
            
            document.getElementById('justLogout').addEventListener('click', () => {
                redirectToHome();
            });
        </script>
        </body>
        </html>
        `;

    return new Response(buildHtmlResponse(html, '', {
        littleNav: true,
        directlyReturn: true,
        enableUnauthorizedOverlay: false
    }), {
        status: 200,
        headers: headers
    });
}
//================workers==================
// 编辑API请求处理/api/script
async function handleEditorRequest(request, accountId, token) {
    const url = new URL(request.url);
    // 路径验证逻辑
    const pathSegments = url.pathname.split('/');
    if (pathSegments.length < 4) {
        return new Response(JSON.stringify({
            success: false,
            error: "Invalid API path"
        }), {
            status: 400,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });
    }
    const workerName = pathSegments[3];
    // 检测模块类型
    function detectModuleType(scriptContent) {
        if (!scriptContent) return 'classic';
        // 检查特殊注释
        const lines = scriptContent.split('\n');
        for (const line of lines.slice(0, 10)) {
            if (line.includes('// @module-type: esm')) return 'esm';
            if (line.includes('// @module-type: classic')) return 'classic';
        }
        // 清理脚本内容，移除注释和字符串内容，避免误判
        const cleanedScript = scriptContent.replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*|`(?:[^`\\]|\\.)*`|'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"/g, '');
        const ESM_PATTERNS = [/^\s*export\s+default\b/m,
            /*export default*/
            /^\s*export\s+{/m,
            /* export { ... }*/
            /^\s*import\s+[\s\S]+?\s+from\s+['"]/m,
            /*import ... from*/
            /^\s*import\s+['"]/m,
            /*import 'module'*/
            /^\s*import\s*\(/m,
            /* import()*/
        ];
        const CLASSIC_PATTERNS = [/^\s*(?:self\.)?addEventListener\s*\(\s*['"](fetch|scheduled)['"]/m];
        // 1. 提前短路：检查基本语法特征
        if (!cleanedScript.includes('export') && !cleanedScript.includes('import') && !cleanedScript.includes('addEventListener')) {
            // 没有关键特征，默认经典模式
            return 'classic';
        }
        // 2. 优化ESM检测：先检测高概率特征
        // export default 是最强的ESM指标，优先检查
        if (ESM_PATTERNS[0].test(cleanedScript)) {
            return 'esm';
        }
        // 3. 完整检测流程
        // 只检查需要检查的模式
        if (cleanedScript.includes('import')) {
            for (let i = 1; i < ESM_PATTERNS.length; i++) {
                if (ESM_PATTERNS[i].test(cleanedScript)) {
                    return 'esm';
                }
            }
        }
        // 4. 经典模式检测
        if (cleanedScript.includes('addEventListener')) {
            if (CLASSIC_PATTERNS[0].test(cleanedScript)) {
                return 'classic';
            }
        }
        // 5. 特殊情况处理
        // 如果有export但没有匹配到ESM模式，可能是ESM的变体
        if (cleanedScript.includes('export')) {
            return 'esm';
        }
        return 'classic';
    }
    // 根据请求方法处理
    try {
        if (request.method === 'GET') {
            // GET 请求 - 获取脚本内容
            const apiUrl = `https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/${workerName}`;
            const response = await fetch(apiUrl, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/javascript'
                }
            });
            if (response.ok) {
                try {
                    await enableLogsForWorker(accountId, token, workerName);
                } catch (logError) {
                    console.warn('启用日志失败:', logError.message);
                    // 注意：不抛出错误，因为Worker上传已经成功
                }
            }
            return new Response(await response.text(), {
                status: response.status,
                headers: {
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
                    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
                    'Access-Control-Max-Age': '86400',
                }
            });
        } else if (request.method === 'PUT') {
            // PUT 请求 - 只读取一次请求体
            const requestBody = await request.text();
            const moduleType = await detectModuleType(requestBody);
            console.log(`检测到模块类型: ${moduleType}, Worker: ${workerName}`);
            if (moduleType === 'esm') {
                // 使用 ES 模块处理，传递请求体
                return await handleESModeRequest(request, accountId, token, requestBody);
            } else {
                // 使用经典模式处理
                const apiUrl = `https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/${workerName}`;
                const response = await fetch(apiUrl, {
                    method: 'PUT',
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/javascript'
                    },
                    body: requestBody // 使用已读取的请求体
                });
                if (response.ok) {
                    await enableLogsForWorker(accountId, token, workerName);
                }
                // 尝试解析响应，处理空响应的情况
                let result;
                const responseText = await response.text();
                try {
                    result = responseText ? JSON.parse(responseText) : {};
                } catch (parseError) {
                    console.error('解析JSON响应失败:', parseError);
                    result = {
                        errors: [{
                            message: "API返回了无效的JSON响应"
                        }],
                        messages: []
                    };
                }
                // 构建完整的响应信息
                const errorMessage = result.errors && result.errors.length > 0 ? result.errors.map(err => err.message).join(', ') : `HTTP ${response.status} ${response.statusText}`;
                return new Response(JSON.stringify({
                    success: response.ok,
                    status: response.status,
                    error: !response.ok ? errorMessage : null,
                    errors: result.errors || null,
                    messages: result.messages || null,
                    moduleType: 'classic'
                }), {
                    status: response.status,
                    headers: {
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*'
                    }
                });
            }
        } else {
            // 不支持的请求方法
            return new Response(JSON.stringify({
                success: false,
                error: "Method not allowed"
            }), {
                status: 405,
                headers: {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                }
            });
        }
    } catch (error) {
        console.error('处理请求时发生错误:', error);
        return new Response(JSON.stringify({
            success: false,
            error: `服务器内部错误: ${error.message}`
        }), {
            status: 500,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });
    }
}
// ES模式处理
async function handleESModeRequest(request, accountId, token, body) {
    const url = new URL(request.url);
    const pathSegments = url.pathname.split('/');
    const workerName = pathSegments[3];
    try {
        // 构建FormData
        const formData = new FormData();
        const metadata = {
            main_module: "worker.js",
            keep_bindings: [
                "kv_namespace",
                "r2_bucket",
                "d1",
                "images",
                "hyperdrive",
                "ai",
                "service",
                "browser",
                "queue",
                "mtls_certificate",
                "analytics_engine",
                "vectorize",
                "durable_object_namespace",
                "plain_text",
                "secret_text",
                "ratelimit",
                "send_email"
            ],
            tags: ["managed-by-worker-editor"]
        };
        formData.append('metadata', new Blob([JSON.stringify(metadata)], {
            type: 'application/json'
        }));
        formData.append('worker.js', new Blob([body], {
            type: 'application/javascript+module'
        }));
        // 上传Worker
        const apiUrl = `https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/${workerName}`;
        let response;
        try {
            response = await fetch(apiUrl, {
                method: 'PUT',
                headers: {
                    'Authorization': `Bearer ${token}`
                },
                body: formData
            });
        } catch (fetchError) {
            throw new Error(`API请求失败: ${fetchError.message}`);
        }
        // 处理响应
        const responseText = await response.text();
        let result = {};
        if (responseText) {
            try {
                result = JSON.parse(responseText);
            } catch (parseError) {
                console.warn('API返回非JSON响应:', responseText.substring(0, 200));
            }
        }
        //启用日志
        if (response.ok) {
            try {
                await enableLogsForWorker(accountId, token, workerName);
            } catch (logError) {
                console.warn('启用日志失败:', logError.message);
                // 注意：不抛出错误，因为Worker上传已经成功
            }
        }
        // 构建响应
        const success = response.ok;
        const status = response.status;
        // 错误信息优先级：API返回的错误 > HTTP状态
        let errorMessage = null;
        if (!success) {
            if (result.errors && result.errors.length > 0) {
                errorMessage = result.errors.map(err => err.message || String(err)).join(', ');
            } else {
                errorMessage = `HTTP ${status} ${response.statusText || 'Unknown Error'}`;
            }
        }
        return new Response(JSON.stringify({
            success,
            status,
            error: errorMessage,
            errors: result.errors || null,
            messages: result.messages || null,
            moduleType: 'esm',
        }), {
            status: success ? 200 : status,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });
    } catch (error) {
        console.error('ES模块上传失败:', error);
        return new Response(JSON.stringify({
            success: false,
            error: `ES模块上传失败: ${error.message}`,
            moduleType: 'esm'
        }), {
            status: 500,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });
    }
}
// 获取Workers列表
async function listWorkers(accountId, apiToken) {
    // Workers列表API地址
    const response = await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts`, {
        headers: {
            'Authorization': `Bearer ${apiToken}`
        }
    })
    const data = await response.json()
    return data.result || []
}
// 处理Workers列表/api/workers
async function handleWorkersAPI(request, accountId, token) {
    try {
        const workers = await listWorkers(accountId, token);
        return new Response(JSON.stringify(workers), {
            headers: {
                'Content-Type': 'application/json'
            }
        });
    } catch (error) {
        return new Response(JSON.stringify({
            error: error.message
        }), {
            status: 500,
            headers: {
                'Content-Type': 'application/json'
            }
        });
    }
}
// 显示列表页面 /list
async function handleListPage(acc, logined) {
    const html = `
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
        <meta charset="UTF-8">
        <link rel="icon" href="/favicon.svg" type="image/svg+xml">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Worker 编辑器|worker 列表</title>
        <link rel="stylesheet" href="/static/style.css">
        <style>
        .workers-container {
        margin-top: 2rem;
        }
        .workers-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 1.5rem;
        flex-wrap: wrap;
        gap: 1rem;
        }
        .workers-header .search-area {
        display: flex;
        gap: 0.5rem;
        align-items: center;
        flex-wrap: wrap;
        }
        .workers-header .search-area input {
        padding: 0.5rem 0.75rem;
        border-radius: var(--radius);
        border: 1px solid var(--border-color);
        background: var(--bg-color);
        color: var(--text-color);
        font-size: 0.9rem;
        min-width: 200px;
        }
        .workers-header .search-area input:focus {
        outline: none;
        border-color: var(--primary-color);
        }
        .worker-item {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 1.25rem;
        margin-bottom: 0.75rem;
        border-radius: var(--radius);
        transition: var(--transition);
        background: var(--surface-color);
        border: 1px solid var(--border-color);
        flex-wrap: wrap;
        gap: 1rem;
        }
        .worker-info {
        flex: 1;
        min-width: 0;
        }
        .worker-info h3 {
        margin-bottom: 0.5rem;
        font-size: 1.1rem;
        font-weight: 600;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
        }
        .worker-date {
        font-size: 0.85rem;
        color: var(--text-secondary);
        display: block;
        line-height: 1.4;
        }
        .worker-actions {
        display: flex;
        gap: 0.75rem;
        flex-wrap: wrap;
        }
        .loading, .error {
        text-align: center;
        padding: 3rem 1rem;
        color: var(--text-secondary);
        }
        .empty-state {
        text-align: center;
        padding: 3rem 1rem;
        color: var(--text-secondary);
        }
        .text-truncate {
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
        }
        .d-flex.gap-2.flex-wrap {
        display: flex;
        overflow-x: auto;
        -webkit-overflow-scrolling: touch;
        padding-bottom: 8px;
        flex-wrap: nowrap;
        white-space: nowrap;
        }
        .d-flex.gap-2.flex-wrap::-webkit-scrollbar {
        height: 4px;
        }
        .d-flex.gap-2.flex-wrap::-webkit-scrollbar-track {
        background: var(--border-color);
        border-radius: 2px;
        }
        .d-flex.gap-2.flex-wrap::-webkit-scrollbar-thumb {
        background: var(--text-secondary);
        border-radius: 2px;
        }
        @media (max-width: 640px) {
        .worker-item {
        flex-direction: column;
        align-items: flex-start;
        }
        .worker-actions {
        width: 100%;
        justify-content: flex-start;
        }
        .worker-actions .btn {
        flex: 1;
        min-width: 60px;
        }
        .workers-header .search-area {
        width: 100%;
        }
        .workers-header .search-area input {
        flex: 1;
        }
        }
        </style>
        </head>
        <body>
        {{NAVBAR}}
        <main class="container">
        <!-- 快速导航 -->
        <div class="card mb-4">
        <h2 class="mb-2">快速导航</h2>
        <div class="d-flex gap-2 flex-wrap">
        <a href="/kv" class="btn btn-outline">KV管理</a>
        <a href="/wtc" class="btn btn-outline">wtc日志</a>
        <a href="/routes" class="btn btn-outline">域名管理</a>
        <a href="/curl" class="btn btn-outline">api请求代理</a>
        </div>
        </div>

        <!-- Workers 列表 -->
        <section class="workers-container">
        <div class="workers-header">
        <h2>Workers 列表</h2>
        <div class="search-area">
        <input type="text" id="searchInput" placeholder="按 Worker ID 搜索..." autocomplete="off">
        <button class="btn btn-sm btn-outline" id="clearSearchBtn">清除</button>
        <button class="btn btn-outline" onclick="refreshWorkers()">刷新</button>
        <a href="/create" class="btn">+ 新建</a>
        </div>
        </div>

        <div class="card">
        <div id="workers-list">
        <div class="loading">正在加载 Workers 列表...</div>
        </div>
        </div>
        </section>
        </main>

        <script>
        let isLoading = false;
        let allWorkers = [];      // 存储所有原始 worker 数据
        let currentSearchTerm = ''; // 当前搜索关键词

        // 根据搜索词过滤并渲染列表
        function filterAndRenderWorkers() {
            const workersList = document.getElementById('workers-list');
            if (!workersList) return;

            // 如果还没有加载过数据（allWorkers 为 null 或加载失败），不做任何渲染，保留现有内容
            if (!allWorkers || allWorkers.length === undefined) {
                return;
            }

            let filteredWorkers = allWorkers;
            if (currentSearchTerm.trim() !== '') {
                const term = currentSearchTerm.trim().toLowerCase();
                filteredWorkers = allWorkers.filter(w => w.id && w.id.toLowerCase().includes(term));
            }

            // 空状态处理
            if (filteredWorkers.length === 0) {
                if (allWorkers.length === 0) {
                    workersList.innerHTML = \`
                    <div class="empty-state">
                    <div style="font-size: 3rem; margin-bottom: 1rem; opacity: 0.5;">🚀</div>
                    <h3>暂无 Workers</h3>
                    <p>点击上方"新建"开始创建您的第一个 Worker</p>
                    <a href="/create" class="btn mt-2">创建 Worker</a>
                    </div>
                    \`;
                } else {
                    workersList.innerHTML = \`
                    <div class="empty-state">
                    <div style="font-size: 3rem; margin-bottom: 1rem; opacity: 0.5;">🔍</div>
                    <h3>未找到匹配的 Worker</h3>
                    <p>没有找到包含 "\${escapeHtml(currentSearchTerm)}" 的 Worker ID</p>
                    <button class="btn btn-outline mt-2" onclick="clearSearchAndReset()">清除搜索</button>
                    </div>
                    \`;
                }
                return;
            }

            // 生成 worker 列表 HTML
            const workerHTML = filteredWorkers.map(w => \`
            <div class="worker-item">
            <div class="worker-info">
            <h3 class="text-truncate" title="\${escapeHtml(w.id)}">\${escapeHtml(w.id)}</h3>
            <div>
            <span class="worker-date">
            创建: \${new Date(w.created_on).toLocaleString('zh-CN')}
            </span>
            <br>
            <span class="worker-date">
            修改: \${new Date(w.modified_on).toLocaleString('zh-CN')}
            </span>
            </div>
            </div>
            <div class="worker-actions">
            <button class="btn btn-sm" onclick="editWorker('\${escapeHtml(w.id)}')">编辑</button>
            <button class="btn btn-sm btn-outline" onclick="manageWorker('\${escapeHtml(w.id)}', 'graphql')">统计</button>
            <button class="btn btn-sm btn-outline" onclick="manageWorker('\${escapeHtml(w.id)}', 'binding')">绑定</button>
            <button class="btn btn-sm btn-outline" onclick="manageWorker('\${escapeHtml(w.id)}', 'version')">版本</button>
            <button class="btn btn-sm btn-outline" onclick="manageWorker('\${escapeHtml(w.id)}', 'setting')">设置</button>
            </div>
            </div>
            \`).join('');

            workersList.innerHTML = workerHTML;
        }

        // 简单的防 XSS 辅助函数
        function escapeHtml(str) {
            if (!str) return '';
            return str.replace(/[&<>]/g, function(m) {
                if (m === '&') return '&amp;';
                if (m === '<') return '&lt;';
                if (m === '>') return '&gt;';
                return m;
            }).replace(/[\uD800-\uDBFF][\uDC00-\uDFFF]/g, function(c) {
                return c;
            });
        }

        // 清除搜索并刷新显示
        function clearSearchAndReset() {
            const searchInput = document.getElementById('searchInput');
            if (searchInput) {
                searchInput.value = '';
            }
            currentSearchTerm = '';
            filterAndRenderWorkers();
        }

        async function loadWorkers() {
        if (isLoading) return;

        const workersList = document.getElementById('workers-list');
        isLoading = true;

        try {
        workersList.innerHTML = '<div class="loading">正在加载 Workers 列表...</div>';

        const response = await fetch('/api/workers', {
        method: 'GET',
        headers: {
        'Content-Type': 'application/json',
        }
        });

        if (!response.ok) {
        throw new Error('获取 Workers 列表失败，状态码: ' + response.status);
        }

        const workers = await response.json();
        // 保存原始数据
        allWorkers = Array.isArray(workers) ? workers : [];

        // 重置搜索框和搜索词
        const searchInput = document.getElementById('searchInput');
        if (searchInput) {
            searchInput.value = '';
        }
        currentSearchTerm = '';

        // 渲染列表
        filterAndRenderWorkers();

        } catch (error) {
        console.error('加载 Workers 失败:', error);
        allWorkers = null; // 标记加载失败，禁用搜索
        workersList.innerHTML = \`
        <div class="error">
        <div>加载失败: \${error.message}</div>
        <button class="btn mt-2" onclick="loadWorkers()">重试</button>
        </div>
        \`;
        } finally {
        isLoading = false;
        }
        }

        // 检查并显示消息提示
        function checkAndShowMessage() {
        const urlParams = new URLSearchParams(window.location.search);
        const message = urlParams.get('message');

        // 移除URL中的message参数，避免刷新后重复显示
        function removeMessageParam() {
        const url = new URL(window.location);
        url.searchParams.delete('message');
        window.history.replaceState({}, '', url);
        }

        if (message) {
        // 创建消息提示框
        const messageDiv = document.createElement('div');
        messageDiv.className = 'message-notification';
        messageDiv.style.cssText = \`
        position: fixed;
        top: 20px;
        right: 20px;
        background: var(--surface-color);
        color: var(--primary-color);
        padding: 1rem 1.5rem;
        border-radius: var(--radius);
        box-shadow: var(--shadow);
        z-index: 1000;
        animation: slideIn 0.3s ease;
        max-width: 400px;
        \`;

        // 添加动画样式
        const style = document.createElement('style');
        style.textContent = \`
        @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
        }
        @keyframes fadeOut {
        from { opacity: 1; }
        to { opacity: 0; }
        }
        \`;
        document.head.appendChild(style);

        // 创建关闭按钮的事件处理函数
        const closeMessage = () => {
        messageDiv.style.animation = 'fadeOut 0.3s ease';
        setTimeout(() => {
        if (messageDiv.parentElement) {
        messageDiv.remove();
        }
        removeMessageParam();
        }, 300);
        };

        messageDiv.innerHTML = \`
        <div style="display: flex; align-items: center; justify-content: space-between; gap: 1rem;">
        <span>\${decodeURIComponent(message)}</span>
        <button id="close-message-btn">确定</button>
        </div>
        \`;

        document.body.appendChild(messageDiv);

        // 绑定按钮点击事件
        const closeBtn = document.getElementById('close-message-btn');
        if (closeBtn) {
        closeBtn.addEventListener('click', closeMessage);
        }

        // 自动移除（5秒后）
        setTimeout(() => {
        if (messageDiv.parentElement) {
        closeMessage();
        }
        }, 5000);
        }
        }

        function refreshWorkers() {
        // 刷新时重置搜索框和搜索词
        const searchInput = document.getElementById('searchInput');
        if (searchInput) {
            searchInput.value = '';
        }
        currentSearchTerm = '';
        loadWorkers();
        }

        function editWorker(workerId) {
        window.location.href = '/edit?worker=' + encodeURIComponent(workerId);
        }

        function manageWorker(workerId, action) {
        const routes = {
        'binding': '/binding',
        'version': '/deployment',
        'setting': '/setting',
        'graphql': '/graphql'
        };
        const path = routes[action] || '/edit';
        window.location.href = path + '?worker=' + encodeURIComponent(workerId);
        }

        document.addEventListener('DOMContentLoaded', function() {
        loadWorkers();
        checkAndShowMessage();

        // 绑定搜索框实时输入事件
        const searchInput = document.getElementById('searchInput');
        if (searchInput) {
            searchInput.addEventListener('input', function(e) {
                currentSearchTerm = e.target.value;
                filterAndRenderWorkers();
            });
        }

        // 绑定清除按钮事件
        const clearBtn = document.getElementById('clearSearchBtn');
        if (clearBtn) {
            clearBtn.addEventListener('click', function() {
                clearSearchAndReset();
            });
        }
        });
        </script>
        </body>
        </html>
        `;
    /*
if (logined) {
    return buildHtmlResponse(html, acc, {
        littleNav: false,
        errorHandler: errHtml,
        homeUrl: '/'
    });
} else {
    return buildHtmlResponse(html, '', {
        littleNav: true,
        errorOverlay: {
            code: 401,
            message: '请先登录',
            redirectUrl: '/login',
            homeOnly: true
        },
        errorHandler: errHtml,
        homeUrl: '/'
    });
}
*/
    return buildHtmlResponse(html, acc, {
        littleNav: false,
        errorHandler: errHtml,
        homeUrl: '/'
    });
}
// 显示编辑页面 /edit
async function handleEditPage(request, acc, logined) {
    const url = new URL(request.url);
    const workerId = url.searchParams.get('worker');
    if (!workerId) {
        return Response.redirect(new URL('/list', request.url).toString(), 302);
    }
    const html = `
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
        <meta charset="UTF-8">
        <link rel="icon" href="/favicon.svg" type="image/svg+xml">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Worker 编辑器|编辑 Worker</title>
        <link rel="stylesheet" href="/static/style.css">
        <!-- 引入 JSHint 用于 JavaScript 代码检查 -->
        <script src="https://cdnjs.cloudflare.com/ajax/libs/jshint/2.13.6/jshint.min.js"></script>
        <style>
        .editor-container {
        display: flex;
        flex-direction: column;
        gap: 1rem;
        margin-top: 1.5rem;
        }
        #scriptContent {
        min-height: 500px;
        resize: vertical;
        font-family: monospace;
        }
        padding: 0.75rem;
        }
        .button-group {display: flex;gap: 0.75rem;flex-wrap: wrap;margin-top: 1rem;}
        .worker-info {background-color: var(--surface-color);padding: 1rem;border-radius: var(--radius);margin-bottom: 1rem;border: 1px solid var(--border-color);}
        #errorOutput {margin-top: 0.5rem;display: none;}
        .error-item {margin: 0.5rem 0;padding: 0.5rem;border-left: 3px solid var(--danger-color);background-color: var(--surface-color);}
        .error-header {display: flex;justify-content: space-between;align-items: center;margin-bottom: 0.75rem;padding-bottom: 0.5rem;border-bottom: 1px solid var(--border-color);}
        .btn-loading {
        position: relative;
        color: transparent !important;
        }
        .btn-loading::after {
        content: "";
        position: absolute;
        width: 16px;
        height: 16px;
        top: 50%;
        left: 50%;
        margin-left: -8px;
        margin-top: -8px;
        border: 2px solid transparent;
        border-top-color: currentColor;
        border-radius: 50%;
        animation: button-spinner 0.8s linear infinite;
        }
        @keyframes button-spinner {
        from { transform: rotate(0turn); }
        to { transform: rotate(1turn); }
        }

        /* Toast 通知样式 */
        .toast-container {
        position: fixed;
        top: 20px;
        right: 20px;
        z-index: 9999;
        display: flex;
        flex-direction: column;
        gap: 10px;
        max-width: 350px;
        }
        .toast {
        padding: 12px 16px;
        border-radius: var(--radius);
        background: var(--surface-color);
        border: 1px solid var(--border-color);
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        display: flex;
        align-items: center;
        gap: 12px;
        animation: toast-slide-in 0.3s ease;
        transform-origin: top right;
        }
        @keyframes toast-slide-in {
        from {
        opacity: 0;
        transform: translateX(100%);
        }
        to {
        opacity: 1;
        transform: translateX(0);
        }
        }
        .toast.success {
        border-left: 4px solid var(--success-color);
        }
        .toast.warning {
        border-left: 4px solid var(--warning-color);
        }
        .toast.error {
        border-left: 4px solid var(--danger-color);
        }
        .toast.info {
        border-left: 4px solid var(--primary-color);
        }
        .toast-icon {
        font-size: 18px;
        }
        .toast-content {
        flex: 1;
        font-size: 14px;
        }
        .toast-close {
        background: none;
        border: none;
        color: var(--text-secondary);
        cursor: pointer;
        padding: 4px;
        border-radius: 4px;
        font-size: 16px;
        }
        .toast-close:hover {
        background: var(--hover-color);
        color: var(--text-color);
        }

        /* 键盘快捷键提示 */
        .keyboard-shortcut {
        font-size: 0.85em;
        color: var(--text-secondary);
        margin-left: 8px;
        background: var(--surface-secondary);
        padding: 2px 6px;
        border-radius: 4px;
        border: 1px solid var(--border-color);
        }
        </style>
        </head>
        <body>
        {{NAVBAR}}
        <main>
        <!-- Toast 通知容器 -->
        <div class="toast-container" id="toastContainer"></div>
        <div class="card worker-info">
        <h2>Worker: ${workerId.replace(/[<>&]/g, c => ({
        '<': '&lt;', '>': '&gt;', '&': '&amp;'
    })[c])}</h2>
        </div>

        <div class="card">
        <textarea id="scriptContent" class="form-group" placeholder="点击加载按钮获取脚本内容"></textarea>

        <div id="errorOutput">
        <div class="error-header">
        <strong>代码检查发现以下问题：</strong>
        <button class="btn btn-secondary" onclick="document.getElementById('errorOutput').style.display='none'">关闭</button>
        </div>
        <div id="errorList"></div>
        </div>

        <div class="button-group">
        <button class="btn" id="loadBtn" onclick="loadScript('${workerId.replace(/'/g, "\\'")}')">
        加载脚本 <span class="keyboard-shortcut">Ctrl+L</span>
        </button>
        <button class="btn btn-secondary" id="checkBtn" onclick="checkScript()">
        检查代码 <span class="keyboard-shortcut">Ctrl+K</span>
        </button>
        <button class="btn" id="saveBtn" onclick="saveScript('${workerId.replace(/'/g, "\\'")}')">
        保存修改 <span class="keyboard-shortcut">Ctrl+S</span>
        </button>
        </div>
        <div class="button-group">
        <button class="btn btn-outline" onclick="copyScript()">
        复制 <span class="keyboard-shortcut">Ctrl+C</span>
        </button>
        <button class="btn btn-outline" onclick="pasteScript()">
        粘贴 <span class="keyboard-shortcut">Ctrl+V</span>
        </button>
        <button class="btn btn-outline" onclick="clearScript()">
        清空 <span class="keyboard-shortcut">Ctrl+D</span>
        </button>
        <button class="btn btn-outline" onclick="downloadScript()">
        下载脚本 <span class="keyboard-shortcut">Ctrl+E</span>
        </button>
        </div>
        </div>
        </main>
        <script>
        // Toast 通知系统
        function showToast(message, type = 'info', duration = 4000) {
        const container = document.getElementById('toastContainer');
        const toast = document.createElement('div');
        toast.className = \`toast \${type}\`;

        // 设置图标
        const icons = {
        success: '✅',
        error: '❌',
        warning: '⚠️',
        info: 'ℹ'
        };

        toast.innerHTML = \`
        <span class="toast-icon">\${icons[type] || icons.info}</span>
        <span class="toast-content">\${message}</span>
        <button class="toast-close" onclick="this.parentElement.remove()">×</button>
        \`;

        container.appendChild(toast);

        // 自动移除
        if (duration > 0) {
        setTimeout(() => {
        if (toast.parentElement) {
        toast.style.animation = 'toast-slide-out 0.3s ease forwards';
        setTimeout(() => toast.remove(), 300);
        }
        }, duration);
        }

        return toast;
        }

        // 键盘快捷键支持
        function initKeyboardShortcuts() {
        const textarea = document.getElementById('scriptContent');

        document.addEventListener('keydown', (e) => {
        // 确保不是在输入框中按快捷键
        if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') {
        return;
        }

        // Ctrl/Cmd + S 保存
        if ((e.ctrlKey || e.metaKey) && e.key === 's') {
        e.preventDefault();
        document.getElementById('saveBtn').click();
        }

        // Ctrl/Cmd + L 加载
        if ((e.ctrlKey || e.metaKey) && e.key === 'l') {
        e.preventDefault();
        document.getElementById('loadBtn').click();
        }

        // Ctrl/Cmd + K 检查
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        document.getElementById('checkBtn').click();
        }

        // Ctrl/Cmd + C 复制（聚焦到编辑器时）
        if ((e.ctrlKey || e.metaKey) && e.key === 'c' && document.activeElement === textarea) {
        setTimeout(() => {
        showToast('代码已复制到剪贴板', 'success', 2000);
        }, 100);
        }
        // Ctrl/Cmd + D 清空
        if ((e.ctrlKey || e.metaKey) && e.key === 'd') {
        e.preventDefault();
        clearScript();
        }
        if ((e.ctrlKey || e.metaKey) && e.key === 'e') {
        e.preventDefault();
        downloadScript();
        }
        });

        // 编辑器内的快捷键提示
        textarea.addEventListener('keydown', (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === 's') {
        e.preventDefault();
        saveScript('${workerId.replace(/'/g, "\\'")}');
        }
        });
        }

        // JSHint 配置选项
        const jshintOptions = {
        esversion: 2020,
        browser: false,
        worker: true,
        node: false,
        moz: true,
        undef: false,
        asi: true,
        eqnull: true,
        sub: true,
        laxbreak: true,
        laxcomma: true,
        expr: true,
        '-W014': false,
        '-W086': false,
        '-W083': false,
        '-W032': false,
        globals: {
        addEventListener: false,
        fetch: false,
        Request: false,
        Response: false,
        URL: false,
        URLSearchParams: false,
        Headers: false,
        FormData: false,
        ReadableStream: false,
        WritableStream: false,
        TransformStream: false,
        TextEncoder: false,
        TextDecoder: false,
        setTimeout: false,
        clearTimeout: false,
        setInterval: false,
        clearInterval: false,
        crypto: false,
        Crypto: false,
        SubtleCrypto: false,
        cryptoKey: false,
        atob: false,
        btoa: false,
        console: false,
        WebSocket: false,
        Event: false,
        CustomEvent: false,
        FetchEvent: false,
        ScheduledEvent: false,
        ErrorEvent: false,
        Promise: false,
        Map: false,
        Set: false,
        WeakMap: false,
        WeakSet: false,
        Symbol: false,
        Proxy: false,
        Reflect: false,
        Intl: false,
        ArrayBuffer: false,
        SharedArrayBuffer: false,
        DataView: false,
        Float32Array: false,
        Float64Array: false,
        Int8Array: false,
        Int16Array: false,
        Int32Array: false,
        Uint8Array: false,
        Uint8ClampedArray: false,
        Uint16Array: false,
        Uint32Array: false,
        self: false,
        caches: false,
        CacheStorage: false,
        Cache: false,
        CacheQueryOptions: false,
        Error: false,
        TypeError: false,
        RangeError: false,
        SyntaxError: false,
        ReferenceError: false,
        URIError: false,
        EvalError: false,
        AggregateError: false,
        AbortController: false,
        AbortSignal: false,
        Blob: false,
        File: false,
        FileReader: false,
        FileReaderSync: false,
        FormDataEntryIterator: false,
        FormDataIterator: false,
        URLPattern: false,
        JSON: false,
        Math: false,
        Date: false,
        RegExp: false,
        Object: false,
        Function: false,
        Boolean: false,
        Number: false,
        String: false,
        Array: false,
        encodeURIComponent: false,
        decodeURIComponent: false,
        encodeURI: false,
        decodeURI: false,
        isNaN: false,
        isFinite: false,
        parseFloat: false,
        parseInt: false,
        Iterator: false,
        AsyncIterator: false,
        Generator: false,
        AsyncGenerator: false,
        eval: false,
        undefined: false,
        Infinity: false,
        NaN: false,
        WebAssembly: false
        }
        };

        async function loadScript(workerId) {
        const loadBtn = document.getElementById('loadBtn');
        const textarea = document.getElementById('scriptContent');

        // 保存原始状态
        const originalText = loadBtn.innerHTML;

        // 设置加载状态
        loadBtn.classList.add('btn-loading');
        loadBtn.disabled = true;

        try {
        const res = await fetch("/api/script/" + encodeURIComponent(workerId));
        if (!res.ok) throw new Error(\`HTTP错误！状态码: \${res.status}\`);

        const script = await res.text();
        textarea.value = script;

        // 显示成功提示
        showToast('脚本加载成功', 'success', 3000);

        // 统计行数和字数
        const lines = script.split('\\n').length;
        const chars = script.length;
        showToast(\`已加载 \${lines} 行，\${chars} 个字符\`, 'info', 2000);

        } catch (err) {
        console.error('加载失败:', err);
        showToast(\`加载失败: \${err.message}\`, 'error', 5000);
        } finally {
        // 恢复按钮状态
        loadBtn.classList.remove('btn-loading');
        loadBtn.disabled = false;
        loadBtn.innerHTML = originalText;
        }
        }

        function checkScript() {
        const script = document.getElementById('scriptContent').value;
        const errorOutput = document.getElementById('errorOutput');
        const errorList = document.getElementById('errorList');
        const checkBtn = document.getElementById('checkBtn');

        errorList.innerHTML = '';
        errorOutput.style.display = 'none';

        if (!script.trim()) {
        showToast('请输入要检查的代码', 'warning', 3000);
        return;
        }

        // 短暂显示检查中状态
        const originalText = checkBtn.innerHTML;
        checkBtn.classList.add('btn-loading');
        checkBtn.disabled = true;

        // 使用 setTimeout 避免阻塞 UI
        setTimeout(() => {
        JSHINT(script, jshintOptions);

        const errors = JSHINT.errors;

        // 恢复按钮状态
        checkBtn.classList.remove('btn-loading');
        checkBtn.disabled = false;
        checkBtn.innerHTML = originalText;

        if (!errors || errors.length === 0) {
        showToast('✓ 代码检查通过，未发现错误', 'success', 3000);
        return;
        }

        const validErrors = errors.filter(error => error);
        const errorCount = validErrors.length;

        // 显示错误统计
        showToast(\`发现 \${errorCount} 个代码问题\`, 'warning', 3000);

        validErrors.forEach(error => {
        if (!error) return;
        const errorItem = document.createElement('div');
        errorItem.className = 'error-item';
        errorItem.innerHTML = \`<strong>第\${error.line}行 第\${error.character}列:</strong> \${error.reason} (\${error.code})\`;
        errorList.appendChild(errorItem);
        });

        errorOutput.style.display = 'block';

        // 自动滚动到错误区域
        errorOutput.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }, 100);
        }

        async function saveScript(workerId) {
        const script = document.getElementById('scriptContent').value;
        const saveBtn = document.getElementById('saveBtn');

        if (!script.trim()) {
        showToast('脚本内容不能为空', 'warning', 3000);
        return;
        }

        // 保存原始状态
        const originalText = saveBtn.innerHTML;

        // 设置保存状态
        saveBtn.classList.add('btn-loading');
        saveBtn.disabled = true;

        // 先检查代码
        JSHINT(script, jshintOptions);
        const errors = JSHINT.errors;

        if (errors && errors.length > 0) {
        const validErrors = errors.filter(e => e);
        const errorCount = validErrors.length;

        if (errorCount > 0) {
        // 使用确认对话框（可以自定义更美观的）
        const confirmSave = confirm(\`发现 \${errorCount} 个代码问题，是否继续保存？\\n\\n点击"取消"查看详细错误。\`);

        if (!confirmSave) {
        // 恢复按钮状态
        saveBtn.classList.remove('btn-loading');
        saveBtn.disabled = false;
        saveBtn.innerHTML = originalText;

        // 显示错误详情
        checkScript();
        return;
        }
        }
        }

        try {
        const res = await fetch("/api/script/" + encodeURIComponent(workerId), {
        method: "PUT",
        body: script,
        headers: {
        'Content-Type': 'text/plain'
        }
        });

        const result = await res.json();

        if (result.success) {
        showToast('脚本保存成功', 'success', 3000);

        // 显示保存信息
        const lines = script.split('\\n').length;
        const chars = script.length;
        showToast(\`已保存 \${lines} 行，\${chars} 个字符\`, 'info', 2000);
        } else {
        showToast(\`保存失败: \${result.error || '未知错误'}\`, 'error', 5000);
        }
        } catch (err) {
        console.error('保存失败:', err);
        showToast(\`保存失败: \${err.message}\`, 'error', 5000);
        } finally {
        // 恢复按钮状态
        saveBtn.classList.remove('btn-loading');
        saveBtn.disabled = false;
        saveBtn.innerHTML = originalText;
        }
        }

        function copyScript() {
        const textarea = document.getElementById('scriptContent');

        if (!textarea.value.trim()) {
        showToast('没有内容可复制', 'warning', 2000);
        return;
        }

        textarea.select();

        try {
        const successful = document.execCommand('copy');
        if (successful) {
        showToast('代码已复制到剪贴板', 'success', 2000);
        } else {
        showToast('复制失败，请手动选择并复制', 'error', 3000);
        }
        } catch (err) {
        // 使用新的 Clipboard API
        navigator.clipboard.writeText(textarea.value)
        .then(() => showToast('代码已复制到剪贴板', 'success', 2000))
        .catch(() => showToast('复制失败，请手动选择并复制', 'error', 3000));
        }
        }

        async function pasteScript() {
        const textarea = document.getElementById('scriptContent');

        try {
        const text = await navigator.clipboard.readText();
        if (!text.trim()) {
        showToast('剪贴板中没有文本内容', 'warning', 2000);
        return;
        }

        // 获取当前光标位置
        const start = textarea.selectionStart;
        const end = textarea.selectionEnd;

        // 插入文本
        textarea.value = textarea.value.substring(0, start) + text + textarea.value.substring(end);

        // 移动光标到插入位置之后
        textarea.selectionStart = textarea.selectionEnd = start + text.length;

        // 聚焦并滚动到插入位置
        textarea.focus();

        showToast('已粘贴剪贴板内容', 'success', 2000);

        // 显示粘贴内容的信息
        const lines = text.split('\\n').length;
        if (lines > 1) {
        showToast(\`粘贴了 \${lines} 行内容\`, 'info', 1500);
        }
        } catch (err) {
        console.error('粘贴失败:', err);
        showToast('无法访问剪贴板，请检查浏览器权限', 'error', 3000);
        }
        }
        function clearScript() {
        const textarea = document.getElementById('scriptContent');

        if (!textarea.value.trim()) {
        showToast('编辑器已经是空的', 'warning', 2000);
        return;
        }

        // 使用确认对话框
        const confirmClear = confirm('确定要清空编辑器内容吗？');

        if (confirmClear) {
        textarea.value = '';
        textarea.focus();
        showToast('编辑器已清空', 'success', 2000);
        }
        }
        function downloadScript() {
        const scriptContent = document.getElementById('scriptContent').value;
        if (!scriptContent.trim()) {
        showToast('没有内容可下载', 'warning', 2000);
        return;
        }

        // 获取当前 worker ID 作为文件名（并清理非法字符）
        const workerId = '${workerId.replace(/'/g, "\\'")}';
        const fileName = \`\${workerId}.js\`;

        // 创建 Blob 并触发下载
        const blob = new Blob([scriptContent], { type: 'application/javascript' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = fileName;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        showToast(\`脚本已保存为 \${fileName}\`, 'success', 3000);
        }
        </script>
        </body>
        </html>
        `;
    /*if (logined) {
        return buildHtmlResponse(html, acc, {
            littleNav: false,
            errorHandler: errHtml,
            homeUrl: '/list'
        });
    } else {
        return buildHtmlResponse(html, '', {
            littleNav: true,
            errorOverlay: {
                code: 401,
                message: '请先登录',
                redirectUrl: '/login',
                homeOnly: true
            },
            errorHandler: errHtml,
            homeUrl: '/'
        });
    }*/
    return buildHtmlResponse(html, acc, {
        littleNav: false,
        errorHandler: errHtml,
        homeUrl: '/list'
    });
}
//=================kv=======================
// 处理kv和命名空间 /api/kv | /api/namespaces
async function handleKvNamespace(request, accountId, apiToken, url, method) {
    const { pathname, searchParams } = url;
    // 定义路由表（顺序重要，优先匹配更具体的规则）
    const routes = [
        // 命名空间列表
        {
            method: 'GET', pattern: new URLPattern({ pathname: '/api/namespaces' }), handler: async (req) => {
                try {
                    const page = parseInt(url.searchParams.get('page') || '1', 10);
                    const per_page = parseInt(url.searchParams.get('per_page') || '20', 10);
                    const result = await listNamespaces(accountId, apiToken, page, per_page);
                    return jsonResponse(result, { status: 200 });  // result 已包含 result_info 分页信息
                } catch (err) {
                    return errorResponse(err);
                }
            }
        },
        // 创建命名空间
        {
            method: 'POST', pattern: new URLPattern({ pathname: '/api/namespaces' }), handler: async (req) => {
                try {
                    const { title } = await req.json();
                    if (!title) return new Response('Missing "title"', { status: 400 });
                    return await createNamespace(accountId, apiToken, title);
                } catch (err) {
                    return errorResponse(err);
                }
            }
        },
        // 删除命名空间
        {
            method: 'DELETE', pattern: new URLPattern({ pathname: '/namespaces/:namespaceId' }), handler: async (match) => {
                try {
                    const { namespaceId } = match.pathname.groups;
                    return await deleteNamespace(accountId, apiToken, namespaceId);
                } catch (err) {
                    return errorResponse(err);
                }
            }
        },

        // 列出 KV 键（支持分页和前缀过滤）
        {
            method: 'GET', pattern: new URLPattern({ pathname: '/api/kv/:namespaceId/keys' }), handler: async (match) => {
                try {
                    const { namespaceId } = match.pathname.groups;
                    const limit = searchParams.get('limit');
                    const cursor = searchParams.get('cursor');
                    const prefix = searchParams.get('prefix');
                    return await listKeys(accountId, apiToken, namespaceId, limit, cursor, prefix);
                } catch (err) {
                    return errorResponse(err);
                }
            }
        },

        // 获取键的元数据
        {
            method: 'GET', pattern: new URLPattern({ pathname: '/api/kv/:namespaceId/metadata/:key' }), handler: async (match) => {
                try {
                    const { namespaceId, key } = match.pathname.groups;
                    return await readMetadata(accountId, apiToken, namespaceId, decodeURIComponent(key));
                } catch (err) {
                    return errorResponse(err);
                }
            }
        },

        // 批量写入
        {
            method: 'POST', pattern: new URLPattern({ pathname: '/api/kv/:namespaceId/bulk' }), handler: (match, req) => {
                try {
                    const { namespaceId } = match.pathname.groups;
                    return handleBulkWrite(accountId, apiToken, namespaceId, req);
                } catch (err) {
                    return errorResponse(err);
                }
            }
        },

        // 流式下载二进制值
        {
            method: 'GET', pattern: new URLPattern({ pathname: '/api/kv/:namespaceId/values/:key/stream' }), handler: async (match) => {
                try {
                    const { namespaceId, key } = match.pathname.groups;
                    return await handleReadKeyStream(accountId, apiToken, namespaceId, decodeURIComponent(key));
                } catch (err) {
                    return errorResponse(err);
                }
            }
        },

        // 读取键值（返回实际内容）
        {
            method: 'GET', pattern: new URLPattern({ pathname: '/api/kv/:namespaceId/values/:key' }), handler: async (match) => {
                try {
                    const { namespaceId, key } = match.pathname.groups;
                    return await handleReadKey(accountId, apiToken, namespaceId, decodeURIComponent(key));
                } catch (err) {
                    return errorResponse(err);
                }
            }
        },

        // 写入键值
        {
            method: 'PUT', pattern: new URLPattern({ pathname: '/api/kv/:namespaceId/values/:key' }), handler: async (match, req) => {
                try {
                    const { namespaceId, key } = match.pathname.groups;
                    return await handleWriteKey(accountId, apiToken, namespaceId, decodeURIComponent(key), req);
                } catch (err) {
                    return errorResponse(err);
                }
            }
        },

        // 删除键
        {
            method: 'DELETE', pattern: new URLPattern({ pathname: '/api/kv/:namespaceId/values/:key' }), handler: async (match) => {
                try {
                    const { namespaceId, key } = match.pathname.groups;
                    return await deleteKey(accountId, apiToken, namespaceId, decodeURIComponent(key));
                } catch (err) {
                    return errorResponse(err);
                }
            }
        },
    ];
    /**
 * 返回错误响应
 */
    function errorResponse(err) {
        const status = err.status || 500;
        const message = status === 404 ? 'Not Found' : err.message;
        return new Response(JSON.stringify({ error: message }), {
            status,
            headers: { 'Content-Type': 'application/json' }
        });
    }
    /**
     * api
     * 请求
     */
    async function apiRequest(path, method, body, token, extraHeaders = {}) {
        const url = `https://api.cloudflare.com/client/v4/${path}`;
        const headers = {
            'Authorization': `Bearer ${token}`,
            ...extraHeaders,
        };
        // 只有传递 body 时才设置 Content-Type
        if (body !== undefined) {
            headers['Content-Type'] = 'application/json';
        }
        const options = { method, headers };
        if (body !== undefined) {
            options.body = JSON.stringify(body);
        }
        const res = await fetch(url, options);
        const data = await res.json();
        if (!res.ok) {
            const err = new Error(`Cloudflare API error (${res.status}): ${JSON.stringify(data)}`);
            throw err;
        }
        return data;
    }
    /**
     * 创建命名空间
     * @param {string} accountId
     * @param {string} token
     * @param {string} title 命名空间名称
     * @returns {Promise<object>} Cloudflare API 返回的结果
     */
    async function createNamespace(accountId, token, title) {
        return apiRequest(
            `accounts/${accountId}/storage/kv/namespaces`,
            'POST',
            { title },
            token
        );
    }
    /**
     * 列出所有命名空间
     * @param {string} accountId
     * @param {string} token
     * @param {number} [page=1] 页码，从 1 开始
     * @param {number} [per_page=50] 每页数量（最大 100）
     * @returns {Promise<object>}
     */
    async function listNamespaces(accountId, token, page = 1, per_page = 20) {
        const params = new URLSearchParams();
        params.set('page', `${page}`);
        // @ts-ignore
        params.set('per_page', Math.min(per_page, 100));
        const path = `accounts/${accountId}/storage/kv/namespaces?${params.toString()}`;
        return apiRequest(path, 'GET', undefined, token);
    }
    /**
     * 删除指定命名空间
     * @param {string} accountId
     * @param {string} token
     * @param {string} namespaceId
     * @returns {Promise<object>}
     */
    async function deleteNamespace(accountId, token, namespaceId) {
        return apiRequest(
            `accounts/${accountId}/storage/kv/namespaces/${namespaceId}`,
            'DELETE',
            undefined,
            token
        );
    }
    /**
     * 列出命名空间下的键
     * @param {string} accountId
     * @param {string} token
     * @param {string} namespaceId
     * @param {number|string} [limit]  返回数量上限
     * @param {string} [cursor]        分页游标
     * @param {string} [prefix]        键名前缀
     * @returns {Promise<object>}
     */
    async function listKeys(accountId, token, namespaceId, limit, cursor, prefix) {
        let path = `accounts/${accountId}/storage/kv/namespaces/${namespaceId}/keys`;
        const params = new URLSearchParams();
        if (limit) params.set('limit', `${limit}`);
        if (cursor) params.set('cursor', cursor);
        if (prefix) params.set('prefix', prefix);
        params.set('include_metadata', 'true');
        params.set('include_expiration', 'true');
        path += '?' + params.toString();
        return apiRequest(path, 'GET', undefined, token);
    }
    /**
     * 读取某个键的值（纯文本）
     * @param {string} accountId
     * @param {string} token
     * @param {string} namespaceId
     * @param {string} key
     * @returns {Promise<string>} 键对应的值
     */
    async function readKey(accountId, token, namespaceId, key) {
        const path = `accounts/${accountId}/storage/kv/namespaces/${namespaceId}/values/${encodeURIComponent(key)}`;
        const url = `https://api.cloudflare.com/client/v4/${path}`;
        const res = await fetch(url, {
            headers: { 'Authorization': `Bearer ${token}` },
        });
        if (!res.ok) {
            const errData = await res.json().catch(() => null);
            throw new Error(`Read key failed (${res.status}): ${JSON.stringify(errData)}`);
        }
        return res.text();
    }
    /**
     * 读取键的元数据
     * @param {string} accountId
     * @param {string} token
     * @param {string} namespaceId
     * @param {string} key
     * @returns {Promise<object>} 包含 metadata 的对象
     */
    async function readMetadata(accountId, token, namespaceId, key) {
        return apiRequest(
            `accounts/${accountId}/storage/kv/namespaces/${namespaceId}/metadata/${encodeURIComponent(key)}`,
            'GET',
            undefined,
            token
        );
    }
    /**
     * 删除某个键
     * @param {string} accountId
     * @param {string} token
     * @param {string} namespaceId
     * @param {string} key
     * @returns {Promise<object>}
     */
    async function deleteKey(accountId, token, namespaceId, key) {
        return apiRequest(
            `accounts/${accountId}/storage/kv/namespaces/${namespaceId}/values/${encodeURIComponent(key)}`,
            'DELETE',
            undefined,
            token
        );
    }
    /**
        * 处理获取键请求
        * @param {string} accountId
        * @param {string} apiToken
        * @param {string} namespaceId
        * @param {string} key
        * @returns Promise<Response>
        */
    async function handleReadKey(accountId, apiToken, namespaceId, key) {
        const { data, metadata } = await readKeyBinary(accountId, apiToken, namespaceId, key);
        try {
            // 尝试以 UTF-8 严格模式解码，若成功则作为文本返回
            const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(data);
            return new Response(text, {
                headers: { 'Content-Type': 'text/plain; charset=utf-8' }
            });
        } catch (e) {
            // 解码失败 → 二进制内容，返回 415 状态码
            return new Response(JSON.stringify({
                error: 'Binary content',
                message: 'This key contains binary data. Use the /stream endpoint to download.'
            }), {
                status: 415,
                headers: { 'Content-Type': 'application/json' }
            });
        }
    }
    /**
     * 将 ArrayBuffer 转换为 Base64 字符串
     */
    function arrayBufferToBase64(buffer) {
        let binary = '';
        const bytes = new Uint8Array(buffer);
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }
    /**
     * 写入单个键值（统一使用批量接口 + Base64 编码）
     * @param {string} accountId
     * @param {string} token
     * @param {string} namespaceId
     * @param {string} key
     * @param {string|Blob} value 要存储的内容（字符串或 Blob）
     * @param {object} [metadata] 元数据对象（可选）
     * @param {number} [expiration] 绝对过期时间（Unix 秒）
     * @param {number} [expirationTtl] 相对过期时间（秒）
     */
    async function writeKeyBase64(accountId, token, namespaceId, key, value, metadata, expiration, expirationTtl) {
        // 构造批量数组（只有一个元素）
        const kvPair = {
            key: key,
        };

        // 处理 value：字符串 或 Blob -> Base64
        if (typeof value === 'string') {
            kvPair.value = value;
            // 字符串不需要 base64 标记
        } else if (value instanceof Blob) {
            // 异步读取 Blob 为 ArrayBuffer，再转为 Base64
            const arrayBuffer = await value.arrayBuffer();
            kvPair.value = arrayBufferToBase64(arrayBuffer);
            kvPair.base64 = true;      // 告诉 Cloudflare 这是 Base64 编码的数据
        } else {
            throw new Error('Unsupported value type, only string or Blob');
        }

        // 附加过期时间与元数据
        if (expiration !== undefined) kvPair.expiration = expiration;
        if (expirationTtl !== undefined) kvPair.expiration_ttl = expirationTtl;
        if (metadata !== undefined) kvPair.metadata = metadata;

        // 调用真正的批量接口
        return bulkWriteKeys(accountId, token, namespaceId, [kvPair]);
    }
    /**
     * 写入键值（支持字符串或 Blob）
     * @param {string} accountId
     * @param {string} token
     * @param {string} namespaceId
     * @param {string} key
     * @param {string|Blob} value 要存储的内容
     * @param {object} [metadata] 元数据对象（可选）
     * @param {number} [expiration] 绝对过期时间（Unix 秒）
     * @param {number} [expirationTtl] 相对过期时间（秒）
     */
    async function writeKey(accountId, token, namespaceId, key, value, metadata, expiration, expirationTtl) {
        const path = `accounts/${accountId}/storage/kv/namespaces/${namespaceId}/values/${encodeURIComponent(key)}`;
        const url = new URL(`https://api.cloudflare.com/client/v4/${path}`);

        // 查询参数：过期时间、元数据
        if (expiration !== undefined) url.searchParams.append('expiration', `${expiration}`);
        if (expirationTtl !== undefined) url.searchParams.append('expiration_ttl', `${expirationTtl}`);
        if (metadata !== undefined) url.searchParams.append('metadata', JSON.stringify(metadata));

        // 确定 Content-Type 和请求体
        let body, contentType;
        if (typeof value === 'string') {
            body = value;
            contentType = 'text/plain;charset=utf-8';
        } else if (value instanceof Blob) {
            body = value;
            contentType = value.type || 'application/octet-stream';
        } else {
            throw new Error('Unsupported value type');
        }

        const res = await fetch(url.toString(), {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': contentType,
            },
            body: body,
        });

        if (!res.ok) {
            const errData = await res.json().catch(() => null);
            const err = new Error(`Write key failed (${res.status}): ${JSON.stringify(errData)}`);
            throw err;
        }
        return res.json();
    }
    /**
     * 批量写入多个键值对（支持 Base64）
     * @param {string} accountId
     * @param {string} token
     * @param {string} namespaceId
     * @param {Array<object>} kvList 每个元素包含 key, value, base64?, metadata?, expiration?, expiration_ttl?
     */
    async function bulkWriteKeys(accountId, token, namespaceId, kvList) {
        const url = `https://api.cloudflare.com/client/v4/accounts/${accountId}/storage/kv/namespaces/${namespaceId}/bulk`;

        const response = await fetch(url, {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(kvList),
        });

        if (!response.ok) {
            const errText = await response.text();
            const err = new Error(`Bulk write failed (${response.status}): ${errText}`);
            throw err;
        }
        return response.json();
    }
    /**
     * 读取键的原始二进制内容
     * @param {string} accountId
     * @param {string} token
     * @param {string} namespaceId
     * @param {string} key
     * @returns {Promise<{data: ArrayBuffer, metadata: object|null}>}
     */
    async function readKeyBinary(accountId, token, namespaceId, key) {
        const path = `accounts/${accountId}/storage/kv/namespaces/${namespaceId}/values/${encodeURIComponent(key)}`;
        const url = `https://api.cloudflare.com/client/v4/${path}`;
        const res = await fetch(url, {
            headers: { 'Authorization': `Bearer ${token}` },
        });
        if (!res.ok) {
            const errData = await res.json().catch(() => null);
            const err = new Error(`Read key failed (${res.status}): ${JSON.stringify(errData)}`);
            throw err;
        }
        const data = await res.arrayBuffer();

        // 获取元数据
        let metadata = null;
        try {
            const metaRes = await apiRequest(
                `accounts/${accountId}/storage/kv/namespaces/${namespaceId}/metadata/${encodeURIComponent(key)}`,
                'GET',
                undefined,
                token
            );
            metadata = metaRes.result || null;
        } catch (e) {
            // 元数据获取失败不影响主流程
            console.warn('Failed to fetch metadata:', e);
        }
        return { data, metadata };
    }
    /**
     * 处理获取键二进制值请求（下载流）
     * @param {string} accountId
     * @param {string} apiToken
     * @param {string} namespaceId
     * @param {string} key
     * @returns Promise<Response>
     */
    async function handleReadKeyStream(accountId, apiToken, namespaceId, key) {
        const { data, metadata } = await readKeyBinary(accountId, apiToken, namespaceId, key);

        // 从元数据中获取 MIME 类型和文件名（优先使用元数据存储的值）
        const mimeType = (metadata && metadata.contentType) ? metadata.contentType : 'application/octet-stream';
        // 文件名：若元数据中有 filename 则使用，否则回退到 key
        const filename = (metadata && metadata.filename) ? metadata.filename : key;

        // 对文件名进行 RFC 5987 编码（支持非ASCII字符），简单起见使用 encodeURIComponent
        const encodedFilename = encodeURIComponent(filename);
        return new Response(data, {
            headers: {
                'Content-Type': mimeType,
                'Content-Length': data.byteLength.toString(),
                'Content-Disposition': `attachment; filename="${encodedFilename}"; filename*=UTF-8''${encodedFilename}`
            }
        });
    }
    async function handleWriteKey(accountId, apiToken, namespaceId, key, request) {
        const contentType = request.headers.get('Content-Type') || '';
        const url = new URL(request.url);
        const searchParams = url.searchParams;

        let value, metadata, expiration, expirationTtl;

        // 检查是否为 Base64 模式（通过查询参数 ?base64=1）
        const isBase64 = searchParams.get('base64') === '1' || searchParams.get('base64') === 'true';

        if (contentType.includes('multipart/form-data')) {
            // 原有 multipart 处理逻辑（略作调整，支持 base64 字段）
            const formData = await request.formData();

            // 如果表单中显式提供了 base64 字段，则优先解码该字段
            const base64Field = formData.get('base64');
            if (base64Field && typeof base64Field === 'string') {
                try {
                    const binaryString = atob(base64Field);
                    const bytes = new Uint8Array(binaryString.length);
                    for (let i = 0; i < binaryString.length; i++) {
                        bytes[i] = binaryString.charCodeAt(i);
                    }
                    value = new Blob([bytes]);
                } catch (e) {
                    return new Response('Invalid base64 content', { status: 400 });
                }
            } else {
                value = formData.get('value');
            }

            // 处理元数据（同上）
            let metaObj = {};
            const metaStr = formData.get('metadata');
            if (metaStr) {
                try {
                    metaObj = JSON.parse(metaStr);
                } catch (e) {
                    return new Response('Invalid metadata JSON', { status: 400 });
                }
            }

            if (value && typeof value === 'object' && value.name !== undefined) {
                if (!metaObj.filename) metaObj.filename = value.name;
                if (!metaObj.contentType && value.type) metaObj.contentType = value.type;
            }
            metadata = Object.keys(metaObj).length ? metaObj : undefined;

            const expStr = formData.get('expiration');
            if (expStr) expiration = parseInt(expStr, 10);
            const ttlStr = formData.get('expiration_ttl');
            if (ttlStr) expirationTtl = parseInt(ttlStr, 10);
        } else {
            // 非表单提交：统一处理文本/二进制 + Base64 解码
            if (isBase64) {
                // 将整个请求体视为 Base64 字符串，解码为二进制 Blob
                const base64Text = await request.text();
                try {
                    const binaryString = atob(base64Text);
                    const bytes = new Uint8Array(binaryString.length);
                    for (let i = 0; i < binaryString.length; i++) {
                        bytes[i] = binaryString.charCodeAt(i);
                    }
                    value = new Blob([bytes]);
                } catch (e) {
                    return new Response('Invalid base64 body', { status: 400 });
                }
            } else {
                // 原有逻辑（此处保留你之前的 isText 判断，但你已经强制设为 false）
                const isText = false; // 可根据需要重新启用判断
                if (!isText) {
                    value = await request.blob();
                } else {
                    value = await request.text();
                }
            }

            // 过期参数可从查询参数获取
            if (searchParams.has('expiration')) expiration = parseInt(searchParams.get('expiration'), 10);
            if (searchParams.has('expiration_ttl')) expirationTtl = parseInt(searchParams.get('expiration_ttl'), 10);
        }

        if (value === null || value === undefined) {
            return new Response('Missing "value" field', { status: 400 });
        }

        const data = await writeKey(accountId, apiToken, namespaceId, key, value, metadata, expiration, expirationTtl);
        return new Response(JSON.stringify(data), {
            headers: { 'Content-Type': 'application/json' }
        });
    }
    /**
     * 批量写入 KV 键值对
     * 请求体应为 JSON 数组，每个元素包含：
     *   - key: string (必填)
     *   - value: string (文本) 或 base64 编码的字符串 (若 base64=true)
     *   - base64?: boolean (可选，指示 value 是否为 base64)
     *   - metadata?: object (可选)
     *   - expiration?: number (可选，绝对过期时间，Unix 秒)
     *   - expiration_ttl?: number (可选，相对过期秒数)
     * 
     * 示例请求体：
     * [
     *   { "key": "doc1", "value": "hello world" },
     *   { "key": "img1", "value": "iVBORw0KGgo...", "base64": true, "metadata": { "contentType": "image/png" } }
     * ]
     */
    async function handleBulkWrite(accountId, token, namespaceId, request) {
        try {
            const kvList = await request.json();
            if (!Array.isArray(kvList)) {
                return new Response(JSON.stringify({ error: 'Request body must be a JSON array' }), {
                    status: 400,
                    headers: { 'Content-Type': 'application/json' }
                });
            }

            // 验证每个元素至少包含 key 和 value
            for (let i = 0; i < kvList.length; i++) {
                const item = kvList[i];
                if (!item.key || item.value === undefined) {
                    return new Response(JSON.stringify({ error: `Item at index ${i} missing 'key' or 'value'` }), {
                        status: 400,
                        headers: { 'Content-Type': 'application/json' }
                    });
                }
                // 如果标记为 base64，需要将 value 解码为二进制 Blob，以便 bulkWriteKeys 内部处理
                if (item.base64 === true && typeof item.value === 'string') {
                    try {
                        const binaryString = atob(item.value);
                        const bytes = new Uint8Array(binaryString.length);
                        for (let j = 0; j < binaryString.length; j++) {
                            bytes[j] = binaryString.charCodeAt(j);
                        }
                        // 替换为 Blob 对象
                        item.value = new Blob([bytes]);
                        // 删除 base64 标记，因为 bulkWriteKeys 期望 blob 对象时不需要该字段
                        delete item.base64;
                    } catch (e) {
                        return new Response(JSON.stringify({ error: `Invalid base64 at index ${i}: ${e.message}` }), {
                            status: 400,
                            headers: { 'Content-Type': 'application/json' }
                        });
                    }
                }
            }

            // 调用已有的批量写入函数
            const result = await bulkWriteKeys(accountId, token, namespaceId, kvList);
            return new Response(JSON.stringify(result), {
                status: 200,
                headers: { 'Content-Type': 'application/json' }
            });
        } catch (err) {
            return new Response(JSON.stringify({ error: err.message }), {
                status: 500,
                headers: { 'Content-Type': 'application/json' }
            });
        }
    }
    // 匹配路由
    for (const route of routes) {
        if (route.method !== method) continue;
        const match = route.pattern.exec({ pathname });
        if (match) {
            try {
                const result = await route.handler(match, request);
                // 如果 handler 返回的是 Response 对象，直接返回；否则包装成 JSON 响应
                return result instanceof Response ? result : jsonResponse(result, { status: 200 });
            } catch (err) {
                return new Response(`Server Error: ${err.message}`, { status: 500 });
            }
        }
    }

    // 无匹配路由
    return new Response('Not Found', { status: 404 });
}
// kv管理html /kv
function handleKVHtml(acc, logined) {
    const html = `
    <!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="stylesheet" href="/static/style.css">
  <title>Worker 编辑器|kv 管理</title>
  <style>
.table-wrapper{overflow-x:auto;-webkit-overflow-scrolling:touch}
.tabs{display:flex;border-bottom:1px solid var(--border-color);margin-bottom:1rem;flex-wrap:wrap}
.tab{padding:.5rem 1rem;border:1px solid transparent;background:transparent;cursor:pointer;font-weight:500;margin-right:.25rem;margin-bottom:-1px;border-radius:var(--radius) var(--radius) 0 0;color:var(--text-secondary);transition:var(--transition)}
.tab:hover{color:var(--primary-color);background-color:var(--surface-color);border-color:var(--border-color) var(--border-color) transparent}
.tab.active{background:var(--bg-color);border-color:var(--border-color) var(--border-color) var(--bg-color);color:var(--text-color)}
.tab-content{display:none}.tab-content.active{display:block}
.error{color:var(--danger-color);margin:.5rem 0;font-size:.875rem}
.global-error{background:var(--surface-color);border:1px solid var(--danger-color);padding:.5rem .75rem;margin-bottom:1rem;border-radius:var(--radius);color:var(--danger-color)}
.info{color:var(--text-secondary);font-size:.875rem;margin:.25rem 0}
.section{margin-bottom:1.5rem}
.flex-row{display:flex;align-items:center;flex-wrap:wrap;gap:.5rem;margin-bottom:.5rem}
.flex-row label{white-space:nowrap}
.hidden{display:none !important}
button.small,.btn.small{background-color: var(--surface-color);color: var(--text-color);border: 1px solid var(--border-color);padding:.125rem .5rem;font-size:.75rem}
input,textarea,select{margin:0}
td button{margin-right:.25rem}
@media (max-width:768px){
.flex-row{flex-direction:column;align-items:stretch}
.flex-row label{white-space:normal}
.tabs{gap:.25rem}
.tab{padding:.375rem .75rem;font-size:.875rem}
}
</style>
</head>
<body>
  {{NAVBAR}}
  <h2>Cloudflare KV 存储管理</h2>
  <div id="globalError" class="global-error hidden"></div>

  <div class="tabs" id="tabBar">
    <button class="tab active" data-tab="ns">命名空间管理</button>
    <button class="tab" data-tab="keys">键值浏览</button>
    <button class="tab" data-tab="edit">键值编辑</button>
  </div>

  <!-- 命名空间管理 -->
  <div id="nsTab" class="tab-content active">
    <div class="section">
      <div class="flex-row">
        <input type="text" id="nsTitle" placeholder="新命名空间名称" style="width:200px;">
        <button class="btn btn-secondary" id="createNsBtn">创建</button>
      </div>
      <div id="nsError" class="error"></div>
      <div class="table-wrapper">
        <table id="nsTable">
          <thead>
            <tr><th>名称</th><th>ID</th><th>操作</th></tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>
      <div id="nsPagination" class="flex-row" style="justify-content: space-between;">
        <div>
          <button class="btn btn-secondary" id="nsPrevBtn" disabled>上一页</button>
          <span id="nsPageInfo">第 1 页</span>
          <button class="btn btn-secondary" id="nsNextBtn">下一页</button>
        </div>
        <div>
          <label>每页
            <select id="nsPerPage">
              <option value="10">10</option>
              <option value="20" selected>20</option>
              <option value="50">50</option>
              <option value="100">100</option>
            </select>
            条
          </label>
        </div>
      </div>
      <div id="nsLoading" class="info hidden">加载中...</div>
    </div>
  </div>

  <!-- 键值浏览 -->
  <div id="keysTab" class="tab-content">
    <div class="section">
      <div id="keysNoNs" class="info">请先在「命名空间管理」中选择一个命名空间。</div>
      <div id="keysContent" class="hidden">
        <div class="flex-row">
          <strong>当前命名空间：</strong><span id="currentNsTitle"></span>
          <button class="btn btn-secondary" id="bulkUploadBtn" class="small">批量写入</button>
        </div>
        <div class="flex-row">
          <input type="text" id="prefixInput" placeholder="前缀筛选（可选）">
          <button class="btn btn-secondary" id="searchKeysBtn">搜索</button>
          <button id="newKeyBtn">新建键</button>
        </div>
        <div id="keysError" class="error"></div>
        <div class="table-wrapper">
          <table id="keysTable">
            <thead><tr><th>键名</th><th>过期时间</th><th>操作</th></tr></thead>
            <tbody></tbody>
          </table>
        </div>
        <div class="flex-row" style="justify-content: space-between;">
          <div>
            <button class="btn btn-secondary" id="keysPrevBtn" disabled>上一页</button>
            <span id="keysPageInfo">第 1 页</span>
            <button class="btn btn-secondary" id="keysNextBtn" disabled>下一页</button>
          </div>
          <span id="keysCursorInfo" class="info"></span>
        </div>
        <div id="keysLoading" class="info hidden">加载中...</div>
      </div>
    </div>
  </div>

  <!-- 键值编辑 -->
  <div id="editTab" class="tab-content">
    <div id="editNoKey" class="info">请先在「键值浏览」中选择一个键进行编辑。</div>
    <div id="editContent" class="hidden">
      <h3>编辑键值 – <span id="editingKey"></span></h3>
      <label>值 (Value)：</label><br>
      <textarea id="valueText"></textarea><br>
      <div class="flex-row">
        <label>上传文件（优先级高于文本）:</label>
        <input type="file" id="fileInput">
      </div>
      <div class="flex-row">
        <a id="downloadLink" href="#" style="display:none;" download>下载内容</a>
        <span id="binaryInfo" style="display:none; color:#555;"></span>
      </div>
      <label>元数据 (JSON，最大1024字节)：</label><br>
      <textarea id="metadataText" placeholder='{"role":"admin","count":42}' rows="3" style="height:60px"></textarea><br>
      <label>过期时间 (可选，选其一)：</label><br>
      <div class="flex-row">
        <input type="number" id="expirationTtl" placeholder="相对过期（秒）" style="width:160px">
        <span>秒后过期</span>
      </div>
      <div class="flex-row">
        <input type="text" id="expiration" placeholder="绝对过期 Unix 时间戳（秒）" style="width:200px">
      </div>
      <div class="flex-row">
        <button id="saveValueBtn">保存</button>
        <button class="btn btn-secondary" id="cancelEditBtn">取消</button>
      </div>
      <div id="valueError" class="error"></div>
      <div id="editLoading" class="info hidden">保存中...</div>
    </div>
  </div>

  <script>
    (function() {
      // ========== 配置 ==========
      const API_BASE = '/api';

      // ========== 状态 ==========
      let selectedNsId = null;
      let selectedNsTitle = '';
      const namespaceMap = new Map(); // id -> title
      const keyExpirations = new Map();

      // 命名空间分页
      let nsCurrentPage = 1;
      let nsTotalPages = 1;

      // 键列表游标分页
      let keyPageIndex = 0;
      let keyCursors = [null]; // cursors[i] 用于请求第 i 页
      let currentPrefix = '';

      // 编辑状态
      let editingKeyName = null;

      // 加载状态防止重复请求
      let nsLoading = false;
      let keysLoading = false;

      // ========== DOM 元素引用 ==========
      const globalError = document.getElementById('globalError');
      const tabBar = document.getElementById('tabBar');
      const nsTab = document.getElementById('nsTab');
      const keysTab = document.getElementById('keysTab');
      const editTab = document.getElementById('editTab');

      // 命名空间元素
      const nsTitleInput = document.getElementById('nsTitle');
      const createNsBtn = document.getElementById('createNsBtn');
      const nsError = document.getElementById('nsError');
      const nsTableBody = document.querySelector('#nsTable tbody');
      const nsPrevBtn = document.getElementById('nsPrevBtn');
      const nsNextBtn = document.getElementById('nsNextBtn');
      const nsPageInfo = document.getElementById('nsPageInfo');
      const nsPerPage = document.getElementById('nsPerPage');
      const nsLoadingDiv = document.getElementById('nsLoading');

      // 键浏览元素
      const keysNoNs = document.getElementById('keysNoNs');
      const keysContent = document.getElementById('keysContent');
      const currentNsTitleSpan = document.getElementById('currentNsTitle');
      const bulkUploadBtn = document.getElementById('bulkUploadBtn');
      const prefixInput = document.getElementById('prefixInput');
      const searchKeysBtn = document.getElementById('searchKeysBtn');
      const newKeyBtn = document.getElementById('newKeyBtn');
      const keysError = document.getElementById('keysError');
      const keysTableBody = document.querySelector('#keysTable tbody');
      const keysPrevBtn = document.getElementById('keysPrevBtn');
      const keysNextBtn = document.getElementById('keysNextBtn');
      const keysPageInfo = document.getElementById('keysPageInfo');
      const keysCursorInfo = document.getElementById('keysCursorInfo');
      const keysLoadingDiv = document.getElementById('keysLoading');

      // 编辑元素
      const editNoKey = document.getElementById('editNoKey');
      const editContent = document.getElementById('editContent');
      const editingKeySpan = document.getElementById('editingKey');
      const valueText = document.getElementById('valueText');
      const fileInput = document.getElementById('fileInput');
      const downloadLink = document.getElementById('downloadLink');
      const binaryInfo = document.getElementById('binaryInfo');
      const metadataText = document.getElementById('metadataText');
      const expirationTtl = document.getElementById('expirationTtl');
      const expiration = document.getElementById('expiration');
      const saveValueBtn = document.getElementById('saveValueBtn');
      const cancelEditBtn = document.getElementById('cancelEditBtn');
      const valueError = document.getElementById('valueError');
      const editLoadingDiv = document.getElementById('editLoading');

      // ========== 工具函数 ==========
      function showGlobalError(msg) {
        globalError.textContent = msg;
        globalError.classList.remove('hidden');
      }
      function clearGlobalError() {
        globalError.classList.add('hidden');
        globalError.textContent = '';
      }
      function showError(el, msg) {
        el.textContent = msg;
      }
      function clearError(el) {
        el.textContent = '';
      }

      async function apiFetch(url, options = {}) {
        clearGlobalError();
        let res;
        try {
          res = await fetch(url, options);
        } catch (e) {
          throw new Error('网络请求失败，请检查网络连接。');
        }
        const contentType = res.headers.get('content-type') || '';
        if (!res.ok) {
          let errMsg = \`\${res.status} \${res.statusText}\`;
          try {
            const body = await res.json();
            if (body.errors && body.errors.length) {
              errMsg += ': ' + body.errors.map(e => e.message).join('; ');
            }
          } catch (e) { /* ignore */ }
          throw new Error(errMsg);
        }
        if (contentType.includes('text/plain')) {
          return res.text();
        }
        return res.json();
      }

      function escapeHtml(str) {
        return String(str)
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;')
          .replace(/'/g, '&#39;');
      }

      // 切换选项卡
      function switchTab(tabId) {
        document.querySelectorAll('.tab').forEach(btn => btn.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));

        document.querySelector(\`.tab[data-tab="\${tabId}"]\`).classList.add('active');
        document.getElementById(\`\${tabId}Tab\`).classList.add('active');

        if (tabId === 'keys' && !selectedNsId) {
          keysNoNs.classList.remove('hidden');
          keysContent.classList.add('hidden');
        } else if (tabId === 'keys') {
          keysNoNs.classList.add('hidden');
          keysContent.classList.remove('hidden');
        }

        if (tabId === 'edit' && !editingKeyName) {
          editNoKey.classList.remove('hidden');
          editContent.classList.add('hidden');
        } else if (tabId === 'edit') {
          editNoKey.classList.add('hidden');
          editContent.classList.remove('hidden');
        }
      }

      // ========== 命名空间操作 ==========
      async function loadNamespaces(page = 1) {
        if (nsLoading) return;
        nsLoading = true;
        nsLoadingDiv.classList.remove('hidden');
        clearError(nsError);
        nsCurrentPage = page;
        const perPage = nsPerPage.value;
        try {
          const data = await apiFetch(\`\${API_BASE}/namespaces?page=\${page}&per_page=\${perPage}\`);
          nsTableBody.innerHTML = '';
          if (!data.result || data.result.length === 0) {
            nsTableBody.innerHTML = '<tr><td colspan="3" style="text-align:center; color:#888;">暂无命名空间</td></tr>';
          } else {
            data.result.forEach(ns => {
              namespaceMap.set(ns.id, ns.title);
              const tr = document.createElement('tr');
              const tdName = document.createElement('td');
              tdName.textContent = ns.title;
              const tdId = document.createElement('td');
              const code = document.createElement('code');
              code.textContent = ns.id;
              tdId.appendChild(code);
              const tdActions = document.createElement('td');
              tdActions.innerHTML = \`
                <button class="small" data-action="select" data-ns-id="\${escapeHtml(ns.id)}">查看键</button>
                <button class="small" data-action="bulk" data-ns-id="\${escapeHtml(ns.id)}">批量写入</button>
                <button class="small" data-action="delete" data-ns-id="\${escapeHtml(ns.id)}">删除</button>
              \`;
              tr.appendChild(tdName);
              tr.appendChild(tdId);
              tr.appendChild(tdActions);
              nsTableBody.appendChild(tr);
            });
          }

          if (data.result_info) {
            nsTotalPages = data.result_info.total_pages || 1;
            nsPageInfo.textContent = \`第 \${nsCurrentPage} / \${nsTotalPages} 页\`;
            nsPrevBtn.disabled = (nsCurrentPage <= 1);
            nsNextBtn.disabled = (nsCurrentPage >= nsTotalPages);
          } else {
            nsPageInfo.textContent = \`第 \${nsCurrentPage} 页\`;
            nsPrevBtn.disabled = (nsCurrentPage <= 1);
            nsNextBtn.disabled = true;
          }
        } catch (err) {
          showError(nsError, err.message);
        } finally {
          nsLoading = false;
          nsLoadingDiv.classList.add('hidden');
        }
      }

      async function createNamespace() {
        const title = nsTitleInput.value.trim();
        if (!title) return;
        clearError(nsError);
        try {
          await apiFetch(\`\${API_BASE}/namespaces\`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ title })
          });
          nsTitleInput.value = '';
          await loadNamespaces(1);
        } catch (err) {
          showError(nsError, err.message);
        }
      }

      async function deleteNamespace(id) {
        if (!confirm('确定删除这个命名空间吗？所有数据将被清除！')) return;
        clearError(nsError);
        try {
          await apiFetch(\`\${API_BASE}/namespaces/\${id}\`, { method: 'DELETE' });
          namespaceMap.delete(id);
          if (selectedNsId === id) {
            deselectNamespace();
          }
          await loadNamespaces(nsCurrentPage);
        } catch (err) {
          showError(nsError, err.message);
        }
      }

      function selectNamespace(id) {
        selectedNsId = id;
        selectedNsTitle = namespaceMap.get(id) || id;
        currentNsTitleSpan.textContent = selectedNsTitle;
        // 重置键列表分页
        keyPageIndex = 0;
        keyCursors = [null];
        currentPrefix = '';
        prefixInput.value = '';
        loadKeysPage(0);
        switchTab('keys');
      }

      function deselectNamespace() {
        selectedNsId = null;
        selectedNsTitle = '';
        keysNoNs.classList.remove('hidden');
        keysContent.classList.add('hidden');
        keyExpirations.clear();
      }

      // 命名空间表格事件委托
      nsTableBody.addEventListener('click', (e) => {
        const btn = e.target.closest('button');
        if (!btn) return;
        const action = btn.dataset.action;
        const nsId = btn.dataset.nsId;
        if (action === 'select') {
          selectNamespace(nsId);
        } else if (action === 'bulk') {
          window.location.href = \`/kv/bulk?ns=\${nsId}\`;
        } else if (action === 'delete') {
          deleteNamespace(nsId);
        }
      });

      // 创建按钮
      createNsBtn.addEventListener('click', createNamespace);
      nsTitleInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') createNamespace();
      });

      // 命名空间分页按钮
      nsPrevBtn.addEventListener('click', () => {
        if (nsCurrentPage > 1) loadNamespaces(nsCurrentPage - 1);
      });
      nsNextBtn.addEventListener('click', () => {
        if (nsCurrentPage < nsTotalPages) loadNamespaces(nsCurrentPage + 1);
      });
      nsPerPage.addEventListener('change', () => {
        nsCurrentPage = 1;
        loadNamespaces(1);
      });

      // ========== 键列表操作 ==========
      async function loadKeysPage(pageIdx) {
        if (!selectedNsId) return;
        if (keysLoading) return;
        keysLoading = true;
        keysLoadingDiv.classList.remove('hidden');
        clearError(keysError);

        const cursor = keyCursors[pageIdx] !== undefined ? keyCursors[pageIdx] : null;
        try {
          const params = new URLSearchParams();
          if (currentPrefix) params.set('prefix', currentPrefix);
          if (cursor) params.set('cursor', cursor);
          params.set('limit', '20');

          const data = await apiFetch(\`\${API_BASE}/kv/\${selectedNsId}/keys?\${params.toString()}\`);
          keysTableBody.innerHTML = '';
          if (!data.result || data.result.length === 0) {
            keysTableBody.innerHTML = '<tr><td colspan="3" style="text-align:center; color:#888;">暂无键</td></tr>';
          } else {
            data.result.forEach(keyObj => {
              keyExpirations.set(keyObj.name, keyObj.expiration ?? null);
              const tr = document.createElement('tr');
              const tdName = document.createElement('td');
              tdName.textContent = keyObj.name;
              const tdExp = document.createElement('td');
              tdExp.textContent = keyObj.expiration ? new Date(keyObj.expiration * 1000).toLocaleString() : '—';
              const tdActions = document.createElement('td');
              const editBtn = document.createElement('button');
              editBtn.className = 'small';
              editBtn.dataset.action = 'edit';
              editBtn.dataset.key = keyObj.name;
              editBtn.textContent = '查看/编辑';
              const delBtn = document.createElement('button');
              delBtn.className = 'small';
              delBtn.dataset.action = 'delete';
              delBtn.dataset.key = keyObj.name;
              delBtn.textContent = '删除';
              tdActions.appendChild(editBtn);
              tdActions.appendChild(delBtn);
              tr.appendChild(tdName);
              tr.appendChild(tdExp);
              tr.appendChild(tdActions);
              keysTableBody.appendChild(tr);
            });
          }

          // 更新游标历史
          const resultInfo = data.result_info;
          if (resultInfo && resultInfo.cursor) {
            keyCursors[pageIdx + 1] = resultInfo.cursor;
            // 删除后续的游标（如果当前页之后有旧的）
            keyCursors.splice(pageIdx + 2);
          } else {
            // 无下一页，清除后续游标
            keyCursors.splice(pageIdx + 1);
          }

          keyPageIndex = pageIdx;
          keysPageInfo.textContent = \`第 \${keyPageIndex + 1} 页\`;
          keysPrevBtn.disabled = (keyPageIndex <= 0);
          keysNextBtn.disabled = (keyCursors[keyPageIndex + 1] === undefined);
          keysCursorInfo.textContent = resultInfo ? \`当前页 \${resultInfo.count} 条\` : '';
        } catch (err) {
          showError(keysError, err.message);
        } finally {
          keysLoading = false;
          keysLoadingDiv.classList.add('hidden');
        }
      }

      function loadKeys(reset = false) {
        if (reset) {
          keyPageIndex = 0;
          keyCursors = [null];
          currentPrefix = prefixInput.value.trim();
          keyExpirations.clear();
        }
        loadKeysPage(keyPageIndex);
      }

      // 键表格事件委托
      keysTableBody.addEventListener('click', (e) => {
        const btn = e.target.closest('button');
        if (!btn) return;
        const action = btn.dataset.action;
        const key = btn.dataset.key;
        if (action === 'edit') {
          editValue(key);
        } else if (action === 'delete') {
          deleteKey(key);
        }
      });

      async function deleteKey(keyName) {
        if (!confirm(\`确定删除键 "\${keyName}" 吗？\`)) return;
        clearError(keysError);
        try {
          await apiFetch(\`\${API_BASE}/kv/\${selectedNsId}/values/\${encodeURIComponent(keyName)}\`, {
            method: 'DELETE'
          });
          // 重新加载当前页
          loadKeysPage(keyPageIndex);
        } catch (err) {
          showError(keysError, err.message);
        }
      }

      function newKey() {
        const keyName = prompt('输入新键名：');
        if (!keyName) return;
        editValue(keyName);
      }

      // 分页按钮
      keysPrevBtn.addEventListener('click', () => {
        if (keyPageIndex > 0) loadKeysPage(keyPageIndex - 1);
      });
      keysNextBtn.addEventListener('click', () => {
        if (keyCursors[keyPageIndex + 1] !== undefined) loadKeysPage(keyPageIndex + 1);
      });

      // 搜索按钮
      searchKeysBtn.addEventListener('click', () => loadKeys(true));
      prefixInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') loadKeys(true);
      });
      newKeyBtn.addEventListener('click', newKey);
      bulkUploadBtn.addEventListener('click', () => {
        if (selectedNsId) window.location.href = \`/bulk?ns=\${selectedNsId}\`;
      });

      // ========== 值编辑操作 ==========
      async function editValue(keyName) {
        clearError(valueError);
        editingKeyName = keyName;
        editingKeySpan.textContent = keyName;
        valueText.value = '';
        valueText.readOnly = false;
        metadataText.value = '';
        expirationTtl.value = '';
        expiration.value = '';
        fileInput.value = '';
        downloadLink.style.display = 'none';
        binaryInfo.style.display = 'none';
        editLoadingDiv.classList.add('hidden');

        // 切换到编辑选项卡
        switchTab('edit');
        editNoKey.classList.add('hidden');
        editContent.classList.remove('hidden');

        // 回填过期时间
        const cachedExp = keyExpirations.get(keyName);
        if (cachedExp) {
          expiration.value = cachedExp;
        }

        // 获取元数据
        let metadataObj = null;
        try {
          const metaRes = await apiFetch(\`\${API_BASE}/kv/\${selectedNsId}/metadata/\${encodeURIComponent(keyName)}\`);
          if (metaRes && metaRes.result && typeof metaRes.result === 'object' && Object.keys(metaRes.result).length > 0) {
            metadataText.value = JSON.stringify(metaRes.result, null, 2);
            metadataObj = metaRes.result;
          } else {
            metadataText.value = '';
          }
        } catch (err) {
          metadataText.value = '';
        }

        // 下载链接
        downloadLink.href = \`\${API_BASE}/kv/\${selectedNsId}/values/\${encodeURIComponent(keyName)}/stream\`;
        downloadLink.download = (metadataObj && metadataObj.filename) ? metadataObj.filename : keyName;
        downloadLink.style.display = 'inline';

        // 获取文本内容
        let isBinary = false;
        try {
          const response = await fetch(\`\${API_BASE}/kv/\${selectedNsId}/values/\${encodeURIComponent(keyName)}\`);
          if (response.status === 415) {
            isBinary = true;
          } else if (!response.ok) {
            throw new Error(\`读取失败 (\${response.status})\`);
          } else {
            const text = await response.text();
            valueText.value = text;
          }
        } catch (err) {
          valueText.value = err.message;
        }

        if (isBinary) {
          valueText.value = '这是一个二进制文件，内容无法在文本框中显示。请点击下方链接下载。';
          binaryInfo.style.display = 'inline';
          binaryInfo.textContent = \` (二进制文件，类型: \${metadataObj?.contentType || '未知'})\`;
        } else {
          binaryInfo.style.display = 'none';
        }
      }

      async function saveValue() {
        if (!editingKeyName) return;
        clearError(valueError);
        editLoadingDiv.classList.remove('hidden');
        saveValueBtn.disabled = true;

        const file = fileInput.files[0];
        const metaStr = metadataText.value.trim();
        const ttl = expirationTtl.value.trim();
        const exp = expiration.value.trim();
        const formData = new FormData();

        try {
          if (file) {
            // 读取文件为 Base64
            const base64String = await new Promise((resolve, reject) => {
              const reader = new FileReader();
              reader.onload = () => {
                const result = reader.result;
                const commaIndex = result.indexOf(',');
                const pureBase64 = commaIndex !== -1 ? result.substring(commaIndex + 1) : result;
                resolve(pureBase64);
              };
              reader.onerror = () => reject(new Error('文件读取失败'));
              reader.readAsDataURL(file);
            });
            formData.append('base64', base64String);

            let metaObj = {};
            if (metaStr) {
              metaObj = JSON.parse(metaStr);
            }
            if (!metaObj.filename) metaObj.filename = file.name;
            if (!metaObj.contentType) metaObj.contentType = file.type || 'application/octet-stream';
            formData.append('metadata', JSON.stringify(metaObj));
          } else {
            formData.append('value', valueText.value);
            if (metaStr) {
              JSON.parse(metaStr); // 验证 JSON
              formData.append('metadata', metaStr);
            }
          }

          if (ttl) formData.append('expiration_ttl', ttl);
          else if (exp) formData.append('expiration', exp);

          const res = await fetch(\`\${API_BASE}/kv/\${selectedNsId}/values/\${encodeURIComponent(editingKeyName)}\`, {
            method: 'PUT',
            body: formData
          });
          if (!res.ok) {
            const errData = await res.json().catch(() => null);
            throw new Error(errData?.errors?.[0]?.message || res.statusText);
          }
          cancelEdit();
          // 返回键浏览并刷新当前页
          switchTab('keys');
          loadKeysPage(keyPageIndex);
        } catch (err) {
          showError(valueError, err.message);
        } finally {
          editLoadingDiv.classList.add('hidden');
          saveValueBtn.disabled = false;
        }
      }

      function cancelEdit() {
        editingKeyName = null;
        valueText.value = '';
        fileInput.value = '';
        downloadLink.style.display = 'none';
        binaryInfo.style.display = 'none';
        editNoKey.classList.remove('hidden');
        editContent.classList.add('hidden');
        switchTab('keys');
      }

      saveValueBtn.addEventListener('click', saveValue);
      cancelEditBtn.addEventListener('click', cancelEdit);

      // ========== 选项卡切换事件 ==========
      tabBar.addEventListener('click', (e) => {
        const btn = e.target.closest('.tab');
        if (!btn) return;
        const tabId = btn.dataset.tab;
        switchTab(tabId);
      });

      // ========== 初始加载 ==========
      window.addEventListener('DOMContentLoaded', () => {
        loadNamespaces(1);
        switchTab('ns');
      });
    })();
  </script>
</body>
</html>
    `
    /*if (logined) {
        return buildHtmlResponse(html, acc, {
            littleNav: false,
            errorHandler: errHtml,
            homeUrl: '/list'
        });
    } else {
        return buildHtmlResponse(html, '', {
            littleNav: true,
            errorOverlay: {
                code: 401,
                message: '请先登录',
                redirectUrl: '/login',
                homeOnly: true
            },
            errorHandler: errHtml,
            homeUrl: '/'
        });
    }*/
    return buildHtmlResponse(html, acc, {
        littleNav: false,
        errorHandler: errHtml,
        homeUrl: '/list'
    });
}
// kv批量写入html /kv/bulk
function handleKVBulkHtml(acc, logined) {
    const html = `
    <!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="/static/style.css">
    <title>Worker 编辑器|kv 管理|批量写入</title>
    <style>
  .item { background: var(--surface-color); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 1rem; margin-bottom: 1rem; }
  .item-header { font-weight: 600; margin-bottom: 0.75rem; color: var(--text-color); }
  .flex { display: flex; gap: 0.75rem; flex-wrap: wrap; align-items: center; margin-bottom: 0.5rem; }
  textarea { width: 100%; max-width: 100%; height: 60px; box-sizing: border-box; }
  .key-input { min-width: 150px; flex: 1 1 50px; }
  .metadata { flex: 2 1 60px; min-width: 150px; }
  .expiration-ttl, .expiration { width: 110px; flex-shrink: 0; }
  .error { color: var(--danger-color); margin: 0.5rem 0; font-size: 0.875rem; }
  .success { color: var(--success-color); margin: 0.5rem 0; font-size: 0.875rem; }
  .remove-item { background: var(--surface-color); color: var(--danger-color); border: 1px solid var(--danger-color); }
  .remove-item:hover { background: var(--danger-color); color: white; }
  #namespaceId { width: 300px; max-width: 100%; }
  @media (max-width: 768px) {
    .flex { flex-direction: column; align-items: stretch; gap: 0.5rem; }
    .expiration-ttl, .expiration { width: 100%; }
    #namespaceId { width: 100%; }
  }
</style>
</head>
{{NAVBAR}}
<body>
<h2>KV 批量写入</h2>
<div>
    <label>命名空间 ID: </label>
    <input type="text" id="namespaceId" placeholder="例如: xxxx-xxxx-xxxx" style="width: 300px;">
    <button id="submitBtn">提交批量写入</button>
</div>
<div id="status" class="error"></div>
<hr>
<div id="itemsContainer"></div>
<button class="btn btn-secondary" id="addItemBtn">+ 添加键值对</button>

<script>
    // API 基础路径 (相对当前页面)
    const API_BASE = '/api';

    let items = [];          // 存储当前所有条目

    // 渲染所有条目表单
    function renderItems() {
        const container = document.getElementById('itemsContainer');
        if (!container) return;
        container.innerHTML = '';
        items.forEach((item, idx) => {
            const div = document.createElement('div');
            div.className = 'item';
            div.dataset.index = idx;
            div.innerHTML = \`
                <div class="item-header">键值对 #\${idx+1}</div>
                <div class="flex">
                    <label>Key<span style="color: red;">*</span> </label>
                    <input type="text" class="key-input" value="\${escapeHtml(item.key || '')}" placeholder="键名" style="width: 200px;">
                    <label>使用上传文件 </label>
                    <input type="checkbox" class="use-file-checkbox" \${item.useFile ? 'checked' : ''}>
                    <label style="margin-left: 8px;">纯文本/文件<span style="color: red;">*</span></label>
                </div>
                <div class="value-area">
                    <textarea class="text-value" placeholder="文本值 (当未勾选文件上传时生效)" style="\${item.useFile ? 'display:none' : ''}">\${escapeHtml(item.textValue || '')}</textarea>
                    <input type="file" class="file-value" style="\${item.useFile ? '' : 'display:none'}">
                </div>
                <div class="flex" style="margin-top: 8px;">
                    <label>元数据(JSON): </label>
                    <input type="text" class="metadata" placeholder='{"contentType":"image/png"}' value='\${escapeJson(item.metadataStr || '')}' style="width: 260px;">
                    <label>相对过期(秒): </label>
                    <input type="number" class="expiration-ttl" placeholder="expiration_ttl" value="\${item.expirationTtl !== undefined ? item.expirationTtl : ''}" style="width: 200px;">
                    <label>绝对过期(unix秒): </label>
                    <input type="number" class="expiration" placeholder="expiration" value="\${item.expiration !== undefined ? item.expiration : ''}" style="width: 200px;">
                    <button class="remove-item" data-idx="\${idx}">删除</button>
                </div>
            \`;
            container.appendChild(div);

            // 绑定事件 (使用事件委托方式，避免重复绑定，但为清晰直接在渲染后绑定)
            const keyInput = div.querySelector('.key-input');
            const useFileCheck = div.querySelector('.use-file-checkbox');
            const textArea = div.querySelector('.text-value');
            const fileInput = div.querySelector('.file-value');
            const metadataInput = div.querySelector('.metadata');
            const expTtlInput = div.querySelector('.expiration-ttl');
            const expInput = div.querySelector('.expiration');
            const removeBtn = div.querySelector('.remove-item');

            // 更新数据模型
            keyInput.addEventListener('input', (e) => { items[idx].key = e.target.value; });
            useFileCheck.addEventListener('change', (e) => {
                items[idx].useFile = e.target.checked;
                textArea.style.display = e.target.checked ? 'none' : '';
                fileInput.style.display = e.target.checked ? '' : 'none';
                // 清除文件选择的值
                if (!e.target.checked) fileInput.value = '';
            });
            textArea.addEventListener('input', (e) => { items[idx].textValue = e.target.value; });
            fileInput.addEventListener('change', (e) => {
                if (e.target.files && e.target.files[0]) {
                    items[idx].file = e.target.files[0];
                } else {
                    items[idx].file = null;
                }
            });
            metadataInput.addEventListener('input', (e) => { items[idx].metadataStr = e.target.value; });
            expTtlInput.addEventListener('input', (e) => { items[idx].expirationTtl = e.target.value ? Number(e.target.value) : undefined; });
            expInput.addEventListener('input', (e) => { items[idx].expiration = e.target.value ? Number(e.target.value) : undefined; });
            removeBtn.addEventListener('click', () => {
                items.splice(idx, 1);
                renderItems();
            });
        });
    }

    // 辅助: 简单防XSS
    function escapeHtml(str) {
        if (!str) return '';
        return String(str).replace(/[&<>]/g, function(m) {
            if (m === '&') return '&amp;';
            if (m === '<') return '&lt;';
            if (m === '>') return '&gt;';
            return m;
        });
    }
    function escapeJson(str) {
        if (!str) return '';
        return String(str).replace(/"/g, '&quot;');
    }

    // 添加空白条目
    function addItem() {
        items.push({
            key: '',
            useFile: false,
            textValue: '',
            file: null,
            metadataStr: '',
            expirationTtl: undefined,
            expiration: undefined
        });
        renderItems();
    }

    // 将文件读取为 base64 (纯字符串)
    function fileToBase64(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => {
                let result = reader.result;
                // 去除 data:xxx;base64, 前缀
                const commaIdx = result.indexOf(',');
                const base64 = commaIdx !== -1 ? result.substring(commaIdx + 1) : result;
                resolve(base64);
            };
            reader.onerror = () => reject(new Error('文件读取失败'));
            reader.readAsDataURL(file);
        });
    }

    // 构建批量请求体 (每个元素符合 Cloudflare bulk 格式)
    async function buildBulkPayload() {
        const payload = [];
        for (let i = 0; i < items.length; i++) {
            const it = items[i];
            if (!it.key || it.key.trim() === '') {
                throw new Error(\`第 \${i+1} 个键值对缺少 key\`);
            }
            const kvItem = { key: it.key.trim() };
            
            // 处理value: 若使用文件且文件存在则转base64; 否则使用文本值
            if (it.useFile && it.file) {
                const base64Str = await fileToBase64(it.file);
                kvItem.value = base64Str;
                kvItem.base64 = true;      // 标记 base64 编码
            } else {
                // 文本模式: 直接字符串
                if (it.textValue === undefined || it.textValue === null) {
                    kvItem.value = '';
                } else {
                    kvItem.value = it.textValue;
                }
                // 文本模式不设置 base64 标记
            }
            
            // 元数据: 尝试解析 JSON
            if (it.metadataStr && it.metadataStr.trim() !== '') {
                try {
                    kvItem.metadata = JSON.parse(it.metadataStr);
                } catch (e) {
                    throw new Error(\`第 \${i+1} 条元数据不是合法 JSON: \${e.message}\`);
                }
            }
            if (it.expirationTtl !== undefined && !isNaN(it.expirationTtl)) {
                kvItem.expiration_ttl = it.expirationTtl;
            }
            if (it.expiration !== undefined && !isNaN(it.expiration)) {
                kvItem.expiration = it.expiration;
            }
            payload.push(kvItem);
        }
        return payload;
    }

    // 提交批量写入
    async function submitBulkWrite() {
        const namespaceIdElem = document.getElementById('namespaceId');
        const namespaceId = namespaceIdElem ? namespaceIdElem.value.trim() : '';
        if (!namespaceId) {
            showStatus('请输入命名空间 ID', 'error');
            return;
        }
        if (items.length === 0) {
            showStatus('请至少添加一个键值对', 'error');
            return;
        }
        
        // 验证每条数据
        for (let i = 0; i < items.length; i++) {
            const it = items[i];
            if (!it.key || it.key.trim() === '') {
                showStatus(\`第 \${i+1} 个条目标题(key)为空\`, 'error');
                return;
            }
            if (it.useFile && !it.file) {
                showStatus(\`第 \${i+1} 个条目 (key: \${it.key}) 勾选了文件上传但没有选择文件\`, 'error');
                return;
            }
            if (!it.useFile && it.textValue === undefined) {
                // 允许空字符串
                items[i].textValue = '';
            }
        }

        let requestPayload;
        try {
            requestPayload = await buildBulkPayload();
        } catch (err) {
            showStatus(\`构建请求失败: \${err.message}\`, 'error');
            return;
        }

        if (requestPayload.length === 0) {
            showStatus('没有有效数据', 'error');
            return;
        }

        const url = \`\${API_BASE}/kv/\${encodeURIComponent(namespaceId)}/bulk\`;
        showStatus('正在提交...', 'info');

        try {
            const response = await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(requestPayload)
            });
            let result;
            const contentType = response.headers.get('content-type') || '';
            if (contentType.includes('application/json')) {
                result = await response.json();
            } else {
                const text = await response.text();
                throw new Error(\`服务器响应异常: \${response.status} \${text}\`);
            }
            if (!response.ok) {
                const errMsg = result.errors ? result.errors.map(e => e.message).join('; ') : (result.error || JSON.stringify(result));
                throw new Error(\`批量写入失败 (\${response.status}): \${errMsg}\`);
            }
            // Cloudflare bulk 成功返回 { success: true, errors: [], messages: [] }
            if (result.success === true || (result.errors && result.errors.length === 0)) {
                showStatus(\`批量写入成功！共写入 \${requestPayload.length} 条记录。\`, 'success');
                // 可选清空表单
                if (confirm('写入成功，是否清空当前列表并保留命名空间ID？')) {
                    items = [];
                    renderItems();
                } else {
                    // 不清空，但可以重置文件选择状态等
                    items.forEach(it => { it.file = null; });
                    renderItems();
                }
            } else {
                const errMsg = result.errors ? result.errors.map(e => e.message).join(', ') : '未知错误';
                throw new Error(\`批量写入失败: \${errMsg}\`);
            }
        } catch (err) {
            showStatus(\`错误: \${err.message}\`, 'error');
        }
    }

    function showStatus(msg, type) {
        const statusDiv = document.getElementById('status');
        if (!statusDiv) return;
        statusDiv.textContent = msg;
        statusDiv.className = type === 'error' ? 'error' : (type === 'success' ? 'success' : 'info');
        if (type !== 'info') {
            setTimeout(() => {
                if (statusDiv.textContent === msg) statusDiv.textContent = '';
            }, 5000);
        }
    }

    // 获取URL query参数支持?namespaceId=xxx 便捷填充
    function prefillNamespaceFromUrl() {
        const params = new URLSearchParams(window.location.search);
        const ns = params.get('namespaceId') || params.get('ns');
        if (ns && document.getElementById('namespaceId')) {
            document.getElementById('namespaceId').value = ns;
        }
    }

    // 初始化
    window.onload = () => {
        prefillNamespaceFromUrl();
        const container = document.getElementById('itemsContainer');
        if (container) {
            // 默认增加两个空白条目方便演示
            items = [];
            addItem(); // 第一条
            addItem(); // 第二条
        }
        const addBtn = document.getElementById('addItemBtn');
        if (addBtn) addBtn.onclick = () => addItem();
        const submitBtn = document.getElementById('submitBtn');
        if (submitBtn) submitBtn.onclick = () => submitBulkWrite();
    };
</script>
</body>
</html>
    `
    /*if (logined) {
        return buildHtmlResponse(html, acc, {
            littleNav: false,
            errorHandler: errHtml,
            homeUrl: '/list'
        });
    } else {
        return buildHtmlResponse(html, '', {
            littleNav: true,
            errorOverlay: {
                code: 401,
                message: '请先登录',
                redirectUrl: '/login',
                homeOnly: true
            },
            errorHandler: errHtml,
            homeUrl: '/'
        });
    }*/
    return buildHtmlResponse(html, acc, {
        littleNav: false,
        errorHandler: errHtml,
        homeUrl: '/list'
    });
}
//=================wtc=====================
// wtc日志查询/api/wtc
async function handleWtc(request, path, accountId, apiToken) {
    try {
        // 解析请求体
        const body = await request.json();
        // 验证参数
        const validationErrors = validateRequest(body);
        if (validationErrors.length > 0) {
            return new Response(JSON.stringify({
                success: false,
                errors: validationErrors
            }), {
                status: 400,
                headers: {
                    'Content-Type': 'application/json'
                }
            });
        }
        // 构建查询参数
        const query = buildQueryParameters(body);
        // 调用 Cloudflare API
        const apiResponse = await queryTelemetryAPI(accountId, apiToken, query);
        const responseData = await apiResponse.json();
        // 检查 API 响应是否成功
        if (!responseData.success) {
            return new Response(JSON.stringify(responseData, null, 2), {
                status: apiResponse.status,
                headers: {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                }
            });
        }
        // 提取有用信息
        const processedResult = {
            success: true,
            data: {
                invocations: extractUsefulLogInfo(responseData.result.invocations || {}),
                pagination: {
                    currentPage: body.page || 1,
                    pageSize: 10,
                    totalItems: responseData.result.statistics?.total || 0,
                    totalPages: Math.ceil((responseData.result.statistics?.total || 0) / 10)
                },
                statistics: {
                    elapsed: responseData.result.statistics?.elapsed || 0,
                    rowsRead: responseData.result.statistics?.rows_read || 0,
                    bytesRead: responseData.result.statistics?.bytes_read || 0
                },
                run: {
                    id: responseData.result.run?.id,
                    status: responseData.result.run?.status,
                    timeframe: responseData.result.run?.timeframe
                }
            }
        };
        // 如果请求指定了页码，添加分页链接
        const currentPage = body.page || 1;
        const totalPages = Math.ceil((responseData.result.statistics?.total || 0) / 10);
        if (totalPages > 1) {
            processedResult.data.pagination.links = {
                first: currentPage > 1 ? 1 : null,
                prev: currentPage > 1 ? currentPage - 1 : null,
                current: currentPage,
                next: currentPage < totalPages ? currentPage + 1 : null,
                last: currentPage < totalPages ? totalPages : null
            };
        }
        // 返回处理后的结果
        return new Response(JSON.stringify(processedResult, null, 2), {
            status: 200,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'POST, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type'
            }
        });
    } catch (error) {
        console.error('Error:', error);
        // 返回错误信息
        return new Response(JSON.stringify({
            success: false,
            error: {
                message: error.message
            }
        }), {
            status: 500,
            headers: {
                'Content-Type': 'application/json'
            }
        });
    }
}
// Cloudflare API 调用函数
async function queryTelemetryAPI(accountId, apiToken, query) {
    const apiUrl = `https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/observability/telemetry/query`;
    const response = await fetch(apiUrl, {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${apiToken}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(query)
    });
    return response;
}
// 映射操作符到 Cloudflare API 支持的格式
function mapOperator(operation) {
    const operatorMap = {
        'nin': 'not_in',
        'contains': 'includes'
    };
    return operatorMap[operation] || operation;
}
// 构建查询参数
function buildQueryParameters(body) {
    const query = {
        view: "invocations",
        queryId: "workers-logs-invocations",
        limit: 10,
        dry: false,
        parameters: {
            datasets: ["cloudflare-workers"],
            filters: [],
            calculations: [],
            groupBys: [],
            havings: []
        },
        timeframe: {
            from: body.from,
            to: body.to
        }
    };
    // Worker 名称过滤
    query.parameters.filters.push({
        key: "$metadata.service",
        type: "string",
        value: body.worker,
        operation: "eq"
    });
    // 过滤条件映射表
    const filterMap = {
        rayid: {
            key: "$metadata.requestId",
            type: "string"
        },
        status: {
            key: "$workers.event.response.status",
            type: "number"
        },
        path: {
            key: "$workers.event.request.path",
            type: "string"
        },
        country: {
            key: "$workers.event.request.cf.country",
            type: "string"
        },
        level: {
            key: "$metadata.level",
            type: "string"
        },
        method: {
            key: "$workers.event.request.method",
            type: "string"
        },
        outcome: {
            key: "$workers.outcome",
            type: "string"
        }
    };
    // 添加单值过滤条件
    for (const [key, config] of Object.entries(filterMap)) {
        if (body[key]) {
            if (typeof body[key] === 'object' && body[key].value !== undefined) {
                // 对象格式: { value: "xxx", operation: "eq" }
                const operation = mapOperator(body[key].operation || "eq");
                query.parameters.filters.push({
                    key: config.key,
                    type: config.type,
                    value: body[key].value,
                    operation: operation
                });
            } else {
                // 简单格式
                query.parameters.filters.push({
                    key: config.key,
                    type: config.type,
                    value: body[key],
                    operation: "eq"
                });
            }
        }
    }
    // 添加列表过滤条件 (in/not_in)
    /*
*现在不支持

for (const [key, config] of Object.entries(filterMap)) {
const inKey = `${key}_in`;
const ninKey = `${key}_nin`;

if (body[inKey] && Array.isArray(body[inKey])) {
query.parameters.filters.push({
key: config.key,
type: config.type,
value: body[inKey],
operation: "in"
});
}

if (body[ninKey] && Array.isArray(body[ninKey])) {
query.parameters.filters.push({
key: config.key,
type: config.type,
value: body[ninKey],
operation: "not_in"
});
}
}
*/
    // 路径包含条件
    if (body.path_contains) {
        query.parameters.filters.push({
            key: "$workers.event.request.path",
            type: "string",
            value: body.path_contains,
            operation: "includes"
        });
    }
    // 分页处理
    if (body.page && body.page > 1) {
        query.offset = (body.page - 1) * 10;
    }
    return query;
}
// 验证请求参数
function validateRequest(body) {
    const errors = [];
    if (!body.worker) errors.push('worker name is required');
    if (!body.from) errors.push('from timestamp is required');
    if (!body.to) errors.push('to timestamp is required');
    // 验证时间戳格式
    if (body.from && typeof body.from !== 'number') errors.push('from must be a number (timestamp in milliseconds)');
    if (body.to && typeof body.to !== 'number') errors.push('to must be a number (timestamp in milliseconds)');
    // 验证时间范围
    if (body.from && body.to && body.from >= body.to) {
        errors.push('from timestamp must be less than to timestamp');
    }
    // 验证列表类型的值必须是数组
    /*
*现在不支持
const listFields = ['status_in',
'status_nin',
'country_in',
'country_nin',
'level_in',
'level_nin',
'method_in',
'method_nin'];
listFields.forEach(field => {
if (body[field] && !Array.isArray(body[field])) {
errors.push(`${field} must be an array`);
}
});
*/
    return errors;
}
// 提取有用的日志信息
function extractUsefulLogInfo(invocations) {
    const result = {};
    for (const [requestId, logs] of Object.entries(invocations)) {
        result[requestId] = logs.map(log => {
            // 构建精简的日志信息
            const usefulLog = {
                timestamp: log.timestamp,
                dataset: log.dataset,
                metadata: {
                    id: log.$metadata?.id,
                    trigger: log.$metadata?.trigger,
                    service: log.$metadata?.service,
                    level: log.$metadata?.level,
                    fingerprint: log.$metadata?.fingerprint
                },
                workers: {
                    scriptName: log.$workers?.scriptName,
                    outcome: log.$workers?.outcome,
                    requestId: log.$workers?.requestId,
                    cpuTimeMs: log.$workers?.cpuTimeMs,
                    wallTimeMs: log.$workers?.wallTimeMs
                },
                source: log.source || null
            };
            // 请求信息
            if (log.$workers?.event?.request) {
                usefulLog.request = {
                    url: log.$workers.event.request.url,
                    method: log.$workers.event.request.method,
                    path: log.$workers.event.request.path,
                    cf: {
                        colo: log.$workers.event.request.cf?.colo,
                        country: log.$workers.event.request.cf?.country,
                        city: log.$workers.event.request.cf?.city,
                        asOrganization: log.$workers.event.request.cf?.asOrganization
                    }
                };
            }
            // 响应信息
            if (log.$workers?.event?.response) {
                usefulLog.response = {
                    status: log.$workers.event.response.status
                };
            }
            return usefulLog;
        });
    }
    return result;
}
// wtc页面 /wtc
function handleWtcPage(acc, logined) {
    const html = `<!DOCTYPE html>
        <html lang="zh-CN">
        <head>
        <meta charset="UTF-8">
        <link rel="icon" href="/favicon.svg" type="image/svg+xml">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Worker 编辑器|日志查询</title>
        <link rel="stylesheet" href="/static/style.css">
        <style>
        .wtc-container {
        max-width: 1400px;
        margin: 0 auto;
        padding: 1.5rem;
        }
        .form-section, .results-section {
        margin-bottom: 2rem;
        }
        .form-row {
        display: flex;
        flex-wrap: wrap;
        gap: 1rem;
        margin-bottom: 1rem;
        }
        .form-row > div {
        flex: 1;
        min-width: 200px;
        }
        .filter-row {
        background: var(--surface-color);
        padding: 1rem;
        border-radius: var(--radius);
        margin-bottom: 0.75rem;
        border: 1px solid var(--border-color);
        }
        .invocation {
        border: 1px solid var(--border-color);
        margin-bottom: 1rem;
        border-radius: var(--radius);
        overflow: hidden;
        background: var(--surface-color);
        }
        .invocation-header {
        background: var(--primary-light);
        padding: 1rem;
        font-weight: 600;
        cursor: pointer;
        display: flex;
        flex-wrap: wrap;
        gap: 1.5rem;
        align-items: center;
        }
        .invocation-details {
        padding: 1.5rem;
        display: none;
        }
        .metadata-grid {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
        gap: 0.75rem;
        margin-bottom: 1rem;
        }
        .metadata-item {
        background: var(--bg-color);
        padding: 0.75rem;
        border-radius: var(--radius);
        border: 1px solid var(--border-color);
        }
        .metadata-label {
        font-weight: 600;
        color: var(--text-secondary);
        font-size: 0.875rem;
        margin-bottom: 0.25rem;
        }
        .pagination {
        display: flex;
        flex-wrap: wrap;
        gap: 0.5rem;
        margin-top: 1.5rem;
        align-items: center;
        }
        .page-btn {
        padding: 0.375rem 0.75rem;
        background: var(--surface-color);
        color: var(--text-color);
        border: 1px solid var(--border-color);
        border-radius: var(--radius);
        cursor: pointer;
        font-size: 0.875rem;
        }
        .page-btn.active {
        background: var(--primary-color);
        color: white;
        border-color: var(--primary-color);
        }
        .page-btn:disabled {
        opacity: 0.5;
        cursor: not-allowed;
        }
        .stats {
        background: var(--surface-color);
        padding: 1rem;
        border-radius: var(--radius);
        margin-bottom: 1rem;
        border: 1px solid var(--border-color);
        }
        .modal {
        display: none;
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0,0,0,0.5);
        z-index: 1000;
        overflow-y: auto;
        padding: 1rem;
        }
        .modal-content {
        background: var(--bg-color);
        margin: 2rem auto;
        padding: 2.5rem 1.5rem 1.5rem;
        border-radius: var(--radius);
        max-width: 900px;
        width: 100%;
        border: 1px solid var(--border-color);
        box-shadow: 0 10px 25px rgba(0,0,0,0.1);
        position: relative;
        }
        .modal-close {
        position: absolute;
        top: 0.75rem;
        right: 1.5rem;
        font-size: 1.5rem;
        cursor: pointer;
        color: var(--text-secondary);
        line-height: 1;
        }
        .modal-close:hover {
        color: var(--text-color);
        }
        .modal-tabs {
        display: flex;
        border-bottom: 1px solid var(--border-color);
        margin-bottom: 1rem;
        }
        .modal-tab {
        padding: 0.5rem 1rem;
        cursor: pointer;
        border: none;
        background: none;
        color: var(--text-secondary);
        border-bottom: 2px solid transparent;
        }
        .modal-tab.active {
        color: var(--primary-color);
        border-bottom-color: var(--primary-color);
        }
        .modal-tab-content {
        display: none;
        }
        .modal-tab-content.active {
        display: block;
        }
        .modal-tab-content pre {
        background: var(--surface-color);
        padding: 0.75rem;
        border-radius: var(--radius);
        max-height: 300px;
        overflow: auto;
        margin: 0;
        }
        .error {
        overflow-wrap: break-word;
        word-wrap: break-word;
        word-break: break-word;
        }
        .input-hint {
        font-size: 0.75rem;
        color: var(--text-secondary);
        margin-top: 0.25rem;
        }

        @media (max-width: 768px) {
        .wtc-container { padding: 1rem; }
        .form-row > div { flex: 1 0 100%; }
        .metadata-grid { grid-template-columns: 1fr; }
        .invocation-header { gap: 0.75rem; }
        .modal-content { margin: 1rem auto; padding: 1rem; }
        }
        </style>
        </head>
        <body>
        {{NAVBAR}}
        <main>
        <div class="wtc-container card">
        <h1>Worker Telemetry 查询</h1>

        <div class="form-section">
        <h2>查询条件</h2>
        <div class="form-row">
        <div>
        <label>Worker名称 <span style="color: var(--danger-color);">*</span></label>
        <input type="text" id="worker" value="" placeholder="例如: auth-service">
        <div class="input-hint">需要查询的Worker脚本名称</div>
        </div>
        <div>
        <label>开始时间 <span style="color: var(--danger-color);">*</span></label>
        <input type="datetime-local" id="from">
        <div class="input-hint">查询开始时间</div>
        </div>
        <div>
        <label>结束时间 <span style="color: var(--danger-color);">*</span></label>
        <input type="datetime-local" id="to">
        <div class="input-hint">查询结束时间</div>
        </div>
        </div>

        <h3>过滤条件</h3>
        <div id="filters-container"></div>
        <button class="btn btn-secondary" id="add-filter">添加过滤条件</button>

        <div class="mt-3">
        <button class="btn" id="query-btn">查询</button>
        <button class="btn btn-secondary" id="reset-btn">重置</button>
        </div>
        </div>

        <div class="results-section">
        <h2>查询结果</h2>
        <div id="stats" class="stats" style="display: none;"></div>
        <div id="error" class="error" style="display: none;"></div>
        <div id="loading" class="loading" style="display: none;">查询中...</div>
        <div id="results"></div>
        <div id="pagination" class="pagination" style="display: none;"></div>
        </div>
        </div>

        <!-- 模态框 -->
        <div id="modal" class="modal">
        <div class="modal-content">
        <span class="modal-close" id="modal-close">&times;</span>
        <div class="modal-tabs">
        <button class="modal-tab active" data-tab="details">详细信息</button>
        <button class="modal-tab" data-tab="json">原始JSON</button>
        </div>
        <div id="modal-details" class="modal-tab-content active"></div>
        <div id="modal-json" class="modal-tab-content">
        <pre id="json-content"></pre>
        </div>
        </div>
        </div>
        </main>
        <script>
        // 从URL参数获取初始值
        const urlParams = new URLSearchParams(window.location.search);
        const initialWorker = urlParams.get('worker') || '';
        document.getElementById('worker').value = initialWorker;

        // 设置默认时间范围（最近1小时）
        const now = new Date();
        const oneHourAgo = new Date(now.getTime() - 60*60*1000);
        document.getElementById('from').value = formatDateTimeLocal(oneHourAgo);
        document.getElementById('to').value = formatDateTimeLocal(now);

        // 过滤条件配置
        const filterTypes = [
        { id: 'status', label: 'HTTP状态码', type: 'number', hint: '例如: 200, 404, 500' },
        { id: 'level', label: '日志级别', type: 'select', options: ['info', 'error', 'warning'], hint: '选择日志级别' },
        { id: 'country', label: '国家代码', type: 'text', hint: '例如: US, CN, JP' },
        { id: 'method', label: '请求方法', type: 'select', options: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'], hint: '选择HTTP方法' },
        { id: 'outcome', label: '请求结果', type: 'text', hint: '例如: exception, success' },
        { id: 'path_contains', label: '路径包含', type: 'text', hint: '例如: /api, /auth' },
        { id: 'rayid', label: '请求ID', type: 'text', hint: '精确匹配请求ID' }
        ];

        let currentPage = 1;
        let totalPages = 1;
        let currentQueryParams = null;
        let currentLogData = null;

        // 添加过滤条件
        document.getElementById('add-filter').addEventListener('click', function() {
        addFilterRow();
        });

        // 查询按钮
        document.getElementById('query-btn').addEventListener('click', function() {
        queryData(1);
        });

        // 重置按钮
        document.getElementById('reset-btn').addEventListener('click', function() {
        document.getElementById('worker').value = '';
        document.getElementById('from').value = '';
        document.getElementById('to').value = '';
        document.getElementById('filters-container').innerHTML = '';
        document.getElementById('results').innerHTML = '';
        document.getElementById('pagination').style.display = 'none';
        document.getElementById('error').style.display = 'none';
        document.getElementById('stats').style.display = 'none';
        });

        // 模态框关闭
        document.getElementById('modal-close').addEventListener('click', function() {
        document.getElementById('modal').style.display = 'none';
        });

        // 点击模态框外部关闭
        window.addEventListener('click', function(event) {
        const modal = document.getElementById('modal');
        if (event.target === modal) {
        modal.style.display = 'none';
        }
        });

        // 选项卡切换
        document.addEventListener('click', function(event) {
        if (event.target.classList.contains('modal-tab')) {
        const tabId = event.target.getAttribute('data-tab');
        const tabs = document.querySelectorAll('.modal-tab');
        const tabContents = document.querySelectorAll('.modal-tab-content');

        tabs.forEach(tab => tab.classList.remove('active'));
        tabContents.forEach(content => content.classList.remove('active'));

        event.target.classList.add('active');
        document.getElementById(\`modal-\${tabId}\`).classList.add('active');
        }
        });

        // 添加过滤条件行
        function addFilterRow(filterType = '', filterValue = '') {
        const container = document.getElementById('filters-container');
        const filterId = 'filter_' + Date.now() + Math.random();

        const filterRow = document.createElement('div');
        filterRow.className = 'filter-row';
        filterRow.id = filterId;

        let optionsHtml = filterTypes.map(type =>
        \`<option value="\${type.id}" \${filterType === type.id ? 'selected' : ''}>\${type.label}</option>\`
        ).join('');

        filterRow.innerHTML = \`
        <div style="display: flex; flex-wrap: wrap; gap: 0.75rem; align-items: flex-start;">
        <div style="flex: 1; min-width: 150px;">
        <label>条件类型</label>
        <select class="filter-type" style="width: 100%;">
        <option value="">-- 选择条件 --</option>
        \${optionsHtml}
        </select>
        </div>
        <div id="value-container-\${filterId}" style="flex: 2; min-width: 200px;"></div>
        <div style="align-self: center;">
        <button class="btn btn-danger" onclick="removeFilter('\${filterId}')" style="padding: 0.375rem 0.75rem; font-size: 0.875rem;">删除</button>
        </div>
        </div>
        \`;

        container.appendChild(filterRow);

        // 绑定类型更改事件
        const typeSelect = filterRow.querySelector('.filter-type');
        typeSelect.addEventListener('change', function() {
        updateFilterValueInput(this.value, filterId, filterValue);
        });

        // 如果有初始值，设置类型并生成输入框
        if (filterType) {
        updateFilterValueInput(filterType, filterId, filterValue);
        }
        }

        // 删除过滤条件
        window.removeFilter = function(filterId) {
        const filterRow = document.getElementById(filterId);
        if (filterRow) {
        filterRow.remove();
        }
        };

        // 更新过滤器值输入框
        function updateFilterValueInput(filterType, filterId, initialValue = '') {
        const container = document.getElementById(\`value-container-\${filterId}\`);
        const filterConfig = filterTypes.find(f => f.id === filterType);

        if (!filterConfig) {
        container.innerHTML = '';
        return;
        }

        let inputHtml = '';

        if (filterConfig.type === 'select') {
        let options = filterConfig.options.map(opt =>
        \`<option value="\${opt}" \${initialValue === opt ? 'selected' : ''}>\${opt}</option>\`
        ).join('');
        inputHtml = \`
        <div>
        <label>值</label>
        <select class="filter-value" style="width: 100%; max-width: 200px;">
        \${options}
        </select>
        <div class="input-hint">\${filterConfig.hint || ''}</div>
        </div>
        \`;
        } else {
        const placeholder = filterConfig.hint || '';
        inputHtml = \`
        <div>
        <label>值</label>
        <input type="\${filterConfig.type}" class="filter-value" value="\${initialValue}"
        placeholder="\${placeholder}" style="width: 100%;">
        <div class="input-hint">\${filterConfig.hint || ''}</div>
        </div>
        \`;
        }

        container.innerHTML = inputHtml;
        }

        // 查询数据
        async function queryData(page = 1) {
        const worker = document.getElementById('worker').value.trim();
        const fromInput = document.getElementById('from').value;
        const toInput = document.getElementById('to').value;

        if (!worker || !fromInput || !toInput) {
        showError('请填写所有必填字段（Worker名称、开始时间、结束时间）');
        return;
        }

        const from = new Date(fromInput).getTime();
        const to = new Date(toInput).getTime();

        if (isNaN(from) || isNaN(to)) {
        showError('时间格式无效');
        return;
        }

        if (from >= to) {
        showError('开始时间必须早于结束时间');
        return;
        }

        const params = { worker, from, to };
        if (page > 1) params.page = page;

        const filterRows = document.querySelectorAll('.filter-row');
        filterRows.forEach(row => {
        const typeSelect = row.querySelector('.filter-type');
        const valueInput = row.querySelector('.filter-value');

        if (typeSelect && typeSelect.value && valueInput) {
        const type = typeSelect.value;
        let value = valueInput.value;

        if (type === 'status') {
        value = parseInt(value);
        if (isNaN(value)) return;
        }

        params[type] = value;
        }
        });

        currentQueryParams = params;
        currentPage = page;

        document.getElementById('loading').style.display = 'block';
        document.getElementById('error').style.display = 'none';
        document.getElementById('results').innerHTML = '';
        document.getElementById('pagination').style.display = 'none';
        document.getElementById('stats').style.display = 'none';

        try {
        const response = await fetch('/api/wtc', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(params)
        });

        const data = await response.json();
        document.getElementById('loading').style.display = 'none';

        if (data.success) {
        displayResults(data.data);
        } else {
        if (data.errors && Array.isArray(data.errors)) {
        showError(data.errors.join(', '));
        } else if (data.error && data.error.message) {
        showError(data.error.message);
        } else {
        showError('查询失败: ' + JSON.stringify(data));
        }
        }
        } catch (error) {
        document.getElementById('loading').style.display = 'none';
        showError('网络错误: ' + error.message);
        }
        }

        // 显示结果
        function displayResults(data) {
        const resultsContainer = document.getElementById('results');
        const paginationContainer = document.getElementById('pagination');
        const statsContainer = document.getElementById('stats');

        currentLogData = data.invocations;

        if (data.statistics) {
        statsContainer.innerHTML = \`
        <div style="margin-bottom: 0.5rem; color: var(--text-color); font-weight: 600;">查询统计:</div>
        <div>查询耗时: \${data.statistics.elapsed}秒</div>
        <div>读取行数: \${data.statistics.rowsRead}</div>
        <div>读取字节数: \${data.statistics.bytesRead}</div>
        \`;
        statsContainer.style.display = 'block';
        }

        if (data.pagination) {
        totalPages = data.pagination.totalPages;
        renderPagination();
        paginationContainer.style.display = 'flex';
        }

        if (data.invocations && Object.keys(data.invocations).length > 0) {
        let resultsHtml = '<h3>查询结果 (' + Object.keys(data.invocations).length + ' 个请求)</h3>';

        Object.entries(data.invocations).forEach(([requestId, logs], index) => {
        if (logs.length > 0) {
        const firstLog = logs[0];
        const timestamp = new Date(firstLog.timestamp).toLocaleString();
        const scriptName = firstLog.workers?.scriptName || 'N/A';
        const status = firstLog.response?.status || 'N/A';

        resultsHtml += \`
        <div class="invocation">
        <div class="invocation-header" onclick="openModal('\${requestId}', \${index})">
        <div>\${timestamp}</div>
        <div><strong>请求ID:</strong> \${requestId.substring(0, 16)}...</div>
        <div><strong>Worker:</strong> \${scriptName}</div>
        <div><strong>状态:</strong> \${status}</div>
        </div>
        </div>
        \`;
        }
        });

        resultsContainer.innerHTML = resultsHtml;
        } else {
        resultsContainer.innerHTML = '<p>没有找到匹配的数据</p>';
        }
        }

        // 打开模态框
        window.openModal = function(requestId, logIndex) {
        if (!currentLogData || !currentLogData[requestId]) {
        showError('日志数据不可用');
        return;
        }

        const logs = currentLogData[requestId];
        const modal = document.getElementById('modal');
        const detailsContainer = document.getElementById('modal-details');
        const jsonContainer = document.getElementById('json-content');

        let detailsHtml = '';

        logs.forEach((log, index) => {
        const timestamp = new Date(log.timestamp).toLocaleString();

        detailsHtml += \`
        <h4>日志记录 \${index + 1} (\${timestamp})</h4>
        <div class="metadata-grid">
        \${renderMetadataItem('日志ID', log.metadata?.id)}
        \${renderMetadataItem('触发事件', log.metadata?.trigger)}
        \${renderMetadataItem('服务名称', log.metadata?.service)}
        \${renderMetadataItem('日志级别', log.metadata?.level)}
        \${renderMetadataItem('错误指纹', log.metadata?.fingerprint)}
        \${renderMetadataItem('执行结果', log.workers?.outcome)}
        \${renderMetadataItem('CPU时间', log.workers?.cpuTimeMs ? log.workers.cpuTimeMs + 'ms' : 'N/A')}
        \${renderMetadataItem('实际时间', log.workers?.wallTimeMs ? log.workers.wallTimeMs + 'ms' : 'N/A')}
        \${renderMetadataItem('请求ID', log.workers?.requestId)}
        \${renderMetadataItem('HTTP方法', log.request?.method)}
        \${renderMetadataItem('请求URL', log.request?.url)}
        \${renderMetadataItem('请求路径', log.request?.path)}
        \${renderMetadataItem('状态码', log.response?.status)}
        \${renderMetadataItem('数据中心', log.request?.cf?.colo)}
        \${renderMetadataItem('国家', log.request?.cf?.country)}
        \${renderMetadataItem('城市', log.request?.cf?.city)}
        \${renderMetadataItem('网络运营商', log.request?.cf?.asOrganization)}
        </div>
        \`;

        if (log.source?.message || log.source?.exception) {
        detailsHtml += '<h5 style="margin-top: 1rem;">错误信息</h5>';

        if (log.source.message) {
        detailsHtml += \`<p style="word-break: break-word; overflow-wrap: break-word;"><strong>消息:</strong> \${log.source.message}</p>\`;
        }

        if (log.source.exception) {
        detailsHtml += \`<p style="word-break: break-word; overflow-wrap: break-word;"><strong>异常类型:</strong> \${log.source.exception.name || 'N/A'}</p>\`;
        detailsHtml += \`<p style="word-break: break-word; overflow-wrap: break-word;"><strong>异常消息:</strong> \${log.source.exception.message || 'N/A'}</p>\`;

        if (log.source.exception.stack) {
        detailsHtml += '<p><strong>堆栈跟踪:</strong></p>';
        detailsHtml += \`<pre style="background: var(--surface-color); padding: 0.75rem; border-radius: var(--radius); max-height: 200px; overflow: auto; word-break: break-word; overflow-wrap: break-word; white-space: pre-wrap;">\${log.source.exception.stack}</pre>\`;
        }
        }
        }

        if (index < logs.length - 1) {
        detailsHtml += '<hr style="margin: 1.5rem 0; border-color: var(--border-color);">';
        }
        });

        detailsContainer.innerHTML = detailsHtml;
        jsonContainer.textContent = JSON.stringify({[requestId]: logs}, null, 2);
        modal.style.display = 'block';
        };

        // 渲染元数据项
        function renderMetadataItem(label, value) {
        if (value === undefined || value === null || value === '') {
        return '';
        }

        return \`
        <div class="metadata-item">
        <div class="metadata-label">\${label}</div>
        <div style="word-break: break-all; font-family: monospace; font-size: 0.875rem;">\${value}</div>
        </div>
        \`;
        }

        // 渲染分页
        function renderPagination() {
        const paginationContainer = document.getElementById('pagination');

        let paginationHtml = '';
        paginationHtml += \`<button class="page-btn" onclick="changePage(1)" \${currentPage === 1 ? 'disabled' : ''}>第一页</button>\`;
        paginationHtml += \`<button class="page-btn" onclick="changePage(\${currentPage - 1})" \${currentPage === 1 ? 'disabled' : ''}>上一页</button>\`;

        const startPage = Math.max(1, currentPage - 2);
        const endPage = Math.min(totalPages, startPage + 4);

        for (let i = startPage; i <= endPage; i++) {
        paginationHtml += \`<button class="page-btn \${i === currentPage ? 'active' : ''}" onclick="changePage(\${i})">\${i}</button>\`;
        }

        paginationHtml += \`<button class="page-btn" onclick="changePage(\${currentPage + 1})" \${currentPage === totalPages ? 'disabled' : ''}>下一页</button>\`;
        paginationHtml += \`<button class="page-btn" onclick="changePage(\${totalPages})" \${currentPage === totalPages ? 'disabled' : ''}>最后一页</button>\`;
        paginationHtml += \`<span style="margin-left: 0.75rem; color: var(--text-secondary);">第 \${currentPage} 页，共 \${totalPages} 页</span>\`;

        paginationContainer.innerHTML = paginationHtml;
        }

        // 切换页面
        window.changePage = function(page) {
        if (page >= 1 && page <= totalPages && page !== currentPage) {
        queryData(page);
        }
        };

        // 显示错误
        function showError(message) {
        const errorContainer = document.getElementById('error');
        errorContainer.innerHTML = \`<div style="color: var(--danger-color);">错误: \${message}</div>\`;
        errorContainer.style.display = 'block';
        }

        // 格式化日期时间
        function formatDateTimeLocal(date) {
        const year = date.getFullYear();
        const month = String(date.getMonth() + 1).padStart(2, '0');
        const day = String(date.getDate()).padStart(2, '0');
        const hours = String(date.getHours()).padStart(2, '0');
        const minutes = String(date.getMinutes()).padStart(2, '0');
        return \`\${year}-\${month}-\${day}T\${hours}:\${minutes}\`;
        }

        // 从URL参数初始化
        function initFromUrlParams() {
        const filterKeys = ['status', 'level', 'country', 'method', 'outcome', 'path_contains', 'rayid'];

        filterKeys.forEach(key => {
        const value = urlParams.get(key);
        if (value) {
        addFilterRow(key, value);
        }
        });

        if (initialWorker && urlParams.get('from') && urlParams.get('to')) {
        const fromParam = urlParams.get('from');
        const toParam = urlParams.get('to');

        if (fromParam && !isNaN(parseInt(fromParam))) {
        document.getElementById('from').value = formatDateTimeLocal(new Date(parseInt(fromParam)));
        }

        if (toParam && !isNaN(parseInt(toParam))) {
        document.getElementById('to').value = formatDateTimeLocal(new Date(parseInt(toParam)));
        }

        setTimeout(() => { queryData(1); }, 500);
        }
        }

        // 初始化
        (function init() {
        // 确保DOM已加载
        if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initializeUI);
        } else {
        initializeUI();
        }
        })();

        function initializeUI() {
        addUrlEncodedField();
        addFormDataField();
        changeBodyType();
        }
        </script>
        </body>
        </html>`;
    /*if (logined) {
        return buildHtmlResponse(html, acc, {
            littleNav: false,
            errorHandler: errHtml,
            homeUrl: '/list'
        });
    } else {
        return buildHtmlResponse(html, '', {
            littleNav: true,
            errorOverlay: {
                code: 401,
                message: '请先登录',
                redirectUrl: '/login',
                homeOnly: true
            },
            errorHandler: errHtml,
            homeUrl: '/'
        });
    }*/
    return buildHtmlResponse(html, acc, {
        littleNav: false,
        errorHandler: errHtml,
        homeUrl: '/list'
    });
}
//===============binding===================
// 绑定管理/api/bindings
async function handleBindings(request, url, accountId, token) {
    const path = url.pathname;
    // 检查是否为密钥相关路径
    if (path.startsWith('/api/bindings/secret/')) {
        return handleSecrets(request, path, accountId, token);
    }
    // 绑定相关逻辑
    const scriptName = path.replace('/api/bindings/', '');
    if (!scriptName) {
        return new Response('Worker script name is required', {
            status: 400
        });
    }
    const apiBase = `https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/${scriptName}`;
    switch (request.method) {
        case 'GET':
            return handleGetBindings(apiBase, accountId, token);
        case 'PATCH':
            return handleUpdateBindings(apiBase, request, accountId, token);
        case 'POST':
            return handleSecretOperation(apiBase, request, accountId, token, scriptName);
        case 'DELETE':
            return handleDeleteSecret(apiBase, request, accountId, token, scriptName);
        default:
            return new Response('Method not allowed', {
                status: 405
            });
    }
    return new Response(JSON.stringify({
        success: false,
        error: "Not Found"
    }), {
        status: 404,
        headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        }
    });
}
// 处理密钥操作
async function handleSecretOperation(apiBase, request, accountId, token, scriptName) {
    try {
        const secretData = await request.json();
        const {
            name,
            text
        } = secretData;
        if (!name || !text) {
            return new Response(JSON.stringify({
                success: false,
                error: 'Missing name or text in request body'
            }), {
                status: 400,
                headers: {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                }
            });
        }
        const secretsApi = `https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/${scriptName}/secrets`;
        const response = await fetch(secretsApi, {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                name: name,
                text: text,
                type: 'secret_text'
            })
        });
        return new Response(await response.text(), {
            status: response.status,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });
    } catch (error) {
        return new Response(JSON.stringify({
            success: false,
            error: error.message
        }), {
            status: 500,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });
    }
}
// 处理密钥删除
async function handleDeleteSecret(apiBase, request, accountId, token, scriptName) {
    try {
        // 从请求URL中获取密钥名称
        const url = new URL(request.url);
        const secretName = url.searchParams.get('name');
        if (!secretName) {
            return new Response(JSON.stringify({
                success: false,
                error: 'Missing secret name in query parameter'
            }), {
                status: 400,
                headers: {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                }
            });
        }
        const secretsApi = `https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/${scriptName}/secrets/${secretName}`;
        const response = await fetch(secretsApi, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        });
        return new Response(await response.text(), {
            status: response.status,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });
    } catch (error) {
        return new Response(JSON.stringify({
            success: false,
            error: error.message
        }), {
            status: 500,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });
    }
}
// 密钥管理
async function handleSecrets(request, path, accountId, token) {
    // 解析路径: /api/bindings/secret/scriptName 或 /api/bindings/secret/scriptName/secretName
    const pathParts = path.replace('/api/bindings/secret/', '').split('/');
    const scriptName = pathParts[0];
    if (!scriptName) {
        return new Response('Worker script name is required', {
            status: 400
        });
    }
    const secretName = pathParts.length > 1 ? pathParts[1] : null;
    const apiBase = `https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/${scriptName}/secrets`;
    switch (request.method) {
        case 'GET':
            // 获取密钥列表或单个密钥
            const secretUrl = secretName ? `${apiBase}/${secretName}` : `${apiBase}/`;
            return fetch(secretUrl, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });
        case 'PUT':
            // 创建或更新密钥（需要请求体包含 name 和 text）
            try {
                const body = await request.json();
                const {
                    name,
                    text
                } = body;
                if (!name || !text) {
                    return new Response('Missing name or text in request body', {
                        status: 400
                    });
                }
                return fetch(`${apiBase}/`, {
                    method: 'PUT',
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        name: name,
                        text: text,
                        type: 'secret_text'
                    })
                });
            } catch (error) {
                return new Response('Invalid JSON body', {
                    status: 400
                });
            }
        case 'DELETE':
            // 删除特定密钥
            if (!secretName) {
                return new Response('Secret name is required for DELETE operation', {
                    status: 400
                });
            }
            return fetch(`${apiBase}/${secretName}`, {
                method: 'DELETE',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });
        default:
            return new Response('Method not allowed', {
                status: 405
            });
    }
    return new Response(JSON.stringify({
        success: false,
        error: "Not Found"
    }), {
        status: 404,
        headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        }
    });
}
// 获取绑定信息
async function handleGetBindings(apiBase, accountId, token, init = false) {
    try {
        const response = await fetch(`${apiBase}/bindings`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        });
        // 检查 HTTP 响应状态
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        let data;
        try {
            data = await response.json();
        } catch (jsonError) {
            throw new Error(`Invalid JSON response: ${jsonError.message}`);
        }
        // 格式化响应
        const formattedResult = {
            success: data.success || response.ok,
            errors: data.errors || [],
            messages: data.messages || [],
            bindings: data.result || []
        };
        if (init) return formattedResult;
        return new Response(JSON.stringify(formattedResult, null, 2), {
            status: response.status,
            headers: {
                'Content-Type': 'application/json',
                'Cache-Control': 'no-cache'
            }
        });
    } catch (error) {
        console.error('Error fetching bindings:', error);
        const errorResponse = {
            success: false,
            errors: [error.message],
            messages: [],
            result: null
        };
        if (init) return errorResponse;
        return new Response(JSON.stringify(errorResponse), {
            status: 500,
            headers: {
                'Content-Type': 'application/json'
            }
        });
    }
}
// 更新绑定信息
async function handleUpdateBindings(apiBase, request, accountId, token) {
    try {
        let requestBody;
        try {
            requestBody = await request.json();
        } catch (e) {
            return new Response('Invalid JSON in request body', { status: 400 });
        }

        if (!Array.isArray(requestBody.bindings)) {
            return new Response('Request body must contain "bindings" array', { status: 400 });
        }

        for (const binding of requestBody.bindings) {
            if (!binding.type || !binding.name) {
                return new Response('Each binding must have "type" and "name" fields', { status: 400 });
            }
            if (binding.type === 'secret_text') return new Response('Requests cannot contain "secret_text",which should be managed by using "/api/bindings/secret/"', { status: 400 });
        }

        const formData = new FormData();
        const settings = JSON.stringify({
            bindings: requestBody.bindings,
            keep_bindings: ["secret_text"]   // 保留所有 Secret，不随本次更新被覆盖
        });
        formData.append('settings', settings);

        const response = await fetch(`${apiBase}/settings`, {
            method: 'PATCH',
            headers: {
                'Authorization': `Bearer ${token}`,
            },
            body: formData
        });

        const data = await response.json();
        return new Response(JSON.stringify(data, null, 2), {
            status: response.status,
            headers: { 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({
            success: false,
            errors: [error.message],
            messages: [],
            result: null
        }), { status: 500 });
    }
}
// binding页面 /binding
function handleBindingsPage(acc, logined) {
    const html = `
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
        <meta charset="UTF-8">
        <link rel="icon" href="/favicon.svg" type="image/svg+xml">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Worker 编辑器|绑定管理</title>
        <link rel="stylesheet" href="/static/style.css">
<style>
    .bindings-list{margin-top:20px}
    .binding-item{background:var(--surface-color);border:1px solid var(--border-color);border-radius:var(--radius);padding:15px;margin-bottom:10px}
    .binding-header{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:10px}
    .binding-type{display:inline-block;padding:3px 8px;border-radius:4px;font-size:12px;font-weight:bold;background-color:var(--primary-light);color:var(--primary-color)}
    .binding-details{font-family:monospace;font-size:13px;background-color:var(--surface-color);padding:10px;border-radius:var(--radius);overflow-x:auto;white-space:pre-wrap;word-break:break-word;border:1px solid var(--border-color)}
    .type-details{margin-top:10px;padding:15px;background-color:var(--surface-color);border-radius:var(--radius);border-left:4px solid var(--primary-color)}
    .secret-form{background-color:var(--surface-color);border:1px solid var(--border-color);border-radius:var(--radius);padding:15px;margin-top:20px}
    .field-row{display:flex;gap:10px;margin-bottom:10px}
    .field-row input,.field-row select{flex:1}
    .secrets-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:10px;margin-top:10px}
    .secret-item{background:var(--surface-color);border:1px solid var(--border-color);border-radius:var(--radius);padding:10px;display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap}
    .secret-actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:15px;margin-bottom:15px;align-items:center}
    .binding-actions{display:flex;gap:10px;margin-top:10px;flex-wrap:wrap}
    .section>button,.section>.btn{margin-right:8px;margin-bottom:8px}
    @media (max-width:768px){
    .field-row{flex-direction:column}  
    .binding-actions{flex-direction:column}
    .binding-actions button{width:100%;margin-bottom:5px}
    .secret-actions{flex-direction:column}
    .secret-actions button{width:100%;margin-bottom:3px}
    .binding-header{flex-direction:column;align-items:flex-start}
    .binding-header .btn-danger{align-self:stretch;text-align:center}
    .secrets-grid{grid-template-columns:1fr}
    .secret-item{flex-wrap:wrap}
    .secret-item button{width:100%;margin-top:5px}
    .section>button,.section>.btn,#loadBindingsBtn,#saveBindingsBtn,#addBindingBtn{width:100%;margin-bottom:10px;text-align:center}
    #addBindingForm .binding-actions button{width:100%}
    input,select,textarea,button,.btn{font-size:16px}
        
    }
    @media (max-width:480px){
    .binding-item{padding:12px
        
    }
    .type-details,.secret-form{padding:12px}
    .binding-details{font-size:12px;padding:8px}
    .secret-item{padding:8px}
    .binding-header strong{font-size:14px;word-break:break-word}
    h1{font-size:1.75rem}
    h2{font-size:1.35rem}}
</style>
        </head>
        <body>
        {{NAVBAR}}
        <main>
        <h1>Cloudflare Worker 绑定管理</h1>

        <div class="section">
        <h2>Worker 信息</h2>
        <div class="form-group">
        <label for="workerName">Worker 名称:</label>
        <input type="text" id="workerName" disabled>
        </div>
        <button id="loadBindingsBtn" class="btn">加载绑定信息</button>
        <button id="saveBindingsBtn" class="btn btn" disabled>保存所有绑定</button>
        </div>

        <div id="status" class="status"></div>

        <div class="section" id="bindingsSection" style="display:none;">
        <h2>当前绑定列表</h2>
        <div id="bindingsList" class="bindings-list">
        <!-- 绑定项将动态添加到这里 -->
        </div>

        <div class="binding-actions">
        <button id="addBindingBtn" class="btn">添加新绑定</button>
        <div style="display: none;">
        </div>
        </div>
        </div>

        <div class="section" id="addBindingForm" style="display:none;">
        <h2>添加新绑定</h2>
        <div class="form-group">
        <label for="bindingType">绑定类型:</label>
        <select id="bindingType">
        <option value="">请选择类型</option>
        <option value="plain_text">环境变量</option>
        <option value="kv_namespace">KV 命名空间</option>
        <option value="r2_bucket">R2 存储桶</option>
        <option value="d1">D1 数据库</option>
        <option value="durable_object_namespace">耐用对象</option>
        <option value="ai">Workers AI</option>
        <option value="service">服务绑定</option>
        <option value="vectorize">Vectorize 索引</option>
        </select>
        </div>

        <div class="form-group">
        <label for="bindingName">绑定变量名称:</label>
        <input type="text" id="bindingName">
        </div>

        <!-- 不同类型需要不同的字段，动态显示 -->
        <div id="typeSpecificFields" class="type-details"></div>

        <div class="binding-actions">
        <button id="addToBindingsBtn" class="btn">添加到列表</button>
        <button id="cancelAddBtn" class="btn btn-secondary">取消</button>
        </div>
        </div>

        <div class="section" id="secretManagement">
        <h2>Secret 管理</h2>
        <p><strong>注意:</strong> Secret 需要单独管理，不会出现在上方列表中</p>

        <div class="secret-form">
        <div class="form-group">
        <label for="secretName">Secret 名称:</label>
        <input type="text" id="secretName" placeholder="例如: API_TOKEN">
        </div>

        <div class="form-group">
        <label for="secretValue">Secret 值:</label>
        <input type="password" id="secretValue" placeholder="输入 secret 值">
        </div>

        <div class="secret-actions">
        <button id="createSecretBtn" class="btn">创建/更新 Secret</button>
        <button id="deleteSecretBtn" class="btn btn-danger">删除 Secret</button>
        <button id="listSecretsBtn" class="btn btn-secondary">查看 Secrets 列表</button>
        </div>

        <div id="secretStatus" class="status"></div>

        <div id="secretsList" class="bindings-list" style="display:none; margin-top:20px;">
        <h4>已配置的 Secrets:</h4>
        <!-- Secrets列表将动态添加到这里 -->
        </div>
        </div>
        </div>
        </main>

        <script>
        // 当前管理的绑定列表
        let currentBindings = [];

        // 从URL获取worker名称
        function getWorkerFromUrl() {
        const urlParams = new URLSearchParams(window.location.search);
        return urlParams.get('worker');
        }

        // 显示状态消息
        function showStatus(message, isError = false) {
        const statusEl = document.getElementById('status');
        statusEl.textContent = message;
        statusEl.className = \`status \${isError ? 'error' : 'success'}\`;

        // 3秒后自动隐藏
        setTimeout(() => {
        statusEl.className = 'status';
        }, 3000);
        }

        // 从API加载绑定信息
        async function loadBindings() {
        const workerName = document.getElementById('workerName').value.trim();

        if (!workerName) {
        showStatus('请输入Worker名称', true);
        return;
        }

        try {
        showStatus('正在加载绑定信息...');

        const response = await fetch(\`/api/bindings/\${workerName}\`);

        if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.errors?.[0]?.message || \`HTTP \${response.status}\`);
        }

        const data = await response.json();

        if (data.success) {
        // 过滤掉 secret_text 类型
        currentBindings = (data.bindings || []).filter(b => b.type !== 'secret_text');
        displayBindings();
        document.getElementById('bindingsSection').style.display = 'block';
        document.getElementById('saveBindingsBtn').disabled = false;
        showStatus(\`成功加载 \${currentBindings.length} 个绑定\`);

        // 更新URL参数
        const newUrl = new URL(window.location);
        newUrl.searchParams.set('worker', workerName);
        window.history.pushState({}, '', newUrl);
        } else {
        throw new Error(data.errors?.[0]?.message || '加载失败');
        }
        } catch (error) {
        showStatus(\`加载失败: \${error.message}\`, true);
        console.error('加载绑定失败:', error);
        }
        }

        // 显示绑定列表
        function displayBindings() {
    const bindingsListEl = document.getElementById('bindingsList');
    if (currentBindings.length === 0) {
        bindingsListEl.innerHTML = '<p>没有绑定信息</p>';
        return;
    }
    bindingsListEl.innerHTML = '';
    currentBindings.forEach((binding, index) => {
        const bindingEl = document.createElement('div');
        bindingEl.className = 'binding-item';
        const displayDetails = { ...binding };
        delete displayDetails.type;
        delete displayDetails.name;

        bindingEl.innerHTML = \`
            <div class="binding-header">
                <div style="word-break: break-word; overflow-wrap: break-word;">
                    <strong>\${binding.name}</strong>
                    <span class="binding-type">\${binding.type}</span>
                </div>
                <button onclick="removeBinding(\${index})" class="btn btn-danger">删除</button>
            </div>
            <div class="binding-details">\${JSON.stringify(displayDetails, null, 2)}</div>
        \`;
        bindingsListEl.appendChild(bindingEl);
    });
}

        // 删除普通绑定
        function removeBinding(index) {
        const binding = currentBindings[index];
        if (confirm('确定要删除这个绑定吗？')) {
        currentBindings.splice(index, 1);
        displayBindings();
        showStatus('绑定已从列表中移除');
        }
        }

        // 保存绑定到服务器
        async function saveBindings() {
        const workerName = document.getElementById('workerName').value.trim();

        if (!workerName) {
        showStatus('请输入Worker名称', true);
        return;
        }
        try {
        showStatus('正在保存绑定配置...');

        const response = await fetch(\`/api/bindings/\${workerName}\`, {
        method: 'PATCH',
        headers: {
        'Content-Type': 'application/json'
        },
        body: JSON.stringify({
        bindings: currentBindings
        })
        });

        if (!response.ok) {
        const errorData = await response.json();
        // alert(JSON.stringify(errorData));
        throw new Error(errorData.errors?.[0]?.message || \`HTTP \${response.status}\`);
        }

        const data = await response.json();

        if (data.success) {
        showStatus('绑定配置保存成功');
        } else {
        throw new Error(data.errors?.[0]?.message || '保存失败');
        }
        } catch (error) {
        showStatus(\`保存失败: \${error.message}\`, true);
        console.error('保存绑定失败:', error);
        }
        }

        // 显示添加绑定表单
        function showAddBindingForm() {
        document.getElementById('addBindingForm').style.display = 'block';
        document.getElementById('bindingsSection').style.display = 'none';
        updateTypeSpecificFields();
        }

        // 隐藏添加绑定表单
        function hideAddBindingForm() {
        document.getElementById('addBindingForm').style.display = 'none';
        document.getElementById('bindingsSection').style.display = 'block';
        clearAddForm();
        }

        // 清空添加表单
        function clearAddForm() {
        document.getElementById('bindingType').value = '';
        document.getElementById('bindingName').value = '';
        document.getElementById('typeSpecificFields').innerHTML = '';
        }

        // 根据选择的类型更新字段
        function updateTypeSpecificFields() {
        const type = document.getElementById('bindingType').value;
        const fieldsEl = document.getElementById('typeSpecificFields');

        fieldsEl.innerHTML = '';

        if (!type) return;

        let html = '<h4>所需参数:</h4>';

        switch(type) {
        case 'plain_text':
        html += \`
        <div class="form-group">
        <p><small>为运行时使用的 Worker 定义环境变量</small></p>
        <label for="textValue">文本值:</label>
        <input type="text" id="textValue">
        </div>
        \`;
        break;

        case 'kv_namespace':
        html += \`
        <div class="form-group">
        <p><small>创建低延迟的全局键值数据存储</small></p>
        <label for="namespaceId">命名空间 ID:</label>
        <input type="text" id="namespaceId">
        </div>
        \`;
        break;

        case 'r2_bucket':
        html += \`
        <div class="form-group">
        <p><small>连接到 R2 对象存储桶来访问数据</small></p>
        <label for="bucketName">存储桶名称:</label>
        <input type="text" id="bucketName">
        </div>
        \`;
        break;

        case 'd1':
        html += \`
        <div class="form-group">
        <p><small>使用无服务器 SQL 数据库存储关系数据</small></p>
        <label for="databaseId">数据库 ID:</label>
        <input type="text" id="databaseId">
        </div>
        \`;
        break;

        case 'durable_object_namespace':
        html += \`
        <div class="form-group">
        <p><small>使用状态计算构建实时协调</small></p>
        <label for="className">类名:</label>
        <input type="text" id="className">
        </div>
        \`;
        break;

        case 'service':
        html += \`
        <div class="form-group">
        <p><small>启用 Worker 间通信，不增加延迟</small></p>
        <label for="serviceName">服务名称:</label>
        <input type="text" id="serviceName">
        </div>
        \`;
        break;

        case 'vectorize':
        html += \`
        <div class="form-group">
        <p><small>使用全球分布的矢量数据库存储和查询矢量数据</small></p>
        <label for="indexName">索引名称:</label>
        <input type="text" id="indexName">
        </div>
        \`;
        break;

        case 'ai':
        html += '<p><small>全局运行由无服务器 GPU 提供支持的机器学习模型</small></p>';
        break;
        }

        fieldsEl.innerHTML = html;
        }

        // 添加新绑定到列表
        function addBindingToList() {
        const type = document.getElementById('bindingType').value;
        const name = document.getElementById('bindingName').value.trim();

        if (!type || !name) {
        showStatus('请填写绑定类型和名称', true);
        return;
        }

        // 创建绑定对象
        const binding = {
        type: type,
        name: name
        };

        // 根据类型添加特定字段
        switch(type) {
        case 'plain_text':
        const textValue = document.getElementById('textValue')?.value.trim();
        if (!textValue) {
        showStatus('请输入文本值', true);
        return;
        }
        binding.text = textValue;
        break;

        case 'kv_namespace':
        const namespaceId = document.getElementById('namespaceId')?.value.trim();
        if (!namespaceId) {
        showStatus('请输入命名空间ID', true);
        return;
        }
        binding.namespace_id = namespaceId;
        break;

        case 'r2_bucket':
        const bucketName = document.getElementById('bucketName')?.value.trim();
        if (!bucketName) {
        showStatus('请输入存储桶名称', true);
        return;
        }
        binding.bucket_name = bucketName;
        break;

        case 'd1':
        const databaseId = document.getElementById('databaseId')?.value.trim();
        if (!databaseId) {
        showStatus('请输入数据库ID', true);
        return;
        }
        binding.database_id = databaseId;
        break;

        case 'durable_object_namespace':
        const className = document.getElementById('className')?.value.trim();
        if (!className) {
        showStatus('请输入类名', true);
        return;
        }
        binding.class_name = className;
        break;

        case 'service':
        const serviceName = document.getElementById('serviceName')?.value.trim();
        if (!serviceName) {
        showStatus('请输入服务名称', true);
        return;
        }
        binding.service = serviceName;
        break;

        case 'vectorize':
        const indexName = document.getElementById('indexName')?.value.trim();
        if (!indexName) {
        showStatus('请输入索引名称', true);
        return;
        }
        binding.index_name = indexName;
        break;

        case 'ai':
        // AI绑定不需要额外参数
        break;
        }

        // 检查是否已存在同名绑定
        if (currentBindings.some(b => b.name === name)) {
        showStatus(\`已存在名为 "\${name}" 的绑定\`, true);
        return;
        }

        // 如果是 secret_text，添加后需要同步到 Secret 管理（通过 API 创建）
        if (type === 'secret_text') {
        // 调用创建 Secret 的 API，而不是直接添加到 currentBindings
        const workerName = document.getElementById('workerName').value.trim();
        if (!workerName) {
        showStatus('请先加载 Worker 名称', true);
        return;
        }
        // 使用已有的 createSecret 逻辑
        (async () => {
        const success = await doCreateSecret(workerName, name, binding.text);
        if (success) {
            // 创建成功后，currentBindings 会在 createSecret 中自动添加，不需要重复添加
            hideAddBindingForm();
        }
        })();
        return;
        }

        // 添加到列表
        currentBindings.push(binding);
        displayBindings();
        hideAddBindingForm();
        showStatus(\`绑定 "\${name}" 已添加到列表\`);
        }

        // Secret 相关函数
        async function doCreateSecret(workerName, secretName, secretValue) {
    try {
        const response = await fetch(\`/api/bindings/secret/\${workerName}\`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: secretName, text: secretValue })
        });
        const data = await response.json();
        if (!response.ok || !data.success) {
            throw new Error(data.errors?.[0]?.message || data.errors?.[0] || '创建失败');
        }
        showSecretStatus(\`Secret "\${secretName}" 创建成功\`);
        return true;
    } catch (error) {
        showSecretStatus(\`创建 Secret 失败: \${error.message}\`, true);
        return false;
    }
}

async function doDeleteSecret(workerName, secretName) {
    try {
        const response = await fetch(\`/api/bindings/secret/\${workerName}/\${secretName}\`, {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' }
        });
        const data = await response.json();
        if (!response.ok || !data.success) {
            throw new Error(data.errors?.[0]?.message || '删除失败');
        }
        showSecretStatus(\`Secret "\${secretName}" 删除成功\`);
        return true;
    } catch (error) {
        showSecretStatus(\`删除 Secret 失败: \${error.message}\`, true);
        return false;
    }
}

        // 显示Secret状态消息（独立区域）
        function showSecretStatus(message, isError = false) {
        const statusEl = document.getElementById('secretStatus');
        statusEl.textContent = message;
        statusEl.className = \`status \${isError ? 'error' : 'success'}\`;
        setTimeout(() => {
        statusEl.className = 'status';
        }, 3000);
        }

        // 创建/更新 Secret（UI 入口）
        async function createSecret() {
        const workerName = document.getElementById('workerName').value.trim();
        const secretName = document.getElementById('secretName').value.trim();
        const secretValue = document.getElementById('secretValue').value.trim();

        if (!workerName || !secretName || !secretValue) {
        showSecretStatus('请填写Worker名称、Secret名称和值', true);
        return;
        }

        showSecretStatus('正在创建/更新 Secret...');
        const success = await doCreateSecret(workerName, secretName, secretValue);
        if (success) {
        document.getElementById('secretValue').value = '';
        await listSecrets(); // 刷新 Secrets 列表
        }
        }

        // 删除 Secret（UI 入口）
        async function deleteSecret() {
        const workerName = document.getElementById('workerName').value.trim();
        const secretName = document.getElementById('secretName').value.trim();

        if (!workerName || !secretName) {
        showSecretStatus('请填写Worker名称和Secret名称', true);
        return;
        }

        if (!confirm(\`确定要删除 Secret "\${secretName}" 吗？此操作不可撤销。\`)) {
        return;
        }

        showSecretStatus('正在删除 Secret...');
        const success = await doDeleteSecret(workerName, secretName);
        if (success) {
        document.getElementById('secretName').value = '';
        document.getElementById('secretValue').value = '';
        await listSecrets();
        }
        }

        // 查看Secrets列表
        async function listSecrets() {
        const workerName = document.getElementById('workerName').value.trim();
        if (!workerName) {
        showSecretStatus('请输入Worker名称', true);
        return;
        }

        try {
        showSecretStatus('正在获取 Secrets 列表...');
        const response = await fetch(\`/api/bindings/secret/\${workerName}\`);
        const data = await response.json();
        if (!response.ok || !data.success) {
        throw new Error(data.errors?.[0]?.message || '加载失败');
        }
        displaySecretsList(data.result || []);
        showSecretStatus(\`成功加载 \${data.result?.length || 0} 个 Secret\`);
        } catch (error) {
        showSecretStatus(\`获取Secrets列表失败: \${error.message}\`, true);
        }
        }

        // 显示Secrets列表
        function displaySecretsList(secrets) {
        const secretsListEl = document.getElementById('secretsList');
        if (secrets.length === 0) {
        secretsListEl.innerHTML = '<p>没有配置任何 Secret</p>';
        secretsListEl.style.display = 'block';
        return;
        }

        let html = '<div class="secrets-grid">';
        secrets.forEach(secret => {
        html += \`
        <div class="secret-item">
        <div>
        <strong>\${secret.name}</strong>
        <div style="font-size: 12px; color: var(--text-secondary);">\${secret.type}</div>
        </div>
        <button onclick="fillSecretName('\${secret.name}')" class="btn btn-secondary" style="padding: 4px 8px; font-size: 12px;">
        选择
        </button>
        </div>
        \`;
        });
        html += '</div>';
        secretsListEl.innerHTML = html;
        secretsListEl.style.display = 'block';
        }

        function fillSecretName(name) {
        document.getElementById('secretName').value = name;
        showSecretStatus(\`已选择 Secret: \${name}\`, false);
        }

        // 初始化页面
        function init() {
        const workerFromUrl = getWorkerFromUrl();
        if (workerFromUrl) {
        document.getElementById('workerName').value = workerFromUrl;
        }

        document.getElementById('loadBindingsBtn').addEventListener('click', loadBindings);
        document.getElementById('saveBindingsBtn').addEventListener('click', saveBindings);
        document.getElementById('addBindingBtn').addEventListener('click', showAddBindingForm);
        document.getElementById('bindingType').addEventListener('change', updateTypeSpecificFields);
        document.getElementById('addToBindingsBtn').addEventListener('click', addBindingToList);
        document.getElementById('cancelAddBtn').addEventListener('click', hideAddBindingForm);
        document.getElementById('listSecretsBtn').addEventListener('click', listSecrets);
        document.getElementById('createSecretBtn').addEventListener('click', createSecret);
        document.getElementById('deleteSecretBtn').addEventListener('click', deleteSecret);
        document.getElementById('workerName').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') loadBindings();
        });

        if (workerFromUrl) {
        setTimeout(() => loadBindings(), 500);
        }
        }

        document.addEventListener('DOMContentLoaded', init);
        window.removeBinding = removeBinding;
        </script>
        </body>
        </html>
        `;
    /*if (logined) {
        return buildHtmlResponse(html, acc, {
            littleNav: false,
            errorHandler: errHtml,
            homeUrl: '/list'
        });
    } else {
        return buildHtmlResponse(html, '', {
            littleNav: true,
            errorOverlay: {
                code: 401,
                message: '请先登录',
                redirectUrl: '/login',
                homeOnly: true
            },
            errorHandler: errHtml,
            homeUrl: '/'
        });
    }*/
    return buildHtmlResponse(html, acc, {
        littleNav: false,
        errorHandler: errHtml,
        homeUrl: '/list'
    });
}
//===============deployment==================
// 版本部署管理/api/deployment
async function handleDeployment(request, url, accountId, token) {
    const path = url.pathname;
    const corsHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };
    try {
        const baseUrl = 'https://api.cloudflare.com/client/v4';
        // 解析路径
        const pathSegments = url.pathname.split('/').filter(seg => seg);
        // 路由处理
        if (pathSegments[2] === 'versions' && request.method === 'GET') {
            return await handleGetVersions(request, url, accountId, token, baseUrl, corsHeaders);
        } else if (pathSegments[2] === 'rollback' && request.method === 'POST') {
            return await handleRollback(request, url, accountId, token, baseUrl, corsHeaders);
        } else if (pathSegments[2] === 'deployments' && request.method === 'GET') {
            return await handleGetDeployments(request, url, accountId, token, baseUrl, corsHeaders);
        } else {
            return new Response(JSON.stringify({
                error: 'Invalid endpoint or method'
            }), {
                status: 404,
                headers: {
                    'Content-Type': 'application/json',
                    ...corsHeaders
                }
            });
        }
    } catch (error) {
        console.error('Error:', error);
        return new Response(JSON.stringify({
            error: 'Internal server error',
            message: error.message
        }), {
            status: 500,
            headers: {
                'Content-Type': 'application/json',
                ...corsHeaders
            }
        });
    }
}
// 处理获取版本列表
async function handleGetVersions(request, url, accountId, token, baseUrl, corsHeaders) {
    const scriptName = url.searchParams.get('script');
    const page = url.searchParams.get('page') || '1';
    const perPage = url.searchParams.get('per_page') || '10';
    if (!scriptName) {
        return new Response(JSON.stringify({
            error: 'Missing script parameter'
        }), {
            status: 400,
            headers: {
                'Content-Type': 'application/json',
                ...corsHeaders
            }
        });
    }
    const apiUrl = `${baseUrl}/accounts/${accountId}/workers/scripts/${encodeURIComponent(scriptName)}/deployments?page=${page}&per_page=${perPage}`;
    const response = await fetch(apiUrl, {
        headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
        },
    });
    const data = await response.json();
    return new Response(JSON.stringify(data), {
        status: response.status,
        headers: {
            'Content-Type': 'application/json',
            ...corsHeaders,
        },
    });
}
// 处理回滚操作
async function handleRollback(request, url, accountId, token, baseUrl, corsHeaders) {
    const body = await request.json();
    const {
        script,
        version_id,
        comment = 'Rollback via deployment API'
    } = body;
    if (!script || !version_id) {
        return new Response(JSON.stringify({
            error: 'Missing script or version_id parameter'
        }), {
            status: 400,
            headers: {
                'Content-Type': 'application/json',
                ...corsHeaders
            }
        });
    }
    const apiUrl = `${baseUrl}/accounts/${accountId}/workers/scripts/${encodeURIComponent(script)}/deployments`;
    const payload = {
        metadata: {
            tag: 'rollback',
            comment: comment,
        },
        versions: [{
            version_id: version_id,
            percentage: 100,
        }],
        allow_overwrite: true,
    };
    const response = await fetch(apiUrl, {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
    });
    const data = await response.json();
    if (response.ok) {
        await enableLogsForWorker(accountId, token, script);
    }
    return new Response(JSON.stringify(data), {
        status: response.status,
        headers: {
            'Content-Type': 'application/json',
            ...corsHeaders,
        },
    });
}
// 获取部署列表
async function handleGetDeployments(request, url, accountId, token, baseUrl, corsHeaders) {
    const scriptName = url.searchParams.get('script');
    const page = url.searchParams.get('page') || '1';
    const perPage = url.searchParams.get('per_page') || '10';
    if (!scriptName) {
        return new Response(JSON.stringify({
            error: 'Missing script parameter'
        }), {
            status: 400,
            headers: {
                'Content-Type': 'application/json',
                ...corsHeaders
            }
        });
    }
    const apiUrl = `${baseUrl}/accounts/${accountId}/workers/scripts/${encodeURIComponent(scriptName)}/deployments?page=${page}&per_page=${perPage}`;
    const response = await fetch(apiUrl, {
        headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
        },
    });
    const data = await response.json();
    return new Response(JSON.stringify(data), {
        status: response.status,
        headers: {
            'Content-Type': 'application/json',
            ...corsHeaders,
        },
    });
}
// 前端页面 /deployment
function handleDeploymentPage(acc, logined) {
    const html = `
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
        <meta charset="UTF-8">
        <link rel="icon" href="/favicon.svg" type="image/svg+xml">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Worker 编辑器|部署管理</title>
        <link rel="stylesheet" href="/static/style.css">
        <style>
        .version-item {
        border: 1px solid var(--border-color);
        padding: 1.5rem;
        margin: 1rem 0;
        }
        .version-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 0.5rem;
        }
        .version-id {
        font-size: 0.75rem;
        color: var(--text-secondary);
        font-family: monospace;
        }
        .status {
        padding: 0.25rem 0.5rem;
        border-radius: var(--radius);
        font-size: 0.75rem;
        display: inline-block;
        margin-top: 0.5rem;
        }
        .badge {
        margin-top: 0.5rem;
        }
        .deployment-id {
        font-size: 0.7rem;
        color: var(--text-secondary);
        margin-left: 0.5rem;
        }
        </style>
        </head>
        <body>
        {{NAVBAR}}
        <main class="container">
        <h1>Worker部署记录</h1>

        <div class="card mb-4">
        <p>Worker: <strong id="worker-name">加载中...</strong></p>
        </div>

        <div id="loading" class="card">正在加载部署列表...</div>

        <div id="version-list" style="display: none;">
        <div id="versions-container"></div>
        </div>

        <div id="error" class="card" style="display: none; border-color: var(--danger-color); background-color: #fef2f2;">
        <h3 class="text-danger">错误</h3>
        <p id="error-message"></p>
        </div>
        </main>

        <script>
        function getQueryParam(name) {
        const urlParams = new URLSearchParams(window.location.search);
        return urlParams.get(name);
        }

        const workerName = getQueryParam('worker');
        if (!workerName) {
        showError('请在URL中指定worker参数');
        } else {
        document.getElementById('worker-name').textContent = workerName;
        loadDeployments();
        }

        function showError(message) {
        document.getElementById('loading').style.display = 'none';
        document.getElementById('version-list').style.display = 'none';
        document.getElementById('error').style.display = 'block';
        document.getElementById('error-message').textContent = message;
        }

        async function loadDeployments() {
        try {
        const apiUrl = \`/api/deployment/deployments?script=\${encodeURIComponent(workerName)}\`;
        const response = await fetch(apiUrl);
        if (!response.ok) throw new Error(\`API请求失败: \${response.status}\`);
        const data = await response.json();
        if (!data.success) throw new Error(data.errors?.join(', ') || '获取部署列表失败');

        const deployments = data.result.deployments || [];
        deployments.sort((a, b) => new Date(b.created_on) - new Date(a.created_on));

        if (deployments.length === 0) {
        document.getElementById('loading').style.display = 'none';
        document.getElementById('version-list').style.display = 'block';
        document.getElementById('versions-container').innerHTML = '<p class="text-center">没有找到任何部署记录</p>';
        return;
        }

        displayAllDeployments(deployments);
        } catch (error) {
        showError(error.message);
        }
        }

        function displayAllDeployments(deployments) {
        document.getElementById('loading').style.display = 'none';
        document.getElementById('error').style.display = 'none';
        document.getElementById('version-list').style.display = 'block';

        const container = document.getElementById('versions-container');
        container.innerHTML = '';

        deployments.forEach((deployment, index) => {
        const scriptVersionId = deployment.versions?.[0]?.version_id || deployment.id;
        const createdDate = new Date(deployment.created_on);
        const timeString = createdDate.toLocaleString('zh-CN');
        const isCurrentVersion = (index === 0); // 最新的部署即为当前生产版本

        const versionElement = document.createElement('div');
        versionElement.className = 'version-item card';
        versionElement.innerHTML = \`
        <div class="version-header">
        <div>
        <div class="d-flex align-center gap-2 mb-2">
        <span class="version-number"><strong>部署时间:</strong> \${timeString}</span>
        <span class="deployment-id">(部署ID: \${deployment.id})</span>
        </div>
        <div class="version-id">脚本版本ID: \${scriptVersionId}</div>
        </div>
        <button class="btn \${isCurrentVersion ? 'btn-secondary' : 'btn-danger'}"
        onclick="rollbackToVersion('\${scriptVersionId}')"
        \${isCurrentVersion ? 'disabled' : ''}>
        \${isCurrentVersion ? '当前生产版本' : '回滚到此版本'}
        </button>
        </div>
        <div class="mb-2"><strong>创建时间:</strong> \${timeString}</div>
        <div class="mb-2"><strong>来源:</strong> \${deployment.source || '未知'}</div>
        \${deployment.author_email ? \`<div class="mb-2"><strong>作者:</strong> \${deployment.author_email}</div>\` : ''}
        <div class="mb-2"><strong>部署策略:</strong> \${deployment.strategy || 'percentage'}</div>
        <div class="badge">
        <span class="status">
        流量占比: \${deployment.versions?.[0]?.percentage ?? 100}%
        </span>
        </div>
        \${deployment.annotations ? \`<div class="mt-2 text-secondary"><small>备注: \${deployment.annotations['workers/message'] || '无'}</small><br>
        <small>触发方式: \${deployment.annotations['workers/triggered_by'] || '未知'}</small></div>\` : ''}
        \`;
        container.appendChild(versionElement);
        });
        }

        async function rollbackToVersion(versionId) {
        if (!confirm(\`确定要回滚到脚本版本 \${versionId} 吗？这将会替换当前生产版本。\`)) {
        return;
        }
        try {
        const response = await fetch('/api/deployment/rollback', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
        script: workerName,
        version_id: versionId,
        comment: \`通过管理界面回滚到版本 \${versionId}\`
        })
        });
        const data = await response.json();
        if (data.success) {
        alert('回滚请求已提交！部署ID: ' + (data.result?.id || '未知'));
        window.location.reload();
        } else {
        throw new Error(data.errors?.join(', ') || '回滚失败');
        }
        } catch (error) {
        alert('回滚失败: ' + error.message);
        }
        }
        </script>
        </body>
        </html>
        `;
    /*if (logined) {
        return buildHtmlResponse(html, acc, {
            littleNav: false,
            errorHandler: errHtml,
            homeUrl: '/list'
        });
    } else {
        return buildHtmlResponse(html, '', {
            littleNav: true,
            errorOverlay: {
                code: 401,
                message: '请先登录',
                redirectUrl: '/login',
                homeOnly: true
            },
            errorHandler: errHtml,
            homeUrl: '/'
        });
    }*/
    return buildHtmlResponse(html, acc, {
        littleNav: false,
        errorHandler: errHtml,
        homeUrl: '/list'
    });
}
//================routes===================
// 路由管理/api/routes
async function handleRoutes(request, url, accountId, token) {
    const path = url.pathname;
    const corsHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Content-Type': 'application/json',
    };
    const apiHeaders = {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
    };
    try {
        // 路由处理
        if (path === '/api/routes' || path === '/api/routes/') {
            switch (request.method) {
                case 'GET':
                    return await getRoutes(apiHeaders, corsHeaders);
                case 'POST':
                    return await createRoute(request, apiHeaders, corsHeaders);
                default:
                    return new Response(JSON.stringify({
                        success: false,
                        errors: [{
                            message: 'Method not allowed'
                        }],
                    }), {
                        status: 405,
                        headers: corsHeaders,
                    });
            }
        } else {
            // 处理 /api/routes/{zone_id}/{route_id} 格式
            const pathParts = path.split('/').filter(p => p);
            if (pathParts.length === 4 && pathParts[0] === 'api' && pathParts[1] === 'routes') {
                const zoneId = pathParts[2];
                const routeId = pathParts[3];
                switch (request.method) {
                    case 'DELETE':
                        return await deleteRoute(zoneId, routeId, apiHeaders, corsHeaders);
                    case 'PUT':
                        return await updateRoute(request, zoneId, routeId, apiHeaders, corsHeaders);
                    case 'GET':
                        return await getRouteDetails(zoneId, routeId, apiHeaders, corsHeaders);
                    default:
                        return new Response(JSON.stringify({
                            success: false,
                            errors: [{
                                message: 'Method not allowed'
                            }],
                        }), {
                            status: 405,
                            headers: corsHeaders,
                        });
                }
            }
            // 处理 /api/routes/zone/{zone_id} 获取特定zone的路由
            if (pathParts.length === 4 && pathParts[0] === 'api' && pathParts[1] === 'routes' && pathParts[2] === 'zone') {
                const zoneId = pathParts[3];
                if (request.method === 'GET') {
                    return await getRoutesByZone(zoneId, apiHeaders, corsHeaders);
                }
            }
        }
        return new Response(JSON.stringify({
            success: false,
            errors: [{
                message: 'Endpoint not found'
            }],
        }), {
            status: 404,
            headers: corsHeaders,
        });
    } catch (error) {
        return new Response(JSON.stringify({
            success: false,
            errors: [{
                message: error.message
            }],
        }), {
            status: 500,
            headers: corsHeaders,
        });
    }
}
// 获取所有zone的路由
async function getRoutes(apiHeaders, corsHeaders) {
    try {
        // 首先获取所有zone
        const zonesResponse = await fetch('https://api.cloudflare.com/client/v4/zones', {
            headers: apiHeaders,
        });
        const zonesData = await zonesResponse.json();
        if (!zonesData.success) {
            throw new Error(zonesData.errors[0]?.message || 'Failed to fetch zones');
        }
        // 为每个zone获取路由
        const allRoutes = [];
        const errors = [];
        for (const zone of zonesData.result) {
            try {
                const routesResponse = await fetch(`https://api.cloudflare.com/client/v4/zones/${zone.id}/workers/routes`, {
                    headers: apiHeaders
                });
                const routesData = await routesResponse.json();
                if (routesData.success) {
                    allRoutes.push({
                        zone_id: zone.id,
                        zone_name: zone.name,
                        routes: routesData.result,
                    });
                } else {
                    errors.push({
                        zone: zone.name,
                        error: routesData.errors[0]?.message,
                    });
                }
            } catch (error) {
                errors.push({
                    zone: zone.name,
                    error: error.message,
                });
            }
        }
        return new Response(JSON.stringify({
            success: true,
            result: allRoutes,
            errors: errors.length > 0 ? errors : undefined,
            messages: [{
                message: `Fetched routes from ${allRoutes.length} zones`,
            },],
        }), {
            headers: corsHeaders,
        });
    } catch (error) {
        throw error;
    }
}
// 获取特定zone的路由
async function getRoutesByZone(zoneId, apiHeaders, corsHeaders) {
    const response = await fetch(`https://api.cloudflare.com/client/v4/zones/${zoneId}/workers/routes`, {
        headers: apiHeaders
    });
    const data = await response.json();
    return new Response(JSON.stringify(data), {
        status: response.status,
        headers: corsHeaders,
    });
}
// 获取路由详情
async function getRouteDetails(zoneId, routeId, apiHeaders, corsHeaders) {
    try {
        // 先获取该zone的所有路由
        const response = await fetch(`https://api.cloudflare.com/client/v4/zones/${zoneId}/workers/routes`, {
            headers: apiHeaders
        });
        const data = await response.json();
        if (!data.success) {
            return new Response(JSON.stringify(data), {
                status: response.status,
                headers: corsHeaders,
            });
        }
        // 查找特定路由
        const route = data.result.find(r => r.id === routeId);
        if (!route) {
            return new Response(JSON.stringify({
                success: false,
                errors: [{
                    message: 'Route not found'
                }],
            }), {
                status: 404,
                headers: corsHeaders,
            });
        }
        return new Response(JSON.stringify({
            success: true,
            result: route,
        }), {
            headers: corsHeaders,
        });
    } catch (error) {
        throw error;
    }
}
// 创建新路由
async function createRoute(request, apiHeaders, corsHeaders) {
    const body = await request.json();
    // 验证必要参数
    const {
        zone_id,
        pattern,
        script,
        enabled = true
    } = body;
    if (!zone_id || !pattern) {
        return new Response(JSON.stringify({
            success: false,
            errors: [{
                message: 'Missing required parameters: zone_id and pattern are required'
            }],
        }), {
            status: 400,
            headers: corsHeaders,
        });
    }
    const routeData = {
        pattern,
        enabled,
    };
    // script是可选的
    if (script) {
        routeData.script = script;
    }
    const response = await fetch(`https://api.cloudflare.com/client/v4/zones/${zone_id}/workers/routes`, {
        method: 'POST',
        headers: apiHeaders,
        body: JSON.stringify(routeData),
    });
    const data = await response.json();
    return new Response(JSON.stringify(data), {
        status: response.status,
        headers: corsHeaders,
    });
}
// 更新路由
async function updateRoute(request, zoneId, routeId, apiHeaders, corsHeaders) {
    const body = await request.json();
    const {
        pattern,
        script,
        enabled
    } = body;
    // 至少需要更新一个字段
    if (!pattern && script === undefined && enabled === undefined) {
        return new Response(JSON.stringify({
            success: false,
            errors: [{
                message: 'At least one parameter (pattern, script, or enabled) must be provided'
            }],
        }), {
            status: 400,
            headers: corsHeaders,
        });
    }
    const routeData = {};
    if (pattern) routeData.pattern = pattern;
    if (script !== undefined) routeData.script = script;
    if (enabled !== undefined) routeData.enabled = enabled;
    const response = await fetch(`https://api.cloudflare.com/client/v4/zones/${zoneId}/workers/routes/${routeId}`, {
        method: 'PUT',
        headers: apiHeaders,
        body: JSON.stringify(routeData),
    });
    const data = await response.json();
    return new Response(JSON.stringify(data), {
        status: response.status,
        headers: corsHeaders,
    });
}
// 删除路由
async function deleteRoute(zoneId, routeId, apiHeaders, corsHeaders) {
    const response = await fetch(`https://api.cloudflare.com/client/v4/zones/${zoneId}/workers/routes/${routeId}`, {
        method: 'DELETE',
        headers: apiHeaders,
    });
    const data = await response.json();
    return new Response(JSON.stringify(data), {
        status: response.status,
        headers: corsHeaders,
    });
}
// 前端页面 /routes
function handleRoutesPage(acc, logined) {
    const html = `
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
        <meta charset="UTF-8">
        <link rel="icon" href="/favicon.svg" type="image/svg+xml">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Worker 编辑器|路由管理</title>
        <link rel="stylesheet" href="/static/style.css">
        <style>
        .container { max-width: 1000px; }
        .message {
        padding: 10px;
        border-radius: var(--radius);
        margin-bottom: 1.5rem;
        display: none;
        }
        .error {
        background-color: rgba(239, 68, 68, 0.1);
        color: var(--danger-color);
        border: 1px solid rgba(239, 68, 68, 0.2);
        }
        .success {
        background-color: rgba(16, 185, 129, 0.1);
        color: var(--success-color);
        border: 1px solid rgba(16, 185, 129, 0.2);
        }
        .domain-input {
        display: flex;
        gap: 10px;
        align-items: center;
        }
        .domain-input input { flex: 2; }
        .domain-input select { flex: 1; }
        .actions { white-space: nowrap; }
        .actions button { margin: 0 0.25rem; }
        .delete-btn { background-color: var(--danger-color); }
        .delete-btn:hover { background-color: #dc2626; }
        #loading { padding: 1rem; text-align: center; }
        #routesTable { overflow-x: auto; }
        table { margin-top: 1.5rem; }
        small { color: var(--text-secondary); }
        </style>
        </head>
        <body>
        {{NAVBAR}}
        <main class="container">
        <h1>Cloudflare Workers 路由管理</h1>

        <div id="message" class="message"></div>

        <div class="card">
        <h2>创建新路由</h2>
        <form id="createRouteForm">
        <div class="form-group">
        <label for="pattern">域名模式：</label>
        <div class="domain-input">
        <input type="text" id="prefix" placeholder="前缀，如: api、www 或留空" />
        <select id="zoneSelect" required>
        <option value="">选择域名...</option>
        </select>
        </div>
        <small>示例: api.example.com 或 www.example.com</small>
        </div>

        <div class="form-group">
        <label for="script">Worker 脚本名称：</label>
        <input type="text" id="script" placeholder="worker脚本名称" required />
        </div>

        <div class="form-group">
        <label for="enabled">状态：</label>
        <select id="enabled">
        <option value="true">启用</option>
        <option value="false">禁用</option>
        </select>
        </div>

        <div class="d-flex gap-2">
        <button type="submit" class="btn">创建路由</button>
        <button type="button" onclick="loadAllRoutes()" class="btn btn-success">刷新列表</button>
        </div>
        </form>
        </div>

        <div class="card mt-4">
        <h2 class="mb-3">所有路由</h2>

        <div id="loading" style="display: none;">加载中...</div>
        <div id="routesTable"></div>
        </div>
        </main>

        <script>
        // 配置
        const API_BASE = '/api/routes';

        // 页面加载时初始化
        window.onload = function() {
        loadZones();
        loadAllRoutes();
        };

        // 加载所有zone（域名）
        async function loadZones() {
        try {
        const response = await fetch(\`\${API_BASE}\`);
        const data = await response.json();

        if (data.success) {
        const zoneSelect = document.getElementById('zoneSelect');
        const zones = new Set();

        data.result.forEach(zoneData => {
        zones.add(zoneData.zone_name);
        });

        // 清空并添加选项
        zoneSelect.innerHTML = '<option value="">选择域名...</option>';
        zones.forEach(zone => {
        const option = document.createElement('option');
        option.value = zone;
        option.textContent = zone;
        zoneSelect.appendChild(option);
        });
        }
        } catch (error) {
        showMessage('加载域名列表失败: ' + error.message, 'error');
        }
        }

        // 加载所有路由
        async function loadAllRoutes() {
        const loading = document.getElementById('loading');
        const tableDiv = document.getElementById('routesTable');

        loading.style.display = 'block';
        tableDiv.innerHTML = '';

        try {
        const response = await fetch(\`\${API_BASE}\`);
        const data = await response.json();

        if (data.success) {
        displayRoutes(data.result);
        } else {
        showMessage('加载路由失败: ' + (data.errors[0]?.message || '未知错误'), 'error');
        }
        } catch (error) {
        showMessage('加载路由失败: ' + error.message, 'error');
        } finally {
        loading.style.display = 'none';
        }
        }

        // 显示路由表格
        function displayRoutes(routesData) {
        const tableDiv = document.getElementById('routesTable');

        if (routesData.length === 0) {
        tableDiv.innerHTML = '<p>暂无路由配置</p>';
        return;
        }

        let html = '<table>';
        html += '<thead><tr><th>域名</th><th>路由模式</th><th>脚本</th><th>操作</th></tr></thead><tbody>';

        routesData.forEach(zoneData => {
        zoneData.routes.forEach(route => {
        const patternParts = route.pattern.split('.');
        const domain = patternParts.slice(-2).join('.');

        html += \`<tr>
        <td>\${domain}</td>
        <td>\${route.pattern}</td>
        <td>\${route.script || '无'}</td>
        <td class="actions">
        <button onclick="deleteRoute('\${zoneData.zone_id}', '\${route.id}')" class="btn delete-btn">
        删除
        </button>
        </td>
        </tr>\`;
        });
        });

        html += '</tbody></table>';
        tableDiv.innerHTML = html;
        }

        // 创建新路由
        document.getElementById('createRouteForm').addEventListener('submit', async (e) => {
        e.preventDefault();

        const prefix = document.getElementById('prefix').value.trim();
        const zone = document.getElementById('zoneSelect').value;
        const script = document.getElementById('script').value.trim();
        const enabled = document.getElementById('enabled').value === 'true';

        if (!zone) {
        showMessage('请选择域名', 'error');
        return;
        }

        if (!script) {
        showMessage('请输入Worker脚本名称', 'error');
        return;
        }

        try {
        const response = await fetch(\`\${API_BASE}\`);
        const data = await response.json();

        if (data.success) {
        const zoneData = data.result.find(z => z.zone_name === zone);
        if (!zoneData) {
        showMessage('找不到该域名的配置信息', 'error');
        return;
        }

        // 构建pattern
        const pattern = prefix ? \`\${prefix}.\${zone}/*\` : \`\${zone}/*\`;

        const routeData = {
        zone_id: zoneData.zone_id,
        pattern: pattern,
        script: script,
        enabled: enabled
        };

        const createResponse = await fetch(\`\${API_BASE}\`, {
        method: 'POST',
        headers: {
        'Content-Type': 'application/json'
        },
        body: JSON.stringify(routeData)
        });

        const result = await createResponse.json();

        if (result.success) {
        showMessage('路由创建成功！', 'success');
        document.getElementById('createRouteForm').reset();
        loadAllRoutes();
        loadZones();
        } else {
        showMessage('创建失败: ' + (result.errors[0]?.message || '未知错误'), 'error');
        }
        }
        } catch (error) {
        showMessage('创建路由失败: ' + error.message, 'error');
        }
        });

        // 删除路由
        async function deleteRoute(zoneId, routeId) {
        if (!confirm('确定要删除这个路由吗？此操作不可恢复。')) {
        return;
        }

        try {
        const response = await fetch(\`\${API_BASE}/\${zoneId}/\${routeId}\`, {
        method: 'DELETE'
        });

        const result = await response.json();

        if (result.success) {
        showMessage('路由删除成功！', 'success');
        loadAllRoutes();
        } else {
        showMessage('删除失败: ' + (result.errors[0]?.message || '未知错误'), 'error');
        }
        } catch (error) {
        showMessage('删除失败: ' + error.message, 'error');
        }
        }

        // 显示消息
        function showMessage(message, type) {
        const messageDiv = document.getElementById('message');
        messageDiv.textContent = message;
        messageDiv.className = \`message \${type}\`;
        messageDiv.style.display = 'block';

        setTimeout(() => {
        messageDiv.style.display = 'none';
        }, 5000);
        }
        </script>
        </body>
        </html>`;
    /*if (logined) {
        return buildHtmlResponse(html, acc, {
            littleNav: false,
            errorHandler: errHtml,
            homeUrl: '/list'
        });
    } else {
        return buildHtmlResponse(html, '', {
            littleNav: true,
            errorOverlay: {
                code: 401,
                message: '请先登录',
                redirectUrl: '/login',
                homeOnly: true
            },
            errorHandler: errHtml,
            homeUrl: '/'
        });
    }*/
    return buildHtmlResponse(html, acc, {
        littleNav: false,
        errorHandler: errHtml,
        homeUrl: '/list'
    });
}
//================setting==================
// worker相关设置/api/setting
async function handleSetting(request, url, accountId, token) {
    const headers = {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };
    // 路由处理
    const pathParts = url.pathname.split('/').filter(p => p);
    if (pathParts.length === 3 && pathParts[2] === 'create') {
        // POST /api/setting/create - 创建Worker
        return handleCreateWorker(request, accountId, token, headers);
    }
    if (pathParts.length === 4 && pathParts[2] === 'delete') {
        // DELETE /api/setting/delete/:scriptName
        const scriptName = pathParts[3];
        return handleDeleteWorker(request, accountId, token, scriptName, headers);
    }
    if (pathParts.length === 4 && pathParts[2] === 'logs') {
        // PATCH /api/setting/logs/:scriptName
        const scriptName = pathParts[3];
        return handleEnableLogs(request, accountId, token, scriptName, headers);
    }
    return new Response('Not Found', {
        status: 404
    });
}
// 创建helloWorld Worker
async function handleCreateWorker(request, accountId, token, headers) {
    if (request.method !== 'POST') {
        return new Response('Method Not Allowed', {
            status: 405,
            headers: {
                ...headers,
                'Allow': 'POST'
            }
        });
    }
    try {
        const body = await request.json();
        const scriptName = body.scriptName || `hello-world-${Date.now()}`;
        // Hello World Worker代码
        const workerCode = `
            /*
            * Created by worker editor at ${new Date()}
            */
            addEventListener('fetch', event => {
            event.respondWith(handleRequest(event.request));
            });

            async function handleRequest(request) {
            return new Response('Hello World!', {
            headers: { 'content-type': 'text/plain' },
            });
            }
            `;
        // 创建metadata
        const now = new Date().toISOString();
        const metadata = {
            body_part: "script",
            bindings: [],
            metadata_annotations: {
                created_at: now,
                last_updated: now,
                created_by: "worker_editor_api",
            }
        };
        // 准备表单数据
        const formData = new FormData();
        formData.append('metadata', JSON.stringify(metadata));
        formData.append('script', workerCode);
        // 调用Cloudflare API创建Worker
        const apiUrl = `https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/${scriptName}`;
        const response = await fetch(apiUrl, {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${token}`,
            },
            body: formData
        });
        const result = await response.json();
        if (response.ok) {
            // 创建成功后立即开启日志记录
            await enableLogsForWorker(accountId, token, scriptName);
            return new Response(JSON.stringify({
                success: true,
                message: `Worker "${scriptName}" created successfully`,
                scriptName,
                result
            }), {
                status: 201,
                headers
            });
        } else {
            return new Response(JSON.stringify({
                success: false,
                message: 'Failed to create worker',
                error: result.errors || result
            }), {
                status: response.status,
                headers
            });
        }
    } catch (error) {
        return new Response(JSON.stringify({
            success: false,
            message: 'Internal server error',
            error: error.message
        }), {
            status: 500,
            headers
        });
    }
}
// 删除Worker
async function handleDeleteWorker(request, accountId, token, scriptName, headers) {
    if (request.method !== 'DELETE') {
        return new Response('Method Not Allowed', {
            status: 405,
            headers: {
                ...headers,
                'Allow': 'DELETE'
            }
        });
    }
    try {
        const apiUrl = `https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/${scriptName}`;
        const response = await fetch(apiUrl, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${token}`,
            }
        });
        const result = await response.json();
        if (response.ok || response.status === 404) {
            return new Response(JSON.stringify({
                success: true,
                message: response.status === 404 ? `Worker "${scriptName}" not found (already deleted?)` : `Worker "${scriptName}" deleted successfully`,
                scriptName
            }), {
                status: 200,
                headers
            });
        } else {
            return new Response(JSON.stringify({
                success: false,
                message: 'Failed to delete worker',
                error: result.errors || result
            }), {
                status: response.status,
                headers
            });
        }
    } catch (error) {
        return new Response(JSON.stringify({
            success: false,
            message: 'Internal server error',
            error: error.message
        }), {
            status: 500,
            headers
        });
    }
}
// 开启Worker日志记录
async function handleEnableLogs(request, accountId, token, scriptName, headers) {
    if (request.method !== 'PATCH' && request.method !== 'POST') {
        return new Response('Method Not Allowed', {
            status: 405,
            headers: {
                ...headers,
                'Allow': 'PATCH, POST'
            }
        });
    }
    try {
        const success = await enableLogsForWorker(accountId, token, scriptName);
        if (success) {
            return new Response(JSON.stringify({
                success: true,
                message: `Logging enabled for worker "${scriptName}"`,
                scriptName
            }), {
                status: 200,
                headers
            });
        } else {
            return new Response(JSON.stringify({
                success: false,
                message: `Failed to enable logging for worker "${scriptName}"`,
                scriptName
            }), {
                status: 500,
                headers
            });
        }
    } catch (error) {
        return new Response(JSON.stringify({
            success: false,
            message: 'Internal server error',
            error: error.message
        }), {
            status: 500,
            headers
        });
    }
}
// 启用日志记录
async function enableLogsForWorker(accountId, token, scriptName) {
    try {
        const apiUrl = `https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/${scriptName}/script-settings`;
        const settings = {
            observability: {
                enabled: true,
                head_sampling_rate: 1,
                logs: {
                    enabled: true,
                    head_sampling_rate: 1,
                    persist: true,
                    invocation_logs: true
                },
                traces: {
                    enabled: false,
                    persist: true,
                    head_sampling_rate: 1
                }
            }
        };
        const response = await fetch(apiUrl, {
            method: 'PATCH',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(settings)
        });
        const result = await response.json();
        return response.ok;
    } catch (error) {
        console.error('Error enabling logs:', error);
        return false;
    }
}
// 前端页面 /setting
function handleSettingPage(acc, logined) {
    const html = `
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
        <meta charset="UTF-8">
        <link rel="icon" href="/favicon.svg" type="image/svg+xml">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Worker 编辑器|设置 Worker</title>
        <link rel="stylesheet" href="/static/style.css">
        <style>
        .container { max-width: 800px; margin: 0 auto; }
        .log { background-color: var(--surface-color); padding: 1rem; border-radius: var(--radius); font-family: monospace; margin-top: 0.5rem; border: 1px solid var(--border-color); }
        .log.error { color: var(--danger-color); border-left: 3px solid var(--danger-color); }
        .log.success { color: var(--success-color); border-left: 3px solid var(--success-color); }
        .btn-danger { background-color: var(--danger-color); }
        .btn-danger:hover { background-color: #dc2626; }

        /* 删除确认模态框样式 */
        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 1000; }
        .modal-content {
        background: var(--surface-color);
        margin: 15% auto;
        padding: 1.5rem;
        width: 90%;
        max-width: 500px;
        border-radius: var(--radius);
        border: 1px solid var(--border-color);
        box-shadow: var(--shadow);
        }
        .modal-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 1rem;
        padding-bottom: 0.75rem;
        border-bottom: 1px solid var(--border-color);
        }
        .close { font-size: 1.5rem; cursor: pointer; color: var(--text-secondary); }
        .close:hover { color: var(--danger-color); }
        .delete-confirm {
        background: rgba(239,68,68,0.1);
        border: 1px solid var(--danger-color);
        padding: 1rem;
        border-radius: var(--radius);
        margin: 1rem 0;
        }
        .confirm-input {
        margin: 0.5rem 0;
        padding: 0.5rem;
        border: 1px solid var(--danger-color);
        border-radius: var(--radius);
        width: 100%;
        }
        .confirm-text {
        font-weight: bold;
        color: var(--danger-color);
        margin-bottom: 0.5rem;
        }
        .confirm-note {
        font-size: 0.875rem;
        color: var(--text-secondary);
        margin-top: 0.5rem;
        }
        .button-group { display: flex; gap: 0.5rem; flex-wrap: wrap; margin-top: 1rem; }
        .danger-zone {
        border: 2px solid var(--danger-color);
        border-radius: var(--radius);
        padding: 1rem;
        margin-top: 1rem;
        }
        </style>
        </head>
        <body>
        {{NAVBAR}}
        <main class="container">
        <h1>Cloudflare Worker管理</h1>

        <!-- URL参数显示 -->
        <div class="card">
        <h3>当前Worker</h3>
        <div id="currentWorker" class="mb-3">未指定</div>
        </div>

        <!-- 创建Worker -->
        <div style="display: none;">
        <div class="card">
        <h3>创建Worker</h3>
        <div class="form-group">
        <input type="text" id="workerName" placeholder="worker名称（留空自动生成）" class="mb-2">
        <button onclick="createWorker()" class="btn">创建Hello World Worker</button>
        </div>
        <div id="createLog" class="log"></div>
        </div>
        </div>

        <!-- 管理日志 -->
        <div class="card">
        <h3>日志设置</h3>
        <button onclick="enableLogs()" class="btn">开启当前Worker日志</button>
        <div id="logsLog" class="log"></div>
        </div>

        <!-- 删除Worker -->
        <div class="card danger-zone">
        <h3 style="color: var(--danger-color);">删除Worker</h3>
        <div class="form-group">
        <input type="text" id="deleteWorkerName" placeholder="要删除的worker名称" class="mb-2">
        <button onclick="promptDeleteWorker()" class="btn btn-danger">删除Worker</button>
        </div>
        <div id="deleteLog" class="log"></div>
        </div>

        <!-- 所有操作日志 -->
        <div style="display: none;">
        <div class="card">
        <h3>操作历史</h3>
        <div id="historyLog" class="log"></div>
        </div>
        </div>
        </div>

        <!-- 删除Worker确认模态框 -->
        <div id="deleteWorkerModal" class="modal">
        <div class="modal-content">
        <div class="modal-header">
        <h3 style="margin: 0; color: var(--danger-color);">确认删除Worker</h3>
        <span class="close" onclick="closeDeleteWorkerModal()">&times;</span>
        </div>
        <div class="delete-confirm">
        <div class="confirm-text">⚠️ 危险操作警告</div>
        <p>您正在尝试删除Worker: <strong id="workerToDeleteName"></strong></p>
        <p>此操作将永久删除该Worker及其所有关联数据，且不可恢复！</p>

        <div class="confirm-note">
        请输入<strong id="workerToDeleteConfirm"></strong>以确认操作:
        </div>
        <input type="text" id="workerConfirmInput" placeholder="请输入Worker名称" class="confirm-input" autocomplete="off">
        </div>
        <div class="button-group">
        <button onclick="confirmDeleteWorker()" id="confirmDeleteWorkerBtn" class="btn btn-danger" disabled>确认删除</button>
        <button onclick="closeDeleteWorkerModal()" class="btn btn-secondary">取消</button>
        </div>
        <div id="workerConfirmError" class="log error" style="display: none; margin-top: 0.5rem;"></div>
        </div>
        </main>
        <script>
        // 从URL获取worker参数
        const urlParams = new URLSearchParams(window.location.search);
        const workerParam = urlParams.get('worker');

        // 显示当前worker
        if (workerParam) {
        document.getElementById('currentWorker').textContent = workerParam;
        document.getElementById('deleteWorkerName').value = workerParam;
        }

        const API_BASE = '/api/setting';
        let workerToDelete = null; // 存储要删除的worker名称

        // 页面加载完成后的初始化
        document.addEventListener('DOMContentLoaded', function() {
        // 监听确认输入框的变化
        document.getElementById('workerConfirmInput').addEventListener('input', function() {
        const confirmBtn = document.getElementById('confirmDeleteWorkerBtn');
        const workerName = workerToDelete || '';
        const inputValue = this.value.trim();

        confirmBtn.disabled = inputValue !== workerName;
        });

        // 添加历史记录
        addHistory('页面加载完成');
        });

        // 添加历史记录
        function addHistory(message, type = 'info') {
        const historyDiv = document.getElementById('historyLog');
        const timestamp = new Date().toLocaleTimeString();
        const color = type === 'error' ? 'var(--danger-color)' :
        type === 'success' ? 'var(--success-color)' : 'var(--text-color)';
        historyDiv.innerHTML = \`<div style="color:\${color}">[\${timestamp}] \${message}</div>\` + historyDiv.innerHTML;
        }

        // 创建Worker
        async function createWorker() {
        const workerName = document.getElementById('workerName').value || \`worker-\${Date.now()}\`;
        const logDiv = document.getElementById('createLog');

        logDiv.textContent = '创建中...';
        logDiv.className = 'log';

        try {
        const response = await fetch(\`\${API_BASE}/create\`, {
        method: 'POST',
        headers: {
        'Content-Type': 'application/json',
        },
        body: JSON.stringify({ scriptName: workerName })
        });

        const result = await response.json();

        if (result.success) {
        logDiv.innerHTML = \`✅ 成功创建: \${workerName}\`;
        logDiv.className = 'log success';
        addHistory(\`创建Worker: \${workerName}\`, 'success');

        // 更新URL并刷新当前worker显示
        window.history.pushState({}, '', \`?worker=\${workerName}\`);
        document.getElementById('currentWorker').textContent = workerName;
        document.getElementById('deleteWorkerName').value = workerName;
        } else {
        logDiv.innerHTML = \`❌ 创建失败: \${result.message}\`;
        logDiv.className = 'log error';
        addHistory(\`创建失败: \${result.message}\`, 'error');
        }
        } catch (error) {
        logDiv.innerHTML = \`❌ 网络错误: \${error.message}\`;
        logDiv.className = 'log error';
        addHistory(\`网络错误: \${error.message}\`, 'error');
        }
        }

        // 开启日志
        async function enableLogs() {
        const workerName = workerParam || document.getElementById('deleteWorkerName').value;
        if (!workerName) {
        alert('请先指定worker名称');
        return;
        }

        const logDiv = document.getElementById('logsLog');
        logDiv.textContent = '开启日志中...';
        logDiv.className = 'log';

        try {
        const response = await fetch(\`\${API_BASE}/logs/\${workerName}\`, {
        method: 'PATCH'
        });

        const result = await response.json();

        if (result.success) {
        logDiv.innerHTML = \`✅ 已开启日志: \${workerName}\`;
        logDiv.className = 'log success';
        addHistory(\`开启日志: \${workerName}\`, 'success');
        } else {
        logDiv.innerHTML = \`❌ 开启日志失败: \${result.message}\`;
        logDiv.className = 'log error';
        addHistory(\`开启日志失败: \${result.message}\`, 'error');
        }
        } catch (error) {
        logDiv.innerHTML = \`❌ 网络错误: \${error.message}\`;
        logDiv.className = 'log error';
        addHistory(\`网络错误: \${error.message}\`, 'error');
        }
        }

        // 显示删除Worker确认模态框
        function promptDeleteWorker() {
        const workerName = document.getElementById('deleteWorkerName').value;
        if (!workerName) {
        alert('请输入要删除的worker名称');
        return;
        }

        workerToDelete = workerName;

        // 重置确认输入
        document.getElementById('workerConfirmInput').value = '';
        document.getElementById('workerToDeleteName').textContent = workerName;
        document.getElementById('workerToDeleteConfirm').textContent = workerName;
        document.getElementById('workerConfirmInput').placeholder = workerName;
        document.getElementById('workerConfirmError').style.display = 'none';
        document.getElementById('confirmDeleteWorkerBtn').disabled = true;

        // 显示模态框
        document.getElementById('deleteWorkerModal').style.display = 'block';
        }

        // 关闭删除Worker确认模态框
        function closeDeleteWorkerModal() {
        document.getElementById('deleteWorkerModal').style.display = 'none';
        workerToDelete = null;
        }

        // 确认删除Worker
        async function confirmDeleteWorker() {
        if (!workerToDelete) return;

        const inputValue = document.getElementById('workerConfirmInput').value.trim();
        const errorDiv = document.getElementById('workerConfirmError');

        if (inputValue !== workerToDelete) {
        errorDiv.textContent = '输入的名称与要删除的Worker名称不匹配';
        errorDiv.style.display = 'block';
        return;
        }

        const logDiv = document.getElementById('deleteLog');
        logDiv.textContent = '删除中...';
        logDiv.className = 'log';

        try {
        const response = await fetch(\`\${API_BASE}/delete/\${workerToDelete}\`, {
        method: 'DELETE'
        });

        const result = await response.json();

        if (result.success) {
        logDiv.innerHTML = \`✅ 已删除: \${workerToDelete}\`;
        logDiv.className = 'log success';
        addHistory(\`删除Worker: \${workerToDelete}\`, 'success');

        // 关闭模态框
        closeDeleteWorkerModal();

        // 删除成功后自动跳转到列表页面并显示成功消息
        setTimeout(() => {
        window.location.href = '/list?message=删除成功';
        }, 1000); // 延迟1秒跳转，让用户看到成功消息
        } else {
        errorDiv.textContent = \`删除失败: \${result.message}\`;
        errorDiv.style.display = 'block';
        addHistory(\`删除失败: \${result.message}\`, 'error');
        }
        } catch (error) {
        errorDiv.textContent = \`网络错误: \${error.message}\`;
        errorDiv.style.display = 'block';
        addHistory(\`网络错误: \${error.message}\`, 'error');
        }
        }

        // 点击模态框外部关闭
        window.onclick = function(event) {
        const modal = document.getElementById('deleteWorkerModal');
        if (event.target === modal) closeDeleteWorkerModal();
        }
        </script>
        </body>
        </html>
        `;

    /*if (logined) {
        return buildHtmlResponse(html, acc, {
            littleNav: false,
            errorHandler: errHtml,
            homeUrl: '/list'
        });
    } else {
        return buildHtmlResponse(html, '', {
            littleNav: true,
            errorOverlay: {
                code: 401,
                message: '请先登录',
                redirectUrl: '/login',
                homeOnly: true
            },
            errorHandler: errHtml,
            homeUrl: '/'
        });
    }*/
    return buildHtmlResponse(html, acc, {
        littleNav: false,
        errorHandler: errHtml,
        homeUrl: '/list'
    });
}
// 新建前端 /create
function handleCreatePage(acc, logined) {
    const html = `
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
        <meta charset="UTF-8">
        <link rel="icon" href="/favicon.svg" type="image/svg+xml">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Worker 编辑器|新建 Worker</title>
        <link rel="stylesheet" href="/static/style.css">
        <style>
        .create-container { max-width: 600px; margin: 0 auto; }
        .log { background-color: var(--surface-color); padding: 1rem; border-radius: var(--radius); font-family: monospace; margin-top: 1rem; border: 1px solid var(--border-color); }
        .log.success { color: var(--success-color); border-left: 3px solid var(--success-color); }
        .log.error { color: var(--danger-color); border-left: 3px solid var(--danger-color); }
        </style>
        </head>
        <body>
        {{NAVBAR}}
        <main>
        <div class="create-container">
        <div class="card">
        <h1>创建Cloudflare Worker</h1>

        <div class="form-group">
        <input type="text" id="workerName" placeholder="输入Worker名称" class="mb-2">
        <button onclick="createWorker()" class="btn">创建Hello World Worker</button>
        </div>

        <div id="result" class="log"></div>
        </div>
        </div>
        </main>
        <script>
        async function createWorker() {
        const nameInput = document.getElementById('workerName');
        const workerName = nameInput.value.trim();

        if (!workerName) {
        alert('请输入Worker名称');
        return;
        }

        const resultDiv = document.getElementById('result');
        resultDiv.textContent = '创建中...';
        resultDiv.className = 'log';

        try {
        const response = await fetch('/api/setting/create', {
        method: 'POST',
        headers: {
        'Content-Type': 'application/json',
        },
        body: JSON.stringify({ scriptName: workerName })
        });

        const data = await response.json();

        if (data.success) {
        resultDiv.innerHTML = \`✅ 创建成功！Worker名称: \${workerName}<br>\${data.message}\`;
        resultDiv.className = 'log success';
        nameInput.value = '';
        } else {
        resultDiv.innerHTML = \`❌ 创建失败: \${data.message}\`;
        resultDiv.className = 'log error';
        }
        } catch (error) {
        resultDiv.innerHTML = \`❌ 网络错误: \${error.message}\`;
        resultDiv.className = 'log error';
        }
        }
        </script>
        </body>
        </html>
        `;
    /*if (logined) {
        return buildHtmlResponse(html, acc, {
            littleNav: false,
            errorHandler: errHtml,
            homeUrl: '/list'
        });
    } else {
        return buildHtmlResponse(html, '', {
            littleNav: true,
            errorOverlay: {
                code: 401,
                message: '请先登录',
                redirectUrl: '/login',
                homeOnly: true
            },
            errorHandler: errHtml,
            homeUrl: '/'
        });
    }*/
    return buildHtmlResponse(html, acc, {
        littleNav: false,
        errorHandler: errHtml,
        homeUrl: '/list'
    });
}
//=================curl===================
// cURL代理/api/curl
async function handleCurl(request, token, url) {
    if (url.pathname === '/api/curl/raw') {
        return handleCurlRaw(request, token);
    }
    // 只接受POST请求
    if (request.method !== 'POST') {
        return new Response(JSON.stringify({
            success: false,
            error: '只支持POST请求'
        }), {
            status: 405,
            headers: {
                'Content-Type': 'application/json'
            }
        });
    }
    try {
        const {
            curl,
            addToken
        } = await request.json();
        if (!curl) {
            return new Response(JSON.stringify({
                success: false,
                error: '未提供cURL命令'
            }), {
                status: 400,
                headers: {
                    'Content-Type': 'application/json'
                }
            });
        }
        // 解析cURL命令
        const parsed = parseCurlCommand(curl);
        if (!parsed.success) {
            return new Response(JSON.stringify({
                success: false,
                error: parsed.error
            }), {
                status: 400,
                headers: {
                    'Content-Type': 'application/json'
                }
            });
        }
        // 验证URL是否为api.cloudflare.com
        if (!parsed.url.hostname.endsWith('api.cloudflare.com')) {
            return new Response(JSON.stringify({
                success: false,
                error: '只能代理到api.cloudflare.com域名的请求'
            }), {
                status: 400,
                headers: {
                    'Content-Type': 'application/json'
                }
            });
        }
        // 准备请求头
        const headers = new Headers(/** @type {Record<string, string>} */(parsed.headers || {}));
        // 如果勾选了附加token，添加认证头
        if (addToken) {
            // 使用Bearer token认证
            headers.set('Authorization', `Bearer ${token}`);
        }
        // 构建代理请求
        const startTime = Date.now();
        const proxyRequest = new Request(parsed.url.toString(), {
            method: parsed.method,
            headers: headers,
            body: parsed.body,
            redirect: 'manual'
        });
        // 发送请求
        const response = await fetch(proxyRequest);
        const duration = Date.now() - startTime;
        // 获取响应数据和头
        const responseText = await response.text();
        const responseHeaders = {};
        response.headers.forEach((value, key) => {
            responseHeaders[key] = value;
        });
        // 尝试解析JSON响应以便格式化显示
        let parsedData = responseText;
        let isJson = false;
        try {
            parsedData = JSON.parse(responseText);
            parsedData = JSON.stringify(parsedData, null, 2);
            isJson = true;
        } catch {
            // 不是JSON，保持原样
        }
        // 返回结果
        return new Response(JSON.stringify({
            success: true,
            data: parsedData,
            isJson: isJson,
            headers: Object.entries(responseHeaders).map(([key, value]) => `${key}: ${value}`).join('\n'),
            url: parsed.url.toString(),
            method: parsed.method,
            addToken: addToken,
            statusCode: response.status,
            duration: duration
        }), {
            headers: {
                'Content-Type': 'application/json'
            }
        });
    } catch (error) {
        return new Response(JSON.stringify({
            success: false,
            error: `处理请求时出错: ${error.message}`
        }), {
            status: 500,
            headers: {
                'Content-Type': 'application/json'
            }
        });
    }
}
// 原始响应
async function handleCurlRaw(request, token) {
    // 只接受POST请求
    if (request.method !== 'POST') {
        return errHtml(405, '只支持POST请求', '/curl', true);
    }
    try {
        // 解析表单数据
        const formData = await request.formData();
        const curl = formData.get('curl');
        const addToken = formData.get('addToken');
        if (!curl) {
            return errHtml(400, '未提供cURL命令', '/curl', true);
        }
        // 解析cURL命令
        const parsed = parseCurlCommand(curl);
        if (!parsed.success) {
            return errHtml(400, parsed.error, '/curl', true);
        }
        // 验证URL是否为api.cloudflare.com
        if (!parsed.url.hostname.endsWith('api.cloudflare.com')) {
            return errHtml(400, '只能代理到api.cloudflare.com域名的请求', '/curl', true);
        }
        // 准备请求头
        const headers = new Headers(/** @type {Record<string, string>} */(parsed.headers || {}));
        // 如果勾选了附加token，添加认证头
        if (addToken) {
            headers.set('Authorization', `Bearer ${token}`);
        }
        // 构建代理请求
        const proxyRequest = new Request(parsed.url.toString(), {
            method: parsed.method,
            headers: headers,
            body: parsed.body,
            redirect: 'manual'
        });
        // 发送请求并直接返回原始响应
        const response = await fetch(proxyRequest);
        // 创建一个新的响应，复制原始响应的所有内容
        const responseHeaders = new Headers(response.headers);
        // 添加 CORS 头以允许跨域访问
        responseHeaders.set('Access-Control-Allow-Origin', '*');
        // 返回原始响应
        return new Response(response.body, {
            status: response.status,
            statusText: response.statusText,
            headers: responseHeaders
        });
    } catch (error) {
        return errHtml(500, `处理请求时出错: ${error.message}`, '/curl', true);
    }
}
// 解析cURL命令
function parseCurlCommand(curlCommand) {
    // 移除多余的空白字符
    const command = curlCommand.trim();
    // 检查是否以curl开头
    if (!command.toLowerCase().startsWith('curl')) {
        return {
            success: false,
            error: '不是有效的cURL命令'
        };
    }
    // 移除curl前缀
    let args = command.substring(4).trim();
    // 解析参数
    let method = 'GET';
    let url = null;
    const headers = {};
    let body = null;
    // 使用正则表达式匹配常见cURL选项
    const regex = /(?:-X\s+(\w+)|--request\s+(\w+)|-H\s+['"]([^'"]+)['"]|--header\s+['"]([^'"]+)['"]|-d\s+['"]([^'"]+)['"]|--data\s+['"]([^'"]+)['"]|--data-binary\s+['"]([^'"]+)['"]|'([^']+)'|"([^"]+)")/g;
    let match;
    const urlCandidates = [];
    while ((match = regex.exec(args)) !== null) {
        // 请求方法
        if (match[1] || match[2]) {
            method = (match[1] || match[2]).toUpperCase();
        }
        // 请求头
        else if (match[3] || match[4]) {
            const header = match[3] || match[4];
            const separator = header.indexOf(':');
            if (separator > 0) {
                const key = header.substring(0, separator).trim();
                const value = header.substring(separator + 1).trim();
                headers[key] = value;
            }
        }
        // 请求体
        else if (match[5] || match[6] || match[7]) {
            body = match[5] || match[6] || match[7];
        }
        // URL（引号包围）
        else if (match[8] || match[9]) {
            const candidate = match[8] || match[9];
            if (candidate.startsWith('http://') || candidate.startsWith('https://')) {
                urlCandidates.push(candidate);
            }
        }
    }
    // 查找没有引号包围的URL（匹配http://或https://开头的部分）
    const urlRegex = /(https?:\/\/[^\s'"]+)/g;
    let urlMatch;
    while ((urlMatch = urlRegex.exec(args)) !== null) {
        urlCandidates.push(urlMatch[1]);
    }
    // 选择最后一个URL（通常是cURL命令中的目标URL）
    if (urlCandidates.length > 0) {
        url = urlCandidates[urlCandidates.length - 1];
    }
    if (!url) {
        return {
            success: false,
            error: '未找到有效的URL'
        };
    }
    // 解析URL
    let parsedUrl;
    try {
        parsedUrl = new URL(url);
    } catch {
        return {
            success: false,
            error: '无效的URL格式'
        };
    }
    // 如果有请求体，设置Content-Type头（如果未指定）
    if (body && !headers['Content-Type']) {
        // 尝试检测是否为JSON
        try {
            JSON.parse(body);
            headers['Content-Type'] = 'application/json';
        } catch {
            // 不是JSON，使用默认类型
            headers['Content-Type'] = 'application/x-www-form-urlencoded';
        }
    }
    return {
        success: true,
        method: method,
        url: parsedUrl,
        headers: headers,
        body: body
    };
}
// 前端页面 /curl
function handleCurlPage(acc, logined) {
    const html = `
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
        <meta charset="UTF-8">
        <link rel="icon" href="/favicon.svg" type="image/svg+xml">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Worker 编辑器|cURL 代理工具</title>
        <link rel="stylesheet" href="/static/style.css">
        <style>
        .container { max-width: 900px; margin: 0 auto; }
        .options { display: flex; gap: 1rem; align-items: center; margin: 1rem 0; }
        .tabs { display: flex; gap: 0.5rem; margin-bottom: 1rem; }
        .tab { padding: 0.5rem 1rem; background-color: var(--surface-color); cursor: pointer; border-radius: var(--radius); border: 1px solid var(--border-color); }
        .tab.active { background-color: var(--primary-color); color: white; }
        pre { background-color: var(--surface-color); padding: 1rem; border-radius: var(--radius); overflow: auto; border: 1px solid var(--border-color); margin: 0; font-family: monospace; }
        textarea { width: 100%; height: 100px; font-family: monospace; margin-bottom: 1rem; }
        .header { color: var(--primary-color); font-weight: bold; }
        .error { color: var(--danger-color); }
        .json { color: var(--text-color); }
        .options { display: flex; gap: 1rem; align-items: center; margin: 1rem 0; flex-wrap: wrap; }
        </style>
        </head>
        <body>
        {{NAVBAR}}
        <main class="container">
        <div class="card">
        <h1>cURL代理工具</h1>
        <p>输入cURL命令，代理将发送到api.cloudflare.com并返回结果</p>
        <textarea id="curlInput" placeholder="例如: curl -X GET https://api.cloudflare.com/client/v4/zones"></textarea>

        <div class="options">
        <label>
        <input type="checkbox" id="addToken"> 附加认证令牌
        </label>
        <label>
        <input type="checkbox" id="openInNewTab"> 打开原始响应
        </label>
        </label>
        <button id="sendBtn" class="btn">发送请求</button>
        </div>

        <div class="result" id="resultContainer" style="display:none;">
        <div class="tabs">
        <div class="tab active" data-tab="response">响应内容</div>
        <div class="tab" data-tab="headers">响应头</div>
        <div class="tab" data-tab="info">请求信息</div>
        </div>
        <pre id="responseOutput"></pre>
        <pre id="headersOutput" style="display:none;"></pre>
        <pre id="infoOutput" style="display:none;"></pre>
        </div>
        </div>
        </main>

        <script>
        const curlInput = document.getElementById('curlInput');
        const sendBtn = document.getElementById('sendBtn');
        const addTokenCheck = document.getElementById('addToken');
        const resultContainer = document.getElementById('resultContainer');
        const responseOutput = document.getElementById('responseOutput');
        const headersOutput = document.getElementById('headersOutput');
        const infoOutput = document.getElementById('infoOutput');

        // 标签切换
        function showTab(tabName) {
        document.querySelectorAll('.tab').forEach(t => {
        t.classList.toggle('active', t.getAttribute('data-tab') === tabName);
        });

        responseOutput.style.display = tabName === 'response' ? 'block' : 'none';
        headersOutput.style.display = tabName === 'headers' ? 'block' : 'none';
        infoOutput.style.display = tabName === 'info' ? 'block' : 'none';
        }

        // 初始化标签点击事件
        document.addEventListener('DOMContentLoaded', function() {
        document.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', function() {
        const tabName = this.getAttribute('data-tab');
        showTab(tabName);
        });
        });
        });

        // 发送请求
        sendBtn.addEventListener('click', async () => {
        const curlCommand = curlInput.value.trim();
        if (!curlCommand) {
        alert('请输入cURL命令');
        return;
        }
        const openInNewTab = document.getElementById('openInNewTab').checked;

        // 如果选择了在新标签页打开，使用表单提交
        if (openInNewTab) {
        // 创建表单并提交
        const form = document.createElement('form');
        form.method = 'POST';
        form.action = '/api/curl/raw';  // 新增的原始响应端点
        form.target = '_blank';  // 在新标签页打开
        form.style.display = 'none';

        // 添加 curl 命令参数
        const curlInputField = document.createElement('input');
        curlInputField.type = 'hidden';
        curlInputField.name = 'curl';
        curlInputField.value = curlCommand;
        form.appendChild(curlInputField);

        // 添加 token 参数
        const tokenInputField = document.createElement('input');
        tokenInputField.type = 'hidden';
        tokenInputField.name = 'addToken';
        tokenInputField.value = addToken;
        form.appendChild(tokenInputField);

        // 将表单添加到页面并提交
        document.body.appendChild(form);
        form.submit();
        document.body.removeChild(form);
        return;
        }
        sendBtn.disabled = true;
        sendBtn.textContent = '发送中...';

        try {
        const response = await fetch('/api/curl/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
        curl: curlCommand,
        addToken: addTokenCheck.checked
        })
        });

        const result = await response.json();

        if (result.success) {
        responseOutput.textContent = result.data;
        responseOutput.className = result.isJson ? 'json' : '';

        headersOutput.textContent = result.headers;

        infoOutput.innerHTML = \`<span class="header">目标URL:</span> \${result.url}\\n\` +
        \`<span class="header">请求方法:</span> \${result.method}\\n\` +
        \`<span class="header">附加Token:</span> \${result.addToken ? '是' : '否'}\\n\` +
        \`<span class="header">状态码:</span> \${result.statusCode}\\n\` +
        \`<span class="header">请求耗时:</span> \${result.duration}ms\`;

        resultContainer.style.display = 'block';
        showTab('response');
        } else {
        responseOutput.textContent = result.error;
        responseOutput.className = 'error';
        resultContainer.style.display = 'block';
        showTab('response');
        }
        } catch (error) {
        responseOutput.textContent = '请求失败: ' + error.message;
        responseOutput.className = 'error';
        resultContainer.style.display = 'block';
        showTab('response');
        } finally {
        sendBtn.disabled = false;
        sendBtn.textContent = '发送请求';
        }
        });
        // 示例cURL命令
        curlInput.value = 'curl -X GET "https://api.cloudflare.com/client/v4/zones"';
        </script>
        </body>
        </html>
        `;
    /*if (logined) {
        return buildHtmlResponse(html, acc, {
            littleNav: false,
            errorHandler: errHtml,
            homeUrl: '/list'
        });
    } else {
        return buildHtmlResponse(html, '', {
            littleNav: true,
            errorOverlay: {
                code: 401,
                message: '请先登录',
                redirectUrl: '/login',
                homeOnly: true
            },
            errorHandler: errHtml,
            homeUrl: '/'
        });
    }*/
    return buildHtmlResponse(html, acc, {
        littleNav: false,
        errorHandler: errHtml,
        homeUrl: '/list'
    });
}
//================graphQL=================
// worker 分析数据/api/graphql
async function handleGraphQL(request, url, accountId, token) {
    // 仅允许GET和POST
    if (request.method !== 'GET' && request.method !== 'POST') {
        return new Response(JSON.stringify({
            error: 'Method not allowed'
        }), {
            status: 405,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
            },
        });
    }

    // 解析请求参数
    let scriptName,
        start,
        end,
        granularity,
        groupBy;
    if (request.method === 'GET') {
        scriptName = url.searchParams.get('scriptName');
        start = url.searchParams.get('start');
        end = url.searchParams.get('end');
        granularity = url.searchParams.get('granularity') || 'hour'; // 默认按小时
        groupBy = url.searchParams.get('groupBy') || 'time'; // 默认按时间分组
    } else {
        const body = await request.json();
        scriptName = body.scriptName;
        start = body.start;
        end = body.end;
        granularity = body.granularity || 'hour';
        groupBy = body.groupBy || 'time';
    }

    if (!scriptName || !start || !end) {
        return new Response(
            JSON.stringify({
                error: 'Missing required parameters: scriptName, start, end'
            }), {
            status: 400,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
        }
        );
    }

    // 定义两种查询模板
    const timeSeriesQuery = `
        query GetWorkerAnalytics($accountTag: String!, $datetimeStart: Time, $datetimeEnd: Time, $scriptName: String) {
        viewer {
        accounts(filter: {accountTag: $accountTag}) {
        workersInvocationsAdaptive(
        limit: 1000,
        filter: {
        scriptName: $scriptName,
        datetime_geq: $datetimeStart,
        datetime_leq: $datetimeEnd
        },
        orderBy: [datetimeFifteenMinutes_ASC]
        ) {
        sum {
        requests
        errors
        subrequests
        }
        quantiles {
        cpuTimeP50
        cpuTimeP99
        }
        dimensions {
        datetimeFifteenMinutes
        }
        }
        }
        }
        }
        `;

    const locationQuery = `
        query GetWorkerRequestDistribution($accountTag: String!, $datetimeStart: Time, $datetimeEnd: Time, $scriptName: String) {
        viewer {
        accounts(filter: {accountTag: $accountTag}) {
        workersInvocationsAdaptive(
        limit: 10000,
        filter: {
        scriptName: $scriptName,
        datetime_geq: $datetimeStart,
        datetime_leq: $datetimeEnd
        }
        ) {
        sum {
        requests
        }
        dimensions {
        coloCode
        }
        }
        }
        }
        }
        `;

    const endpoint = 'https://api.cloudflare.com/client/v4/graphql';
    const headers = {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
    };

    const variables = {
        accountTag: accountId,
        datetimeStart: start,
        datetimeEnd: end,
        scriptName: scriptName,
    };

    let queryToUse,
        operationName;
    let outputMeta = {};

    if (groupBy === 'colo') {
        // 使用位置查询，忽略粒度
        queryToUse = locationQuery;
        operationName = 'GetWorkerRequestDistribution';
        outputMeta = {
            groupBy: 'colo'
        };
    } else {
        // 使用时序查询，应用粒度替换
        queryToUse = timeSeriesQuery;
        operationName = 'GetWorkerAnalytics';
        // 应用粒度替换
        const suffix = getGranularitySuffix(granularity);
        queryToUse = timeSeriesQuery.replace(/datetimeFifteenMinutes/g, suffix);
    }


    const body = JSON.stringify({
        operationName,
        variables,
        query: queryToUse,
    });

    try {
        const response = await fetch(endpoint, {
            method: 'POST',
            headers,
            body,
        });
        const data = await response.json();

        // 根据 groupBy 调整输出结构，保持清晰
        let result;
        if (groupBy === 'colo') {
            // 提取位置分布数据，格式化为简单数组
            const accounts = data?.data?.viewer?.accounts || [];
            const invocations = accounts[0]?.workersInvocationsAdaptive || [];
            const locationData = invocations.map(item => ({
                coloCode: item.dimensions.coloCode,
                requests: item.sum.requests,
            }));
            result = {
                success: true,
                meta: outputMeta,
                data: locationData,
            };
        } else {
            // 保持原有时间序列结构
            result = {
                success: true,
                meta: outputMeta,
                response: data,
            };
        }

        return new Response(JSON.stringify(result, null, 2), {
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
            },
        });
    } catch (error) {
        return new Response(
            JSON.stringify({
                success: false,
                error: error.message
            }), {
            status: 500,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
        }
        );
    }
}

// 将用户输入的粒度映射到Cloudflare GraphQL维度后缀
function getGranularitySuffix(granularity) {
    const map = {
        'minute': 'datetimeMinute',
        '15min': 'datetimeFifteenMinutes',
        'hour': 'datetimeHour',
        '6hour': 'datetimeSixHours',
        'day': 'datetimeDay'
    };
    return map[granularity] || 'Hour'; // 默认小时
}
// 前端 /graphql
function handleGraphQLPage(acc, logined) {
    const html = `<!DOCTYPE html>
        <html lang="zh-CN">
        <head>
        <meta charset="UTF-8">
        <link rel="icon" href="/favicon.svg" type="image/svg+xml">
        <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=yes">
        <title>Worker 编辑器|统计数据</title>
        <link rel="stylesheet" href="/static/style.css">
        <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.5.0/chart.umd.min.js"></script>
        <style>
        * {
        box-sizing: border-box;
        }
        body {
        font-family: system-ui, 'Segoe UI', Roboto, sans-serif;
        margin: 0;
        padding: 1rem;
        background: var(--bg-color);
        color: var(--text-color);
        transition: var(--transition);
        }
        .container {
        max-width: 1400px;
        margin: 0 auto;
        background: var(--surface-color);
        border-radius: 1.2rem;
        padding: 1.2rem;
        box-shadow: var(--shadow);
        border: 1px solid var(--border-color);
        }
        .toolbar {
        display: flex;
        flex-wrap: wrap;
        gap: 0.6rem;
        align-items: center;
        margin-bottom: 1.2rem;
        }
        button, input {
        padding: 0.4rem 0.9rem;
        border-radius: 2rem;
        border: 1px solid var(--border-color);
        background: var(--bg-color);
        color: var(--text-color);
        cursor: pointer;
        font-size: 0.85rem;
        transition: var(--transition);
        }
        button.primary {
        background: var(--primary-color);
        color: white;
        border: none;
        }
        button:active {
        transform: scale(0.97);
        }
        .flex-row {
        display: flex;
        flex-wrap: wrap;
        gap: 0.5rem;
        align-items: center;
        }
        .chart-card {
        background: var(--surface-color);
        border-radius: 1rem;
        margin: 1rem 0 1.2rem 0;
        padding: 0.2rem 0 0.6rem 0;
        border: 1px solid var(--border-color);
        }
        .section-header {
        display: flex;
        justify-content: space-between;
        align-items: baseline;
        flex-wrap: wrap;
        margin: 0.8rem 0 0.4rem 0;
        cursor: pointer;
        user-select: none;
        }
        .section-header h3 {
        margin: 0;
        font-size: 1.2rem;
        font-weight: 600;
        display: inline-flex;
        align-items: center;
        gap: 8px;
        color: var(--text-color);
        }
        .collapse-icon {
        font-size: 1rem;
        color: var(--text-secondary);
        transition: transform 0.2s;
        }
        .table-collapsible {
        overflow: hidden;
        transition: max-height 0.25s ease-out;
        max-height: 800px;
        }
        .table-collapsible.collapsed {
        max-height: 0px;
        }
        .scrollable-chart {
        overflow-x: auto;
        overflow-y: hidden;
        width: 100%;
        margin: 0.5rem 0;
        position: relative;
        }
        .chart-canvas-container {
        display: inline-block;
        min-width: 100%;
        }
        canvas.time-canvas, canvas.cpu-canvas {
        width: 100%;
        height: auto;
        background: var(--bg-color);
        }
        .scrollable-chart .chart-canvas-container canvas {
        max-height: 260px;
        width: 100%;
        height: auto !important;
        }
        .subnote {
        font-size: 0.7rem;
        color: var(--text-secondary);
        margin-top: 0.2rem;
        text-align: right;
        }
        table {
        width: 100%;
        border-collapse: collapse;
        font-size: 0.8rem;
        background: var(--surface-color);
        color: var(--text-color);
        }
        th, td {
        border-bottom: 1px solid var(--border-color);
        padding: 0.5rem 0.4rem;
        text-align: left;
        }
        th {
        font-weight: 600;
        color: var(--text-color);
        background-color: var(--primary-light);
        }
        .error {
        color: var(--danger-color);
        background: rgba(239, 68, 68, 0.1);
        padding: 0.5rem;
        border-radius: 0.75rem;
        margin: 0.5rem 0;
        border-left: 3px solid var(--danger-color);
        }
        .loading {
        color: var(--primary-color);
        }
        hr {
        margin: 0.8rem 0;
        border-color: var(--border-color);
        }
        .badge {
        font-size: 0.7rem;
        background: var(--primary-light);
        color: var(--primary-dark);
        padding: 0.2rem 0.6rem;
        border-radius: 1rem;
        }
        /* 按钮状态 */
        button:disabled, .btn:disabled {
        opacity: 0.5;
        cursor: not-allowed;
        pointer-events: none;
        }
        /* 填充折线图背景颜色 */
        #timeChart, #cpuChart {
        background-color: var(--bg-color);
        }
        /* 表格横向滚动容器 */
        .table-responsive {
        overflow-x: auto;
        overflow-y: auto;
        width: 100%;
        max-height: 30vw;          /* 保持纵向最大高度，产生纵向滑动 */
        -webkit-overflow-scrolling: touch;
        }
        .table-responsive table {
        width: 100%;
        white-space: nowrap;       /* 单元格内容不换行，强制横向撑开 */
        }
        .table-responsive th,
        .table-responsive td {
        white-space: nowrap;
        }
        /* 饼图容器稳定化 */
        #coloChart {
        max-height: 320px;
        width: 100% !important;
        height: auto !important;
        }
        /* 响应式 */
        @media (max-width: 640px) {
        .container {
        padding: 0.9rem;
        }
        th, td {
        font-size: 0.7rem;
        padding: 0.4rem 0.2rem;
        }
        }
        .text-center { text-align: center; }
        .mt-2 { margin-top: 0.5rem; }
        .mb-2 { margin-bottom: 0.5rem; }
        .no-data-message {
    font-size: 0.95rem;
    border: 1px dashed var(--border-color);
    background: var(--surface-color);
}
        </style>
        </head>
        {{NAVBAR}}
        <body>
        <div class="container">
        <h2 style="margin-top:0;">Worker 请求分析</h2>
        <div class="toolbar">
        <div class="flex-row">
        <label>Worker名称：</label>
        <input type="text" id="workerName" readonly style="min-width: 160px; cursor:default;">
        </div>
        <div class="flex-row">
        <button data-range="20m">20分钟</button>
        <button data-range="3h">3小时</button>
        <button data-range="24h">24小时</button>
        <button data-range="30d">30天</button>
        </div>
        <button id="refreshBtn" style="background:var(--primary-dark);color:var(--bg-color);">查询</button>
        </div>
        <div id="statusMsg"></div>

        <!-- 请求趋势 + CPU 趋势区块 -->
        <div class="chart-card">
        <div class="section-header" id="toggleTimeTableHeader">
        <h3>请求 & CPU 时序 <span class="badge">可左右滑动</span></h3>
        <span class="collapse-icon" id="timeTableIcon">▼</span>
        </div>
        <!-- 请求数+错误数 折线图容器 (带水平滚动) -->
        <div class="scrollable-chart" id="timeScrollWrapper">
        <!-- 请求数 & 错误数无数据提示 -->
<div id="timeNoDataMsg" class="no-data-message" style="display:none; text-align:center; padding:60px 20px; color:var(--text-secondary); background:var(--bg-color); border-radius:1rem;">
    📊 暂无请求数据
</div>
        <div class="chart-canvas-container" id="timeCanvasContainer">
        
        <canvas id="timeChart" style="display: block;"></canvas>
        </div>
        </div>
        <!-- CPU P50/P99 折线图容器 -->
        <div class="scrollable-chart" id="cpuScrollWrapper">
                <!-- CPU 无数据提示 -->
<div id="cpuNoDataMsg" class="no-data-message" style="display:none; text-align:center; padding:60px 20px; color:var(--text-secondary); background:var(--bg-color); border-radius:1rem;">
    ⚙️ 暂无 CPU 数据
</div>
        <div class="chart-canvas-container" id="cpuCanvasContainer">
        <canvas id="cpuChart" style="display: block;"></canvas>
        </div>
        </div>
        <!-- 时序表格 (可折叠) -->
        <div id="timeTableArea" class="table-collapsible">
        <!-- 动态表格会插入此处 -->
        </div>
        </div>

        <hr>

        <!-- 地理分布区域 (饼图) -->
        <div class="chart-card">
        <div class="section-header" id="toggleColoTableHeader">
        <h3>请求分布 (边缘节点)</h3>
        <span class="collapse-icon" id="coloTableIcon">▼</span>
        </div>
        <div class="subnote">cloudflare的边缘节点地理位置命名与所在地区机场命名(IATA)一致</div>
        <div class="scrollable-chart" style="overflow-x: auto;">
        <div style="min-width: 260px; max-width: 500px; margin: 0 auto;">
        <canvas id="coloChart" style="width:100%; max-height: 320px;"></canvas>
        </div>
        <div id="coloNoDataMsg" class="no-data-message" style="display:none; text-align:center; padding:60px 20px; color:var(--text-secondary); background:var(--bg-color); border-radius:1rem;">
    🌍 无地理位置数据
</div>
        </div>
        <div id="coloTableArea" class="table-collapsible">
        <!-- 地理表格动态 -->
        </div>
        </div>
        </div>

        <script>
        (function(){
        // DOM 元素
        const workerInput = document.getElementById('workerName');
        const refreshBtn = document.getElementById('refreshBtn');
        const statusDiv = document.getElementById('statusMsg');
        const timeCanvas = document.getElementById('timeChart');
        const cpuCanvas = document.getElementById('cpuChart');
        const coloCanvas = document.getElementById('coloChart');
        const timeTableArea = document.getElementById('timeTableArea');
        const coloTableArea = document.getElementById('coloTableArea');

        // 折叠控制
        const toggleTimeHeader = document.getElementById('toggleTimeTableHeader');
        const timeTableIcon = document.getElementById('timeTableIcon');
        const toggleColoHeader = document.getElementById('toggleColoTableHeader');
        const coloTableIcon = document.getElementById('coloTableIcon');

        let timeChart = null;
        let cpuChartInstance = null;
        let coloChart = null;
        let currentStart = null, currentEnd = null;
        let currentGranularity = 'hour';

        // 补全后的完整时间序列数据 (用于图表渲染)
        let fullLabels = [];
        let fullRequests = [];
        let fullErrors = [];
        let fullCpuP50 = [];
        let fullCpuP99 = [];

        // ----- 辅助函数：根据时间范围决定粒度 (增强：支持30天范围使用6小时) -----
        function getAutoGranularity(start, end) {
        const diffHours = (end - start) / (1000 * 3600);
        if (diffHours <= 1) return 'minute';
        if (diffHours <= 6) return '15min';
        if (diffHours <= 48) return 'hour';
        // 需求2: 一个月(30天)周期由天改为6小时 -> 对于 diffHours <= 30天 (720小时) 使用 '6hour'
        if (diffHours <= 720) return '6hour';   // 30天 = 720小时
        return 'day';
        }

        // 预设时间范围
        function getRangeDates(rangeId) {
        const now = new Date();
        let start = new Date(now);
        switch(rangeId) {
        case '20m': start.setMinutes(now.getMinutes() - 20); break;
        case '3h': start.setHours(now.getHours() - 3); break;
        case '24h': start.setDate(now.getDate() - 1); break;
        case '30d': start.setDate(now.getDate() - 30); break;
        default: start.setHours(now.getHours() - 3);
        }
        return { start, end: now };
        }

        let currentRangeId = '3h';
        function setTimeRangeById(rangeId) {
        currentRangeId = rangeId;
        const { start, end } = getRangeDates(rangeId);
        currentStart = start;
        currentEnd = end;
        currentGranularity = getAutoGranularity(start, end);
        statusDiv.innerHTML = \`时段: \${start.toLocaleString()} → \${end.toLocaleString()} (粒度: \${currentGranularity})\`;
        }
        setTimeRangeById('3h');

        function highlightRangeButton(activeId) {
        document.querySelectorAll('[data-range]').forEach(btn => {
        if(btn.getAttribute('data-range') === activeId) {
        btn.style.background = '#1e3a8a';
        btn.style.color = 'white';
        btn.style.border = 'none';
        } else {
        btn.style.background = '';
        btn.style.color = '';
        btn.style.border = '1px solid #ccc';
        }
        });
        }
        highlightRangeButton('3h');

        // 通用请求
        async function fetchData(groupBy) {
        const workerName = workerInput.value.trim();
        if(!workerName) throw new Error('请输入 Worker 名称');
        const params = new URLSearchParams();
        params.set('scriptName', workerName);
        params.set('start', currentStart.toISOString());
        params.set('end', currentEnd.toISOString());
        params.set('groupBy', groupBy);
        if(groupBy === 'time') params.set('granularity', currentGranularity);
        const resp = await fetch(\`/api/graphql?\${params.toString()}\`);
        if(!resp.ok) throw new Error(\`HTTP \${resp.status}\`);
        const json = await resp.json();
        if(json.success === false) throw new Error(json.error || '请求失败');
        return json;
        }

        // ========== 核心: 补全时间序列 (填补缺失0值，包括CPU指标) ==========
        function generateFullTimeSeries(startDate, endDate, granularity, rawInvocations, timeFieldKey) {
        // 生成完整的时间点列表 (基于 start / end, 左闭右闭)
        const points = [];
        let current = new Date(startDate);
        const end = new Date(endDate);

        const addMinutes = (date, mins) => new Date(date.getTime() + mins * 60000);
        const addHours = (date, hrs) => new Date(date.getTime() + hrs * 3600000);
        const addDays = (date, days) => new Date(date.getTime() + days * 86400000);

        while (current <= end) {
        points.push(new Date(current));
        if (granularity === 'minute') current = addMinutes(current, 1);
        else if (granularity === '15min') current = addMinutes(current, 15);
        else if (granularity === 'hour') current = addHours(current, 1);
        else if (granularity === '6hour') current = addHours(current, 6);
        else if (granularity === 'day') current = addDays(current, 1);
        else break;
        }

        // 构建映射: 时间key(标准化为时间戳) -> 原始数据项
        const map = new Map();
        for (let item of rawInvocations) {
        let rawTime = item.dimensions[timeFieldKey];
        if (!rawTime) continue;
        let dateKey = new Date(rawTime);
        // 对齐到粒度边界（因为API返回时间点可能是整点/整分）
        let aligned = alignDateToGranularity(dateKey, granularity);
        map.set(aligned.getTime(), item);
        }

        const labels = [];
        const requests = [];
        const errors = [];
        const cpuP50 = [];
        const cpuP99 = [];

        for (let pt of points) {
        let boundary = alignDateToGranularity(pt, granularity);
        let ts = boundary.getTime();
        let item = map.get(ts);
        let req = 0, err = 0, p50 = 0, p99 = 0;   // 需求1: CPU指标缺省补0，同请求数
        if (item) {
        req = item.sum?.requests || 0;
        err = item.sum?.errors || 0;
        // 存在item时，若quantiles字段缺失或值为null/undefined，也统一为0
        p50 = (item.quantiles?.cpuTimeP50 !== undefined && item.quantiles?.cpuTimeP50 !== null) ? item.quantiles.cpuTimeP50 : 0;
        p99 = (item.quantiles?.cpuTimeP99 !== undefined && item.quantiles?.cpuTimeP99 !== null) ? item.quantiles.cpuTimeP99 : 0;
        }
        // 格式化显示文本 (用于tooltip)
        let displayLabel = formatTimeLabel(boundary.toISOString(), granularity);
        labels.push(displayLabel);
        requests.push(req);
        errors.push(err);
        cpuP50.push(p50);
        cpuP99.push(p99);
        }
        return { labels, requests, errors, cpuP50, cpuP99 };
        }

        // 对齐时间到粒度边界 (支持6hour)
        function alignDateToGranularity(date, granularity) {
        let d = new Date(date);
        if (granularity === 'minute') {
        d.setSeconds(0, 0);
        } else if (granularity === '15min') {
        let mins = d.getMinutes();
        let rounded = Math.floor(mins / 15) * 15;
        d.setMinutes(rounded, 0, 0);
        } else if (granularity === 'hour') {
        d.setMinutes(0, 0, 0);
        } else if (granularity === '6hour') {
        // 对齐到最近的6小时边界: 0,6,12,18时
        let hours = d.getHours();
        let roundedHour = Math.floor(hours / 6) * 6;
        d.setHours(roundedHour, 0, 0, 0);
        } else if (granularity === 'day') {
        d.setHours(0, 0, 0, 0);
        }
        return d;
        }

        // 格式化时间标签 (支持6hour)
        function formatTimeLabel(iso, granularity) {
        if(!iso) return '';
        try {
        const d = new Date(iso);
        if(isNaN(d.getTime())) return iso.substring(0,16);
        if(granularity === 'day') return \`\${d.getMonth()+1}/\${d.getDate()}\`;
        if(granularity === 'hour') return \`\${d.getMonth()+1}/\${d.getDate()} \${d.getHours()}:00\`;
        if(granularity === '6hour') return \`\${d.getMonth()+1}/\${d.getDate()} \${d.getHours()}:00\`;  // 显示整6小时边界时刻
        if(granularity === '15min') return \`\${d.getMonth()+1}/\${d.getDate()} \${d.getHours()}:\${String(d.getMinutes()).padStart(2,'0')}\`;
        return \`\${d.getMonth()+1}/\${d.getDate()} \${d.getHours()}:\${String(d.getMinutes()).padStart(2,'0')}\`;
        } catch(e) { return iso; }
        }

        // 设置图表水平滚动宽度 (根据数据点数量)

        let lastWidthCache = {}; // 记录每个 wrapper 上一次设置的宽度

        function applyHorizontalScroll(wrapperId, canvasId, chartInstance, pointsCount) {
        if (!wrapperId || !canvasId || typeof pointsCount !== 'number' || pointsCount <= 0) return;
    const wrapper = document.getElementById(wrapperId);
    if (!wrapper) return;
    const container = wrapper.querySelector('.chart-canvas-container');
    const canvas = document.getElementById(canvasId);
    if (!container || !canvas) return;

    // 计算每个数据点的宽度，动态调整整体画布宽度
    let pointWidth = 55;
    if (pointsCount > 80) pointWidth = 42;
    if (pointsCount > 150) pointWidth = 36;
    const baseWidth = Math.max(wrapper.clientWidth, pointsCount * pointWidth);
    const baseHeight = 260;  // 固定高度

    // 跳过重复设置，避免抖动
    if (lastWidthCache[wrapperId] === baseWidth) return;
    lastWidthCache[wrapperId] = baseWidth;

    // 1.设置 canvas 逻辑像素尺寸
    canvas.width = baseWidth;
    canvas.height = baseHeight;

    // 2.容器宽度与 canvas 保持一致
    container.style.width = baseWidth + 'px';

    // 3.通知 Chart.js 重新适配尺寸
    if (chartInstance) {
        chartInstance.resize();
    }

    // 可选：保留 CSS 宽高，保证在容器内填满
    canvas.style.width = '100%';
    canvas.style.height = 'auto';
}

        // 渲染时序双图 (请求趋势 + CPU趋势)
        function renderTimeSeries(data) {
        // 获取提示元素和图表容器
    const timeWrapper = document.getElementById('timeScrollWrapper');
    const cpuWrapper = document.getElementById('cpuScrollWrapper');
    const timeNoData = document.getElementById('timeNoDataMsg');
    const cpuNoData = document.getElementById('cpuNoDataMsg');
    const timeCanvasContainer = document.getElementById('timeCanvasContainer');
    const cpuCanvasContainer = document.getElementById('cpuCanvasContainer');
        let invocations = [];
        // 隐藏提示层
    if (timeNoData) timeNoData.style.display = 'none';
    if (cpuNoData) cpuNoData.style.display = 'none';
    if (timeCanvasContainer) timeCanvasContainer.style.display = 'block';
    if (cpuCanvasContainer) cpuCanvasContainer.style.display = 'block';
        try {
        const respObj = data.response;
        if(!respObj?.data?.viewer?.accounts?.length) throw new Error('无时序数据');
        invocations = respObj.data.viewer.accounts[0].workersInvocationsAdaptive || [];
        if(!invocations.length) throw new Error('该时段无任何请求数据');
        } catch(e) {
        if (timeNoData) timeNoData.style.display = 'block';
        if (cpuNoData) cpuNoData.style.display = 'block';
        if (timeCanvasContainer) timeCanvasContainer.style.display = 'none';
        if (cpuCanvasContainer) cpuCanvasContainer.style.display = 'none';
        timeTableArea.innerHTML = \`<div class="error">⚠️ \${e.message}</div>\`;
        if(timeChart) { timeChart.destroy(); timeChart = null; }
        if(cpuChartInstance) { cpuChartInstance.destroy(); cpuChartInstance = null; }
        return;
        }

        // 找到时间维度字段名
        const timeKey = Object.keys(invocations[0].dimensions).find(k => k.startsWith('datetime'));
        if(!timeKey) throw new Error('时间字段缺失');

        // 补全缺失时间点（零值填充 + cpu补0）
        const { labels, requests, errors, cpuP50, cpuP99 } = generateFullTimeSeries(
        currentStart, currentEnd, currentGranularity, invocations, timeKey
        );

        if(labels.length === 0) {
        if (timeNoData) timeNoData.style.display = 'block';
        if (cpuNoData) cpuNoData.style.display = 'block';
        if (timeCanvasContainer) timeCanvasContainer.style.display = 'none';
        if (cpuCanvasContainer) cpuCanvasContainer.style.display = 'none';
        timeTableArea.innerHTML = '<div class="error">时间序列生成失败</div>';
        return;
        }
        if (timeNoData) timeNoData.style.display = 'none';
    if (cpuNoData) cpuNoData.style.display = 'none';
    if (timeCanvasContainer) timeCanvasContainer.style.display = 'block';
    if (cpuCanvasContainer) cpuCanvasContainer.style.display = 'block';

        fullLabels = labels;
        fullRequests = requests;
        fullErrors = errors;
        fullCpuP50 = cpuP50;
        fullCpuP99 = cpuP99;

        // ========= 1) 请求数+错误数 折线图 =========
        if(timeChart) timeChart.destroy();
        const ctx = timeCanvas.getContext('2d');
        timeChart = new Chart(ctx, {
        type: 'line',
        data: {
        labels: labels,
        datasets: [
        { label: '请求数', data: requests, borderColor: '#3b82f6', backgroundColor: 'rgba(59,130,246,0.08)', fill: true, tension: 0.2, pointRadius: 2, pointHoverRadius: 4, borderWidth: 2 },
        { label: '错误数', data: errors, borderColor: '#ef4444', borderDash: [6,4], tension: 0.2, pointRadius: 1, pointBackgroundColor: '#ef4444', fill: false, borderWidth: 1.8 }
        ]
        },
        options: {
        responsive: true,
        maintainAspectRatio: true,
        plugins: {
        tooltip: { mode: 'index', intersect: false },
        legend: { position: 'top', labels: { boxWidth: 12, font: { size: 11 } } }
        },
        scales: {
        y: { beginAtZero: true, title: { display: true, text: '请求 / 错误数', font: { size: 10 } }, grid: { color: '#e9ecef' } },
        x: { ticks: { display: false },   // 隐去坐标轴字符（紧凑）
        grid: { display: false },
        title: { display: false }
        }
        },
        elements: { point: { radius: 1.5 } }
        }
        });

        // ========= 2) CPU P50/P99 折线图 (补0后不断点) =========
        if(cpuChartInstance) cpuChartInstance.destroy();
        const cpuCtx = cpuCanvas.getContext('2d');
        cpuChartInstance = new Chart(cpuCtx, {
        type: 'line',
        data: {
        labels: labels,
        datasets: [
        { label: 'CPU P50 (ms)', data: cpuP50, borderColor: '#f59e0b', backgroundColor: 'transparent', borderWidth: 2, tension: 0.2, pointRadius: 1.5, pointBackgroundColor: '#f59e0b', spanGaps: false },
        { label: 'CPU P99 (ms)', data: cpuP99, borderColor: '#dc2626', borderWidth: 2, tension: 0.2, pointRadius: 1.5, pointBackgroundColor: '#dc2626', spanGaps: false }
        ]
        },
        options: {
        responsive: true,
        maintainAspectRatio: true,
        plugins: {
        tooltip: { mode: 'index', intersect: false, callbacks: { label: (ctx) => \`\${ctx.dataset.label}: \${ctx.raw !== undefined ? ctx.raw.toFixed(2) : '0.00'} ms\` } },
        legend: { position: 'top', labels: { boxWidth: 12, font: { size: 11 } } }
        },
        scales: {
        y: { beginAtZero: true, title: { display: true, text: 'CPU时间 (ms)', font: { size: 10 } }, grid: { color: '#e9ecef' } },
        x: { ticks: { display: false }, grid: { display: false }, title: { display: false } }
        }
        }
        });

        // 水平滚动条设置 (根据点数动态宽度)
const pointsCount = labels.length;
applyHorizontalScroll('timeScrollWrapper', 'timeChart', timeChart, pointsCount);
applyHorizontalScroll('cpuScrollWrapper', 'cpuChart', cpuChartInstance, pointsCount);

        // 表格渲染 (可折叠内)
        let tableHtml = \`<div class="table-responsive" style="margin-top:0.8rem;"><table>
        <thead><tr><th>时间段</th><th>请求数</th><th>错误数</th><th>CPU P50 (ms)</th><th>CPU P99 (ms)</th></tr></thead><tbody>\`;
        for(let i=0; i<labels.length; i++) {
        let p50Show = (fullCpuP50[i] !== null && fullCpuP50[i] !== undefined) ? fullCpuP50[i].toFixed(2) : '0.00';
        let p99Show = (fullCpuP99[i] !== null && fullCpuP99[i] !== undefined) ? fullCpuP99[i].toFixed(2) : '0.00';
        tableHtml += \`<tr>
        <td>\${escapeHtml(labels[i])}</td>
        <td>\${fullRequests[i].toLocaleString()}</td>
        <td>\${fullErrors[i].toLocaleString()}</td>
        <td>\${p50Show}</td>
        <td>\${p99Show}</td>
        </tr>\`;
        }
        timeTableArea.innerHTML = tableHtml;
        }

        // 饼图: 地理分布 (colo 合并前N项，其余归为Other)
        function renderColoDistribution(data) {
        const coloNoData = document.getElementById('coloNoDataMsg');
    const coloCanvasContainer = document.querySelector('#coloChart').parentNode;
    // 确保 canvas 的父容器存在
    let canvasParent = document.getElementById('coloChart')?.parentNode;
    
    if (coloNoData) coloNoData.style.display = 'none';
    if (canvasParent) canvasParent.style.display = 'block';
        let rawItems = [];
        try {
        // 兼容原返回格式: 可能data.data 或者 data.response? 原逻辑使用 data.data || []
        if(Array.isArray(data)) rawItems = data;
        else if(data.data && Array.isArray(data.data)) rawItems = data.data;
        else if(data.response && data.response.data && Array.isArray(data.response.data)) rawItems = data.response.data;
        else rawItems = [];
        } catch(e) { rawItems = []; }

        if(!rawItems.length) {
        if (coloNoData) coloNoData.style.display = 'block';
        if (canvasParent) canvasParent.style.display = 'none';
        coloTableArea.innerHTML = '<div class="error">无地理位置数据</div>';
        if(coloChart) { coloChart.destroy(); coloChart = null; }
        return;
        }
        if (coloNoData) coloNoData.style.display = 'none';
    if (canvasParent) canvasParent.style.display = 'block';
        // 过滤掉请求为0的节点
        let filtered = rawItems.filter(item => (item.requests || 0) > 0);
        if(filtered.length === 0) {
        coloTableArea.innerHTML = '<div class="error">所有节点请求数为0</div>';
        if(coloChart) { coloChart.destroy(); coloChart = null; }
        return;
        }

        // 排序，取前8个，其余合并为 "其他"
        filtered.sort((a,b) => (b.requests || 0) - (a.requests || 0));
        const TOP_N = 7;
        const topItems = filtered.slice(0, TOP_N);
        let otherSum = 0;
        if(filtered.length > TOP_N) {
        otherSum = filtered.slice(TOP_N).reduce((acc,cur) => acc + (cur.requests || 0), 0);
        }

        const labels = [];
        const values = [];
        for(let item of topItems) {
        labels.push(item.coloCode || '未知');
        values.push(item.requests || 0);
        }
        if(otherSum > 0) {
        labels.push('其他节点');
        values.push(otherSum);
        }

        const total = values.reduce((a,b)=>a+b,0);
        // 饼图绘制
        if(coloChart) coloChart.destroy();
        const ctx = coloCanvas.getContext('2d');
        coloChart = new Chart(ctx, {
        type: 'pie',
        data: {
        labels: labels,
        datasets: [{
        data: values,
        backgroundColor: ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#ec489a', '#14b8a6', '#6b7280'],
        borderWidth: 1,
        borderColor: '#fff'
        }]
        },
        options: {
        responsive: true,
        maintainAspectRatio: true,
        plugins: {
        legend: { position: 'right', labels: { boxWidth: 12, font: { size: 10 } } },
        tooltip: { callbacks: { label: (ctx) => \`\${ctx.label}: \${ctx.raw.toLocaleString()} 次 (\${((ctx.raw/total)*100).toFixed(1)}%)\` } }
        }
        }
        });

        // 表格展示完整分布 (折叠区域)
        let tableHtml = \`<div class="table-responsive" style="margin-top:1rem;"><table>
        <thead><tr><th>coloCode</th><th>请求数</th><th>占比</th></tr></thead><tbody>\`;
        for(let item of filtered) {
        const pct = ((item.requests / total)*100).toFixed(1);
        tableHtml += \`<tr><td>\${escapeHtml(item.coloCode || '-')}</td><td>\${item.requests.toLocaleString()}</td><td>\${pct}%</td></tr>\`;
        }
        tableHtml += \`</tbody></table></div><div class="subnote">📡 总计请求: \${total.toLocaleString()}</div>\`;
        coloTableArea.innerHTML = tableHtml;
        }

        function escapeHtml(str) { return String(str).replace(/[&<>]/g, function(m){ return {'&':'&amp;','<':'&lt;','>':'&gt;'}[m]; }); }

        // 刷新主流程
        async function refreshAll() {
        // 从URL获取worker参数
        const urlParams = new URLSearchParams(window.location.search);
        const workerParam = urlParams.get('worker');
        if (workerParam) {
        workerInput.value = workerParam;
        }
        const workerName = workerInput.value.trim() || workerParam;
        if(!workerName) {
        statusDiv.innerHTML = '<span class="error">请输入 Worker 名称</span>';
        return;
        }
        statusDiv.innerHTML = '<span class="loading">⏳ 查询中，请稍后...</span>';
        try {
        const [timeData, coloData] = await Promise.all([
        fetchData('time'),
        fetchData('colo')
        ]);
        renderTimeSeries(timeData);
        renderColoDistribution(coloData);
        statusDiv.innerHTML = \`✅ 加载成功 <div class="subnote">\${currentStart.toLocaleString()} ~ \${currentEnd.toLocaleString()} (粒度: \${currentGranularity})</div>\`;
        } catch(err) {
        statusDiv.innerHTML = \`<span class="error">❌ 错误: \${err.message}</span>\`;
        if(timeChart) { timeChart.destroy(); timeChart = null; }
        if(cpuChartInstance) { cpuChartInstance.destroy(); cpuChartInstance = null; }
        if(coloChart) { coloChart.destroy(); coloChart = null; }
        timeTableArea.innerHTML = '<div class="error">时序数据加载失败</div>';
        coloTableArea.innerHTML = '<div class="error">位置数据加载失败</div>';
        }
        }

        // 折叠功能: 表格可收折 (默认折叠表格，图表保持可见，满足紧凑)
        function initCollapse() {
        // 默认表格折叠（节省空间）
        timeTableArea.classList.add('collapsed');
        coloTableArea.classList.add('collapsed');
        timeTableIcon.innerText = '▶';
        coloTableIcon.innerText = '▶';

        toggleTimeHeader.addEventListener('click', () => {
        const isCollapsed = timeTableArea.classList.contains('collapsed');
        if(isCollapsed) {
        timeTableArea.classList.remove('collapsed');
        timeTableIcon.innerText = '▼';
        } else {
        timeTableArea.classList.add('collapsed');
        timeTableIcon.innerText = '▶';
        }
        });
        toggleColoHeader.addEventListener('click', () => {
        const isCollapsed = coloTableArea.classList.contains('collapsed');
        if(isCollapsed) {
        coloTableArea.classList.remove('collapsed');
        coloTableIcon.innerText = '▼';
        } else {
        coloTableArea.classList.add('collapsed');
        coloTableIcon.innerText = '▶';
        }
        });
        }

        // 事件绑定
        document.querySelectorAll('[data-range]').forEach(btn => {
        btn.addEventListener('click', () => {
        const range = btn.getAttribute('data-range');
        setTimeRangeById(range);
        highlightRangeButton(range);
        currentGranularity = getAutoGranularity(currentStart, currentEnd);
        refreshAll();
        });
        });
        refreshBtn.addEventListener('click', refreshAll);
        workerInput.addEventListener('keypress', e => { if(e.key === 'Enter') refreshAll(); });

        // 监听窗口resize重新校准滚动宽度
        let resizeTimer;
        window.addEventListener('resize', () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => {
        if (fullLabels && fullLabels.length) {
            lastWidthCache = {};
            if (timeChart) {
                applyHorizontalScroll('timeScrollWrapper', 'timeChart', timeChart, fullLabels.length);
            }
            if (cpuChartInstance) {
                applyHorizontalScroll('cpuScrollWrapper', 'cpuChart', cpuChartInstance, fullLabels.length);
            }
        }
    }, 150);
});
        initCollapse();
        refreshAll();
        })();
        </script>
        </body>
        </html>
        `
    /*if (logined) {
        return buildHtmlResponse(html, acc, {
            littleNav: false,
            errorHandler: errHtml,
            homeUrl: '/list'
        });
    } else {
        return buildHtmlResponse(html, '', {
            littleNav: true,
            errorOverlay: {
                code: 401,
                message: '请先登录',
                redirectUrl: '/login',
                homeOnly: true
            },
            errorHandler: errHtml,
            homeUrl: '/'
        });
    }*/
    return buildHtmlResponse(html, acc, {
        littleNav: false,
        errorHandler: errHtml,
        homeUrl: '/list'
    });
}

//==================end====================