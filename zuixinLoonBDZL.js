/**
 * Loon Custom协议 | 百度免流直连（UDP优先 + 状态校验）
 * 适配：Loon custom type，使用明文HTTP代理（配置中不要加 tls=true）
 * 使用示例：
 * [Proxy]
 * BaiduFree = custom, 153.3.236.22, 443, script-path=脚本地址
 * 
 * 特性：
 * - 动态UA、40位随机TraceID、TLS Padding抗指纹
 * - UDP特征域名优先，其次红果/字节系
 * - 校验代理返回的HTTP状态码，非200时自动断开
 * - 基于readTo()可靠握手
 */

const CONFIG = {
    T5_AUTH_KEY: "683556433",
    ENABLE_FINGERPRINT_MASK: true,
    MIN_PADDING: 8,
    MAX_PADDING: 48,
    LOG_DEBUG: false   // 调试时改为true
};

// 百度UA池
const BAIDU_UA_POOL = [
    "baiduboxapp/8.5.0.0 (Linux; Android 12; Mi 13 Pro)",
    "baiduboxapp/9.0.1.0 (Linux; Android 13; SM-S928B)",
    "Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Mobile Safari/537.36 baiduboxapp/8.2.5",
    "baiduboxapp/7.8.5.0 (iPhone; iOS 16.5; Scale/3.00)",
    "baiduboxapp/8.8.8.8 (Linux; Android 14; Pixel 8 Pro)",
    "netdisk;11.18.3;android-android;12;Mobile"
];

// 红果/字节系域名关键词
const HK_DOMAINS = [
    "zijie", "hongguo", "novel", "pangolin", "sigmob",
    "amemv", "douyin", "iesdouyin", "byteimg",
    "toutiao", "ixigua", "snssdk", "bdurl", "pstatp"
];

// UDP特征关键词（UDP优先）
const UDP_MASK_DOMAINS = [
    "udp", "quic", "game", "minecraft", "dota", "lol",
    "valorant", "genshin", "bilibili", "qpic", "video", "cdn", "streaming", "live"
];

// 会话状态
const sessionMap = {};
const STATUS = {
    INIT: 0,
    HEADER_SENT: 1,
    ESTABLISHED: 2
};

// ===================== 工具函数 =====================
function log(msg) {
    if (CONFIG.LOG_DEBUG) console.log(`[BD-MASK] ${msg}`);
}

function randomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function generateTraceId() {
    const hex = "0123456789abcdef";
    let res = "";
    for (let i = 0; i < 40; i++) {
        res += hex[randomInt(0, 15)];
    }
    return res;
}

function getRandomUA() {
    return BAIDU_UA_POOL[randomInt(0, BAIDU_UA_POOL.length - 1)];
}

function getRandomPadding() {
    if (!CONFIG.ENABLE_FINGERPRINT_MASK) return "";
    const len = randomInt(CONFIG.MIN_PADDING, CONFIG.MAX_PADDING);
    return `X-TLS-Padding: ${"x".repeat(len)}\n`;
}

function isHongguoHost(host) {
    if (!host) return false;
    const h = host.toLowerCase();
    return HK_DOMAINS.some(k => h.includes(k));
}

function matchUdpKeyword(host) {
    if (!host) return false;
    const h = host.toLowerCase();
    return UDP_MASK_DOMAINS.some(k => h.includes(k));
}

function getSessionState(uuid) {
    if (!sessionMap[uuid]) {
        sessionMap[uuid] = {
            status: STATUS.INIT,
            lastHeartbeat: 0
        };
    }
    return sessionMap[uuid];
}

// ===================== CONNECT报文构造 =====================
function buildHeader(targetHost, targetPort, gwHost) {
    const traceId = generateTraceId();
    const ua = getRandomUA();
    const padding = getRandomPadding();
    const isUdp = matchUdpKeyword(targetHost);
    const isHg = isHongguoHost(targetHost);

    let template;
    // UDP 优先
    if (isUdp) {
        template = `CONNECT ${targetHost}:${targetPort} HTTP/1.1
Host: ${gwHost}
Proxy-Connection: Keep-Alive
Connection: keep-alive
X-T5-Auth: ${CONFIG.T5_AUTH_KEY}
User-Agent: ${ua}
X-Bd-Traceid: ${traceId}
X-Bd-Product: BDUSS
X-Bd-Uid: 0
X-Bd-Client-Type: UDP-TRANS
X-Bd-Trans-Type: masquerade
X-Bd-Request-Mode: tunnel
X-TLS-Version: TLSv1.3
${padding}Accept: */*
Content-Length: 0

`;
    } else if (isHg) {
        template = `CONNECT ${targetHost}:${targetPort} HTTP/1.1
Host: ${gwHost}
Proxy-Connection: Keep-Alive
Connection: keep-alive
X-T5-Auth: ${CONFIG.T5_AUTH_KEY}
User-Agent: ${ua}
X-Bd-Traceid: ${traceId}
X-Bd-Product: BDUSS
X-Bd-Uid: 0
X-TLS-Version: TLSv1.3
${padding}Accept: */*

`;
    } else {
        template = `CONNECT ${targetHost}:${targetPort} HTTP/1.1
Host: ${gwHost}
Proxy-Connection: Keep-Alive
Connection: keep-alive
X-T5-Auth: ${CONFIG.T5_AUTH_KEY}
User-Agent: ${ua}
X-Bd-Traceid: ${traceId}
X-TLS-Version: TLSv1.3
${padding}

`;
    }
    return template.replace(/\n/g, "\r\n");
}

// ===================== Loon 生命周期回调 =====================
function tunnelDidConnected() {
    const sess = getSessionState($session.uuid);
    const gwHost = `${$session.proxy.host}:${$session.proxy.port}`;
    const targetHost = $session.conHost;
    const targetPort = $session.conPort;

    if (!$session.proxy.isTLS) {
        const header = buildHeader(targetHost, targetPort, gwHost);
        $tunnel.write($session, header);
        sess.status = STATUS.HEADER_SENT;
        $tunnel.readTo($session, "\r\n\r\n");
        log(`CONNECT sent (non-TLS) -> ${targetHost}:${targetPort}`);
    }
    return true;
}

function tunnelTLSFinished() {
    // 由于配置中未启用tls，该回调不会触发，保留以防万一
    const sess = getSessionState($session.uuid);
    const gwHost = `${$session.proxy.host}:${$session.proxy.port}`;
    const targetHost = $session.conHost;
    const targetPort = $session.conPort;

    const header = buildHeader(targetHost, targetPort, gwHost);
    $tunnel.write($session, header);
    sess.status = STATUS.HEADER_SENT;
    $tunnel.readTo($session, "\r\n\r\n");
    log(`CONNECT sent (TLS fallback) -> ${targetHost}:${targetPort}`);
    return true;
}

function tunnelDidRead(data) {
    const sess = getSessionState($session.uuid);
    if (sess.status === STATUS.HEADER_SENT) {
        // 解析HTTP状态码
        const match = data.match(/HTTP\/\d\.\d\s+(\d+)/);
        if (match) {
            const code = parseInt(match[1], 10);
            if (code !== 200) {
                log(`Proxy returned HTTP ${code}, closing tunnel`);
                $tunnel.close($session);
                return null;
            }
        } else {
            // 无法解析状态码，视为异常
            log("Invalid proxy response, closing");
            $tunnel.close($session);
            return null;
        }
        // 状态200，握手成功
        sess.status = STATUS.ESTABLISHED;
        $tunnel.established($session);
        log("Tunnel established (HTTP 200)");
        return null;   // 丢弃响应头
    }
    return data;
}

function tunnelDidWrite() {
    // 不做任何主动写入
    return true;
}

function tunnelDidClose() {
    delete sessionMap[$session.uuid];
    log(`Session closed: ${$session.uuid}`);
    return true;
}