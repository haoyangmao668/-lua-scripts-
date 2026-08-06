/**
 * Loon Custom协议 百度直连（星璃框架 + 小火箭Lua移植）
 * 基于星璃原版，完整迁移动态UA/TraceID/Padding/域名识别/UDP优先
 * 配置示例：
 * [Proxy]
 * BaiduFree = custom, 153.3.236.22, 443, script-path=本脚本地址
 * 注意：不要加 tls=true，使用明文HTTP代理
 * 
 * 特性：
 * - 动态生成40位TraceID
 * - 随机百度UA池
 * - TLS Padding抗指纹
 * - 自动识别UDP特征域名（优先）、红果/字节系域名
 * - 三套CONNECT模板
 * - 校验代理返回的HTTP状态码，只接受200
 */

// ===================== 状态常量 =====================
let HTTP_STATUS_INVALID = -1;
let HTTP_STATUS_CONNECTED = 0;
let HTTP_STATUS_WAITRESPONSE = 1;
let HTTP_STATUS_FORWARDING = 2;
var httpStatus = HTTP_STATUS_INVALID;

// ===================== 配置 =====================
const CONFIG = {
    GW_HOST: "153.3.236.22:443",      // 免流网关（Host头）
    T5_AUTH_KEY: "683556433",         // 固定鉴权（与Lua一致）
    ENABLE_FINGERPRINT_MASK: true,
    MIN_PADDING: 8,
    MAX_PADDING: 48,
    LOG_DEBUG: false                  // 调试时改为true
};

// ===================== UA池 & 域名关键词 =====================
const BAIDU_UA_POOL = [
    "baiduboxapp/8.5.0.0 (Linux; Android 12; Mi 13 Pro)",
    "baiduboxapp/9.0.1.0 (Linux; Android 13; SM-S928B)",
    "Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Mobile Safari/537.36 baiduboxapp/8.2.5",
    "baiduboxapp/7.8.5.0 (iPhone; iOS 16.5; Scale/3.00)",
    "baiduboxapp/8.8.8.8 (Linux; Android 14; Pixel 8 Pro)",
    "netdisk;11.18.3;android-android;12;Mobile"
];

const HK_DOMAINS = [
    "zijie", "hongguo", "novel", "pangolin", "sigmob",
    "amemv", "douyin", "iesdouyin", "byteimg",
    "toutiao", "ixigua", "snssdk", "bdurl", "pstatp"
];

const UDP_MASK_DOMAINS = [
    "udp", "quic", "game", "minecraft", "dota", "lol",
    "valorant", "genshin", "bilibili", "qpic", "video", "cdn", "streaming", "live"
];

// ===================== 工具函数（完全对应Lua） =====================
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

// ===================== CONNECT报文构造（UDP优先） =====================
function buildHeader(targetHost, targetPort) {
    const traceId = generateTraceId();
    const ua = getRandomUA();
    const padding = getRandomPadding();
    const isUdp = matchUdpKeyword(targetHost);
    const isHg = isHongguoHost(targetHost);
    const gwHost = CONFIG.GW_HOST;

    let template;
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

// ===================== Loon 生命周期回调（星璃原版结构） =====================
function tunnelDidConnected() {
    console.log($session);
    if (!$session.proxy.isTLS) {
        _writeHttpHeader();
        httpStatus = HTTP_STATUS_CONNECTED;
    }
    return true;
}

function tunnelTLSFinished() {
    // 如果误加了 tls=true，也能工作
    _writeHttpHeader();
    httpStatus = HTTP_STATUS_CONNECTED;
    return true;
}

function tunnelDidRead(data) {
    if (httpStatus == HTTP_STATUS_WAITRESPONSE) {
        // 校验HTTP状态码
        const match = data.match(/HTTP\/\d\.\d\s+(\d+)/);
        if (match && parseInt(match[1], 10) === 200) {
            console.log('HTTP handshake success (200)');
            httpStatus = HTTP_STATUS_FORWARDING;
            $tunnel.established($session);
            return null; // 丢弃响应头
        } else {
            console.log('Proxy returned non-200, closing tunnel');
            $tunnel.close($session);
            return null;
        }
    } else if (httpStatus == HTTP_STATUS_FORWARDING) {
        return data;
    }
    return data;
}

function tunnelDidWrite() {
    if (httpStatus == HTTP_STATUS_CONNECTED) {
        console.log('CONNECT header sent, waiting for response');
        httpStatus = HTTP_STATUS_WAITRESPONSE;
        $tunnel.readTo($session, '\x0D\x0A\x0D\x0A');
        return false; // 暂停后续写回调
    }
    return true;
}

function tunnelDidClose() {
    return true;
}

// ===================== 发送CONNECT头 =====================
function _writeHttpHeader() {
    const header = buildHeader($session.conHost, $session.conPort);
    $tunnel.write($session, header);
}