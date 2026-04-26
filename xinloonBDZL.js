/**
 * 终极提速版｜百度直连Loon Custom脚本
 * 特性：无日志、无多余校验、极简握手、减少阻塞
 */
let httpStatus = -1;

// 极速哈希算法，低CPU消耗
function createVerify(host) {
    let hash = 0;
    for (let i = 0; i < host.length; i++) {
        hash = ((hash << 5) - hash) + host.charCodeAt(i);
        hash |= 0;
    }
    return hash & 0x7FFFFFFF;
}

function tunnelDidConnected() {
    httpStatus = 0;
    _writeHeader();
    return true;
}

function tunnelTLSFinished() {
    httpStatus = 0;
    _writeHeader();
    return true;
}

function tunnelDidRead(data) {
    if (httpStatus === 1) {
        httpStatus = 2;
        $tunnel.established($session);
        return null;
    }
    return data;
}

function tunnelDidWrite() {
    if (httpStatus === 0) {
        httpStatus = 1;
        $tunnel.readTo($session, '\r\n\r\n');
        return false;
    }
    return true;
}

function tunnelDidClose() {
    return true;
}

// 极致压缩请求头，减少数据包体积
function _writeHeader() {
    const h = $session.conHost;
    const p = $session.conPort;
    const auth = createVerify(h);
    const header = `CONNECT ${h}:${p} HTTP/1.1\r\nHost:${h}\r\nX-T5-Auth:${auth}\r\nConnection:keep-alive\r\n\r\n`;
    $tunnel.write($session, header);
}
