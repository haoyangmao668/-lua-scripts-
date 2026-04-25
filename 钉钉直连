/**
 * 钉钉单层锁流 (Loon custom)
 * 仅伪装 CONNECT 握手 (Host 写死 oapi.dingtalk.com, Auth 动态)
 * 后续数据透明转发, 无写入干扰
 * 
 * 使用方式:
 * [Proxy]
 * customDing = custom, cloudnproxy.baidu.com, 443, script-path=你的脚本链接
 */

let HTTP_STATUS_INIT = -1;
let HTTP_STATUS_HEADER_SENT = 0;
let HTTP_STATUS_WAIT_RESPONSE = 1;
let HTTP_STATUS_FORWARDING = 2;
var httpStatus = HTTP_STATUS_INIT;

function createVerify(address) {
    let index = 0;
    const factor = 1318293;
    for (let i = 0; i < address.length; i++) {
        index = (index * factor & 0x7FFFFFFF) + address.charCodeAt(i);
    }
    if (index < 0) {
        index = index & 0x7FFFFFFF;
    }
    return index;
}

function _buildHttpHeader() {
    let conHost = $session.conHost;
    let conPort = $session.conPort;
    // Auth 基于真实目标 host:port 生成 (与原 Lua 一致)
    let authCode = createVerify(conHost + ":" + conPort);
    
    // Host 头写死为 oapi.dingtalk.com:443 (钉钉伪装)
    return "CONNECT " + conHost + ":" + conPort + " HTTP/1.1\r\n" +
           "Host: oapi.dingtalk.com:443\r\n" +
           "X-T5-Auth: " + authCode + "\r\n" +
           "Proxy-Connection: Keep-Alive\r\n\r\n";
}

function _sendHttpHeader() {
    if (httpStatus === HTTP_STATUS_INIT) {
        let header = _buildHttpHeader();
        $tunnel.write($session, header);
        httpStatus = HTTP_STATUS_HEADER_SENT;
        console.log("DingTalk CONNECT header sent");
    }
}

// --- 生命周期回调 ---

function tunnelDidConnected() {
    if (!$session.proxy.isTLS) {
        _sendHttpHeader();
    }
    return true;
}

function tunnelTLSFinished() {
    if ($session.proxy.isTLS) {
        _sendHttpHeader();
    }
    return true;
}

function tunnelDidRead(data) {
    if (httpStatus === HTTP_STATUS_WAIT_RESPONSE) {
        try {
            let dataString = String.fromCharCode.apply(null, new Uint8Array(data));
            if (dataString.indexOf("200") !== -1) {
                console.log("DingTalk tunnel established (200)");
                httpStatus = HTTP_STATUS_FORWARDING;
                $tunnel.established($session); // 立即开始转发
                return null;
            } else {
                console.log("Tunnel failed: " + dataString.split("\r\n")[0]);
                $tunnel.close($session);
                return null;
            }
        } catch (e) {
            console.log("Error parsing response: " + e);
            $tunnel.close($session);
            return null;
        }
    } else if (httpStatus === HTTP_STATUS_FORWARDING) {
        return data; // 透明转发
    }
    return null;
}

function tunnelDidWrite() {
    if (httpStatus === HTTP_STATUS_HEADER_SENT) {
        httpStatus = HTTP_STATUS_WAIT_RESPONSE;
        $tunnel.readTo($session, "\r\n\r\n");
        return false;
    }
    return true;
}

function tunnelDidClose() {
    console.log("Session closed: " + $session.uuid);
    return true;
}
