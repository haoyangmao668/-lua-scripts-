/**
 * Loon 百度直连 - 性能优化版
 * 适配 Loon custom 协议，带校验缓存、错误处理、无IPv6逻辑
 */

let HTTP_STATUS_INVALID = -1;
let HTTP_STATUS_CONNECTED = 0;
let HTTP_STATUS_WAITRESPONSE = 1;
let HTTP_STATUS_FORWARDING = 2;
let httpStatus = HTTP_STATUS_INVALID;

// 校验缓存，避免重复计算
const authCache = new Map();

// 原版星璃校验算法 + 缓存优化
function createVerify(address) {
  if (authCache.has(address)) {
    return authCache.get(address);
  }
  let index = 0;
  for (let i = 0; i < address.length; i++) {
    index = ((index * 1318293) & 0x7FFFFFFF) + address.charCodeAt(i);
  }
  if (index < 0) {
    index = index & 0x7FFFFFFF;
  }
  authCache.set(address, index);
  // 缓存上限清理，防止长期运行内存堆积
  if (authCache.size > 30) {
    authCache.clear();
  }
  return index;
}

// 检查响应是否为200 OK，过滤无效握手
function isSuccessResponse(buf) {
  const text = typeof buf === 'string' ? buf : String.fromCharCode.apply(null, new Uint8Array(buf));
  return /^HTTP\/\d\.\d 200 /.test(text);
}

function tunnelDidConnected() {
  if ($session.proxy.isTLS) {
    // TLS 连接时，等待 tunnelTLSFinished 回调再发请求头
  } else {
    _writeHttpHeader();
    httpStatus = HTTP_STATUS_CONNECTED;
  }
  return true;
}

function tunnelTLSFinished() {
  _writeHttpHeader();
  httpStatus = HTTP_STATUS_CONNECTED;
  return true;
}

function tunnelDidRead(data) {
  if (httpStatus === HTTP_STATUS_WAITRESPONSE) {
    // 校验响应状态
    if (isSuccessResponse(data)) {
      httpStatus = HTTP_STATUS_FORWARDING;
      $tunnel.established($session);
      return null;
    } else {
      // 响应非200，直接关闭会话，避免卡死
      console.log(`握手失败，响应非200，关闭会话`);
      $tunnel.close($session);
      return null;
    }
  } else if (httpStatus === HTTP_STATUS_FORWARDING) {
    return data;
  }
  return null;
}

function tunnelDidWrite() {
  if (httpStatus === HTTP_STATUS_CONNECTED) {
    httpStatus = HTTP_STATUS_WAITRESPONSE;
    // 读取响应头，直到\r\n\r\n结束
    $tunnel.readTo($session, '\x0D\x0A\x0D\x0A');
    return false;
  }
  return true;
}

function tunnelDidClose() {
  // 重置状态，避免跨会话污染
  httpStatus = HTTP_STATUS_INVALID;
  return true;
}

// 发送CONNECT请求头
function _writeHttpHeader() {
  const conHost = $session.conHost;
  const conPort = $session.conPort;
  const verify = createVerify(conHost);

  const header = `CONNECT ${conHost}:${conPort} HTTP/1.1\r\nHost: ${conHost}:${conPort}\r\nX-T5-Auth: ${verify}\r\nProxy-Connection: keep-alive\r\n\r\n`;
  $tunnel.write($session, header);
}