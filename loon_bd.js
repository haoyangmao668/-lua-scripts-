// 联通百度直连 · 稳健高性能版
const STATUS_INIT = 0;
const STATUS_HEADER_SENT = 1;
const STATUS_FORWARDING = 2;
let status = STATUS_INIT;

function createVerify(host) {
  let r = 0;
  for (let i = 0; i < host.length; i++) {
    r = (r * 1318293 & 0x7FFFFFFF) + host.charCodeAt(i);
  }
  return r < 0 ? r & 0x7FFFFFFF : r;
}

function tunnelDidConnected() {
  // 如果是非 TLS 节点，直接发送头
  if (!$session.proxy.isTLS) {
    sendHeader();
    status = STATUS_HEADER_SENT;
  }
  return true;
}

function tunnelTLSFinished() {
  sendHeader();
  status = STATUS_HEADER_SENT;
  return true;
}

function tunnelDidRead(data) {
  if (status === STATUS_HEADER_SENT) {
    // 收到代理服务器返回的第一个响应包，代表握手成功
    // 不需要强制读到\r\n\r\n，有数据过来就说明隧道已通
    status = STATUS_FORWARDING;
    $tunnel.established($session);
    // 注意：返回 null，不把代理的响应头传给应用
    return null;
  } else if (status === STATUS_FORWARDING) {
    // 正常转发数据
    return data;
  }
  // 异常状态，断开
  return null;
}

function tunnelDidWrite() {
  if (status === STATUS_HEADER_SENT) {
    // 发送完头后，设置异步读，等待服务器的第一个响应字节
    // 这里用 read 而不是 readTo，因为 readTo 可能会等很久凑齐\r\n\r\n
    $tunnel.read($session);
    return false;
  }
  return true;
}

function tunnelDidClose() {
  return true;
}

function sendHeader() {
  const host = $session.conHost;
  const port = $session.conPort;
  const auth = createVerify(host);
  const header = `CONNECT ${host}:${port} HTTP/1.1\r\n` +
                 `Host: ${host}:${port}\r\n` +
                 `X-T5-Auth: ${auth}\r\n` +
                 `Proxy-Connection: keep-alive\r\n` +
                 `\r\n`;
  $tunnel.write($session, header);
}