// Loon 百度直连 · 异步无阻塞 · 联通优化版
const STATUS_CONNECT = 0;
const STATUS_FORWARD = 1;
let state = STATUS_CONNECT;

function createVerify(host) {
  let r = 0;
  for (let i = 0; i < host.length; i++) {
    r = (r * 1318293 & 0x7FFFFFFF) + host.charCodeAt(i);
  }
  return r < 0 ? r & 0x7FFFFFFF : r;
}

function tunnelDidConnected() {
  return true;
}

function tunnelTLSFinished() {
  const conHost = $session.conHost;
  const conPort = $session.conPort;
  const auth = createVerify(conHost);
  const req = 
`CONNECT ${conHost}:${conPort} HTTP/1.1
Host: ${conHost}:${conPort}
X-T5-Auth: ${auth}
Proxy-Connection: keep-alive

`;
  $tunnel.write($session, req);
  state = STATUS_FORWARD;
  return true;
}

function tunnelDidRead(data) {
  if (state === STATUS_FORWARD) {
    return data;
  }
  // 不读、不等待响应头，直接透传
  state = STATUS_FORWARD;
  $tunnel.established($session);
  return null;
}

function tunnelDidWrite() {
  return state === STATUS_FORWARD;
}

function tunnelDidClose() {
  return true;
}