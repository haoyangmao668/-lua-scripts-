/*
同源星璃｜和小火箭Lua同算法
无固定443、无端口判断、纯双层注入
依靠规则隔离非443，零断网
*/
let HTTP_STATUS_INVALID = -1;
let HTTP_STATUS_CONNECTED = 0;
let HTTP_STATUS_WAITRESPONSE = 1;
let HTTP_STATUS_FORWARDING = 2;
var httpStatus = HTTP_STATUS_INVALID;

function createVerify(address) {
  let index = 0;
  for(let i = 0; i < address.length; i++) {
    index = (index * 1318293 & 0x7FFFFFFF) + address.charCodeAt(i);
  }
  if(index < 0) index = index & 0x7FFFFFFF;
  return `X-T5-Auth: ${index}\r\n`;
}

function rewriteHttpRequest(buf,host,port,auth){
  let idx = buf.indexOf('/');
  if(idx === -1) return buf;
  let method = buf.substring(0,idx);
  let rest = buf.substring(idx);
  let rn = rest.indexOf("\r\n");
  if(rn === -1) return buf;
  let line = rest.substring(0,rn);
  let last = rest.substring(rn);
  return `${method}${line}\r\nHost: ${host}:${port}\r\n${auth}${last}`;
}

function tunnelDidConnected() {
  if (!$session.proxy.isTLS) {
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
    httpStatus = HTTP_STATUS_FORWARDING;
    $tunnel.established($session);
    return null;
  }
  return data;
}

function tunnelDidWrite(data) {
  let host = $session.conHost;
  let port = $session.conPort;
  if (httpStatus === HTTP_STATUS_CONNECTED) {
    httpStatus = HTTP_STATUS_WAITRESPONSE;
    $tunnel.readTo($session, '\x0D\x0A\x0D\x0A');
    return false;
  }
  if(httpStatus === HTTP_STATUS_FORWARDING && data.toString().includes("HTTP/")){
    let auth = createVerify(host);
    return rewriteHttpRequest(data.toString(),host,port,auth);
  }
  return data;
}

function tunnelDidClose() {
  httpStatus = HTTP_STATUS_INVALID;
  return true;
}

function _writeHttpHeader() {
  let conHost = $session.conHost;
  let conPort = $session.conPort;
  let verify = createVerify(conHost);
  let header = `CONNECT ${conHost}:${conPort} HTTP/1.1\r\nHost: ${conHost}:${conPort}\r\nProxy-Connection: keep-alive\r\n${verify}\r\n`;
  $tunnel.write($session, header);
}