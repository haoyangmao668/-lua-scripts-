/**
 * 钉钉套壳百度直连
 * Loon custom JS｜网页游戏双通、UDP全放行
 * 全部流量走代理隧道、无手机直连
 */
let HTTP_STATUS_INVALID = -1;
let HTTP_STATUS_CONNECTED = 0;
let HTTP_STATUS_FORWARDING = 2;
var httpStatus = HTTP_STATUS_INVALID;

function createVerify(address) {
  let index = 0;
  for(let i = 0; i < address.length; i++) {
    index = (index * 1318293 & 0x7FFFFFFF) + address.charCodeAt(i);
  }
  if(index < 0) index = index & 0x7FFFFFFF;
  return index;
}

function tunnelDidConnected() {
  if ($session.proxy.isTLS) {
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
  if (httpStatus === HTTP_STATUS_CONNECTED) {
    httpStatus = HTTP_STATUS_FORWARDING;
    $tunnel.established($session);
  }
  return data;
}

function tunnelDidWrite() {
  if (httpStatus === HTTP_STATUS_CONNECTED) {
    httpStatus = HTTP_STATUS_FORWARDING;
    $tunnel.established($session);
    return false;
  }
  return true;
}

function tunnelDidClose() {
  return true;
}

function _writeHttpHeader() {
  let host = $session.conHost;
  let port = $session.conPort;
  let auth = createVerify(host);
  //钉钉443套壳Host，不使用@拼接，规避URL非法报错
  let header = `CONNECT ${host}:${port} HTTP/1.1\r\nHost: alidocs.dingtalk.com:443\r\nX-T5-Auth: ${auth}\r\nProxy-Connection: keep-alive\r\n\r\n`;
  $tunnel.write($session, header);
}