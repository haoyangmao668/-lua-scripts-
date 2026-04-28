/**
 * 百度直连｜删除200校验+域名缓存+游戏UDP全放行
 * Loon custom专用 纯百度原生 零报错
 * 全部流量锁代理、无直连
 */
let HTTP_STATUS_INVALID = -1;
let HTTP_STATUS_CONNECTED = 0;
let HTTP_STATUS_WAITRESPONSE = 1;
let HTTP_STATUS_FORWARDING = 2;
var httpStatus = HTTP_STATUS_INVALID;
//域名缓存
const authCache = new Map();

function createVerify(address) {
  if(authCache.has(address)) return authCache.get(address);
  let index = 0;
  for(let i = 0; i < address.length; i++) {
    index = (index * 1318293 & 0x7FFFFFFF) + address.charCodeAt(i);
  }
  if(index < 0) index = index & 0x7FFFFFFF;
  authCache.set(address,index);
  //限制缓存数量
  if(authCache.size > 25) authCache.clear();
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

//删除200状态判断，无脑全部放行
function tunnelDidRead(data) {
  if (httpStatus == HTTP_STATUS_WAITRESPONSE) {
    httpStatus = HTTP_STATUS_FORWARDING;
    $tunnel.established($session);
    return null;
  } else if (httpStatus == HTTP_STATUS_FORWARDING) {
    return data;
  }
  return data;
}

function tunnelDidWrite() {
  if (httpStatus == HTTP_STATUS_CONNECTED) {
    httpStatus = HTTP_STATUS_WAITRESPONSE;
    $tunnel.readTo($session, '\x0D\x0A\x0D\x0A');
    return false;
  }
  return true;
}

//关闭清空缓存会话，防止堆连接涨跳
function tunnelDidClose() {
  const host = $session.conHost;
  if(authCache.has(host)) authCache.delete(host);
  return true;
}

function _writeHttpHeader() {
  let conHost = $session.conHost;
  let conPort = $session.conPort;
  let verify = createVerify(conHost);
  var header = `CONNECT ${conHost}:${conPort} HTTP/1.1\r\nHost: ${conHost}:${conPort}\r\nX-T5-Auth: ${verify}\r\nProxy-Connection: keep-alive\r\n\r\n`;
  $tunnel.write($session, header);
}