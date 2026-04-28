/**
 * 百度直连｜彻底解除UDP阻塞 游戏全通
 * 纯百度 无钉钉 不直连 解除响应头等待阻塞
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

//取消等待响应头，直接放行转发，不阻塞UDP
function tunnelDidRead(data) {
  if (httpStatus === HTTP_STATUS_CONNECTED) {
    httpStatus = HTTP_STATUS_FORWARDING;
    $tunnel.established($session);
  }
  return data;
}

function tunnelDidWrite() {
  if (httpStatus === HTTP_STATUS_CONNECTED) {
    //删掉readTo等待头，杜绝UDP阻塞
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
  let conHost = $session.conHost;
  let conPort = $session.conPort;
  let verify = createVerify(conHost);
  var header = `CONNECT ${conHost}:${conPort} HTTP/1.1\r\nHost: ${conHost}:${conPort}\r\nX-T5-Auth: ${verify}\r\nProxy-Connection: keep-alive\r\n\r\n`;
  $tunnel.write($session, header);
}