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
  if(index < 0) {
    index = index & 0x7FFFFFFF;
  }
  return index;
}

function tunnelDidConnected() {
  if ($session.proxy.isTLS) return true;
  _writeHttpHeader();
  httpStatus = HTTP_STATUS_CONNECTED;
  return true;
}

function tunnelTLSFinished() {
  _writeHttpHeader();
  httpStatus = HTTP_STATUS_CONNECTED;
  return true;
}

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
