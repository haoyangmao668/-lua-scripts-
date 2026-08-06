function buildHeader(targetHost, targetPort, gwHost) {
    const traceId = generateTraceId();
    const ua = getRandomUA();
    const padding = getRandomPadding();
    const hgMatch = isHongguoHost(targetHost);
    const udpSim = matchUdpKeyword(targetHost);

    let template;
    // 优先红果，其次UDP（也可保持原顺序）
    if (hgMatch) {
        template = `CONNECT ${targetHost}:${targetPort} HTTP/1.1
Host: ${gwHost}
Proxy-Connection: Keep-Alive
Connection: keep-alive
X-T5-Auth: ${CONFIG.T5_AUTH_KEY}
User-Agent: ${ua}
X-Bd-Traceid: ${traceId}
X-Bd-Product: BDUSS
X-Bd-Uid: 0
X-TLS-Version: TLSv1.3
${padding}Accept: */*

`;
    } else if (udpSim) {
        template = `CONNECT ${targetHost}:${targetPort} HTTP/1.1
Host: ${gwHost}
Proxy-Connection: Keep-Alive
Connection: keep-alive
X-T5-Auth: ${CONFIG.T5_AUTH_KEY}
User-Agent: ${ua}
X-Bd-Traceid: ${traceId}
X-Bd-Product: BDUSS
X-Bd-Uid: 0
X-Bd-Client-Type: UDP-TRANS
X-Bd-Trans-Type: masquerade
X-Bd-Request-Mode: tunnel
X-TLS-Version: TLSv1.3
${padding}Accept: */*
Content-Length: 0

`;
    } else {
        template = `CONNECT ${targetHost}:${targetPort} HTTP/1.1
Host: ${gwHost}
Proxy-Connection: Keep-Alive
Connection: keep-alive
X-T5-Auth: ${CONFIG.T5_AUTH_KEY}
User-Agent: ${ua}
X-Bd-Traceid: ${traceId}
X-TLS-Version: TLSv1.3
${padding}

`;  // ← 关键：末尾有两个换行
    }
    return template.replace(/\n/g, "\r\n");
}