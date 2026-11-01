// Synthetic demonstration capture. No real traffic or customer data is included.
const CLIENT = '192.168.1.108';
const GATEWAY = '192.168.1.1';
const API = '203.0.113.42';
const METRICS = '198.51.100.24';
const SIP_SERVER = '198.51.100.40';
const encoder = new TextEncoder();
const encode = (text) => Array.from(encoder.encode(text));
const word = (n) => [(n >>> 8) & 255, n & 255];
const dword = (n) => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255];
const ipBytes = (ip) => ip.split('.').map(Number);
const clientMac = [0xa4, 0x83, 0xe7, 0x2a, 0x91, 0x08];
const gatewayMac = [0x84, 0xa9, 0x3e, 0x6c, 0x21, 0x01];

const dashboardBody = JSON.stringify({ status: 'ok', data: { requests: 24816, latency_ms: 42, uptime: 99.98 } });
const eventBody = JSON.stringify({ events: [{ id: 'evt_001', type: 'page_view', path: '/dashboard' }], total: 1 });
const healthBody = JSON.stringify({ status: 'healthy', version: '1.8.2' });
const request = (path) => `GET ${path} HTTP/1.1\r\nHost: api.atlas.local\r\nUser-Agent: Atlas-Web/1.8.2\r\nAccept: application/json\r\nConnection: keep-alive\r\n\r\n`;
const response = (body) => `HTTP/1.1 200 OK\r\nServer: nginx/1.26.2\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: ${encode(body).length}\r\nConnection: keep-alive\r\n\r\n${body}`;

function checksum(bytes) {
  let sum = 0;
  for (let i = 0; i < bytes.length; i += 2) sum += (bytes[i] << 8) + (bytes[i + 1] || 0);
  while (sum >>> 16) sum = (sum & 65535) + (sum >>> 16);
  return (~sum) & 65535;
}

function dnsPayload(name, answer, transaction, answerIp) {
  const labels = name.split('.').flatMap((part) => [part.length, ...encode(part)]);
  return [...word(transaction), ...word(answer ? 0x8180 : 0x0100), 0, 1, 0, answer ? 1 : 0, 0, 0, 0, 0,
    ...labels, 0, 0, 1, 0, 1,
    ...(answer ? [0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, ...ipBytes(answerIp)] : [])];
}

function tlsPayload(size, seed, recordType = 23) {
  // Encrypted bytes are illustrative and are deliberately not decryptable TLS records.
  return [recordType, 3, 3, ...word(size - 5), ...Array.from({ length: size - 5 }, (_, i) => (i * 73 + seed * 31) % 256)];
}

const sipSdpOffer = [
  'v=0',
  'o=alice 1 1 IN IP4 192.168.1.108',
  's=WebShark demo offer',
  'c=IN IP4 192.168.1.108',
  't=0 0',
  'a=group:BUNDLE 0 1',
  'a=msid-semantic: WMS atlas',
  'm=audio 20000 RTP/AVP 0 96 97',
  'c=IN IP4 192.168.1.108',
  'a=sendrecv',
  'a=rtpmap:0 PCMU/8000',
  'a=rtpmap:96 AMR-WB/16000',
  'a=fmtp:96 octet-align=1',
  'a=rtpmap:97 AMR/8000',
  'a=fmtp:97 octet-align=1',
  'a=ptime:20',
  'a=maxptime:60',
  'm=video 20002 RTP/AVP 98 99',
  'c=IN IP4 192.168.1.108',
  'a=sendrecv',
  'a=rtpmap:98 H264/90000',
  'a=fmtp:98 packetization-mode=1;profile-level-id=42e01f',
  'a=rtpmap:99 VP8/90000',
  'a=rtcp-fb:98 nack pli',
  'a=rtcp-fb:99 nack pli',
].join('\r\n') + '\r\n';
const sipSdpAnswer = [
  'v=0',
  'o=bob 2 2 IN IP4 198.51.100.40',
  's=WebShark demo answer',
  'c=IN IP4 198.51.100.40',
  't=0 0',
  'a=group:BUNDLE 0 1',
  'a=msid-semantic: WMS atlas',
  'm=audio 21000 RTP/AVP 0 96',
  'c=IN IP4 198.51.100.40',
  'a=sendrecv',
  'a=rtpmap:0 PCMU/8000',
  'a=rtpmap:96 AMR-WB/16000',
  'a=fmtp:96 octet-align=1',
  'a=ptime:30',
  'm=video 21002 RTP/AVP 98',
  'c=IN IP4 198.51.100.40',
  'a=recvonly',
  'a=rtpmap:98 H264/90000',
  'a=fmtp:98 packetization-mode=1;profile-level-id=640c1f',
  'a=rtcp-fb:98 nack pli',
  'a=rtcp-fb:98 goog-remb',
  'a=rtcp-mux',
].join('\r\n') + '\r\n';
const sipMessage = (startLine, headers, body = '') => `${startLine}\r\n${headers.join('\r\n')}\r\nContent-Length: ${encode(body).length}\r\n\r\n${body}`;
const sipInvite = sipMessage('INVITE sip:bob@atlas.local SIP/2.0', [
  'Via: SIP/2.0/UDP 192.168.1.108:5062;branch=z9hG4bK-7f4a',
  'Max-Forwards: 70',
  'From: <sip:alice@atlas.local>;tag=alice-001',
  'To: <sip:bob@atlas.local>',
  'Call-ID: call-7f4a@atlas.local',
  'CSeq: 1 INVITE',
  'Contact: <sip:alice@192.168.1.108:5062>',
  'Content-Type: application/sdp',
], sipSdpOffer);
const sipTrying = sipMessage('SIP/2.0 100 Trying', [
  'Via: SIP/2.0/UDP 192.168.1.108:5062;branch=z9hG4bK-7f4a',
  'From: <sip:alice@atlas.local>;tag=alice-001',
  'To: <sip:bob@atlas.local>',
  'Call-ID: call-7f4a@atlas.local',
  'CSeq: 1 INVITE',
]);
const sipRinging = sipMessage('SIP/2.0 180 Ringing', [
  'Via: SIP/2.0/UDP 192.168.1.108:5062;branch=z9hG4bK-7f4a',
  'From: <sip:alice@atlas.local>;tag=alice-001',
  'To: <sip:bob@atlas.local>;tag=bob-002',
  'Call-ID: call-7f4a@atlas.local',
  'CSeq: 1 INVITE',
]);
const sipOk = sipMessage('SIP/2.0 200 OK', [
  'Via: SIP/2.0/UDP 192.168.1.108:5062;branch=z9hG4bK-7f4a',
  'From: <sip:alice@atlas.local>;tag=alice-001',
  'To: <sip:bob@atlas.local>;tag=bob-002',
  'Call-ID: call-7f4a@atlas.local',
  'CSeq: 1 INVITE',
  'Contact: <sip:bob@198.51.100.40:5060>',
  'Content-Type: application/sdp',
], sipSdpAnswer);
const sipAck = sipMessage('ACK sip:bob@atlas.local SIP/2.0', [
  'Via: SIP/2.0/UDP 192.168.1.108:5062;branch=z9hG4bK-7f4a-ack',
  'Max-Forwards: 70',
  'From: <sip:alice@atlas.local>;tag=alice-001',
  'To: <sip:bob@atlas.local>;tag=bob-002',
  'Call-ID: call-7f4a@atlas.local',
  'CSeq: 1 ACK',
]);
const sipBye = sipMessage('BYE sip:bob@atlas.local SIP/2.0', [
  'Via: SIP/2.0/UDP 192.168.1.108:5062;branch=z9hG4bK-7f4a-bye',
  'Max-Forwards: 70',
  'From: <sip:alice@atlas.local>;tag=alice-001',
  'To: <sip:bob@atlas.local>;tag=bob-002',
  'Call-ID: call-7f4a@atlas.local',
  'CSeq: 2 BYE',
]);
const sipByeOk = sipMessage('SIP/2.0 200 OK', [
  'Via: SIP/2.0/UDP 192.168.1.108:5062;branch=z9hG4bK-7f4a-bye',
  'From: <sip:alice@atlas.local>;tag=alice-001',
  'To: <sip:bob@atlas.local>;tag=bob-002',
  'Call-ID: call-7f4a@atlas.local',
  'CSeq: 2 BYE',
]);

const definitions = [
  { time: 0, protocol: 'ARP', source: CLIENT, destination: GATEWAY, info: 'Who has 192.168.1.1? Tell 192.168.1.108', arpReply: false },
  { time: 0.000482, protocol: 'ARP', source: GATEWAY, destination: CLIENT, info: '192.168.1.1 is at 84:a9:3e:6c:21:01', arpReply: true },
  { time: 0.001294, protocol: 'DNS', source: CLIENT, destination: GATEWAY, srcPort: 54821, dstPort: 53, dnsName: 'api.atlas.local', transaction: 0x1a2b },
  { time: 0.007658, protocol: 'DNS', source: GATEWAY, destination: CLIENT, srcPort: 53, dstPort: 54821, dnsName: 'api.atlas.local', transaction: 0x1a2b, dnsAnswer: API },
  { time: 0.008104, protocol: 'TCP', stream: 0, flags: 'SYN' },
  { time: 0.021361, protocol: 'TCP', stream: 0, reverse: true, flags: 'SYN, ACK' },
  { time: 0.021498, protocol: 'TCP', stream: 0, flags: 'ACK' },
  { time: 0.022014, protocol: 'HTTP', stream: 0, payload: request('/api/v1/dashboard'), info: 'GET /api/v1/dashboard HTTP/1.1', flags: 'PSH, ACK' },
  { time: 0.035212, protocol: 'TCP', stream: 0, reverse: true, flags: 'ACK' },
  { time: 0.064821, protocol: 'HTTP', stream: 0, reverse: true, payload: response(dashboardBody), info: 'HTTP/1.1 200 OK (application/json)', flags: 'PSH, ACK' },
  { time: 0.064984, protocol: 'TCP', stream: 0, flags: 'ACK' },
  { time: 0.072103, protocol: 'DNS', source: CLIENT, destination: GATEWAY, srcPort: 54822, dstPort: 53, dnsName: 'metrics.atlas.local', transaction: 0x1a2c },
  { time: 0.079548, protocol: 'DNS', source: GATEWAY, destination: CLIENT, srcPort: 53, dstPort: 54822, dnsName: 'metrics.atlas.local', transaction: 0x1a2c, dnsAnswer: METRICS },
  { time: 0.080022, protocol: 'TCP', stream: 1, flags: 'SYN' },
  { time: 0.093247, protocol: 'TCP', stream: 1, reverse: true, flags: 'SYN, ACK' },
  { time: 0.093402, protocol: 'TCP', stream: 1, flags: 'ACK' },
  { time: 0.094183, protocol: 'TLSv1.3', stream: 1, payloadBytes: tlsPayload(303, 17, 22), info: 'Client Hello (SNI=metrics.atlas.local)', flags: 'PSH, ACK' },
  { time: 0.108459, protocol: 'TLSv1.3', stream: 1, reverse: true, payloadBytes: tlsPayload(512, 18, 22), info: 'Server Hello, Change Cipher Spec, Encrypted Extensions', flags: 'PSH, ACK' },
  { time: 0.108512, protocol: 'TLSv1.3', stream: 1, reverse: true, payloadBytes: tlsPayload(384, 19), info: 'Application Data', flags: 'PSH, ACK' },
  { time: 0.108744, protocol: 'TLSv1.3', stream: 1, payloadBytes: tlsPayload(80, 20), info: 'Change Cipher Spec, Finished', flags: 'PSH, ACK' },
  { time: 0.121963, protocol: 'TCP', stream: 1, reverse: true, flags: 'ACK' },
  { time: 0.123214, protocol: 'TLSv1.3', stream: 1, payloadBytes: tlsPayload(260, 22), info: 'Application Data', flags: 'PSH, ACK' },
  { time: 0.136512, protocol: 'TCP', stream: 1, reverse: true, flags: 'ACK' },
  { time: 0.142031, protocol: 'UDP', source: CLIENT, destination: '198.51.100.18', srcPort: 56701, dstPort: 5000, payloadBytes: encode('atlas:heartbeat:0001'), info: '56701 → 5000 Len=20' },
  { time: 0.158304, protocol: 'HTTP', stream: 0, payload: request('/api/v1/events'), info: 'GET /api/v1/events HTTP/1.1', flags: 'PSH, ACK' },
  { time: 0.171563, protocol: 'TCP', stream: 0, reverse: true, flags: 'ACK' },
  { time: 0.198812, protocol: 'HTTP', stream: 0, reverse: true, payload: response(eventBody), info: 'HTTP/1.1 200 OK (application/json)', flags: 'PSH, ACK' },
  { time: 0.198981, protocol: 'TCP', stream: 0, flags: 'ACK' },
  { time: 0.403125, protocol: 'TCP', stream: 0, reverse: true, retransmitOf: 27, issue: 'retransmission', info: '[TCP Retransmission] 80 → 51234 [PSH, ACK]', flags: 'PSH, ACK' },
  { time: 0.403283, protocol: 'TCP', stream: 0, issue: 'duplicate_ack', flags: 'ACK', info: '[TCP Dup ACK 28#1] 51234 → 80 [ACK]' },
  { time: 0.418214, protocol: 'TLSv1.3', stream: 1, reverse: true, payloadBytes: tlsPayload(680, 31), info: 'Application Data', flags: 'PSH, ACK' },
  { time: 0.418385, protocol: 'TCP', stream: 1, flags: 'ACK' },
  { time: 0.512098, protocol: 'ICMP', source: CLIENT, destination: GATEWAY, echoReply: false, info: 'Echo (ping) request id=0x1201, seq=1, ttl=64' },
  { time: 0.513642, protocol: 'ICMP', source: GATEWAY, destination: CLIENT, echoReply: true, info: 'Echo (ping) reply id=0x1201, seq=1, ttl=64' },
  { time: 0.621542, protocol: 'HTTP', stream: 0, payload: request('/health'), info: 'GET /health HTTP/1.1', flags: 'PSH, ACK' },
  { time: 0.634794, protocol: 'TCP', stream: 0, reverse: true, flags: 'ACK' },
  { time: 0.640291, protocol: 'HTTP', stream: 0, reverse: true, payload: response(healthBody), info: 'HTTP/1.1 200 OK (application/json)', flags: 'PSH, ACK' },
  { time: 0.640452, protocol: 'TCP', stream: 0, flags: 'ACK' },
  { time: 0.732841, protocol: 'DNS', source: CLIENT, destination: GATEWAY, srcPort: 54823, dstPort: 53, dnsName: 'cdn.atlas.local', transaction: 0x1a2d },
  { time: 0.739193, protocol: 'DNS', source: GATEWAY, destination: CLIENT, srcPort: 53, dstPort: 54823, dnsName: 'cdn.atlas.local', transaction: 0x1a2d, dnsAnswer: '203.0.113.80' },
  { time: 0.842031, protocol: 'UDP', source: CLIENT, destination: '198.51.100.18', srcPort: 56701, dstPort: 5000, payloadBytes: encode('atlas:heartbeat:0002'), info: '56701 → 5000 Len=20' },
  { time: 0.902144, protocol: 'TLSv1.3', stream: 1, payloadBytes: tlsPayload(192, 42), info: 'Application Data', flags: 'PSH, ACK' },
  { time: 0.915408, protocol: 'TCP', stream: 1, reverse: true, flags: 'ACK' },
  { time: 1.021847, protocol: 'TCP', stream: 0, flags: 'FIN, ACK' },
  { time: 1.035094, protocol: 'TCP', stream: 0, reverse: true, flags: 'ACK' },
  { time: 1.035292, protocol: 'TCP', stream: 0, reverse: true, flags: 'FIN, ACK' },
  { time: 1.035451, protocol: 'TCP', stream: 0, flags: 'ACK' },
  { time: 1.542031, protocol: 'UDP', source: CLIENT, destination: '198.51.100.18', srcPort: 56701, dstPort: 5000, payloadBytes: encode('atlas:heartbeat:0003'), info: '56701 → 5000 Len=20' },
  { time: 3.500000, protocol: 'SIP', source: CLIENT, destination: SIP_SERVER, srcPort: 5062, dstPort: 5060, payloadBytes: encode(sipInvite), info: 'INVITE sip:bob@atlas.local' },
  { time: 3.501200, protocol: 'SIP', source: SIP_SERVER, destination: CLIENT, srcPort: 5060, dstPort: 5062, payloadBytes: encode(sipTrying), info: 'SIP/2.0 100 Trying' },
  { time: 3.502400, protocol: 'SIP', source: SIP_SERVER, destination: CLIENT, srcPort: 5060, dstPort: 5062, payloadBytes: encode(sipRinging), info: 'SIP/2.0 180 Ringing' },
  { time: 3.503800, protocol: 'SIP', source: SIP_SERVER, destination: CLIENT, srcPort: 5060, dstPort: 5062, payloadBytes: encode(sipOk), info: 'SIP/2.0 200 OK (SDP)' },
  { time: 3.504700, protocol: 'SIP', source: CLIENT, destination: SIP_SERVER, srcPort: 5062, dstPort: 5060, payloadBytes: encode(sipAck), info: 'ACK sip:bob@atlas.local' },
  { time: 3.800000, protocol: 'SIP', source: CLIENT, destination: SIP_SERVER, srcPort: 5062, dstPort: 5060, payloadBytes: encode(sipBye), info: 'BYE sip:bob@atlas.local' },
  { time: 3.801200, protocol: 'SIP', source: SIP_SERVER, destination: CLIENT, srcPort: 5060, dstPort: 5062, payloadBytes: encode(sipByeOk), info: 'SIP/2.0 200 OK (BYE)' },
];

function makeBytes(packet) {
  const fromClient = packet.source === CLIENT;
  const srcMac = fromClient ? clientMac : gatewayMac;
  const dstMac = packet.protocol === 'ARP' && !packet.arpReply ? Array(6).fill(255) : fromClient ? gatewayMac : clientMac;
  const ethernet = [...dstMac, ...srcMac, 8, packet.protocol === 'ARP' ? 6 : 0];
  if (packet.protocol === 'ARP') {
    const arp = [0, 1, 8, 0, 6, 4, 0, packet.arpReply ? 2 : 1, ...srcMac, ...ipBytes(packet.source),
      ...(packet.arpReply ? dstMac : Array(6).fill(0)), ...ipBytes(packet.destination)];
    return [...ethernet, ...arp, ...Array(18).fill(0)];
  }
  let transport;
  const protocolNumber = packet.transport === 'TCP' ? 6 : packet.transport === 'UDP' ? 17 : 1;
  if (packet.transport === 'TCP') {
    const flagByte = (packet.flags.includes('FIN') ? 1 : 0) | (packet.flags.includes('SYN') ? 2 : 0) |
      (packet.flags.includes('PSH') ? 8 : 0) | (packet.flags.includes('ACK') ? 16 : 0);
    transport = [...word(packet.srcPort), ...word(packet.dstPort), ...dword(packet.seq), ...dword(packet.ack), 0x50, flagByte, ...word(64240), 0, 0, 0, 0, ...packet.payloadBytes];
  } else if (packet.transport === 'UDP') {
    transport = [...word(packet.srcPort), ...word(packet.dstPort), ...word(8 + packet.payloadBytes.length), 0, 0, ...packet.payloadBytes];
  } else {
    transport = [packet.echoReply ? 0 : 8, 0, 0, 0, 0x12, 1, 0, 1, ...encode('abcdefghijklmnopqrstuvwabcdefghi')];
    transport.splice(2, 2, ...word(checksum(transport)));
  }
  if (packet.transport === 'TCP' || packet.transport === 'UDP') {
    const pseudo = [...ipBytes(packet.source), ...ipBytes(packet.destination), 0, protocolNumber, ...word(transport.length), ...transport];
    transport.splice(packet.transport === 'TCP' ? 16 : 6, 2, ...word(checksum(pseudo)));
  }
  const header = [0x45, 0, ...word(20 + transport.length), ...word(packet.no), 0x40, 0, 64, protocolNumber, 0, 0, ...ipBytes(packet.source), ...ipBytes(packet.destination)];
  header.splice(10, 2, ...word(checksum(header)));
  const bytes = [...ethernet, ...header, ...transport];
  return bytes.length < 60 ? [...bytes, ...Array(60 - bytes.length).fill(0)] : bytes;
}

function buildPackets() {
  const sequence = { 0: [0, 0], 1: [0, 0] };
  const result = [];
  for (const [index, definition] of definitions.entries()) {
    const packet = { no: index + 1, srcPort: null, dstPort: null, stream: null, issue: null, flags: '', payload: '', payloadBytes: [], ...definition };
    packet.transport = ['TCP', 'HTTP', 'TLSv1.3'].includes(packet.protocol) ? 'TCP' : ['UDP', 'DNS', 'SIP'].includes(packet.protocol) ? 'UDP' : packet.protocol;
    if (packet.transport === 'TCP') {
      const reverse = Boolean(packet.reverse);
      const server = packet.stream === 0 ? API : METRICS;
      const serverPort = packet.stream === 0 ? 80 : 443;
      const clientPort = packet.stream === 0 ? 51234 : 51235;
      Object.assign(packet, { source: reverse ? server : CLIENT, destination: reverse ? CLIENT : server, srcPort: reverse ? serverPort : clientPort, dstPort: reverse ? clientPort : serverPort });
      const side = reverse ? 1 : 0;
      packet.seq = sequence[packet.stream][side];
      packet.ack = packet.flags.includes('ACK') ? sequence[packet.stream][1 - side] : 0;
      if (packet.payload) packet.payloadBytes = encode(packet.payload);
      if (packet.retransmitOf) {
        const original = result[packet.retransmitOf - 1];
        Object.assign(packet, { seq: original.seq, ack: original.ack, payload: original.payload, payloadBytes: [...original.payloadBytes] });
      } else {
        sequence[packet.stream][side] += packet.payloadBytes.length + (packet.flags.includes('SYN') || packet.flags.includes('FIN') ? 1 : 0);
      }
      packet.info ||= `${packet.srcPort} → ${packet.dstPort} [${packet.flags}] Seq=${packet.seq} Ack=${packet.ack} Win=64240 Len=${packet.payloadBytes.length}`;
    }
    if (packet.protocol === 'DNS') {
      packet.payloadBytes = dnsPayload(packet.dnsName, Boolean(packet.dnsAnswer), packet.transaction, packet.dnsAnswer);
      packet.info = `Standard query${packet.dnsAnswer ? ' response' : ''} 0x${packet.transaction.toString(16)} A ${packet.dnsName}${packet.dnsAnswer ? ` A ${packet.dnsAnswer}` : ''}`;
    }
    if (packet.protocol === 'UDP' && !packet.info) packet.info = `${packet.srcPort} → ${packet.dstPort} Len=${packet.payloadBytes.length}`;
    packet.bytes = makeBytes(packet);
    packet.length = packet.bytes.length;
    result.push(packet);
  }
  return result;
}

export const packets = buildPackets();

function splitExpression(expression, separator) {
  const parts = [];
  let quote = false;
  let depth = 0;
  let start = 0;
  for (let i = 0; i < expression.length; i += 1) {
    const char = expression[i];
    if (char === '"' && expression[i - 1] !== '\\') quote = !quote;
    if (quote) continue;
    if (char === '(') depth += 1;
    if (char === ')') depth -= 1;
    if (depth < 0) throw new Error('过滤表达式中的括号不匹配');
    if (depth === 0 && expression.slice(i, i + separator.length) === separator) {
      parts.push(expression.slice(start, i).trim());
      start = i + separator.length;
      i += separator.length - 1;
    }
  }
  if (quote) throw new Error('过滤表达式缺少闭合双引号');
  if (depth !== 0) throw new Error('过滤表达式中的括号不匹配');
  parts.push(expression.slice(start).trim());
  if (parts.some((part) => !part)) throw new Error('逻辑运算符两侧都需要过滤条件');
  return parts;
}

function compileFilter(expression) {
  const text = expression.trim();
  const orParts = splitExpression(text, '||');
  if (orParts.length > 1) {
    const predicates = orParts.map(compileFilter);
    return (packet) => predicates.some((predicate) => predicate(packet));
  }
  const andParts = splitExpression(text, '&&');
  if (andParts.length > 1) {
    const predicates = andParts.map(compileFilter);
    return (packet) => predicates.every((predicate) => predicate(packet));
  }
  if (text.startsWith('(') && text.endsWith(')')) return compileFilter(text.slice(1, -1));
  const simple = text.toLowerCase();
  if (['tcp', 'udp', 'http', 'dns', 'tls', 'tlsv1.3', 'sip', 'icmp', 'arp'].includes(simple)) {
    return (packet) => simple === 'tcp' || simple === 'udp'
      ? packet.transport.toLowerCase() === simple
      : packet.protocol.toLowerCase() === (simple === 'tls' ? 'tlsv1.3' : simple);
  }
  if (simple === 'tcp.analysis.retransmission') return (packet) => packet.issue === 'retransmission';
  if (simple === 'tcp.analysis.duplicate_ack') return (packet) => packet.issue === 'duplicate_ack';
  let match = text.match(/^ip\.(addr|src|dst)\s*(?:==|eq)\s*(\d{1,3}(?:\.\d{1,3}){3})$/i);
  if (match) {
    const [, field, address] = match;
    if (address.split('.').some((part) => Number(part) > 255)) throw new Error('IP 地址无效：每段必须在 0–255 之间');
    return (packet) => packet.protocol !== 'ARP' && (field.toLowerCase() === 'src' ? packet.source === address : field.toLowerCase() === 'dst' ? packet.destination === address : packet.source === address || packet.destination === address);
  }
  match = text.match(/^(tcp|udp)\.(port|srcport|dstport)\s*(?:==|eq)\s*(\d+)$/i);
  if (match) {
    const [, transport, field, value] = match;
    const port = Number(value);
    if (port > 65535) throw new Error('端口号必须在 0–65535 之间');
    return (packet) => packet.transport.toLowerCase() === transport.toLowerCase() && (field.toLowerCase() === 'srcport' ? packet.srcPort === port : field.toLowerCase() === 'dstport' ? packet.dstPort === port : packet.srcPort === port || packet.dstPort === port);
  }
  match = text.match(/^tcp\.stream\s*(?:==|eq)\s*(\d+)$/i);
  if (match) return (packet) => packet.transport === 'TCP' && packet.stream === Number(match[1]);
  match = text.match(/^frame\s+contains\s+("(?:[^"\\]|\\.)*")$/i);
  if (match) {
    let needle;
    try { needle = encode(JSON.parse(match[1])); } catch { throw new Error('frame contains 的文本必须是有效的双引号字符串'); }
    return (packet) => packet.bytes.some((_, offset) => needle.every((byte, index) => packet.bytes[offset + index] === byte));
  }
  throw new Error(`演示版暂不支持此过滤条件：${text}`);
}

export function filterPackets(inputPackets, expression) {
  if (!String(expression || '').trim()) return { packets: inputPackets, error: null };
  try {
    const predicate = compileFilter(String(expression));
    return { packets: inputPackets.filter(predicate), error: null };
  } catch (error) {
    return { packets: [], error: error.message };
  }
}

export function protocolStats(inputPackets) {
  const grouped = new Map();
  for (const packet of inputPackets) {
    const row = grouped.get(packet.protocol) || { protocol: packet.protocol, count: 0, bytes: 0, percentage: 0 };
    row.count += 1;
    row.bytes += packet.length;
    grouped.set(packet.protocol, row);
  }
  return [...grouped.values()].map((row) => ({ ...row, percentage: inputPackets.length ? (row.count / inputPackets.length) * 100 : 0 })).sort((a, b) => b.count - a.count);
}

export function getPacketLayers(packet) {
  if (!packet) return [];
  const mac = (bytes) => bytes.map((byte) => byte.toString(16).padStart(2, '0')).join(':');
  const layers = [
    { id: 'frame', label: `Frame ${packet.no}: ${packet.length} bytes on wire (${packet.length * 8} bits), ${packet.length} bytes captured`, fields: [
      { name: 'Interface', value: 'en0 (synthetic demo capture)' },
      { name: 'Arrival time', value: `Oct 30, 2026 14:32:${(14 + packet.time).toFixed(6)} CST` },
      { name: 'Time since first frame', value: `${packet.time.toFixed(6)} seconds` },
      { name: 'Frame number', value: String(packet.no) },
      { name: 'Frame length', value: `${packet.length} bytes` },
      { name: 'Capture length', value: `${packet.length} bytes` },
    ] },
    { id: 'eth', label: `Ethernet II, Src: ${mac(packet.bytes.slice(6, 12))}, Dst: ${mac(packet.bytes.slice(0, 6))}`, fields: [
      { name: 'Destination', value: mac(packet.bytes.slice(0, 6)) },
      { name: 'Source', value: mac(packet.bytes.slice(6, 12)) },
      { name: 'Type', value: packet.protocol === 'ARP' ? 'ARP (0x0806)' : 'IPv4 (0x0800)' },
    ] },
  ];
  if (packet.protocol === 'ARP') {
    layers.push({ id: 'arp', label: `Address Resolution Protocol (${packet.arpReply ? 'reply' : 'request'})`, fields: [
      { name: 'Hardware type', value: 'Ethernet (1)' }, { name: 'Protocol type', value: 'IPv4 (0x0800)' },
      { name: 'Opcode', value: packet.arpReply ? 'reply (2)' : 'request (1)' },
      { name: 'Sender IP address', value: packet.source }, { name: 'Target IP address', value: packet.destination },
    ] });
    return layers;
  }
  layers.push({ id: 'ip', label: `Internet Protocol Version 4, Src: ${packet.source}, Dst: ${packet.destination}`, fields: [
    { name: 'Version', value: '4' }, { name: 'Header length', value: '20 bytes (5)' },
    { name: 'Total length', value: String((packet.bytes[16] << 8) + packet.bytes[17]) },
    { name: 'Time to live', value: '64' }, { name: 'Protocol', value: packet.transport },
    { name: 'Source address', value: packet.source }, { name: 'Destination address', value: packet.destination },
  ] });
  if (packet.transport === 'TCP') layers.push({ id: 'tcp', label: `Transmission Control Protocol, Src Port: ${packet.srcPort}, Dst Port: ${packet.dstPort}, Seq: ${packet.seq}, Ack: ${packet.ack}, Len: ${packet.payloadBytes.length}`, fields: [
    { name: 'Source port', value: String(packet.srcPort) }, { name: 'Destination port', value: String(packet.dstPort) },
    { name: 'Stream index', value: String(packet.stream) }, { name: 'Sequence number', value: `${packet.seq} (relative)` },
    { name: 'Acknowledgment number', value: `${packet.ack} (relative)` }, { name: 'TCP segment length', value: String(packet.payloadBytes.length) },
    { name: 'Flags', value: packet.flags }, { name: 'Window', value: '64240' },
    ...(packet.issue ? [{ name: 'Expert information', value: packet.issue === 'retransmission' ? 'Suspected retransmission; original frame 27' : 'Duplicate ACK; previous acknowledgment in frame 28' }] : []),
  ] });
  if (packet.transport === 'UDP') layers.push({ id: 'udp', label: `User Datagram Protocol, Src Port: ${packet.srcPort}, Dst Port: ${packet.dstPort}`, fields: [
    { name: 'Source port', value: String(packet.srcPort) }, { name: 'Destination port', value: String(packet.dstPort) }, { name: 'Length', value: `${packet.payloadBytes.length + 8} bytes` },
  ] });
  if (packet.protocol === 'HTTP') {
    const [header, body = ''] = packet.payload.split('\r\n\r\n');
    layers.push({ id: 'http', label: 'Hypertext Transfer Protocol', fields: [
      { name: packet.reverse ? 'Status line' : 'Request line', value: header.split('\r\n')[0] },
      ...header.split('\r\n').slice(1).map((line) => ({ name: line.slice(0, line.indexOf(':')), value: line.slice(line.indexOf(':') + 1).trim() })),
      ...(body ? [{ name: 'Response body', value: body }] : []),
    ] });
  }
  if (packet.protocol === 'DNS') layers.push({ id: 'dns', label: `Domain Name System (${packet.dnsAnswer ? 'response' : 'query'})`, fields: [
    { name: 'Transaction ID', value: `0x${packet.transaction.toString(16)}` }, { name: 'Queries', value: `${packet.dnsName}: type A, class IN` },
    { name: 'Questions', value: '1' }, { name: 'Answer RRs', value: packet.dnsAnswer ? '1' : '0' },
    ...(packet.dnsAnswer ? [{ name: 'Address', value: packet.dnsAnswer }, { name: 'Time to live', value: '60 seconds' }] : []),
  ] });
  if (packet.protocol === 'TLSv1.3') layers.push({ id: 'tls', label: 'Transport Layer Security — illustrative TLS 1.3 metadata', fields: [
    { name: 'Record summary', value: packet.info }, { name: 'Legacy record version', value: 'TLS 1.2 (0x0303)' },
    { name: 'Negotiated version', value: 'TLS 1.3 (0x0304)' }, { name: 'Server name', value: 'metrics.atlas.local' },
    { name: 'Record length', value: String(packet.payloadBytes.length - 5) },
    { name: 'Note', value: 'Synthetic encrypted bytes; plaintext is unavailable in this preview.' },
  ] });
  if (packet.protocol === 'ICMP') layers.push({ id: 'icmp', label: 'Internet Control Message Protocol', fields: [
    { name: 'Type', value: packet.echoReply ? '0 (Echo reply)' : '8 (Echo request)' }, { name: 'Code', value: '0' },
    { name: 'Identifier', value: '0x1201' }, { name: 'Sequence number', value: '1' }, { name: 'Data', value: '32 bytes' },
  ] });
  if (packet.protocol === 'UDP') layers.push({ id: 'data', label: `Data (${packet.payloadBytes.length} bytes)`, fields: [{ name: 'Payload', value: new TextDecoder().decode(new Uint8Array(packet.payloadBytes)) }] });
  return layers;
}

export function getStreamContent(packet, inputPackets = packets) {
  if (!packet || packet.transport !== 'TCP') return { client: '—', server: '—', request: '', response: '', number: null };
  const inStream = inputPackets.filter((item) => item.transport === 'TCP' && item.stream === packet.stream && !item.retransmitOf);
  const first = inStream.find((item) => !item.reverse) || packet;
  const client = first.reverse ? `${first.destination}:${first.dstPort}` : `${first.source}:${first.srcPort}`;
  const server = first.reverse ? `${first.source}:${first.srcPort}` : `${first.destination}:${first.dstPort}`;
  if (inStream.some((item) => item.protocol === 'TLSv1.3')) return {
    client, server, number: packet.stream,
    request: '[TLS 1.3 encrypted application data]\n此演示流已加密，未配置会话密钥，无法显示明文。',
    response: '[TLS 1.3 encrypted application data]\nEncrypted records are shown in the packet bytes panel.',
  };
  return { client, server, number: packet.stream,
    request: inStream.filter((item) => !item.reverse && item.payload).map((item) => item.payload).join('\n'),
    response: inStream.filter((item) => item.reverse && item.payload).map((item) => item.payload).join('\n'),
  };
}
