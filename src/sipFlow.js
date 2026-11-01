// Call identity is independent of packet order: interleaved dialogs must stay together.
export function sipMessage(packet) {
  const fields = packet.fields || {};
  const info = String(packet.info || "")
    .replace(/\s*\|.*$/, "")
    .trim();
  const response = info.match(
    /^(?:Status:\s*)?(?:SIP\/\d\.\d\s+)?(\d{3})\s*([^()]*)/i,
  );
  const method =
    fields["sip.CSeq.method"] ||
    info.match(/^(?:Request:\s*)?([A-Z]+)\b/)?.[1] ||
    "SIP";
  const code = Number(fields["sip.Status-Code"] || response?.[1] || 0);
  return {
    label: response ? `${response[1]} ${response[2].trim()}` : method,
    method,
    code,
    hasSdp:
      /SDP/i.test(packet.protocol || "") ||
      /SDP/i.test(packet.info || "") ||
      fields["sip.Content-Type"]?.includes("application/sdp"),
    detail: response ? `响应 · ${method}` : `请求 · ${method}`,
  };
}

export function sipCallKey(packet) {
  const fields = packet.fields || {};
  const id = fields["sip.Call-ID"] || fields["sip.call-id"];
  if (id) return `call:${id}`;
  const pair = [packet.source, packet.destination].sort().join("|");
  return `transport:${packet.transport || "UDP"}:${packet.stream ?? pair}`;
}

export function sipEndpoints(packets) {
  return [
    ...new Set(
      packets.flatMap((p) => [p.source, p.destination]).filter(Boolean),
    ),
  ];
}

export function endpointLetter(index) {
  return index < 26 ? String.fromCharCode(65 + index) : `N${index + 1}`;
}

export function buildSipCalls(packets) {
  const calls = new Map();
  [...packets]
    .sort((a, b) => a.time - b.time || a.no - b.no)
    .forEach((packet) => {
      if (
        !/^sip(?:\/|$)/i.test(packet.protocol || "") &&
        !packet.fields?.["sip.Call-ID"]
      )
        return;
      const key = sipCallKey(packet);
      if (!calls.has(key))
        calls.set(key, { key, index: calls.size, packets: [] });
      calls.get(key).packets.push(packet);
    });
  return [...calls.values()].map((call) => {
    const first = call.packets[0];
    const messages = call.packets.map(sipMessage);
    const has = (method) =>
      messages.some((m) => !m.code && m.method === method);
    const status = has("CANCEL")
      ? "已取消"
      : messages.some((m) => m.code >= 300 && m.method === "INVITE")
        ? "呼叫失败"
        : has("BYE")
          ? "已结束"
          : messages.some(
                (m) => m.code >= 200 && m.code < 300 && m.method === "INVITE",
              )
            ? "已接通"
            : messages.some((m) => m.code === 180 || m.code === 183)
              ? "振铃中"
              : "建立中";
    return {
      ...call,
      callId:
        first.fields?.["sip.Call-ID"] ||
        first.fields?.["sip.call-id"] ||
        "未解析 Call-ID · 按传输会话分组",
      endpoints: sipEndpoints(call.packets),
      start: Number(first.time),
      duration: Math.max(
        0,
        Number(call.packets.at(-1).time) - Number(first.time),
      ),
      status,
    };
  });
}

export function sipFlowRows(calls) {
  return calls
    .flatMap((call) =>
      call.packets.map((packet, index) => ({
        packet,
        call,
        message: sipMessage(packet),
        delta: index
          ? Math.max(0, (packet.time - call.packets[index - 1].time) * 1000)
          : null,
      })),
    )
    .sort((a, b) => a.packet.time - b.packet.time || a.packet.no - b.packet.no);
}
