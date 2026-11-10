// Call identity is independent of packet order: interleaved dialogs must stay together.
export function sipDisplayFilter(filter = "") {
  const value = filter.trim();
  return !value || value === "sip" ? "sip" : `(${value}) && sip`;
}

export function selectSipCalls(calls, { search = "", status = "all", sort = "start" } = {}) {
  const query = search.toLowerCase().trim();
  const matching = calls.filter((call) =>
    (status === "all" || call.status === status) &&
    (!query || `${call.callId} ${call.endpoints.join(" ")} ${call.status}`.toLowerCase().includes(query)),
  );
  const compare = {
    start: (a, b) => a.start - b.start,
    newest: (a, b) => b.start - a.start,
    duration: (a, b) => b.duration - a.duration,
    packets: (a, b) => b.packets.length - a.packets.length,
  }[sort] || ((a, b) => a.start - b.start);
  return matching.sort((a, b) => compare(a, b) || a.index - b.index);
}

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
    // A Call-ID can contain authentication retries, forks and re-INVITEs.
    // Only the initial INVITE outcome determines whether call setup failed;
    // a later 2xx keeps the dialog connected even when another branch or a
    // re-INVITE returns an error.
    const inviteResponses = messages.filter(
      (m) => m.code > 0 && m.method === "INVITE",
    );
    const firstInviteIndex = messages.findIndex(
      (m) => !m.code && m.method === "INVITE",
    );
    const firstInviteTime =
      firstInviteIndex >= 0 ? Number(call.packets[firstInviteIndex].time) : Number(first.time);
    const responsePackets = call.packets
      .map((packet, index) => ({ packet, message: messages[index] }))
      .filter(({ message }) => message.code > 0);
    const inviteResponsePackets = responsePackets.filter(
      ({ message }) => message.method === "INVITE",
    );
    const connected = inviteResponses.some(
      (m) => m.code >= 200 && m.code < 300,
    );
    const failedSetup = !connected && inviteResponses.some((m) => m.code >= 300 && m.code !== 401 && m.code !== 407);
    let status = "建立中";
    if (connected) status = has("BYE") ? "已结束" : "已接通";
    else if (has("BYE") && !failedSetup) status = "已结束";
    else if (has("CANCEL")) status = "已取消";
    else if (failedSetup) status = "呼叫失败";
    else if (messages.some((m) => m.code === 180 || m.code === 183))
      status = "振铃中";
    else if (inviteResponses.some((m) => m.code === 401 || m.code === 407))
      status = "认证中";
    else if (firstInviteIndex < 0 && !inviteResponses.length) {
      const responses = messages.filter((m) => m.code >= 200);
      const lastCode = responses.at(-1)?.code;
      status = lastCode === 401 || lastCode === 407 ? "认证中"
        : lastCode >= 300 ? "事务失败"
          : lastCode >= 200 ? "事务完成" : "仅信令";
    }
    const firstResponse = inviteResponsePackets[0];
    const ringing = inviteResponsePackets.find(
      ({ message }) => message.code === 180 || message.code === 183,
    );
    const connectedResponse = inviteResponsePackets.find(
      ({ message }) => message.code >= 200 && message.code < 300,
    );
    const finalResponses = inviteResponsePackets.filter(
      ({ message }) => message.code >= 200,
    );
    const toTags = new Set(call.packets.map((packet) => packet.fields?.["sip.to.tag"]).filter(Boolean));
    const fromTags = new Set(call.packets.map((packet) => packet.fields?.["sip.from.tag"]).filter(Boolean));
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
      diagnostics: {
        inviteAttempts: messages.filter((m) => !m.code && m.method === "INVITE").length,
        authChallenges: inviteResponsePackets.filter(
          ({ message }) => message.code === 401 || message.code === 407,
        ).length,
        firstResponseMs:
          firstResponse && Number.isFinite(firstInviteTime)
            ? Math.max(0, (Number(firstResponse.packet.time) - firstInviteTime) * 1000)
            : null,
        ringingMs:
          ringing && Number.isFinite(firstInviteTime)
            ? Math.max(0, (Number(ringing.packet.time) - firstInviteTime) * 1000)
            : null,
        connectedMs:
          connectedResponse && Number.isFinite(firstInviteTime)
            ? Math.max(0, (Number(connectedResponse.packet.time) - firstInviteTime) * 1000)
            : null,
        finalCode: finalResponses.at(-1)?.message.code || null,
        ackSeen: has("ACK"),
        byeSeen: has("BYE"),
        forkCount: Math.max(toTags.size, fromTags.size),
      },
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
