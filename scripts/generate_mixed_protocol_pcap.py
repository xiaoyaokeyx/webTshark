#!/usr/bin/env python3
"""Generate a deterministic ~200 MiB PCAP containing SIP, RTP, TCP, HTTP and MRCPv2."""

from __future__ import annotations

import argparse
import ipaddress
import json
import struct
import time
from pathlib import Path


PCAP_GLOBAL = struct.pack(
    "<IHHIIII",
    0xA1B2C3D4,
    2,
    4,
    0,
    0,
    65535,
    1,
)
ETHERNET_HEADER_LEN = 14
IP_HEADER_LEN = 20
UDP_HEADER_LEN = 8
TCP_HEADER_LEN = 20
PCAP_RECORD_HEADER_LEN = 16

MAC_CLIENT = bytes.fromhex("020000000101")
MAC_SERVER = bytes.fromhex("020000000202")


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4(src: str, dst: str, protocol: int, payload: bytes, ident: int) -> bytes:
    total_length = IP_HEADER_LEN + len(payload)
    header = struct.pack(
        "!BBHHHBBHII",
        0x45,
        0,
        total_length,
        ident & 0xFFFF,
        0,
        64,
        protocol,
        0,
        int(ipaddress.IPv4Address(src)),
        int(ipaddress.IPv4Address(dst)),
    )
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


def ethernet(src_mac: bytes, dst_mac: bytes, ip_packet: bytes) -> bytes:
    return dst_mac + src_mac + struct.pack("!H", 0x0800) + ip_packet


def udp(src: str, dst: str, src_port: int, dst_port: int, payload: bytes, ident: int) -> bytes:
    header = struct.pack("!HHHH", src_port, dst_port, UDP_HEADER_LEN + len(payload), 0)
    return ethernet(MAC_CLIENT, MAC_SERVER, ipv4(src, dst, 17, header + payload, ident))


def tcp(
    src: str,
    dst: str,
    src_port: int,
    dst_port: int,
    payload: bytes,
    ident: int,
    seq: int,
    ack: int,
    flags: int,
) -> bytes:
    header = struct.pack(
        "!HHIIHHHH",
        src_port,
        dst_port,
        seq & 0xFFFFFFFF,
        ack & 0xFFFFFFFF,
        (5 << 12) | flags,
        65535,
        0,
        0,
    )
    return ethernet(MAC_CLIENT, MAC_SERVER, ipv4(src, dst, 6, header + payload, ident))


def record(packet: bytes, index: int) -> bytes:
    seconds = 1_735_000_000 + index // 1000
    micros = (index % 1000) * 1000
    return struct.pack("<IIII", seconds, micros, len(packet), len(packet)) + packet


def sip_message(start_line: str, call_id: str, cseq: str, body: str = "") -> bytes:
    body_bytes = body.encode("ascii")
    headers = [
        start_line,
        "Via: SIP/2.0/UDP 10.10.0.10:5060;branch=z9hG4bK-load-test",
        "From: <sip:alice@10.10.0.10>;tag=load-a",
        "To: <sip:bob@10.10.0.20>;tag=load-b",
        f"Call-ID: {call_id}",
        f"CSeq: {cseq}",
        "Max-Forwards: 70",
        "Contact: <sip:alice@10.10.0.10:5060>",
        "Content-Type: application/sdp" if body_bytes else "Content-Length: 0",
    ]
    if body_bytes:
        headers.extend([f"Content-Length: {len(body_bytes)}", ""])
    else:
        headers.append("")
    return ("\r\n".join(headers) + "\r\n").encode("ascii") + body_bytes


def mrcp_message(start_line: str, headers: list[str]) -> bytes:
    provisional = f"MRCP/2.0 0 {start_line}\r\n" + "\r\n".join(headers) + "\r\n\r\n"
    payload = provisional.encode("ascii")
    length = len(payload)
    return payload.replace(b"MRCP/2.0 0 ", f"MRCP/2.0 {length} ".encode("ascii"), 1)


SDP = (
    "v=0\r\n"
    "o=webshark 1 1 IN IP4 10.10.0.20\r\n"
    "s=Mixed protocol load test\r\n"
    "c=IN IP4 10.10.0.20\r\n"
    "t=0 0\r\n"
    "m=audio 20000 RTP/AVP 0 96\r\n"
    "a=rtpmap:0 PCMU/8000\r\n"
    "a=rtpmap:96 AMR/8000\r\n"
    "a=rtcp:20001\r\n"
    "m=application 1544 TCP/MRCPv2 1\r\n"
    "a=resource:speechrecog\r\n"
    "a=channel:8F23@speechrecog\r\n"
    "a=cmid:2\r\n"
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target-mb", type=int, default=200)
    args = parser.parse_args()

    target_size = args.target_mb * 1024 * 1024
    args.output.parent.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    counters = {"sip": 0, "rtp": 0, "tcp": 0, "http": 0, "mrcpv2": 0}
    packet_index = 0
    file_size = len(PCAP_GLOBAL)
    ident = 1

    with args.output.open("wb", buffering=1024 * 1024) as out:
        out.write(PCAP_GLOBAL)

        def emit(packet: bytes, protocol: str) -> None:
            nonlocal packet_index, file_size, ident
            chunk = record(packet, packet_index)
            out.write(chunk)
            file_size += len(chunk)
            packet_index += 1
            ident += 1
            counters[protocol] += 1

        # SIP call setup/teardown over UDP, plus a small SIP-over-TCP exchange.
        sip_packets = [
            ("INVITE sip:bob@10.10.0.20 SIP/2.0", "1 INVITE", SDP),
            ("SIP/2.0 100 Trying", "1 INVITE", ""),
            ("SIP/2.0 180 Ringing", "1 INVITE", ""),
            ("SIP/2.0 200 OK", "1 INVITE", SDP),
            ("ACK sip:bob@10.10.0.20 SIP/2.0", "1 ACK", ""),
            ("BYE sip:bob@10.10.0.20 SIP/2.0", "2 BYE", ""),
            ("SIP/2.0 200 OK", "2 BYE", ""),
        ]
        for call_index in range(2):
            call_id = f"mixed-load-call-{call_index}@webshark.test"
            for start_line, cseq, body in sip_packets:
                source, destination = (
                    ("10.10.0.10", "10.10.0.20")
                    if "SIP/2.0" not in start_line or "100" in start_line or "180" in start_line or "200" in start_line
                    else ("10.10.0.10", "10.10.0.20")
                )
                if start_line.startswith("SIP/2.0") and ("100" in start_line or "180" in start_line or "200" in start_line):
                    source, destination = "10.10.0.20", "10.10.0.10"
                emit(
                    udp(
                        source,
                        destination,
                        5060,
                        5060,
                        sip_message(start_line, call_id, cseq, body),
                        ident,
                    ),
                    "sip",
                )

        # TCP handshake and protocol payloads for HTTP, MRCPv2 and SIP-over-TCP.
        tcp_streams = [
            ("192.168.10.10", "192.168.10.20", 41000, 80, "http"),
            ("172.16.0.10", "172.16.0.20", 42000, 1544, "mrcpv2"),
            ("10.20.0.10", "10.20.0.20", 43000, 5060, "sip"),
        ]
        stream_seq = {}
        for source, destination, src_port, dst_port, protocol in tcp_streams:
            stream_seq[(source, destination, src_port, dst_port)] = (1000, 5000)
            emit(tcp(source, destination, src_port, dst_port, b"", ident, 1000, 0, 0x02), "tcp")
            emit(tcp(destination, source, dst_port, src_port, b"", ident, 5000, 1001, 0x12), "tcp")
            emit(tcp(source, destination, src_port, dst_port, b"", ident, 1001, 5001, 0x10), "tcp")

            if protocol == "http":
                request, response = (
                    b"GET /capture/health HTTP/1.1\r\nHost: webshark.test\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n",
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 41\r\nConnection: keep-alive\r\n\r\n{\"status\":\"ok\",\"protocols\":[\"sip\",\"rtp\"]}",
                )
            elif protocol == "mrcpv2":
                request, response = (
                    mrcp_message(
                        "SPEAK 1",
                        [
                            "Channel-Identifier: speechrecog@load-test",
                            "Content-Type: application/sdp",
                            "Content-Length: 0",
                        ],
                    ),
                    mrcp_message(
                        "1 200 IN-PROGRESS",
                        [
                            "Channel-Identifier: speechrecog@load-test",
                            "Completion-Cause: 000 success",
                            "Content-Length: 0",
                        ],
                    ),
                )
            else:
                request, response = (
                    sip_message("OPTIONS sip:10.20.0.20 SIP/2.0", "tcp-load-test@webshark.test", "1 OPTIONS"),
                    sip_message("SIP/2.0 200 OK", "tcp-load-test@webshark.test", "1 OPTIONS"),
                )

            emit(tcp(source, destination, src_port, dst_port, request, ident, 1001, 5001, 0x18), protocol)
            emit(
                tcp(destination, source, dst_port, src_port, response, ident, 5001, 1001 + len(request), 0x18),
                protocol,
            )

        # RTP is the bulk payload: two directions, realistic RTP headers and PCMU bytes.
        rtp_payload = bytes((i * 17) & 0xFF for i in range(1200))
        rtp_seq = [0, 0]
        rtp_ts = [0, 0]
        rtp_streams = [
            ("10.10.0.10", "10.10.0.20", 20000, 20002, 0x11223344),
            ("10.10.0.20", "10.10.0.10", 20002, 20000, 0x55667788),
        ]
        while file_size < target_size:
            remaining = target_size - file_size
            record_overhead = PCAP_RECORD_HEADER_LEN + ETHERNET_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN
            if remaining < record_overhead + 12:
                break
            stream_index = counters["rtp"] % 2
            source, destination, src_port, dst_port, ssrc = rtp_streams[stream_index]
            payload_len = min(len(rtp_payload), remaining - record_overhead - 12)
            if remaining <= record_overhead + 12 + len(rtp_payload) + 57:
                payload_len = remaining - record_overhead - 12
            payload_len = max(0, payload_len)
            rtp_header = struct.pack(
                "!BBHII",
                0x80,
                0,
                rtp_seq[stream_index] & 0xFFFF,
                rtp_ts[stream_index] & 0xFFFFFFFF,
                ssrc,
            )
            emit(
                udp(source, destination, src_port, dst_port, rtp_header + rtp_payload[:payload_len], ident),
                "rtp",
            )
            rtp_seq[stream_index] += 1
            rtp_ts[stream_index] += 160

    if file_size != target_size:
        raise RuntimeError(f"could not reach target size: {file_size} != {target_size}")

    print(
        json.dumps(
            {
                "path": str(args.output),
                "bytes": file_size,
                "mib": round(file_size / (1024 * 1024), 3),
                "packets": packet_index,
                "protocol_packets": counters,
                "generation_ms": round((time.perf_counter() - started) * 1000, 1),
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
