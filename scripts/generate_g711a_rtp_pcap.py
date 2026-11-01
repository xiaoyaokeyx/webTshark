#!/usr/bin/env python3
"""Generate a small SIP + G.711 A-law (PCMA) RTP capture for WebShark."""

from __future__ import annotations

import argparse
import math
import struct
from pathlib import Path

from generate_mixed_protocol_pcap import PCAP_GLOBAL, sip_message, udp


SAMPLE_RATE = 8000
SAMPLES_PER_PACKET = 160
PACKETS_PER_SECOND = SAMPLE_RATE // SAMPLES_PER_PACKET
CLIENT = "10.10.0.10"
SERVER = "10.10.0.20"
RTP_CLIENT_PORT = 20000
RTP_SERVER_PORT = 20002
MELODY = [
    261.63,
    293.66,
    329.63,
    392.00,
    329.63,
    293.66,
    261.63,
    220.00,
    246.94,
    293.66,
    329.63,
    440.00,
    392.00,
    329.63,
    293.66,
    261.63,
]


def linear_to_alaw(sample: int) -> int:
    """Encode one signed 16-bit PCM sample as G.711 A-law."""
    sample = max(-32768, min(32767, sample))
    sign = 0x80 if sample < 0 else 0
    value = abs(sample)
    if value >= 32635:
        encoded = 0x7F
    else:
        value += 0x84
        exponent = 7
        mask = 0x4000
        while exponent > 0 and not (value & mask):
            exponent -= 1
            mask >>= 1
        mantissa = (value >> (exponent + 3)) & 0x0F
        encoded = (exponent << 4) | mantissa
    return (encoded ^ (sign | 0x55)) & 0xFF


def music_sample(sample_index: int, voice: int = 0) -> int:
    """Create a simple repeating melody with bass and harmonics."""
    beat_samples = SAMPLE_RATE // 2
    beat = (sample_index // beat_samples) % len(MELODY)
    frequency = MELODY[beat]
    if voice == 1:
        frequency *= 0.5
    elif voice == 2:
        frequency *= 1.5
    time = sample_index / SAMPLE_RATE
    phase = (sample_index % beat_samples) / beat_samples
    envelope = min(1.0, phase * 18.0) * min(1.0, (1.0 - phase) * 5.0)
    value = 7200.0 * envelope * math.sin(2 * math.pi * frequency * time)
    value += 2200.0 * math.sin(2 * math.pi * frequency * 2.0 * time)
    value += 1200.0 * math.sin(2 * math.pi * frequency * 3.0 * time)
    value += 1800.0 * math.sin(2 * math.pi * frequency * 0.5 * time)
    if voice == 1:
        value *= 0.72
    return int(max(-15000, min(15000, value)))


def music_payload(packet_index: int, voice: int = 0) -> bytes:
    start = packet_index * SAMPLES_PER_PACKET
    return bytes(
        linear_to_alaw(music_sample(start + i, voice))
        for i in range(SAMPLES_PER_PACKET)
    )


def rtp(sequence: int, timestamp: int, ssrc: int, payload: bytes) -> bytes:
    header = struct.pack("!BBHII", 0x80, 8, sequence & 0xFFFF, timestamp, ssrc)
    return header + payload


def sdp(address: str, media_port: int) -> str:
    return (
        "v=0\r\n"
        f"o=g711a-demo 1 1 IN IP4 {address}\r\n"
        "s=WebShark G.711A test call\r\n"
        f"c=IN IP4 {address}\r\n"
        "t=0 0\r\n"
        f"m=audio {media_port} RTP/AVP 8\r\n"
        "a=rtpmap:8 PCMA/8000\r\n"
        "a=ptime:20\r\n"
        f"a=rtcp:{media_port + 1}\r\n"
    )


def timed_record(packet: bytes, seconds: float) -> bytes:
    whole_seconds = 1_735_000_000 + int(seconds)
    micros = int(round((seconds - int(seconds)) * 1_000_000))
    return struct.pack("<IIII", whole_seconds, micros, len(packet), len(packet)) + packet


def build_capture(output: Path, packets_per_direction: int = 1500) -> dict:
    output.parent.mkdir(parents=True, exist_ok=True)
    call_id = "g711a-demo@webshark.local"
    ident = 1
    packet_index = 0

    with output.open("wb") as stream:
        stream.write(PCAP_GLOBAL)

        def emit(packet: bytes, capture_time: float) -> None:
            nonlocal ident, packet_index
            stream.write(timed_record(packet, capture_time))
            ident += 1
            packet_index += 1

        emit(
            udp(
                CLIENT,
                SERVER,
                5060,
                5060,
                sip_message(
                    "INVITE sip:bob@10.10.0.20 SIP/2.0",
                    call_id,
                    "1 INVITE",
                    sdp(SERVER, RTP_SERVER_PORT),
                ),
                ident,
            ),
            0.000,
        )
        emit(
            udp(
                SERVER,
                CLIENT,
                5060,
                5060,
                sip_message(
                    "SIP/2.0 200 OK",
                    call_id,
                    "1 INVITE",
                    sdp(SERVER, RTP_SERVER_PORT),
                ),
                ident,
            ),
            0.001,
        )
        emit(
            udp(
                CLIENT,
                SERVER,
                5060,
                5060,
                sip_message(
                    "ACK sip:bob@10.10.0.20 SIP/2.0",
                    call_id,
                    "1 ACK",
                ),
                ident,
            ),
            0.002,
        )

        for index in range(packets_per_direction):
            emit(
                udp(
                    CLIENT,
                    SERVER,
                    RTP_CLIENT_PORT,
                    RTP_SERVER_PORT,
                    rtp(
                        1000 + index,
                        index * SAMPLES_PER_PACKET,
                        0xA11CE001,
                        music_payload(index, 0),
                    ),
                    ident,
                ),
                0.02 * index + 0.003,
            )
            emit(
                udp(
                    SERVER,
                    CLIENT,
                    RTP_SERVER_PORT,
                    RTP_CLIENT_PORT,
                    rtp(
                        2000 + index,
                        index * SAMPLES_PER_PACKET,
                        0xB0BCE002,
                        music_payload(index, 1),
                    ),
                    ident,
                ),
                0.02 * index + 0.013,
            )

        emit(
            udp(
                CLIENT,
                SERVER,
                5060,
                5060,
                sip_message("BYE sip:bob@10.10.0.20 SIP/2.0", call_id, "2 BYE"),
                ident,
            ),
            0.02 * packets_per_direction + 0.003,
        )
        emit(
            udp(
                SERVER,
                CLIENT,
                5060,
                5060,
                sip_message("SIP/2.0 200 OK", call_id, "2 BYE"),
                ident,
            ),
            0.02 * packets_per_direction + 0.004,
        )

    return {
        "path": str(output),
        "packets": packet_index,
        "bytes": output.stat().st_size,
        "rtp_packets": packets_per_direction * 2,
        "duration_seconds": packets_per_direction / PACKETS_PER_SECOND,
        "codec": "PCMA / G.711 A-law",
        "sample_rate": SAMPLE_RATE,
        "rtp_ports": [RTP_CLIENT_PORT, RTP_SERVER_PORT],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seconds", type=float, default=30)
    parser.add_argument("--packets-per-direction", type=int)
    args = parser.parse_args()
    packets_per_direction = args.packets_per_direction or round(
        args.seconds * PACKETS_PER_SECOND
    )
    if not 1 <= packets_per_direction <= 30000:
        parser.error("packets per direction must be between 1 and 30000")
    print(build_capture(args.output, packets_per_direction))


if __name__ == "__main__":
    main()
