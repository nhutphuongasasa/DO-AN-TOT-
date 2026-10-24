#!/usr/bin/env python3
"""ml/gen_synthetic.py — Bộ sinh dữ liệu PCAP và metadata tổng hợp cho pipeline Edge AI.

Mục đích:
    Tạo dữ liệu lưu lượng mạng giả lập (synthetic network traffic) để kiểm thử
    pipeline ML (Task 2) mà không cần thiết bị phần cứng Raspberry Pi vật lý.

Đầu ra tương thích với định dạng của tools/capture_session.py:
    - captures/synthetic/capture_synthetic_batch{b}.pcap : File PCAP chuẩn scapy
    - captures/synthetic/session_synthetic_batch{b}.json : File nhãn metadata
"""

from __future__ import annotations

import argparse
import datetime
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple

import numpy as np
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw
from scapy.utils import PcapWriter


# ---------------------------------------------------------------------------
# Danh sách 8 ứng dụng mặc định
# ---------------------------------------------------------------------------

DEFAULT_APPS: List[str] = [
    "youtube",
    "zalo",
    "spotify",
    "meet",
    "chatgpt",
    "other-idle",
    "other-web",
    "other-update",
]


# ---------------------------------------------------------------------------
# Cấu trúc dữ liệu gói tin tổng hợp
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class SyntheticPacket:
    """Biểu diễn siêu dữ liệu một gói tin mạng trước khi dựng thành frame Ethernet."""

    timestamp: float
    is_downlink: bool
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str  # "TCP" hoặc "UDP"
    wire_length: int
    tcp_flags: str = "PA"


# ---------------------------------------------------------------------------
# Các hàm sinh đặc trưng lưu lượng từng ứng dụng
# ---------------------------------------------------------------------------

def generate_youtube_traffic(
    rng: np.random.Generator,
    start_time: float,
    duration_s: float,
    client_ip: str,
    server_ip: str = "142.250.190.46",
    server_port: int = 443,
    client_port: int = 50443,
) -> List[SyntheticPacket]:
    """Simulate YouTube traffic (QUIC/UDP 443).

    Đặc trưng:
        - Protocol: UDP (QUIC port 443)
        - bytes_down >> bytes_up (ratio ~35-48x)
        - IAT giữa các packet downlink đều đặn: 20-50ms trong video chunk buffer
        - pkt_size downlink: 1300-1460 bytes, uplink ACK: 65-90 bytes
        - Video chunk buffer diễn ra định kỳ mỗi 2-4 giây
    """
    packets: List[SyntheticPacket] = []
    cur_t = start_time
    end_t = start_time + duration_s

    while cur_t < end_t:
        # Chu kỳ buffer video chunk
        cycle_period = float(rng.uniform(2.2, 3.8))
        chunk_pkts_down = int(rng.integers(6, 11))

        # Client gửi gói control/request nhỏ ban đầu
        req_size = int(rng.integers(70, 110))
        packets.append(SyntheticPacket(
            timestamp=cur_t,
            is_downlink=False,
            src_ip=client_ip,
            dst_ip=server_ip,
            src_port=client_port,
            dst_port=server_port,
            proto="UDP",
            wire_length=req_size,
        ))

        # Tải chunk các gói downlink lớn với IAT đều 20-50ms
        t_pkt = cur_t + float(rng.uniform(0.015, 0.035))
        for down_idx in range(chunk_pkts_down):
            if t_pkt >= end_t:
                break
            down_size = int(rng.integers(1300, 1461))
            packets.append(SyntheticPacket(
                timestamp=t_pkt,
                is_downlink=True,
                src_ip=server_ip,
                dst_ip=client_ip,
                src_port=server_port,
                dst_port=client_port,
                proto="UDP",
                wire_length=down_size,
            ))

            # Mỗi 2-3 gói down, client gửi 1 gói ACK nhỏ uplink để giữ ratio 30-50x
            if (down_idx + 1) % 3 == 0:
                ack_size = int(rng.integers(65, 85))
                packets.append(SyntheticPacket(
                    timestamp=t_pkt + 0.002,
                    is_downlink=False,
                    src_ip=client_ip,
                    dst_ip=server_ip,
                    src_port=client_port,
                    dst_port=server_port,
                    proto="UDP",
                    wire_length=ack_size,
                ))

            t_pkt += float(rng.uniform(0.020, 0.050))

        cur_t += cycle_period

    return packets


def generate_zalo_traffic(
    rng: np.random.Generator,
    start_time: float,
    duration_s: float,
    client_ip: str,
    server_ip: str = "49.213.68.12",
    server_port: int = 443,
    client_port: int = 51443,
) -> List[SyntheticPacket]:
    """Simulate Zalo traffic (TCP 443 chat).

    Đặc trưng:
        - Protocol: TCP 443
        - bytes_down ≈ bytes_up (chat text / stickers / ảnh nhỏ)
        - Burst nhỏ khi nhắn tin, IAT giữa các tin lớn 2-30s
        - pkt_size: 100-800 bytes
        - Xen kẽ TCP keepalive heartbeat nền
    """
    packets: List[SyntheticPacket] = []
    cur_t = start_time
    end_t = start_time + duration_s

    while cur_t < end_t:
        # Khoảng dừng giữa các lần tương tác tin nhắn: 4-22s
        pause_s = float(rng.uniform(4.0, 22.0))

        # Nếu khoảng nghỉ dài > 12s, phát gói keepalive heartbeat nhỏ
        if pause_s > 12.0:
            hb_t = cur_t + float(rng.uniform(4.0, 8.0))
            if hb_t < end_t:
                packets.append(SyntheticPacket(
                    timestamp=hb_t,
                    is_downlink=False,
                    src_ip=client_ip,
                    dst_ip=server_ip,
                    src_port=client_port,
                    dst_port=server_port,
                    proto="TCP",
                    wire_length=int(rng.integers(60, 75)),
                    tcp_flags="A",
                ))
                packets.append(SyntheticPacket(
                    timestamp=hb_t + 0.025,
                    is_downlink=True,
                    src_ip=server_ip,
                    dst_ip=client_ip,
                    src_port=server_port,
                    dst_port=client_port,
                    proto="TCP",
                    wire_length=int(rng.integers(60, 80)),
                    tcp_flags="A",
                ))

        cur_t += pause_s
        if cur_t >= end_t:
            break

        # Tin nhắn burst
        is_media = bool(rng.random() < 0.15)  # 15% là tin ảnh nhỏ
        if is_media:
            msg_count = int(rng.integers(2, 5))
            size_min, size_max = 500, 800
        else:
            msg_count = int(rng.integers(1, 3))
            size_min, size_max = 120, 380

        burst_t = cur_t
        for _ in range(msg_count):
            # Client gửi tin nhắn (Uplink)
            up_len = int(rng.integers(size_min, size_max))
            packets.append(SyntheticPacket(
                timestamp=burst_t,
                is_downlink=False,
                src_ip=client_ip,
                dst_ip=server_ip,
                src_port=client_port,
                dst_port=server_port,
                proto="TCP",
                wire_length=up_len,
            ))
            # Server phản hồi tin nhắn hoặc ACK kèm nội dung (Downlink, kích thước tương đương)
            down_len = int(rng.integers(size_min, size_max))
            burst_t += float(rng.uniform(0.020, 0.070))
            packets.append(SyntheticPacket(
                timestamp=burst_t,
                is_downlink=True,
                src_ip=server_ip,
                dst_ip=client_ip,
                src_port=server_port,
                dst_port=client_port,
                proto="TCP",
                wire_length=down_len,
            ))
            burst_t += float(rng.uniform(0.010, 0.040))

        cur_t = burst_t

    return packets


def generate_spotify_traffic(
    rng: np.random.Generator,
    start_time: float,
    duration_s: float,
    client_ip: str,
    server_ip: str = "35.186.224.25",
    server_port: int = 443,
    client_port: int = 52443,
) -> List[SyntheticPacket]:
    """Simulate Spotify traffic (TCP 443 music streaming).

    Đặc trưng:
        - Protocol: TCP 443
        - bytes_down >> bytes_up (ratio ~18-24x)
        - Audio buffering chunk burst mỗi 2.5-4.5s rồi im lặng nghe nhạc
        - pkt_size downlink: 800-1400 bytes, uplink ACK/req: 60-120 bytes
    """
    packets: List[SyntheticPacket] = []
    cur_t = start_time
    end_t = start_time + duration_s

    while cur_t < end_t:
        cycle_len = float(rng.uniform(2.5, 4.5))
        n_down = int(rng.integers(6, 10))

        # Client request audio chunk
        packets.append(SyntheticPacket(
            timestamp=cur_t,
            is_downlink=False,
            src_ip=client_ip,
            dst_ip=server_ip,
            src_port=client_port,
            dst_port=server_port,
            proto="TCP",
            wire_length=int(rng.integers(90, 150)),
        ))

        # Downlink burst audio packets
        t_pkt = cur_t + float(rng.uniform(0.010, 0.025))
        for d_idx in range(n_down):
            if t_pkt >= end_t:
                break
            d_size = int(rng.integers(800, 1401))
            packets.append(SyntheticPacket(
                timestamp=t_pkt,
                is_downlink=True,
                src_ip=server_ip,
                dst_ip=client_ip,
                src_port=server_port,
                dst_port=client_port,
                proto="TCP",
                wire_length=d_size,
            ))

            # Client ACK cứ mỗi 2-3 gói down
            if (d_idx + 1) % 3 == 0:
                packets.append(SyntheticPacket(
                    timestamp=t_pkt + 0.001,
                    is_downlink=False,
                    src_ip=client_ip,
                    dst_ip=server_ip,
                    src_port=client_port,
                    dst_port=server_port,
                    proto="TCP",
                    wire_length=int(rng.integers(60, 75)),
                    tcp_flags="A",
                ))

            t_pkt += float(rng.uniform(0.008, 0.022))

        cur_t += cycle_len

    return packets


def generate_meet_traffic(
    rng: np.random.Generator,
    start_time: float,
    duration_s: float,
    client_ip: str,
    server_ip: str = "142.250.180.120",
    server_port: int = 19305,
    client_port: int = 53443,
) -> List[SyntheticPacket]:
    """Simulate Google Meet traffic (WebRTC UDP 19302-19309).

    Đặc trưng:
        - Protocol: UDP port 19302-19309
        - bytes_down ≈ bytes_up (ratio ~1.0-1.2x)
        - IAT đều đặn: ~30-45ms (luồng RTP video + audio 2 chiều)
        - pkt_size: ~1200 bytes (phân phối chuẩn quanh 1200 bytes)
    """
    packets: List[SyntheticPacket] = []
    cur_t = start_time
    end_t = start_time + duration_s

    while cur_t < end_t:
        # Bước thời gian ~35-48ms (22-28 fps RTP stream)
        iat = float(rng.uniform(0.035, 0.050))

        # Uplink frame (camera + mic)
        up_size = int(np.clip(rng.normal(1180, 45), 1050, 1320))
        packets.append(SyntheticPacket(
            timestamp=cur_t,
            is_downlink=False,
            src_ip=client_ip,
            dst_ip=server_ip,
            src_port=client_port,
            dst_port=server_port,
            proto="UDP",
            wire_length=up_size,
        ))

        # Downlink frame (remote participant video + audio)
        down_size = int(np.clip(rng.normal(1220, 45), 1080, 1350))
        packets.append(SyntheticPacket(
            timestamp=cur_t + float(rng.uniform(0.002, 0.012)),
            is_downlink=True,
            src_ip=server_ip,
            dst_ip=client_ip,
            src_port=server_port,
            dst_port=client_port,
            proto="UDP",
            wire_length=down_size,
        ))

        cur_t += iat

    return packets


def generate_chatgpt_traffic(
    rng: np.random.Generator,
    start_time: float,
    duration_s: float,
    client_ip: str,
    server_ip: str = "104.18.32.115",
    server_port: int = 443,
    client_port: int = 54443,
) -> List[SyntheticPacket]:
    """Simulate ChatGPT traffic (TCP 443 token streaming).

    Đặc trưng:
        - Protocol: TCP 443
        - bytes_down > bytes_up (ratio ~6-9x)
        - Token streaming: nhiều gói nhỏ nhanh (180-420 bytes, IAT 15-35ms)
        - Xen kẽ khoảng dừng người dùng đọc kết quả (15-30s)
    """
    packets: List[SyntheticPacket] = []
    cur_t = start_time
    end_t = start_time + duration_s

    while cur_t < end_t:
        # Bước 1: Client gửi Prompt (Uplink: 2-3 gói)
        prompt_pkts = int(rng.integers(2, 4))
        p_time = cur_t
        for _ in range(prompt_pkts):
            if p_time >= end_t:
                break
            packets.append(SyntheticPacket(
                timestamp=p_time,
                is_downlink=False,
                src_ip=client_ip,
                dst_ip=server_ip,
                src_port=client_port,
                dst_port=server_port,
                proto="TCP",
                wire_length=int(rng.integers(300, 650)),
            ))
            p_time += float(rng.uniform(0.040, 0.120))

        # Bước 2: Token streaming phản hồi từ server (Downlink: 35-55 gói nhỏ nhanh)
        stream_t = p_time + float(rng.uniform(0.200, 0.500))  # TTFT (Time to first token)
        token_count = int(rng.integers(35, 55))
        for tok_idx in range(token_count):
            if stream_t >= end_t:
                break
            tok_size = int(rng.integers(180, 420))
            packets.append(SyntheticPacket(
                timestamp=stream_t,
                is_downlink=True,
                src_ip=server_ip,
                dst_ip=client_ip,
                src_port=server_port,
                dst_port=client_port,
                proto="TCP",
                wire_length=tok_size,
            ))

            # Client ACK cứ mỗi 4-6 gói streaming
            if (tok_idx + 1) % 5 == 0:
                packets.append(SyntheticPacket(
                    timestamp=stream_t + 0.002,
                    is_downlink=False,
                    src_ip=client_ip,
                    dst_ip=server_ip,
                    src_port=client_port,
                    dst_port=server_port,
                    proto="TCP",
                    wire_length=int(rng.integers(60, 75)),
                    tcp_flags="A",
                ))

            stream_t += float(rng.uniform(0.015, 0.035))

        # Bước 3: Khoảng dừng đọc (reading pause): 15-28s
        pause_s = float(rng.uniform(15.0, 28.0))
        # Keepalive trong lúc pause
        if pause_s > 10.0:
            hb_t = stream_t + pause_s * 0.5
            if hb_t < end_t:
                packets.append(SyntheticPacket(
                    timestamp=hb_t,
                    is_downlink=False,
                    src_ip=client_ip,
                    dst_ip=server_ip,
                    src_port=client_port,
                    dst_port=server_port,
                    proto="TCP",
                    wire_length=64,
                    tcp_flags="A",
                ))

        cur_t = stream_t + pause_s

    return packets


def generate_other_idle_traffic(
    rng: np.random.Generator,
    start_time: float,
    duration_s: float,
    client_ip: str,
    server_ip: str = "17.57.146.88",
    server_port: int = 443,
    client_port: int = 55443,
) -> List[SyntheticPacket]:
    """Simulate Idle background traffic (heartbeat / push notifications).

    Đặc trưng:
        - Rất ít gói trong toàn bộ phiên (khoảng 150-250 gói / 30 phút)
        - pkt_size nhỏ: 60-120 bytes
        - IAT rất lớn: >10s (12-28s) giữa các ping/pong keepalive
    """
    packets: List[SyntheticPacket] = []
    cur_t = start_time
    end_t = start_time + duration_s

    while cur_t < end_t:
        interval_s = float(rng.uniform(12.0, 28.0))
        cur_t += interval_s
        if cur_t >= end_t:
            break

        # Ping từ thiết bị
        packets.append(SyntheticPacket(
            timestamp=cur_t,
            is_downlink=False,
            src_ip=client_ip,
            dst_ip=server_ip,
            src_port=client_port,
            dst_port=server_port,
            proto="TCP",
            wire_length=int(rng.integers(60, 85)),
            tcp_flags="A",
        ))

        # Pong từ máy chủ nền
        packets.append(SyntheticPacket(
            timestamp=cur_t + float(rng.uniform(0.020, 0.050)),
            is_downlink=True,
            src_ip=server_ip,
            dst_ip=client_ip,
            src_port=server_port,
            dst_port=client_port,
            proto="TCP",
            wire_length=int(rng.integers(60, 95)),
            tcp_flags="A",
        ))

        # 8% xác suất có 1 push notification nhỏ (150-240 bytes)
        if rng.random() < 0.08:
            push_t = cur_t + float(rng.uniform(0.1, 0.3))
            if push_t < end_t:
                packets.append(SyntheticPacket(
                    timestamp=push_t,
                    is_downlink=True,
                    src_ip=server_ip,
                    dst_ip=client_ip,
                    src_port=server_port,
                    dst_port=client_port,
                    proto="TCP",
                    wire_length=int(rng.integers(140, 240)),
                ))
                packets.append(SyntheticPacket(
                    timestamp=push_t + 0.025,
                    is_downlink=False,
                    src_ip=client_ip,
                    dst_ip=server_ip,
                    src_port=client_port,
                    dst_port=server_port,
                    proto="TCP",
                    wire_length=60,
                    tcp_flags="A",
                ))

    return packets


def generate_other_web_traffic(
    rng: np.random.Generator,
    start_time: float,
    duration_s: float,
    client_ip: str,
    server_ip: str = "111.65.250.11",
    server_port: int = 443,
    client_port: int = 56443,
) -> List[SyntheticPacket]:
    """Simulate Web browsing traffic (TCP 443).

    Đặc trưng:
        - Burst ngắn với nhiều luồng song song (mở tab / click trang mới)
        - pkt_size vừa phải: 400-1300 bytes cho tài nguyên web
        - IAT vừa phải: 20-60ms trong quá trình tải trang
        - Xen kẽ khoảng nghỉ đọc báo 25-50s
    """
    packets: List[SyntheticPacket] = []
    cur_t = start_time
    end_t = start_time + duration_s

    web_servers = ["111.65.250.11", "104.26.12.33", "23.50.62.114", "151.101.65.140"]

    while cur_t < end_t:
        pause_s = float(rng.uniform(25.0, 50.0))
        cur_t += pause_s
        if cur_t >= end_t:
            break

        # Tải trang web: mở 3-5 flow song song
        num_flows = int(rng.integers(3, 6))
        page_t = cur_t

        for f_idx in range(num_flows):
            s_ip = web_servers[f_idx % len(web_servers)]
            f_port = client_port + f_idx * 10
            flow_t = page_t + float(rng.uniform(0.005, 0.050))

            # Client GET request
            packets.append(SyntheticPacket(
                timestamp=flow_t,
                is_downlink=False,
                src_ip=client_ip,
                dst_ip=s_ip,
                src_port=f_port,
                dst_port=server_port,
                proto="TCP",
                wire_length=int(rng.integers(300, 600)),
            ))

            # Server trả về response các packet tài nguyên
            n_res = int(rng.integers(5, 12))
            res_t = flow_t + float(rng.uniform(0.030, 0.080))
            for r_idx in range(n_res):
                if res_t >= end_t:
                    break
                r_size = int(rng.integers(400, 1300))
                packets.append(SyntheticPacket(
                    timestamp=res_t,
                    is_downlink=True,
                    src_ip=s_ip,
                    dst_ip=client_ip,
                    src_port=server_port,
                    dst_port=f_port,
                    proto="TCP",
                    wire_length=r_size,
                ))

                if (r_idx + 1) % 3 == 0:
                    packets.append(SyntheticPacket(
                        timestamp=res_t + 0.002,
                        is_downlink=False,
                        src_ip=client_ip,
                        dst_ip=s_ip,
                        src_port=f_port,
                        dst_port=server_port,
                        proto="TCP",
                        wire_length=int(rng.integers(60, 75)),
                        tcp_flags="A",
                    ))

                res_t += float(rng.uniform(0.020, 0.055))

        cur_t = page_t + 2.5

    return packets


def generate_other_update_traffic(
    rng: np.random.Generator,
    start_time: float,
    duration_s: float,
    client_ip: str,
    server_ip: str = "17.253.144.10",
    server_port: int = 443,
    client_port: int = 57443,
) -> List[SyntheticPacket]:
    """Simulate App/OS Update traffic (tải file lớn, burst ngắn).

    Đặc trưng:
        - Burst lớn ngắn kéo dài 20-35s tải dữ liệu liên tục
        - Tỷ lệ bytes_down / bytes_up rất cao (~30-45x) giống YouTube
        - IAT nhỏ (10-25ms) trong lúc tải file
        - Xen kẽ nhiều đợt tải update trong 1800s để bảo đảm window 30s nào cũng có packet
    """
    packets: List[SyntheticPacket] = []
    cur_t = start_time
    end_t = start_time + duration_s

    while cur_t < end_t:
        # Đợt tải cập nhật kéo dài 20-35 giây
        burst_dur = float(rng.uniform(20.0, 35.0))
        burst_end = min(cur_t + burst_dur, end_t)

        # Trong đợt update: tải dữ liệu liên tục tốc độ cao
        t_pkt = cur_t
        while t_pkt < burst_end:
            down_size = int(rng.integers(1350, 1461))
            packets.append(SyntheticPacket(
                timestamp=t_pkt,
                is_downlink=True,
                src_ip=server_ip,
                dst_ip=client_ip,
                src_port=server_port,
                dst_port=client_port,
                proto="TCP",
                wire_length=down_size,
            ))

            # Mỗi 3 gói down, client gửi 1 TCP ACK 60-70 bytes -> ratio ~35x
            if rng.random() < 0.35:
                packets.append(SyntheticPacket(
                    timestamp=t_pkt + 0.001,
                    is_downlink=False,
                    src_ip=client_ip,
                    dst_ip=server_ip,
                    src_port=client_port,
                    dst_port=server_port,
                    proto="TCP",
                    wire_length=int(rng.integers(60, 70)),
                    tcp_flags="A",
                ))

            t_pkt += float(rng.uniform(0.010, 0.025))

        # Khoảng nghỉ giữa các đợt tải cập nhật (70-120s)
        pause_s = float(rng.uniform(70.0, 120.0))
        pause_end = min(burst_end + pause_s, end_t)

        # Giữ heartbeat thỉnh thoảng trong khoảng pause
        hb_t = burst_end + float(rng.uniform(15.0, 25.0))
        while hb_t < pause_end:
            packets.append(SyntheticPacket(
                timestamp=hb_t,
                is_downlink=False,
                src_ip=client_ip,
                dst_ip=server_ip,
                src_port=client_port,
                dst_port=server_port,
                proto="TCP",
                wire_length=60,
                tcp_flags="A",
            ))
            packets.append(SyntheticPacket(
                timestamp=hb_t + 0.025,
                is_downlink=True,
                src_ip=server_ip,
                dst_ip=client_ip,
                src_port=server_port,
                dst_port=client_port,
                proto="TCP",
                wire_length=60,
                tcp_flags="A",
            ))
            hb_t += float(rng.uniform(20.0, 35.0))

        cur_t = pause_end

    return packets


# ---------------------------------------------------------------------------
# Mapping tên app sang hàm generator tương ứng
# ---------------------------------------------------------------------------

APP_GENERATORS: Dict[str, Callable[..., List[SyntheticPacket]]] = {
    "youtube": generate_youtube_traffic,
    "zalo": generate_zalo_traffic,
    "spotify": generate_spotify_traffic,
    "meet": generate_meet_traffic,
    "chatgpt": generate_chatgpt_traffic,
    "other-idle": generate_other_idle_traffic,
    "other-web": generate_other_web_traffic,
    "other-update": generate_other_update_traffic,
}


# ---------------------------------------------------------------------------
# Chuyển đổi SyntheticPacket sang khung Scapy Ethernet thực
# ---------------------------------------------------------------------------

def packet_to_scapy(
    pkt: SyntheticPacket,
    client_mac: str,
    gateway_mac: str,
) -> Packet:
    """Xây dựng đối tượng Scapy Packet từ SyntheticPacket với wirelen chính xác.

    Đảm bảo:
        - Hướng MAC và IP:
            * Downlink: src=gateway_mac, dst=client_mac, src_ip=server, dst_ip=client
            * Uplink:   src=client_mac, dst=gateway_mac, src_ip=client, dst_ip=server
        - Kích thước frame Ethernet (wirelen) bằng chính xác pkt.wire_length
        - Timestamp được gán vào trường `pkt.time`
    """
    if pkt.is_downlink:
        src_mac = gateway_mac
        dst_mac = client_mac
        src_ip = pkt.src_ip
        dst_ip = pkt.dst_ip
        sport = pkt.src_port
        dport = pkt.dst_port
    else:
        src_mac = client_mac
        dst_mac = gateway_mac
        src_ip = pkt.src_ip
        dst_ip = pkt.dst_ip
        sport = pkt.src_port
        dport = pkt.dst_port

    eth_layer = Ether(src=src_mac, dst=dst_mac)

    if pkt.proto == "TCP":
        # Ethernet(14) + IP(20) + TCP(20) = 54 bytes
        min_hdr_len = 54
        wire_len = max(min_hdr_len, pkt.wire_length)
        payload_len = wire_len - min_hdr_len
        ip_layer = IP(src=src_ip, dst=dst_ip)
        tcp_layer = TCP(sport=sport, dport=dport, flags=pkt.tcp_flags)
        if payload_len > 0:
            scapy_pkt = eth_layer / ip_layer / tcp_layer / Raw(b"\x00" * payload_len)
        else:
            scapy_pkt = eth_layer / ip_layer / tcp_layer
    else:
        # UDP: Ethernet(14) + IP(20) + UDP(8) = 42 bytes
        min_hdr_len = 42
        wire_len = max(min_hdr_len, pkt.wire_length)
        payload_len = wire_len - min_hdr_len
        ip_layer = IP(src=src_ip, dst=dst_ip)
        udp_layer = UDP(sport=sport, dport=dport)
        if payload_len > 0:
            scapy_pkt = eth_layer / ip_layer / udp_layer / Raw(b"\x00" * payload_len)
        else:
            scapy_pkt = eth_layer / ip_layer / udp_layer

    scapy_pkt.time = pkt.timestamp
    return scapy_pkt


# ---------------------------------------------------------------------------
# Tiến trình sinh từng đợt (batch)
# ---------------------------------------------------------------------------

def generate_batch(
    batch_idx: int,
    out_dir: Path,
    seed: int,
    duration_per_app_min: int = 30,
    cooldown_s: int = 45,
    trim_s: int = 15,
    apps: Optional[Sequence[str]] = None,
) -> Tuple[Path, Path]:
    """Sinh một batch hoàn chỉnh gồm file PCAP và file session metadata JSON.

    Args:
        batch_idx: Chỉ số batch (bắt đầu từ 1).
        out_dir: Thư mục lưu kết quả.
        seed: Random seed gốc.
        duration_per_app_min: Thời lượng giả lập mỗi app (phút).
        cooldown_s: Giây nghỉ giữa các app.
        trim_s: Giây cắt đầu/cuối ghi trong session JSON.
        apps: Danh sách app cần sinh (mặc định toàn bộ 8 app).

    Returns:
        Tuple chứa (đường dẫn file pcap, đường dẫn file json).
    """
    app_list = list(apps) if apps else DEFAULT_APPS
    batch_name = f"synthetic_batch{batch_idx}"
    pcap_filename = f"capture_{batch_name}.pcap"
    json_filename = f"session_{batch_name}.json"
    pcap_path = out_dir / pcap_filename
    json_path = out_dir / json_filename

    # Khởi tạo RNG riêng biệt theo từng batch
    batch_seed = int(seed + batch_idx * 1000)
    rng = np.random.default_rng(batch_seed)

    # Cấu hình thiết bị riêng biệt cho từng batch
    # MAC nguồn cố định theo batch (ví dụ simulate iPhone/Android khác nhau)
    client_mac = f"d8:3a:dd:00:{batch_idx:02x}:01"
    gateway_mac = "dc:a6:32:00:00:01"
    client_ip = f"192.168.4.{10 + batch_idx}"

    # Mốc thời gian xuất phát của batch
    # Mốc cơ sở: 2024-10-13 10:00:00 (1728817200 UTC) hoặc tương đương
    base_timestamp = 1728820800.0 + (batch_idx - 1) * 86400.0
    ts_str = datetime.datetime.fromtimestamp(base_timestamp).strftime("%Y%m%d_%H%M%S")

    dur_s = float(duration_per_app_min * 60)
    current_time = base_timestamp
    apps_records: List[Dict[str, Any]] = []
    all_packets: List[SyntheticPacket] = []

    print(f"\n[Batch {batch_idx}] Khởi tạo: {batch_name} (MAC: {client_mac}, IP: {client_ip})")

    for app_name in app_list:
        generator_fn = APP_GENERATORS.get(app_name)
        if generator_fn is None:
            raise ValueError(f"Ứng dụng không được hỗ trợ: {app_name}")

        app_t_start = current_time
        app_t_end = app_t_start + dur_s

        # Gọi generator sinh các SyntheticPacket cho app
        app_pkts = generator_fn(
            rng=rng,
            start_time=app_t_start,
            duration_s=dur_s,
            client_ip=client_ip,
        )

        all_packets.extend(app_pkts)

        # Tính toán thống kê nhanh
        down_bytes = sum(p.wire_length for p in app_pkts if p.is_downlink)
        up_bytes = sum(p.wire_length for p in app_pkts if not p.is_downlink)
        ratio_str = f"{down_bytes / max(1, up_bytes):.1f}x" if up_bytes > 0 else "inf"
        print(f"  -> {app_name:<13}: {len(app_pkts):>5} pkts | Down: {down_bytes/1e6:>5.2f}MB, "
              f"Up: {up_bytes/1e6:>5.2f}MB (Down/Up: {ratio_str:>5})")

        apps_records.append({
            "app": app_name,
            "note": "",
            "t_start": round(app_t_start, 2),
            "t_end": round(app_t_end, 2),
            "duration_s": round(dur_s, 2),
        })

        # Cooldown giữa các ứng dụng
        current_time = app_t_end + float(cooldown_s)

    # 1. Sắp xếp toàn bộ gói tin theo thứ tự thời gian tăng dần
    all_packets.sort(key=lambda p: p.timestamp)

    # 2. Ghi ra file PCAP
    print(f"  Đang ghi {len(all_packets)} gói tin vào PCAP: {pcap_path.name}...")
    t_write_start = time.time()
    pcap_writer = PcapWriter(str(pcap_path), append=False, sync=False)
    for pkt in all_packets:
        scapy_pkt = packet_to_scapy(pkt, client_mac=client_mac, gateway_mac=gateway_mac)
        pcap_writer.write(scapy_pkt)
    pcap_writer.close()
    write_dur = time.time() - t_write_start
    pcap_size_mb = pcap_path.stat().st_size / (1024 * 1024)
    print(f"  ✔ Ghi xong PCAP trong {write_dur:.2f}s ({pcap_size_mb:.2f} MB)")

    # 3. Ghi file session metadata JSON đúng chuẩn
    session_data: Dict[str, Any] = {
        "batch": batch_name,
        "timestamp": ts_str,
        "iface": "synthetic",
        "dry_run": False,
        "duration_per_app_min": duration_per_app_min,
        "trim_s": trim_s,
        "cooldown_s": cooldown_s,
        "pcap_file": pcap_filename,
        "label_file": None,
        "filter": "",
        "apps": apps_records,
    }

    json_path.write_text(json.dumps(session_data, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"  ✔ Ghi metadata: {json_path.name}")

    return pcap_path, json_path


# ---------------------------------------------------------------------------
# CLI Parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Tạo parser dòng lệnh cho công cụ sinh dữ liệu synthetic."""
    parser = argparse.ArgumentParser(
        description="Tạo dữ liệu PCAP và nhãn JSON tổng hợp để kiểm thử pipeline ML.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("captures/synthetic"),
        help="Thư mục lưu trữ các file PCAP và JSON sinh ra.",
    )
    parser.add_argument(
        "--batches",
        type=int,
        default=5,
        help="Số lượng batch cần tạo (mỗi batch là 1 phiên thu độc lập).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Hạt giống sinh số ngẫu nhiên ban đầu.",
    )
    parser.add_argument(
        "--dur",
        type=int,
        default=30,
        help="Thời lượng giả lập mỗi ứng dụng (phút).",
    )
    parser.add_argument(
        "--cooldown",
        type=int,
        default=45,
        help="Thời gian nghỉ (cooldown) giữa các ứng dụng (giây).",
    )
    parser.add_argument(
        "--trim",
        type=int,
        default=15,
        help="Giây cắt đầu/cuối mỗi phiên thu (trim_s trong metadata).",
    )
    parser.add_argument(
        "--apps",
        nargs="+",
        choices=DEFAULT_APPS + ["all"],
        default=None,
        help=f"Danh sách ứng dụng cần sinh. Chọn từ {DEFAULT_APPS} hoặc 'all'.",
    )
    return parser


def main() -> None:
    """Điểm khởi chạy chính của script gen_synthetic."""
    parser = build_parser()
    args = parser.parse_args()

    out_dir: Path = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    apps: Optional[List[str]] = None
    if args.apps:
        if "all" in args.apps:
            apps = DEFAULT_APPS
        else:
            apps = [a for a in args.apps if a in DEFAULT_APPS]

    print("=" * 70)
    print("  EDGE AI TRAFFIC CLASSIFICATION — SYNTHETIC DATA GENERATOR")
    print("=" * 70)
    print(f"Thư mục đầu ra    : {out_dir.resolve()}")
    print(f"Số lượng batches  : {args.batches}")
    print(f"Thời lượng mỗi app: {args.dur} phút")
    print(f"Cooldown giữa app : {args.cooldown} giây")
    print(f"Random seed       : {args.seed}")
    print(f"Ứng dụng giả lập  : {', '.join(apps or DEFAULT_APPS)}")

    t_start = time.time()
    for b in range(1, args.batches + 1):
        generate_batch(
            batch_idx=b,
            out_dir=out_dir,
            seed=args.seed,
            duration_per_app_min=args.dur,
            cooldown_s=args.cooldown,
            trim_s=args.trim,
            apps=apps,
        )

    total_time = time.time() - t_start
    print("\n" + "=" * 70)
    print(f"Hoàn tất tạo {args.batches} batches trong {total_time:.2f} giây!")
    print(f"Vị trí lưu: {out_dir.resolve()}")
    print("=" * 70)


if __name__ == "__main__":
    main()
