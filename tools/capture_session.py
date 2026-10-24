#!/usr/bin/env python3
"""capture_session.py — Chạy trên Raspberry Pi để thu traffic và ghi nhãn START/END.

Yêu cầu hệ thống:
    sudo apt install tcpdump ethtool ntp
    sudo python3 capture_session.py --batch batch1 --iface wlan0 --dur 30

Ví dụ dry-run (5 phút/app):
    sudo python3 capture_session.py --batch dryrun --iface wlan0 --dur 5 --dry-run

Output:
    captures/<batch>/capture_<batch>_<timestamp>.pcap   — file PCAP (tcpdump)
    captures/<batch>/labels_<batch>_<timestamp>.jsonl   — nhãn START/END từng app
    captures/<batch>/session_<batch>_<timestamp>.json   — summary để dataset_builder đọc
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import random
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Danh sách app mặc định và kịch bản
# ---------------------------------------------------------------------------

DEFAULT_APPS = [
    "youtube",
    "zalo",
    "spotify",
    "meet",
    "chatgpt",
    "other-idle",
    "other-web",
    "other-update",
]

APP_SCENARIOS = {
    "youtube":      "Xem video liên tục. Đổi video + chất lượng (360p/720p/1080p) mỗi 10 phút.",
    "zalo":         "Gửi tin nhắn văn bản ~2 phút/lần, gửi ảnh ~5 phút/lần, 1 cuộc gọi thoại nếu có người.",
    "spotify":      "Nghe nhạc playlist liên tục (không tạm dừng). Thử podcast nếu muốn.",
    "meet":         "Gọi video 2 chiều với người thứ hai. KHÔNG gọi 1 chiều (thiếu download).",
    "chatgpt":      "Đặt câu hỏi dài → nhận streaming response. Xen lẫn câu hỏi ngắn. Ghi rõ: dùng WEB hay APP?",
    "other-idle":   "Để màn hình bật, không tương tác. Chấp nhận push notification nền.",
    "other-web":    "Duyệt nhiều trang khác nhau (báo, Wikipedia, GitHub...). KHÔNG mở ChatGPT.",
    "other-update": "Chủ động tải cập nhật ứng dụng từ App Store / Play Store. Lên kế hoạch trước.",
}

# ---------------------------------------------------------------------------
# Màu terminal (ANSI)
# ---------------------------------------------------------------------------

class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    RED    = "\033[91m"
    CYAN   = "\033[96m"
    GRAY   = "\033[90m"

def print_header(text: str) -> None:
    width = 60
    print(f"\n{C.BOLD}{C.CYAN}{'═' * width}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  {text}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}{'═' * width}{C.RESET}\n")

def print_ok(text: str)   -> None: print(f"  {C.GREEN}✔{C.RESET}  {text}")
def print_warn(text: str) -> None: print(f"  {C.YELLOW}⚠{C.RESET}  {text}")
def print_err(text: str)  -> None: print(f"  {C.RED}✘{C.RESET}  {text}")
def print_info(text: str) -> None: print(f"  {C.GRAY}→{C.RESET}  {text}")


# ---------------------------------------------------------------------------
# Kiểm tra môi trường Pi
# ---------------------------------------------------------------------------

def check_root() -> None:
    if os.geteuid() != 0:
        print_err("Cần chạy với sudo: sudo python3 capture_session.py ...")
        sys.exit(1)

def check_time_sync(max_offset_s: float = 5.0) -> bool:
    """Kiểm tra đồng bộ NTP. Pi không có RTC pin nên giờ có thể sai sau khi boot."""
    print_header("Kiểm Tra Đồng Hồ Pi")
    try:
        out = subprocess.check_output(
            ["timedatectl", "show", "--property=NTPSynchronized,TimeUSec"],
            text=True,
        )
        synced = "NTPSynchronized=yes" in out
        if synced:
            print_ok(f"NTP đã đồng bộ.")
        else:
            print_warn("NTP chưa đồng bộ! Đang thử ntpdate...")
            subprocess.run(["ntpdate", "-u", "pool.ntp.org"], timeout=15)
            print_ok("Đã đồng bộ giờ qua ntpdate.")
        return True
    except Exception as exc:
        print_warn(f"Không kiểm tra được NTP: {exc}")
        answer = input("  Tiếp tục không? [y/N] ").strip().lower()
        return answer == "y"

def disable_offload(iface: str) -> None:
    """Tắt GRO/GSO/TSO để tcpdump thấy gói đúng kích thước thật (không lớn hơn MTU)."""
    print_header(f"Tắt Offload Trên {iface}")
    if not shutil.which("ethtool"):
        print_warn("ethtool không tìm thấy, bỏ qua. Cài bằng: sudo apt install ethtool")
        return
    for feature in ("gro", "gso", "tso"):
        try:
            subprocess.run(
                ["ethtool", "-K", iface, feature, "off"],
                check=True, capture_output=True,
            )
            print_ok(f"{feature.upper()} off trên {iface}")
        except subprocess.CalledProcessError as e:
            # Một số interface không hỗ trợ tất cả offload — không nghiêm trọng
            print_warn(f"Không tắt được {feature} trên {iface}: {e.stderr.decode().strip()}")

def check_iface(iface: str) -> None:
    print_header(f"Kiểm Tra Interface {iface}")
    result = subprocess.run(["ip", "link", "show", iface], capture_output=True, text=True)
    if result.returncode != 0:
        print_err(f"Interface '{iface}' không tồn tại.")
        available = subprocess.check_output(["ip", "-br", "link", "show"], text=True)
        print_info("Interface hiện có:\n" + available)
        sys.exit(1)
    if "UP" in result.stdout:
        print_ok(f"{iface} UP")
    else:
        print_warn(f"{iface} không ở trạng thái UP — traffic có thể không đi qua.")


# ---------------------------------------------------------------------------
# Quản lý tcpdump
# ---------------------------------------------------------------------------

class TcpdumpProcess:
    """Bọc tiến trình tcpdump nền."""

    def __init__(self, iface: str, pcap_path: Path, filter_expr: str = "") -> None:
        self.iface = iface
        self.pcap_path = pcap_path
        self.filter_expr = filter_expr
        self._proc: Optional[subprocess.Popen] = None

    def start(self) -> None:
        cmd = [
            "tcpdump",
            "-i", self.iface,
            "-s", "128",          # Chỉ lưu 128 byte header, không lưu payload
            "-w", str(self.pcap_path),
            "--immediate-mode",
        ]
        if self.filter_expr:
            cmd += self.filter_expr.split()
        print_info(f"tcpdump: {' '.join(cmd)}")
        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        time.sleep(0.5)
        if self._proc.poll() is not None:
            err = self._proc.stderr.read().decode()
            print_err(f"tcpdump khởi động thất bại: {err}")
            sys.exit(1)
        print_ok(f"tcpdump đang chạy (PID {self._proc.pid}), ghi vào {self.pcap_path.name}")

    def stop(self) -> None:
        if self._proc and self._proc.poll() is None:
            self._proc.send_signal(signal.SIGTERM)
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        print_ok("tcpdump đã dừng.")


# ---------------------------------------------------------------------------
# Ghi nhãn (JSONL)
# ---------------------------------------------------------------------------

class LabelLogger:
    """Ghi nhãn START/END từng app vào file JSONL theo đồng hồ Pi."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._fh = path.open("a", buffering=1)  # Line-buffered

    def _write(self, event: str, app: str, note: str = "") -> float:
        ts = time.time()
        dt = datetime.datetime.fromtimestamp(ts).isoformat(timespec="milliseconds")
        record = {"event": event, "app": app, "epoch": ts, "datetime": dt, "note": note}
        self._fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        return ts

    def start(self, app: str, note: str = "") -> float:
        return self._write("START", app, note)

    def end(self, app: str, note: str = "") -> float:
        return self._write("END", app, note)

    def close(self) -> None:
        self._fh.close()


# ---------------------------------------------------------------------------
# Đếm ngược terminal
# ---------------------------------------------------------------------------

def countdown(seconds: int, message: str) -> None:
    """Hiện thanh đếm ngược inline, không xóa màn hình."""
    for remaining in range(seconds, 0, -1):
        bar_len = 30
        filled = int(bar_len * (seconds - remaining) / seconds)
        bar = "█" * filled + "░" * (bar_len - filled)
        print(
            f"\r  {C.YELLOW}{message}{C.RESET}  [{bar}] {remaining:3d}s ",
            end="", flush=True,
        )
        time.sleep(1)
    print(f"\r  {C.GREEN}✔ {message} xong!{C.RESET}" + " " * 30)


def wait_for_app_duration(dur_minutes: int, app: str) -> None:
    """Đếm ngược trong khi user đang dùng app."""
    total_sec = dur_minutes * 60
    print(f"\n  {C.BOLD}Đang thu '{app}' — {dur_minutes} phút{C.RESET}")
    for remaining in range(total_sec, 0, -1):
        m, s = divmod(remaining, 60)
        bar_len = 40
        filled = int(bar_len * (total_sec - remaining) / total_sec)
        bar = "█" * filled + "░" * (bar_len - filled)
        print(
            f"\r  [{bar}] {m:02d}:{s:02d} còn lại ",
            end="", flush=True,
        )
        time.sleep(1)
    print(f"\r  {C.GREEN}✔ Xong '{app}'!{C.RESET}" + " " * 50)


# ---------------------------------------------------------------------------
# Luồng chính một đợt thu
# ---------------------------------------------------------------------------

def run_session(args: argparse.Namespace) -> None:
    check_root()

    # --- Chuẩn bị thư mục output ---
    ts_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = Path("captures") / args.batch
    out_dir.mkdir(parents=True, exist_ok=True)
    pcap_path   = out_dir / f"capture_{args.batch}_{ts_str}.pcap"
    label_path  = out_dir / f"labels_{args.batch}_{ts_str}.jsonl"
    summary_path = out_dir / f"session_{args.batch}_{ts_str}.json"

    # --- Kiểm tra hạ tầng ---
    check_iface(args.iface)
    if not check_time_sync():
        sys.exit(1)
    disable_offload(args.iface)

    # --- Chọn danh sách app ---
    apps = list(args.apps) if args.apps else list(DEFAULT_APPS)
    if args.shuffle:
        random.shuffle(apps)
        print_info(f"Thứ tự app (đã shuffle): {' → '.join(apps)}")
    else:
        print_info(f"Thứ tự app: {' → '.join(apps)}")

    dur = args.dur  # phút mỗi app
    cooldown = args.cooldown  # giây nghỉ giữa các app
    trim_s = args.trim  # giây cắt đầu/cuối khi build dataset (ghi vào summary)

    # --- Xác nhận trước khi bắt đầu ---
    print_header("Xác Nhận Thông Số")
    print_info(f"Batch:           {args.batch}")
    print_info(f"Interface:       {args.iface}")
    print_info(f"PCAP output:     {pcap_path}")
    print_info(f"Thời gian/app:   {dur} phút")
    print_info(f"Nghỉ giữa app:   {cooldown} giây")
    print_info(f"Cắt đầu/cuối:    {trim_s} giây (áp dụng khi build dataset)")
    print_info(f"Dry run:         {'CÓ (5 phút/app)' if args.dry_run else 'KHÔNG'}")
    print_info(f"Tổng thời gian ước tính: "
               f"{len(apps) * dur + (len(apps)-1) * cooldown // 60} phút")
    print()
    input(f"  {C.BOLD}Nhấn Enter để bắt đầu...{C.RESET} ")

    # --- Khởi động tcpdump ---
    filter_expr = args.filter or ""
    tcpdump = TcpdumpProcess(args.iface, pcap_path, filter_expr)
    tcpdump.start()

    logger = LabelLogger(label_path)
    session_records = []

    # --- Vòng lặp từng app ---
    for idx, app in enumerate(apps):
        print_header(f"APP {idx+1}/{len(apps)}: {app.upper()}")

        # Hiện kịch bản
        scenario = APP_SCENARIOS.get(app, "(Không có kịch bản mô tả)")
        print(f"  {C.BOLD}Kịch bản:{C.RESET} {scenario}\n")

        # Ghi chú đặc biệt nếu cần
        note = ""
        if app == "chatgpt":
            note = input("  ChatGPT chạy bằng [w]eb browser hay [a]pp native? ").strip()
            note = "web" if note.startswith("w") else "app"
            print_info(f"Ghi nhận: chatgpt/{note}")
        if app == "meet":
            print_warn("Đảm bảo có người ở đầu bên kia để có traffic 2 chiều!")
            input("  Nhấn Enter khi sẵn sàng... ")

        # Đếm ngược chuẩn bị (tắt app cũ)
        if idx > 0:
            print()
            print_warn(f"Tắt hoàn toàn app trước, rồi mở '{app}'.")
            countdown(10, "Chuẩn bị")

        # Chờ user sẵn sàng
        input(f"\n  {C.BOLD}Mở '{app}' rồi nhấn Enter để bắt đầu thu...{C.RESET} ")

        # Ghi START
        t_start = logger.start(app, note)
        print_ok(f"[START] {app}  @ {datetime.datetime.fromtimestamp(t_start).strftime('%H:%M:%S')}")

        # Thu trong dur phút
        actual_dur = 5 if args.dry_run else dur
        wait_for_app_duration(actual_dur, app)

        # Ghi END
        t_end = logger.end(app, note)
        print_ok(f"[END]   {app}  @ {datetime.datetime.fromtimestamp(t_end).strftime('%H:%M:%S')}")

        session_records.append({
            "app": app,
            "note": note,
            "t_start": t_start,
            "t_end": t_end,
            "duration_s": t_end - t_start,
        })

        # Nghỉ bắt buộc giữa các app (không áp dụng cho app cuối)
        if idx < len(apps) - 1:
            print()
            countdown(cooldown, f"Nghỉ {cooldown}s trước app tiếp theo")

    # --- Dừng tcpdump ---
    print_header("Kết Thúc Đợt Thu")
    tcpdump.stop()
    logger.close()

    # --- Ghi summary JSON ---
    summary = {
        "batch": args.batch,
        "timestamp": ts_str,
        "iface": args.iface,
        "dry_run": args.dry_run,
        "duration_per_app_min": 5 if args.dry_run else dur,
        "trim_s": trim_s,
        "cooldown_s": cooldown,
        "pcap_file": pcap_path.name,
        "label_file": label_path.name,
        "filter": filter_expr,
        "apps": session_records,
    }
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False))

    # --- Báo cáo cuối ---
    print_ok(f"PCAP:    {pcap_path}  ({pcap_path.stat().st_size / 1e6:.1f} MB)")
    print_ok(f"Labels:  {label_path}")
    print_ok(f"Summary: {summary_path}")
    print()
    print(f"  {C.BOLD}{C.GREEN}Đợt thu '{args.batch}' hoàn tất!{C.RESET}")
    print(f"  {C.GRAY}Bước tiếp theo: python3 -m ml.dataset_builder "
          f"--session {summary_path}{C.RESET}\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Thu traffic và ghi nhãn START/END trên Raspberry Pi.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ví dụ:
  # Dry run (5 phút/app, kiểm tra pipeline):
  sudo python3 tools/capture_session.py --batch dryrun --iface wlan0 --dry-run

  # Thu thật (30 phút/app, shuffle thứ tự):
  sudo python3 tools/capture_session.py --batch batch1 --iface wlan0 --dur 30 --shuffle

  # Chỉ thu 3 app, lọc theo IP thiết bị:
  sudo python3 tools/capture_session.py --batch batch2 --iface wlan0 \\
      --apps youtube zalo chatgpt \\
      --filter "host 192.168.4.2"
        """,
    )
    p.add_argument("--batch",    required=True,
                   help="Tên đợt thu, VD: batch1, dryrun, batch_iphone_4g")
    p.add_argument("--iface",    default="wlan0",
                   help="Interface phía LAN của Pi (default: wlan0)")
    p.add_argument("--dur",      type=int, default=30,
                   help="Phút thu mỗi app (default: 30). Bị ghi đè bởi --dry-run")
    p.add_argument("--cooldown", type=int, default=45,
                   help="Giây nghỉ bắt buộc giữa các app (default: 45)")
    p.add_argument("--trim",     type=int, default=15,
                   help="Giây cắt đầu/cuối mỗi phiên khi build dataset (default: 15)")
    p.add_argument("--apps",     nargs="+", choices=DEFAULT_APPS + ["all"], default=None,
                   help=f"Danh sách app cần thu (default: tất cả). Chọn từ: {DEFAULT_APPS}")
    p.add_argument("--shuffle",  action="store_true",
                   help="Ngẫu nhiên hóa thứ tự app (khuyên dùng giữa các đợt)")
    p.add_argument("--filter",   default="",
                   help="BPF filter cho tcpdump, VD: 'host 192.168.4.2 or host 192.168.4.3'")
    p.add_argument("--dry-run",  action="store_true",
                   help="Thu 5 phút/app thay vì --dur, dùng để test pipeline")
    return p


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()

    # Nếu chọn "all" hoặc không chọn gì → dùng tất cả
    if args.apps and "all" in args.apps:
        args.apps = DEFAULT_APPS

    try:
        run_session(args)
    except KeyboardInterrupt:
        print(f"\n\n  {C.RED}Bị ngắt bởi Ctrl+C. File PCAP vẫn được lưu.{C.RESET}\n")
        sys.exit(130)
