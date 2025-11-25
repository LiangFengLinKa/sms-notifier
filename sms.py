from __future__ import annotations
from win11toast import toast as win_toast

import winreg
import sys
import socket
import re
import pyperclip
import logging
import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from queue import Queue, Empty
from typing import Dict, Optional

from flask import Flask, jsonify, request

try:
    from win10toast import ToastNotifier  # type: ignore
except Exception:  # pragma: no cover - optional dependency for non-Windows
    ToastNotifier = None  # type: ignore

try:
    import tkinter as tk
    from tkinter import ttk
except Exception as exc:  # pragma: no cover - UI import guard
    raise SystemExit(
        "Tkinter is required to run the visual UI. Install Python with Tk support."
    ) from exc

app = Flask(__name__)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

CODE_EXPIRE_TIME = int(os.getenv("CODE_EXPIRE_TIME", "300"))
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "5000"))

toaster: Optional[ToastNotifier]
if ToastNotifier:
    try:
        toaster = ToastNotifier()
    except Exception:
        toaster = None
else:
    toaster = None


def now_timestamp() -> int:
    return int(time.time())


def human_time(ts: int) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def get_local_ip() -> str:
    """
    尝试自动获取局域网 IPv4 地址，例如 192.168.x.x。
    失败时退回 127.0.0.1。
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # 不用连接到互联网
        ip = s.getsockname()[0]    # 获取本机的局域网 IP 地址
        s.close()
        return ip
    except Exception as exc:
        logger.warning("自动获取本机 IP 失败，使用 127.0.0.1: %s", exc)
        return "127.0.0.1"


@dataclass
class CodeRecord:
    code: str
    timestamp: int
    ip: str

    @property
    def expires_in(self) -> int:
        return max(0, CODE_EXPIRE_TIME - (now_timestamp() - self.timestamp))

    @property
    def timestamp_str(self) -> str:
        return human_time(self.timestamp)


def extract_code(raw: str) -> Optional[str]:
    """
    从原始内容里提取 4~8 位数字验证码。
    如果本身就是纯数字，就原样返回。
    """
    raw = raw.strip()
    if raw.isdigit():
        return raw

    m = re.search(r"\d{4,8}", raw)
    if m:
        return m.group(0)
    return None


verification_codes: Dict[str, CodeRecord] = {}
ui_queue: "Queue[CodeRecord]" = Queue()
_codes_lock = threading.Lock()


def _cleanup_expired() -> None:
    now = now_timestamp()
    expired_keys = [key for key, data in verification_codes.items() if now - data.timestamp > CODE_EXPIRE_TIME]
    for key in expired_keys:
        del verification_codes[key]


def _show_toast(code: str, client_ip: str) -> None:
    """
    使用 win11toast 在 Win10/11 上弹出系统通知
    """
    message = (
        f"验证码: {code}\n"
        f"来源IP: {client_ip}\n"
        f"接收时间: {human_time(now_timestamp())}\n"
        f"有效期: {CODE_EXPIRE_TIME}秒"
    )

    try:
        # 标题 + 正文，duration 可以是 'short' 或 'long'
        win_toast("短信验证码提醒", message, duration="short")
        logger.info("已调用 win11toast 发送系统通知。")
    except Exception as exc:
        logger.warning("显示系统通知失败（win11toast）: %s", exc)


@app.route("/api/code", methods=["POST"])
def receive_code():
    data = request.get_json(silent=True) or {}

    raw = data.get("code")
    if not raw:
        return jsonify({"status": "error", "message": "Invalid request"}), 400

    # 先从原始内容里提取真正的数字验证码
    code = extract_code(str(raw))
    if not code:
        logger.warning("未在内容中找到数字验证码: %r", raw)
        return jsonify({"status": "error", "message": "no numeric code found"}), 400

    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")
    ts = now_timestamp()
    record = CodeRecord(code=code, timestamp=ts, ip=client_ip)

    # 存储记录
    with _codes_lock:
        verification_codes[client_ip] = record
        _cleanup_expired()

    # 推给 UI 线程
    ui_queue.put(record)

    logger.info("收到验证码 - 来源IP: %s, 原始内容: %r, 提取结果: %s", client_ip, raw, code)

    # 复制到剪贴板
    try:
        pyperclip.copy(code)
        logger.info("验证码已复制到剪贴板: %s", code)
    except Exception as exc:
        logger.warning("复制到剪贴板失败: %s", exc)

    # 发送 toast 通知（用提取后的纯数字）
    _show_toast(code, client_ip)

    return jsonify({"status": "success"})


@app.route("/api/codes", methods=["GET"])
def get_codes():
    with _codes_lock:
        _cleanup_expired()
        codes = list(verification_codes.values())
    return jsonify(
        {
            "codes": [
                {"code": c.code, "timestamp": c.timestamp, "ip": c.ip, "expires_in": c.expires_in}
                for c in codes
            ]
        }
    )


class CodeUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("短信验证码提醒")
        self.root.geometry("520x400")  # 增加高度，给按钮留空间
        self.root.resizable(False, False)

        # 创建表格显示验证码记录
        self.tree = ttk.Treeview(
            root,
            columns=("code", "time", "ip", "ttl"),
            show="headings",
            height=12,
        )
        self.tree.heading("code", text="验证码")
        self.tree.heading("time", text="接收时间")
        self.tree.heading("ip", text="来源IP")
        self.tree.heading("ttl", text="剩余秒数")

        self.tree.column("code", width=80, anchor=tk.CENTER)
        self.tree.column("time", width=170, anchor=tk.CENTER)
        self.tree.column("ip", width=140, anchor=tk.CENTER)
        self.tree.column("ttl", width=90, anchor=tk.CENTER)

        self.tree.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

        # 显示本机 IP + 监听信息
        local_ip = get_local_ip()
        self.status = tk.StringVar(
            value=(
                f"服务运行中：本机 IP {local_ip}:{PORT} "
                f"(监听 {HOST}:{PORT})，有效期 {CODE_EXPIRE_TIME} 秒"
            )
        )
        ttk.Label(root, textvariable=self.status).pack(anchor="w", padx=12, pady=(0, 10))

        logger.info("推测本机局域网 IP：%s（手机里填 http://%s:%s）", local_ip, local_ip, PORT)

        # 添加控制开机启动的按钮
        self.startup_button = ttk.Button(
            root,
            text="开启开机启动",
            command=self.toggle_startup  # 绑定到 toggle_startup 方法
        )
        self.startup_button.pack(padx=12, pady=10)

        self._refresh_ui()

    def toggle_startup(self):
        """
        切换开机启动功能：开启或关闭。
        """
        exe_path = sys.executable
        if self.is_startup_enabled():
            self.remove_from_startup()
            self.startup_button.config(text="开启开机启动")
            logger.info("已从开机启动项移除")
        else:
            self.add_to_startup(exe_path)
            self.startup_button.config(text="关闭开机启动")
            logger.info("已添加到开机启动项")

    def is_startup_enabled(self) -> bool:
        """检查当前是否已启用开机启动"""
        reg_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_READ)
            value, _ = winreg.QueryValueEx(key, "sms_notifier")
            winreg.CloseKey(key)
            return value != ""
        except Exception:
            return False

    def add_to_startup(self, exe_path: str) -> None:
        """将程序添加到开机启动项"""
        try:
            reg_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_WRITE)
            winreg.SetValueEx(key, "sms_notifier", 0, winreg.REG_SZ, exe_path)
            winreg.CloseKey(key)
        except Exception as e:
            logger.error(f"添加开机启动失败: {e}")

    def remove_from_startup(self) -> None:
        """从开机启动项删除程序"""
        try:
            reg_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_WRITE)
            winreg.DeleteValue(key, "sms_notifier")
            winreg.CloseKey(key)
        except Exception as e:
            logger.error(f"删除开机启动失败: {e}")

    def add_code(self, record: CodeRecord) -> None:
        self.tree.insert(
            "",
            0,
            values=(record.code, record.timestamp_str, record.ip, record.expires_in),
        )
        # Keep only the latest 50 entries to avoid bloating the widget
        if len(self.tree.get_children()) > 50:
            for item in self.tree.get_children()[50:]:
                self.tree.delete(item)

    def refresh_ttl(self) -> None:
        for item in self.tree.get_children():
            _, ts, ip, _ = self.tree.item(item, "values")
            try:
                ts_int = int(datetime.strptime(ts, "%Y-%m-%d %H:%M:%S").timestamp())
            except ValueError:
                continue
            ttl = max(0, CODE_EXPIRE_TIME - (now_timestamp() - ts_int))
            self.tree.set(item, column="ttl", value=str(ttl))

    def _refresh_ui(self) -> None:
        self.refresh_ttl()
        try:
            while True:
                record = ui_queue.get_nowait()
                self.add_code(record)
        except Empty:
            pass
        self.root.after(1000, self._refresh_ui)



    def add_code(self, record: CodeRecord) -> None:
        self.tree.insert(
            "",
            0,
            values=(record.code, record.timestamp_str, record.ip, record.expires_in),
        )
        # Keep only the latest 50 entries to avoid bloating the widget
        if len(self.tree.get_children()) > 50:
            for item in self.tree.get_children()[50:]:
                self.tree.delete(item)

    def refresh_ttl(self) -> None:
        for item in self.tree.get_children():
            _, ts, ip, _ = self.tree.item(item, "values")
            try:
                ts_int = int(datetime.strptime(ts, "%Y-%m-%d %H:%M:%S").timestamp())
            except ValueError:
                continue
            ttl = max(0, CODE_EXPIRE_TIME - (now_timestamp() - ts_int))
            self.tree.set(item, column="ttl", value=str(ttl))

    def _refresh_ui(self) -> None:
        self.refresh_ttl()
        try:
            while True:
                record = ui_queue.get_nowait()
                self.add_code(record)
        except Empty:
            pass
        self.root.after(1000, self._refresh_ui)


def _start_flask() -> None:
    app.run(host=HOST, port=PORT, use_reloader=False, threaded=True)


def main() -> None:
    flask_thread = threading.Thread(target=_start_flask, daemon=True)
    flask_thread.start()
    logger.info("Flask 接口已启动：http://%s:%s", HOST, PORT)

    root = tk.Tk()
    ui = CodeUI(root)
    root.mainloop()
    logger.info("UI 已关闭，退出程序")


if __name__ == "__main__":
    main()
