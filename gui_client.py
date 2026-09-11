"""gui_client.py —— 分层重构版《基于 Socket 的局域网文件加密传输系统》客户端界面。

架构（业务逻辑 / 界面严格分离）：
  * ClientEngine —— 纯业务逻辑，不依赖 tkinter，可在无头环境被导入与测试。
  * ClientApp    —— tkinter 界面，复用同一条长连接；engine 的回调通过
                    queue.Queue + root.after(100) 轮询转到 UI 线程，规避线程安全 bug。

运行： python gui_client.py
"""
from __future__ import annotations

import os
import queue
import socket
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import config, protocol, session  # noqa: E402

DEFAULT_PASSWORD = "123456"
CHUNK_LABEL = f"{config.CHUNK_SIZE // 1024} KiB"
CIPHER_LABEL = "AES-256-GCM"


# ===========================================================================
# 1. 纯业务逻辑：ClientEngine（无任何 tkinter 依赖）
# ===========================================================================
class ClientEngine:
    """客户端引擎：复用同一条长连接，提供连接 / 上传 / 下载 / 断开。

    公开接口：
        connect(host=None, port=None, password=None) -> bool
        disconnect()
        upload(path) -> Optional[dict]
        download(name, dest_dir=None) -> Optional[dict]
        progress_snapshot() -> dict
        is_connected 属性

    回调（由 UI 注入）：
        on_log(str)
        on_progress(done, total, name)
        on_state(status_str)
    """

    def __init__(self, cfg=None, on_log=None, on_progress=None, on_state=None):
        self.cfg = cfg or config.ClientConfig()
        self.cfg.ensure_dirs()
        self._on_log = on_log or (lambda s: None)
        self._on_progress = on_progress or (lambda d, t, n: None)
        self._on_state = on_state or (lambda s: None)

        self._sock = None
        self._enc_key = None
        self._connected = threading.Event()
        self._lock = threading.Lock()

        self._progress = {"active": False, "done": 0, "total": 1, "name": ""}
        self._progress_lock = threading.Lock()

    @property
    def is_connected(self) -> bool:
        return self._connected.is_set()

    def _emit_state(self) -> None:
        status = f"已连接 {self.cfg.host}:{self.cfg.port}" if self._connected.is_set() else "未连接"
        self._on_state(status)

    def _set_progress(self, done: int, total: int, name: str) -> None:
        with self._progress_lock:
            self._progress = {"active": True, "done": done, "total": total or 1, "name": name}
        self._on_progress(done, total or 1, name)

    def _clear_progress(self) -> None:
        with self._progress_lock:
            self._progress = {"active": False, "done": 0, "total": 1, "name": ""}

    def progress_snapshot(self) -> dict:
        with self._progress_lock:
            return dict(self._progress)

    # ---- 控制接口 ----
    def connect(self, host=None, port=None, password=None) -> bool:
        if self._connected.is_set():
            self._emit_log("已连接，复用长连接")
            return True
        if host is not None:
            self.cfg.host = host
        if port is not None:
            self.cfg.port = port
        if password is not None:
            self.cfg.password = password
        self.cfg.ensure_dirs()
        try:
            sock = socket.create_connection((self.cfg.host, self.cfg.port), timeout=15)
        except OSError as e:
            self._emit_log(f"连接失败：{e}，请确认服务端已启动")
            return False
        try:
            enc_key, _mac = session.client_handshake(sock, self.cfg.password)
        except session.AuthError as e:
            self._emit_log(f"认证失败：{e}")
            sock.close()
            return False
        except (session.SessionError, protocol.ProtocolError) as e:
            self._emit_log(f"握手异常：{e}")
            sock.close()
            return False

        with self._lock:
            self._sock = sock
            self._enc_key = enc_key
        self._connected.set()
        self._emit_log(f"已连接服务端 {self.cfg.host}:{self.cfg.port}，认证通过，长连接可用")
        self._emit_state()
        return True

    def upload(self, path) -> "dict | None":
        if not self._connected.is_set():
            self._emit_log("未连接服务端，无法上传")
            return None
        if not os.path.isfile(path):
            self._emit_log(f"文件不存在：{path}")
            return None
        with self._lock:
            sock, enc_key = self._sock, self._enc_key
        self._set_progress(0, 1, "上传中")
        try:
            res = session.request_upload(
                sock, enc_key, path,
                progress=lambda d, t: self._set_progress(d, t, "上传中"),
            )
            self._emit_log(f"【上传】{os.path.basename(path)} 完成：{res.get('message')}")
            return res
        except Exception as e:  # noqa: BLE001
            self._emit_log(f"上传异常：{e}")
            return None
        finally:
            self._clear_progress()

    def download(self, name, dest_dir=None) -> "dict | None":
        if not self._connected.is_set():
            self._emit_log("未连接服务端，无法下载")
            return None
        name = os.path.basename(str(name).strip())
        if not name:
            self._emit_log("请填写要下载的文件名")
            return None
        with self._lock:
            sock, enc_key = self._sock, self._enc_key
        target = Path(dest_dir) if dest_dir else self.cfg.download_dir
        self._set_progress(0, 1, "下载中")
        try:
            res = session.request_download(
                sock, enc_key, name, target,
                progress=lambda d, t: self._set_progress(d, t, "下载中"),
            )
            self._emit_log(f"【下载】{name}：{res.get('message')}  保存：{res.get('saved_as')}")
            return res
        except Exception as e:  # noqa: BLE001
            self._emit_log(f"下载异常：{e}")
            return None
        finally:
            self._clear_progress()

    def disconnect(self) -> None:
        with self._lock:
            sock = self._sock
            self._sock = None
        if sock is not None:
            try:
                protocol.send_frame(sock, protocol.MessageType.BYE)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass
        self._enc_key = None
        self._connected.clear()
        self._emit_log("已手动断开连接")
        self._emit_state()

    def _emit_log(self, msg: str) -> None:
        self._on_log(msg)


# ===========================================================================
# 2. tkinter 界面（仅在此处使用 tkinter；顶层绝不创建 Tk()，仅在 __main__ 创建）
#    懒加载 tkinter，保证 `import gui_client` 在无头环境也能通过。
# ===========================================================================
def _load_tkinter():
    import tkinter as tk  # noqa: E402
    from tkinter import ttk, scrolledtext, filedialog, messagebox  # noqa: E402
    globals().update(tk=tk, ttk=ttk, scrolledtext=scrolledtext,
                     filedialog=filedialog, messagebox=messagebox)
    return tk


class ClientApp:
    def __init__(self, root, engine: ClientEngine):
        _load_tkinter()  # 懒加载，确保无头 import 不触碰 tkinter
        self.root = root
        self.engine = engine
        self.log_q: "queue.Queue" = queue.Queue()
        self._pending = None
        self._busy = False
        self._last_p = (0.0, 0)
        self._poll_id = None  # 轮询 after 的 id，便于窗口销毁时取消
        engine._on_log = self._enq_log
        engine._on_progress = self._enq_progress
        engine._on_state = self._enq_state
        self._build()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._poll_id = root.after(100, self._poll)

    def _enq_log(self, msg):
        self.log_q.put(("log", msg))

    def _enq_progress(self, done, total, name):
        self.log_q.put(("progress", done, total, name))

    def _enq_state(self, status):
        self.log_q.put(("state", status))

    # ---- 构建界面 ----
    def _build(self):
        root = self.root
        root.title("局域网加密文件传输 - 客户端")
        root.geometry("800x620")
        f = ("微软雅黑", 10)

        self.status_var = tk.StringVar(value="未连接")
        tk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN,
                 anchor="w", font=f, bg="#eef").pack(side=tk.BOTTOM, fill=tk.X)

        # 1. 服务端连接配置区
        fc = tk.LabelFrame(root, text="服务端连接配置区", font=f, bd=2, relief=tk.GROOVE)
        fc.pack(fill=tk.X, padx=10, pady=6)
        tk.Label(fc, text="服务端IP：", font=f).grid(row=0, column=0, padx=5, pady=6)
        self.ip_var = tk.StringVar(value=self.engine.cfg.host)
        tk.Entry(fc, textvariable=self.ip_var, width=40, font=f).grid(row=0, column=1, padx=5)
        tk.Label(fc, text="连接密码：", font=f).grid(row=1, column=0, padx=5, pady=6)
        self.pwd_var = tk.StringVar(value="")
        tk.Entry(fc, textvariable=self.pwd_var, width=40, font=f, show="*").grid(row=1, column=1, padx=5)
        self.conn_btn = tk.Button(fc, text="连接服务端", command=self._on_connect,
                                  width=14, font=f)
        self.conn_btn.grid(row=0, column=2, rowspan=2, padx=8, pady=6, sticky="ns")

        # 2. 待上传文件选择区
        ff = tk.LabelFrame(root, text="待上传文件选择区", font=f, bd=2, relief=tk.GROOVE)
        ff.pack(fill=tk.X, padx=10, pady=6)
        tk.Button(ff, text="浏览选择文件", command=self._on_select,
                  width=14, font=f).grid(row=0, column=0, padx=5, pady=6)
        self.file_label = tk.Label(ff, text="未选择任何文件", width=55, anchor="w", font=f)
        self.file_label.grid(row=0, column=1)

        # 3. 传输操作区
        fo = tk.LabelFrame(root, text="传输操作区", font=f, bd=2, relief=tk.GROOVE)
        fo.pack(fill=tk.X, padx=10, pady=6)
        self.up_btn = tk.Button(fo, text="开始加密上传", command=self._on_upload,
                                width=18, height=2, font=f)
        self.up_btn.grid(row=0, column=0, padx=10, pady=6)
        self.cut_btn = tk.Button(fo, text="手动断开连接", command=self._on_disconnect,
                                 width=18, height=2, font=f, bg="#ff6666")
        self.cut_btn.grid(row=0, column=1, padx=10, pady=6)

        # 4. 下载远端文件区
        fdl = tk.LabelFrame(root, text="下载远端文件区（协议无列目录，请填文件名）",
                            font=f, bd=2, relief=tk.GROOVE)
        fdl.pack(fill=tk.X, padx=10, pady=6)
        tk.Label(fdl, text="文件名：", font=f).grid(row=0, column=0, padx=5, pady=6)
        self.dl_var = tk.StringVar()
        tk.Entry(fdl, textvariable=self.dl_var, width=40, font=f).grid(row=0, column=1, padx=5)
        self.dl_btn = tk.Button(fdl, text="下载远端文件", command=self._on_download,
                                width=16, font=f, bg="#99ccff")
        self.dl_btn.grid(row=0, column=2, padx=8, pady=6)
        self.dldir_label = tk.Label(fdl, text=f"下载目录：{self.engine.cfg.download_dir}",
                                    font=("微软雅黑", 9), anchor="w")
        self.dldir_label.grid(row=1, column=0, columnspan=3, sticky="w", padx=5)

        # 进度条
        pf = tk.LabelFrame(root, text="传输进度", font=f, bd=2, relief=tk.GROOVE)
        pf.pack(fill=tk.X, padx=10, pady=4)
        self.pb = ttk.Progressbar(pf, orient="horizontal", mode="determinate", length=320)
        self.pb.grid(row=0, column=0, padx=6, pady=6, sticky="ew")
        pf.columnconfigure(0, weight=1)
        self.pb_label = tk.Label(pf, text="0.0%  0.00 / 0.00 MB  0.00 MB/s",
                                 font=f, anchor="w")
        self.pb_label.grid(row=0, column=1, padx=6)

        # 运行状态区
        fi = tk.LabelFrame(root, text="运行状态区", font=f, bd=2, relief=tk.GROOVE)
        fi.pack(fill=tk.X, padx=10, pady=4)
        self.info_label = tk.Label(fi, text=self._info_text(), font=("微软雅黑", 9), anchor="w")
        self.info_label.pack(pady=5, fill=tk.X)

        # 传输日志信息区
        fl = tk.LabelFrame(root, text="传输日志信息区", font=f, bd=2, relief=tk.GROOVE)
        fl.pack(fill=tk.BOTH, expand=True, padx=10, pady=8)
        self.log = scrolledtext.ScrolledText(fl, font=("Consolas", 9))
        self.log.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)

    def _info_text(self):
        return (f"加密算法：{CIPHER_LABEL}  分块大小：{CHUNK_LABEL}  "
                f"口令：{self.engine.cfg.password}（生产环境请改口令）")

    # ---- 按钮回调 ----
    def _on_connect(self):
        host = self.ip_var.get().strip()
        pwd = self.pwd_var.get()
        if not pwd:
            self._enq_log("请输入连接密码！")
            return
        self.engine.connect(host=host, password=pwd)

    def _on_select(self):
        path = filedialog.askopenfilename()
        if path:
            self._pending = path
            self.file_label.config(text=f"待上传：{os.path.basename(path)}")
            self._enq_log(f"待上传文件：{path}")

    def _on_upload(self):
        if self._busy:
            return
        if not self._pending:
            self._enq_log("请先选择要上传的文件！")
            return
        if not self.engine.is_connected:
            self._enq_log("请先连接服务端！")
            return
        self._busy = True
        self._set_buttons(False)
        path = self._pending
        threading.Thread(target=self._upload_worker, args=(path,), daemon=True).start()

    def _upload_worker(self, path):
        self.engine.upload(path)
        self._busy = False
        self.root.after(0, lambda: self._set_buttons(True))

    def _on_download(self):
        if self._busy:
            return
        if not self.engine.is_connected:
            self._enq_log("请先连接服务端！")
            return
        name = self.dl_var.get().strip()
        if not name:
            self._enq_log("请输入要下载的文件名！")
            return
        self._busy = True
        self._set_buttons(False)
        threading.Thread(target=self._download_worker, args=(name,), daemon=True).start()

    def _download_worker(self, name):
        self.engine.download(name)
        self._busy = False
        self.root.after(0, lambda: self._set_buttons(True))

    def _on_disconnect(self):
        self.engine.disconnect()

    def _set_buttons(self, enabled):
        state = tk.NORMAL if enabled else tk.DISABLED
        self.up_btn.config(state=state)
        self.dl_btn.config(state=state)

    # ---- 窗口关闭：先取消轮询再断开引擎 ----
    def _on_close(self):
        if self._poll_id is not None:
            try:
                self.root.after_cancel(self._poll_id)
            except Exception:  # noqa: BLE001
                pass
            self._poll_id = None
        self.engine.disconnect()
        self.root.destroy()

    # ---- 队列轮询（UI 线程） ----
    def _poll(self):
        if not self.root.winfo_exists():
            return
        try:
            while True:
                item = self.log_q.get_nowait()
                kind = item[0]
                if kind == "log":
                    self.log.insert(tk.END, item[1] + "\n")
                    self.log.see(tk.END)
                elif kind == "progress":
                    self._update_progress(item[1], item[2], item[3])
                elif kind == "state":
                    self._update_state(item[1])
        except queue.Empty:
            pass
        self._poll_id = self.root.after(100, self._poll)

    def _update_progress(self, done, total, name):
        total = total or 1
        pct = done / total * 100.0
        self.pb["value"] = pct
        done_mb = done / (1024 * 1024)
        total_mb = total / (1024 * 1024)
        now = time.monotonic()
        last_t, last_d = self._last_p
        rate = (done - last_d) / (now - last_t) / (1024 * 1024) if (last_t and now - last_t > 0) else 0.0
        self._last_p = (now, done)
        self.pb_label.config(text=f"{pct:.1f}%  {done_mb:.2f} / {total_mb:.2f} MB  {rate:.2f} MB/s  {name}")

    def _update_state(self, status):
        self.status_var.set(f"状态：{status}  |  {CIPHER_LABEL}  |  分块 {CHUNK_LABEL}")
        self.info_label.config(text=self._info_text())


if __name__ == "__main__":
    r = tk.Tk()
    eng = ClientEngine()
    ClientApp(r, eng)
    r.mainloop()
