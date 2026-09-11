"""gui_server.py —— 分层重构版《基于 Socket 的局域网文件加密传输系统》服务端界面。

架构（业务逻辑 / 界面严格分离）：
  * ServerEngine —— 纯业务逻辑，不依赖 tkinter，可在无头环境被导入与测试。
  * ServerApp    —— tkinter 界面，只调用 engine 的方法；engine 的回调通过
                    queue.Queue + root.after(100) 轮询转到 UI 线程，规避经典线程安全 bug。

运行： python gui_server.py
"""
from __future__ import annotations

import os
import queue
import socket
import sys
import threading
import time
from pathlib import Path

# 确保从本目录导入 app 包（避免上级遗留 inspect.py 遮蔽标准库）
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import config, protocol, session  # noqa: E402

# 默认演示口令（教学用，生产环境请改）
DEFAULT_PASSWORD = "123456"
CHUNK_LABEL = f"{config.CHUNK_SIZE // 1024} KiB"
CIPHER_LABEL = "AES-256-GCM"


# ===========================================================================
# 1. 纯业务逻辑：ServerEngine（无任何 tkinter 依赖）
# ===========================================================================
class ServerEngine:
    """服务端引擎：持有 listener 与当前连接，后台线程处理握手与请求分派。

    公开接口：
        start(host=None, port=None)
        stop()
        disconnect_current_client()
        prepare_share(src_path) -> Optional[str]
        upload_progress_snapshot() -> dict
        is_running / client_addr 属性

    回调（由 UI 注入，线程安全由调用方保证）：
        on_log(str)
        on_progress(done, total, name)
        on_state(status_str)
    """

    def __init__(self, cfg=None, on_log=None, on_progress=None, on_state=None):
        self.cfg = cfg or config.ServerConfig()
        self.cfg.ensure_dirs()
        self._on_log = on_log or (lambda s: None)
        self._on_progress = on_progress or (lambda d, t, n: None)
        self._on_state = on_state or (lambda s: None)

        self._listener = None
        self._conn = None
        self._conn_addr = None
        self._enc_key = None
        self._conn_lock = threading.Lock()
        self._running = threading.Event()
        self._accept_thread = None

        self._progress = {"active": False, "done": 0, "total": 1, "name": ""}
        self._progress_lock = threading.Lock()

    # ---- 只读属性 ----
    @property
    def is_running(self) -> bool:
        return self._running.is_set()

    @property
    def client_addr(self):
        return self._conn_addr

    # ---- 进度 / 状态上报 ----
    def _emit_state(self) -> None:
        if not self._running.is_set():
            status = "未启动"
        elif self._conn is not None:
            status = f"已连接 {self._conn_addr}"
        else:
            status = f"监听中 {self.cfg.host}:{self.cfg.port}"
        self._on_state(status)

    def _set_progress(self, done: int, total: int, name: str) -> None:
        with self._progress_lock:
            self._progress = {"active": True, "done": done, "total": total or 1, "name": name}
        self._on_progress(done, total or 1, name)

    def _clear_progress(self) -> None:
        with self._progress_lock:
            self._progress = {"active": False, "done": 0, "total": 1, "name": ""}

    def upload_progress_snapshot(self) -> dict:
        """当前传输进度快照（供 UI 或测试读取）。"""
        with self._progress_lock:
            return dict(self._progress)

    # ---- 控制接口 ----
    def start(self, host=None, port=None) -> None:
        if self._running.is_set():
            self._emit_log("服务端已在运行")
            return
        if host is not None:
            self.cfg.host = host
        if port is not None:
            self.cfg.port = port
        self.cfg.ensure_dirs()
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((self.cfg.host, self.cfg.port))
        self._listener.listen(5)
        self.cfg.port = self._listener.getsockname()[1]
        self._running.set()
        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._accept_thread.start()
        self._emit_log(
            f"服务端启动成功，监听 {self.cfg.host}:{self.cfg.port}  "
            f"加密：{CIPHER_LABEL} 分块：{CHUNK_LABEL}"
        )
        self._emit_state()

    def stop(self) -> None:
        self._running.clear()
        with self._conn_lock:
            if self._conn is not None:
                try:
                    self._conn.close()
                except OSError:
                    pass
                self._conn = None
                self._conn_addr = None
        if self._listener is not None:
            try:
                self._listener.close()
            except OSError:
                pass
            self._listener = None
        self._emit_log("服务端已停止")
        self._emit_state()

    def disconnect_current_client(self) -> None:
        with self._conn_lock:
            conn = self._conn
            addr = self._conn_addr
            if conn is None:
                self._emit_log("当前无客户端在线，无需断开")
                return
            try:
                conn.close()
            except OSError:
                pass
            self._conn = None
            self._conn_addr = None
        self._emit_log(f"手动断开客户端连接：{addr}")
        self._emit_state()

    def prepare_share(self, src_path) -> "str | None":
        """把本地文件放入下发目录（share_dir），供已连接客户端按文件名下载。

        注：新协议为「客户端发起下载」，服务端不能主动推送，因此「下发」动作
        即把文件准备好放进 share_dir，客户端在下载框输入文件名即可拉取。
        """
        src = Path(src_path)
        if not src.is_file():
            self._emit_log(f"文件不存在，无法下发：{src}")
            return None
        self.cfg.share_dir.mkdir(parents=True, exist_ok=True)
        dest = self.cfg.share_dir / src.name
        dest.write_bytes(src.read_bytes())
        self._emit_log(
            f"已加入下发目录：{src.name}（客户端可在下载框输入该文件名下载）"
        )
        return dest.name

    # ---- 内部循环 ----
    def _accept_loop(self) -> None:
        self._listener.settimeout(0.5)
        while self._running.is_set():
            try:
                conn, addr = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with self._conn_lock:
                if self._conn is not None:
                    try:
                        self._conn.close()
                    except OSError:
                        pass
                self._conn = conn
                self._conn_addr = addr
            self._emit_log(f"客户端接入：{addr}")
            self._emit_state()
            try:
                self._serve_client(conn, addr)
            finally:
                with self._conn_lock:
                    if self._conn is conn:
                        self._conn = None
                        self._conn_addr = None
                try:
                    conn.close()
                except OSError:
                    pass
                self._emit_log(f"客户端 {addr} 连接已结束")
                self._emit_state()

    def _serve_client(self, conn, addr) -> None:
        try:
            enc_key, _mac = session.server_handshake(
                conn, self.cfg.password, self.cfg.pbkdf2_iterations
            )
        except (session.AuthError, session.SessionError, protocol.ProtocolError) as e:
            self._emit_log(f"认证失败，断开：{e}")
            return

        self._enc_key = enc_key
        self._emit_log(f"客户端 {addr} 认证通过，建立长连接（支持上传 / 下发）")
        self._emit_state()

        while True:
            try:
                frame = session.next_request_frame(conn)
            except (ConnectionError, OSError, protocol.ProtocolError) as e:
                self._emit_log(f"读取请求帧异常，连接中断：{e}")
                break

            ftype = frame.type
            if ftype == protocol.MessageType.BYE:
                self._emit_log("收到 BYE，客户端正常断开")
                break
            elif ftype == protocol.MessageType.PUT_BEGIN:
                self._set_progress(0, 1, "上传中")
                try:
                    res = session.handle_upload(
                        conn, enc_key, self.cfg.recv_dir,
                        progress=lambda d, t: self._set_progress(d, t, "上传中"),
                        first_frame=frame,
                    )
                    self._emit_log(f"【上传】{res.get('name')} 完成：{res.get('message')}")
                except Exception as e:  # noqa: BLE001
                    self._emit_log(f"上传处理异常：{e}")
                    break
                finally:
                    self._clear_progress()
            elif ftype == protocol.MessageType.GET_BEGIN:
                self._set_progress(0, 1, "下发中")
                try:
                    res = session.handle_download(
                        conn, enc_key, self.cfg.share_dir,
                        progress=lambda d, t: self._set_progress(d, t, "下发中"),
                        first_frame=frame,
                    )
                    self._emit_log(f"【下发】{res.get('name')}：{res.get('message')}")
                except Exception as e:  # noqa: BLE001
                    self._emit_log(f"下发处理异常：{e}")
                    break
                finally:
                    self._clear_progress()
            else:
                self._emit_log(f"未知请求类型 0x{ftype:02x}，返回错误并断开")
                try:
                    session.send_error(conn, f"unsupported request 0x{ftype:02x}")
                except OSError:
                    pass
                break

        self._clear_progress()
        self._emit_state()

    def _emit_log(self, msg: str) -> None:
        self._on_log(msg)


# ===========================================================================
# 2. tkinter 界面（仅在此处使用 tkinter；顶层绝不创建 Tk()，仅在 __main__ 创建）
#    注意：tkinter 在部分无显示环境 / 精简 Python 中未必可用，因此采用「懒加载」——
#    只在构建 App 时才 import tkinter 并注入模块全局，保证 `import gui_server`
#    在无头环境也能通过（证明模块顶层没有创建窗口）。
# ===========================================================================
def _load_tkinter():
    import tkinter as tk  # noqa: E402
    from tkinter import ttk, scrolledtext, filedialog, messagebox  # noqa: E402
    globals().update(tk=tk, ttk=ttk, scrolledtext=scrolledtext,
                     filedialog=filedialog, messagebox=messagebox)
    return tk


class ServerApp:
    def __init__(self, root, engine: ServerEngine):
        _load_tkinter()  # 懒加载，确保无头 import 不触碰 tkinter
        self.root = root
        self.engine = engine
        self.log_q: "queue.Queue" = queue.Queue()
        self._pending = None
        self._last_p = (0.0, 0)
        self._poll_id = None  # 轮询 after 的 id，便于窗口销毁时取消
        # 把 engine 的回调接入 UI 队列（子线程只入队，UI 线程出队）
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
        root.title("局域网加密文件传输 - 服务端")
        root.geometry("800x580")
        f = ("微软雅黑", 10)

        self.status_var = tk.StringVar(value="未启动")
        tk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN,
                 anchor="w", font=f, bg="#eef").pack(side=tk.BOTTOM, fill=tk.X)

        # 1. 服务控制区
        fc = tk.LabelFrame(root, text="服务控制区", font=f, bd=2, relief=tk.GROOVE)
        fc.pack(fill=tk.X, padx=10, pady=6)
        self.start_btn = tk.Button(fc, text="启动服务端", command=self._on_start,
                                   width=16, height=2, font=f)
        self.start_btn.grid(row=0, column=0, padx=8, pady=6)
        self.disc_btn = tk.Button(fc, text="手动断开客户端", command=self._on_disconnect,
                                  width=16, height=2, font=f, bg="#ff6666")
        self.disc_btn.grid(row=0, column=1, padx=8, pady=6)
        self.open_btn = tk.Button(fc, text="打开发送目录", command=self._on_open_share,
                                  width=16, font=f)
        self.open_btn.grid(row=0, column=2, padx=8, pady=6)

        # 2. 文件下发区
        fd = tk.LabelFrame(root, text="文件下发区（放入下发目录供客户端下载）",
                           font=f, bd=2, relief=tk.GROOVE)
        fd.pack(fill=tk.X, padx=10, pady=6)
        tk.Button(fd, text="选择下发文件", command=self._on_select,
                  width=14, font=f).grid(row=0, column=0, padx=5, pady=6)
        self.down_label = tk.Label(fd, text="未选择下发文件", width=42, anchor="w", font=f)
        self.down_label.grid(row=0, column=1, padx=5)
        self.send_btn = tk.Button(fd, text="下发文件给客户端", command=self._on_send,
                                  width=18, bg="#99ccff", font=f)
        self.send_btn.grid(row=1, column=0, columnspan=2, pady=6)

        # 目录信息
        self.dir_label = tk.Label(root, text=self._dir_text(), font=("微软雅黑", 9),
                                  anchor="w", justify="left")
        self.dir_label.pack(fill=tk.X, padx=12)

        # 进度条
        pf = tk.LabelFrame(root, text="传输进度", font=f, bd=2, relief=tk.GROOVE)
        pf.pack(fill=tk.X, padx=10, pady=4)
        self.pb = ttk.Progressbar(pf, orient="horizontal", mode="determinate", length=320)
        self.pb.grid(row=0, column=0, padx=6, pady=6, sticky="ew")
        pf.columnconfigure(0, weight=1)
        self.pb_label = tk.Label(pf, text="0.0%  0.00 / 0.00 MB  0.00 MB/s",
                                 font=f, anchor="w")
        self.pb_label.grid(row=0, column=1, padx=6)

        # 3. 运行状态区
        fi = tk.LabelFrame(root, text="运行状态区", font=f, bd=2, relief=tk.GROOVE)
        fi.pack(fill=tk.X, padx=10, pady=4)
        self.info_label = tk.Label(fi, text=self._info_text(), font=("微软雅黑", 9), anchor="w")
        self.info_label.pack(pady=5, fill=tk.X)

        # 4. 传输日志区
        fl = tk.LabelFrame(root, text="传输日志区", font=f, bd=2, relief=tk.GROOVE)
        fl.pack(fill=tk.BOTH, expand=True, padx=10, pady=8)
        self.log = scrolledtext.ScrolledText(fl, font=("Consolas", 9))
        self.log.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)

    def _dir_text(self):
        return f"接收目录：{self.engine.cfg.recv_dir}\n下发目录：{self.engine.cfg.share_dir}"

    def _info_text(self):
        return (f"加密算法：{CIPHER_LABEL}  分块大小：{CHUNK_LABEL}  "
                f"口令：{self.engine.cfg.password}（生产环境请改口令）")

    # ---- 按钮回调 ----
    def _on_start(self):
        self.engine.start(host=self.engine.cfg.host, port=self.engine.cfg.port)
        self.dir_label.config(text=self._dir_text())
        self.info_label.config(text=self._info_text())

    def _on_disconnect(self):
        self.engine.disconnect_current_client()

    def _on_select(self):
        path = filedialog.askopenfilename()
        if path:
            self._pending = path
            self.down_label.config(text=f"待下发文件：{os.path.basename(path)}")
            self._enq_log(f"已选择下发文件：{path}")

    def _on_send(self):
        if not self._pending:
            self._enq_log("请先选择要下发的文件！")
            return
        self.engine.prepare_share(self._pending)

    def _on_open_share(self):
        d = self.engine.cfg.share_dir
        try:
            os.startfile(str(d))
        except Exception as e:  # noqa: BLE001
            self._enq_log(f"打开目录失败：{e}")

    # ---- 窗口关闭：先取消轮询再停引擎 ----
    def _on_close(self):
        if self._poll_id is not None:
            try:
                self.root.after_cancel(self._poll_id)
            except Exception:  # noqa: BLE001
                pass
            self._poll_id = None
        self.engine.stop()
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
    eng = ServerEngine()
    ServerApp(r, eng)
    r.mainloop()
