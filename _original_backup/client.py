import socket
import hashlib
import os
import tkinter as tk
from tkinter import scrolledtext, filedialog
import threading
# 导入外部AES加密文件
from aes_crypto import aes_cbc_encrypt, aes_cbc_decrypt

# 连接配置
SERVER_IP = "10.188.234.167"
PORT = 5001
SEND_FILE_PATH = ""
# 全局socket对象，长连接复用
client_socket: socket.socket | None = None


# 获取文件MD5哈希，分块读取降低内存占用
def get_md5(file_path):
    if not os.path.exists(file_path):
        return None
    md5 = hashlib.md5()
    with open(file_path, 'rb') as f:
        while chunk := f.read(4096):
            md5.update(chunk)
    return md5.hexdigest()


# 日志打印，自动滚动到最新消息
def log_print(text):
    log_text.insert(tk.END, text + "\n")
    log_text.see(tk.END)
    log_text.update_idletasks()


# 手动断开连接
def disconnect_server():
    global client_socket
    temp_sock = client_socket
    if temp_sock is not None:
        try:
            temp_sock.close()
            log_print("手动主动断开与服务端的长连接，通道已销毁")
        except (ConnectionError, OSError, socket.error) as e:
            log_print(f"断开异常：{e}")
        client_socket = None
    else:
        log_print("当前未连接服务端，无需断开")


# 弹窗选择待上传文件
def select_file():
    global SEND_FILE_PATH
    path = filedialog.askopenfilename()
    if path:
        SEND_FILE_PATH = path
        file_label.config(text=f"待上传：{os.path.basename(path)}")
        log_print(f"待上传文件路径：{path}")


# 定长读取工具，解决TCP粘包、半包问题
def recv_exact(sock, length):
    buf = b""
    while len(buf) < length:
        chunk = sock.recv(length - len(buf))
        if not chunk:
            raise ConnectionResetError("连接断开")
        buf += chunk
    return buf


# 后台独立线程：持续监听服务端下发文件
def listen_server_down_task():
    global client_socket
    while True:
        temp_sock = client_socket
        if temp_sock is None:
            break
        try:
            # 读取1字节指令标识
            cmd_byte = recv_exact(temp_sock, 1)
            cmd = cmd_byte[0]
            if cmd == 0x02:
                # 0x02：服务端下发文件逻辑
                name_len_data = recv_exact(temp_sock, 4)
                name_len = int.from_bytes(name_len_data, byteorder="big")
                file_name = recv_exact(temp_sock, name_len).decode("utf-8")

                md5_len_data = recv_exact(temp_sock, 4)
                md5_len = int.from_bytes(md5_len_data, byteorder="big")
                origin_md5 = recv_exact(temp_sock, md5_len).decode("utf-8")

                file_len_data = recv_exact(temp_sock, 4)
                file_total_len = int.from_bytes(file_len_data, byteorder="big")
                encrypt_data = recv_exact(temp_sock, file_total_len)

                # 解密并保存下发文件
                plain_data = aes_cbc_decrypt(encrypt_data)
                save_path = "down_" + file_name
                with open(save_path, "wb") as f:
                    f.write(plain_data)
                new_md5 = get_md5(save_path)
                if new_md5 == origin_md5:
                    log_print(f"【服务端下发】文件 {file_name} 接收完成，MD5校验通过，保存为 {save_path}")
                else:
                    log_print(f"【服务端下发】文件 {file_name} 校验失败，文件损坏")
            elif cmd == 0x01:
                # 0x01：客户端上传指令，服务端自行处理，客户端跳过本轮循环
                continue
        except (ConnectionError, OSError, socket.error):
            break


# 客户端上传文件核心逻辑，长连接复用
def send_file():
    global SEND_FILE_PATH, client_socket
    if not SEND_FILE_PATH:
        log_print("请先选择要上传的文件！")
        return

    # 获取界面输入密码
    pwd = pwd_entry.get().strip()
    if not pwd:
        log_print("请输入连接密码！")
        return

    file_md5 = get_md5(SEND_FILE_PATH)
    if file_md5 is None:
        log_print("文件不存在，传输终止！")
        return

    target_ip = ip_entry.get().strip()

    # 首次连接：新建socket、密码校验、启动下发监听线程
    if client_socket is None:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client_socket.connect((target_ip, PORT))
            log_print(f"首次连接服务端 {target_ip}:{PORT}")
            # 发送密码校验数据包
            pwd_bytes = pwd.encode("utf-8")
            client_socket.send(len(pwd_bytes).to_bytes(4, byteorder="big"))
            client_socket.send(pwd_bytes)
            log_print("已发送验证密码，服务端校验通过，长连接建立完成，可上传/接收下发文件")
            # 启动后台监听下发文件守护线程
            listen_thread = threading.Thread(target=listen_server_down_task, daemon=True)
            listen_thread.start()
        except (ConnectionError, OSError, socket.error) as e:
            log_print(f"连接失败：{e}，请先启动服务端")
            client_socket.close()
            client_socket = None
            return
    else:
        log_print("复用已有长连接通道，上传新文件...")

    file_name = os.path.basename(SEND_FILE_PATH)
    name_bytes = file_name.encode("utf-8")
    md5_bytes = file_md5.encode("utf-8")

    # 读取源文件并AES加密
    with open(SEND_FILE_PATH, "rb") as f:
        raw_data = f.read()
    encrypt_all = aes_cbc_encrypt(raw_data)

    # 发送传输指令：0x01 代表客户端上传文件
    client_socket.send(bytes([0x01]))
    # 发送文件名包头
    client_socket.send(len(name_bytes).to_bytes(4, byteorder="big"))
    client_socket.send(name_bytes)
    # 发送MD5包头
    client_socket.send(len(md5_bytes).to_bytes(4, byteorder="big"))
    client_socket.send(md5_bytes)
    # 发送加密文件总长度包头，解决TCP粘包
    encrypt_len = len(encrypt_all)
    len_header = encrypt_len.to_bytes(4, byteorder="big")
    client_socket.send(len_header)

    # 发送密文，精准捕获网络异常
    try:
        client_socket.sendall(encrypt_all)
        log_print(f"【客户端上传】文件 {file_name} 发送完成！可继续上传或等待服务端下发文件")
    except (ConnectionError, OSError, socket.error) as e:
        log_print(f"传输中途连接异常：{e}，销毁通道")
        client_socket.close()
        client_socket = None


# 新开守护线程执行上传，防止UI界面卡死
def start_send():
    upload_thread = threading.Thread(target=send_file, daemon=True)
    upload_thread.start()


# ---------------------- GUI可视化界面布局 ----------------------
root = tk.Tk()
root.title("局域网加密文件传输 - 客户端(双向传输版)")
root.geometry("740x560")

# 1. 服务端IP、密码输入区
frame_conn = tk.LabelFrame(root, text="服务端连接配置区", bd=2, relief=tk.GROOVE)
frame_conn.pack(fill=tk.X, padx=10, pady=6)
tk.Label(frame_conn, text="服务端IP：", font=("微软雅黑", 10)).grid(row=0, column=0, padx=5, pady=6)
ip_entry = tk.Entry(frame_conn, width=40, font=("微软雅黑", 10))
ip_entry.grid(row=0, column=1, padx=5)
ip_entry.insert(0, SERVER_IP)
tk.Label(frame_conn, text="连接密码：", font=("微软雅黑", 10)).grid(row=1, column=0, padx=5, pady=6)
pwd_entry = tk.Entry(frame_conn, width=40, font=("微软雅黑", 10), show="*")
pwd_entry.grid(row=1, column=1, padx=5)
pwd_entry.insert(0, "")

# 2. 本地文件选择区（上传用）
frame_file = tk.LabelFrame(root, text="待上传文件选择区", bd=2, relief=tk.GROOVE)
frame_file.pack(fill=tk.X, padx=10, pady=6)
select_btn = tk.Button(frame_file, text="浏览选择文件", command=select_file, width=12)
select_btn.grid(row=0, column=0, padx=5, pady=6)
file_label = tk.Label(frame_file, text="未选择任何文件", width=62, anchor="w")
file_label.grid(row=0, column=1)

# 3. 操作按钮区：上传、断开连接
frame_opt = tk.LabelFrame(root, text="传输操作区", bd=2, relief=tk.GROOVE)
frame_opt.pack(fill=tk.X, padx=10, pady=6)
send_btn = tk.Button(frame_opt, text="开始加密上传", command=start_send, width=18, height=2, font=("微软雅黑", 10))
send_btn.grid(row=0, column=0, padx=10, pady=6)
cut_btn = tk.Button(frame_opt, text="手动断开连接", command=disconnect_server, width=18, height=2,
                    font=("微软雅黑", 10), bg="#ff6666")
cut_btn.grid(row=0, column=1, padx=10, pady=6)

# 4. 实时滚动日志窗口
frame_log = tk.LabelFrame(root, text="传输日志信息区", bd=2, relief=tk.GROOVE)
frame_log.pack(fill=tk.BOTH, expand=True, padx=10, pady=8)
log_text = scrolledtext.ScrolledText(frame_log, width=90, height=18)
log_text.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)

root.mainloop()