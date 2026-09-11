import socket
import hashlib
import tkinter as tk
from tkinter import scrolledtext, filedialog
import threading
import os
# 导入外部AES加密文件
from aes_crypto import aes_cbc_decrypt, aes_cbc_encrypt

# 网络配置
HOST = "10.188.234.167"
PORT = 5001
VERIFY_PWD = "123456"

# 全局变量类型注解
current_conn: socket.socket | None = None
client_addr_info: tuple | None = None
send_down_file_path = ""  # 待下发文件路径

# MD5 文件完整性校验函数
def get_md5(file_path):
    md5 = hashlib.md5()
    with open(file_path, 'rb') as f:
        while chunk := f.read(4096):
            md5.update(chunk)
    return md5.hexdigest()

# 日志打印工具
def log_print(text):
    log_text.insert(tk.END, text + "\n")
    log_text.see(tk.END)
    log_text.update_idletasks()

# 手动断开客户端连接
def disconnect_client():
    global current_conn, client_addr_info
    temp_conn = current_conn
    temp_addr = client_addr_info
    if temp_conn is not None:
        try:
            temp_conn.close()
            log_print(f"手动断开客户端连接：{temp_addr}")
        except (ConnectionError, OSError, socket.error) as e:
            log_print(f"断开连接异常：{e}")
        current_conn = None
        client_addr_info = None
    else:
        log_print("当前无客户端在线，无需断开")

# 选择下发文件
def select_down_file():
    global send_down_file_path
    path = filedialog.askopenfilename()
    if path:
        send_down_file_path = path
        down_file_label.config(text=f"待下发文件：{os.path.basename(path)}")
        log_print(f"已选择下发文件：{path}")

# 文件下发核心函数
def down_file_to_client():
    # 补充完整全局声明
    global current_conn, send_down_file_path, client_addr_info
    temp_conn = current_conn
    if temp_conn is None:
        log_print("无已连接客户端，无法下发文件！")
        return
    if not send_down_file_path or not os.path.exists(send_down_file_path):
        log_print("请先选择要下发的文件！")
        return

    try:
        file_name = os.path.basename(send_down_file_path)
        file_md5 = get_md5(send_down_file_path)
        with open(send_down_file_path, "rb") as f:
            raw_data = f.read()
        encrypt_all = aes_cbc_encrypt(raw_data)

        # 1字节指令标识：0x02=服务端下发文件
        temp_conn.send(bytes([0x02]))

        # 发送文件名包头+文件名
        name_bytes = file_name.encode("utf-8")
        temp_conn.send(len(name_bytes).to_bytes(4, byteorder="big"))
        temp_conn.send(name_bytes)

        # 发送MD5包头+MD5字符串
        md5_bytes = file_md5.encode("utf-8")
        temp_conn.send(len(md5_bytes).to_bytes(4, byteorder="big"))
        temp_conn.send(md5_bytes)

        # 发送加密文件长度包头+密文
        encrypt_len = len(encrypt_all)
        temp_conn.send(encrypt_len.to_bytes(4, byteorder="big"))
        temp_conn.sendall(encrypt_all)

        # 显式使用client_addr_info，消除未使用局部变量警告
        log_print(f"【下发成功】文件 {file_name} 已发送至客户端 {client_addr_info}")
    except (ConnectionError, OSError, socket.error) as e:
        log_print(f"下发文件失败，连接异常：{e}")
        temp_conn.close()
        current_conn = None
        client_addr_info = None

# 开启下发子线程，防止界面卡死
def start_down_task():
    t = threading.Thread(target=down_file_to_client, daemon=True)
    t.start()

# 定长读取工具，解决TCP粘包半包
def recv_exact(sock, length):
    buf = b""
    while len(buf) < length:
        chunk = sock.recv(length - len(buf))
        if not chunk:
            raise ConnectionResetError("客户端连接断开")
        buf += chunk
    return buf

# 服务端主监听循环（长连接，支持客户端上传+服务端下发）
def server_run():
    global current_conn, client_addr_info
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(1)
    log_print("服务端启动成功，端口5001，等待客户端连接...")

    while True:
        conn, addr = s.accept()
        current_conn = conn
        client_addr_info = addr
        log_print(f"客户端接入：{addr}，等待密码验证")

        # 接收密码长度
        try:
            pwd_len_data = recv_exact(conn, 4)
        except ConnectionResetError:
            conn.close()
            current_conn = None
            client_addr_info = None
            continue
        pwd_len = int.from_bytes(pwd_len_data, byteorder="big")
        client_pwd = recv_exact(conn, pwd_len).decode("utf-8")

        # 密码校验失败直接断开
        if client_pwd != VERIFY_PWD:
            log_print(f"{addr} 密码错误，断开连接")
            conn.close()
            current_conn = None
            client_addr_info = None
            continue
        log_print(f"{addr} 密码验证通过，建立长连接，支持双向文件传输")

        # 长连接循环持续接收客户端上传文件
        run_flag = True
        while run_flag:
            try:
                # 读取1字节指令区分传输类型
                cmd_byte = recv_exact(conn, 1)
                cmd = cmd_byte[0]

                if cmd == 0x01:
                    # 0x01：客户端上传文件逻辑
                    name_len_data = recv_exact(conn, 4)
                    name_len = int.from_bytes(name_len_data, byteorder="big")
                    file_name = recv_exact(conn, name_len).decode("utf-8")

                    md5_len_data = recv_exact(conn, 4)
                    md5_len = int.from_bytes(md5_len_data, byteorder="big")
                    origin_md5 = recv_exact(conn, md5_len).decode("utf-8")

                    file_len_data = recv_exact(conn, 4)
                    file_total_len = int.from_bytes(file_len_data, byteorder="big")
                    all_encrypt_data = recv_exact(conn, file_total_len)

                    # 解密保存文件
                    all_plain = aes_cbc_decrypt(all_encrypt_data)
                    save_path = "recv_" + file_name
                    with open(save_path, "wb") as f:
                        f.write(all_plain)

                    new_md5 = get_md5(save_path)
                    if new_md5 == origin_md5:
                        log_print(f"【客户端上传】文件 {file_name} 传输完成，MD5校验通过！源MD5:{origin_md5} 保存路径：{save_path}，等待下一个文件...")
                    else:
                        log_print(f"【客户端上传】文件 {file_name} 传输损坏，校验不匹配！接收MD5:{origin_md5} 文件存储位置：{save_path}，等待下一个文件...")
                else:
                    log_print(f"收到未知传输指令 {cmd}，断开连接")
                    run_flag = False

            except ConnectionResetError:
                log_print(f"{addr} 连接中断，关闭通道")
                run_flag = False
            except (OSError, socket.error) as e:
                log_print(f"接收文件异常：{e}，断开当前连接")
                run_flag = False
        # 长连接结束后关闭套接字
        conn.close()
        current_conn = None
        client_addr_info = None

# 启动服务端守护线程，不阻塞UI
def start_server():
    t = threading.Thread(target=server_run, daemon=True)
    t.start()

# ---------------------- GUI界面布局 ----------------------
root = tk.Tk()
root.title("局域网加密文件传输 - 服务端")
root.geometry("760x520")

# 1. 服务启停与断开控制区
frame_control = tk.LabelFrame(root, text="服务控制区", bd=2, relief=tk.GROOVE)
frame_control.pack(fill=tk.X, padx=10, pady=6)
start_btn = tk.Button(frame_control, text="启动服务端", command=start_server, width=14, height=2, font=("微软雅黑",10))
start_btn.grid(row=0, column=0, padx=8, pady=6)
disconnect_btn = tk.Button(frame_control, text="手动断开客户端", command=disconnect_client, width=14, height=2, font=("微软雅黑",10), bg="#ff6666")
disconnect_btn.grid(row=0, column=1, padx=8, pady=6)

# 2. 文件下发操作区
frame_down = tk.LabelFrame(root, text="文件下发区（主动发给客户端）", bd=2, relief=tk.GROOVE)
frame_down.pack(fill=tk.X, padx=10, pady=6)
select_down_btn = tk.Button(frame_down, text="选择下发文件", command=select_down_file, width=12)
select_down_btn.grid(row=0, column=0, padx=5, pady=6)
down_file_label = tk.Label(frame_down, text="未选择下发文件", width=45, anchor="w")
down_file_label.grid(row=0, column=1)
send_down_btn = tk.Button(frame_down, text="下发文件给客户端", command=start_down_task, width=16, bg="#99ccff")
send_down_btn.grid(row=1, column=0, columnspan=2, pady=6)

# 3. 运行状态提示区
frame_info = tk.LabelFrame(root, text="运行状态区", bd=2, relief=tk.GROOVE)
frame_info.pack(fill=tk.X, padx=10, pady=4)
state_label = tk.Label(frame_info, text=f"监听地址：0.0.0.0  端口：{PORT}  验证密码：{VERIFY_PWD} 加密模式：AES-CBC | 长连接支持上传+下发", font=("微软雅黑",9))
state_label.pack(pady=5)

# 4. 实时日志输出区
frame_log = tk.LabelFrame(root, text="传输日志区", bd=2, relief=tk.GROOVE)
frame_log.pack(fill=tk.BOTH, expand=True, padx=10, pady=8)
log_text = scrolledtext.ScrolledText(frame_log, width=88, height=16)
log_text.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)

root.mainloop()