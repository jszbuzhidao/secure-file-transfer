# 安全文件传输系统 - 服务端镜像
FROM python:3.13-slim

WORKDIR /app

# 先装依赖，利用层缓存（requirements.txt 不变则不必重装）
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# 再拷源码
COPY . .

# 创建非 root 用户并切换
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# 配置（cli_server.py 的 argparse 默认走 ServerConfig，会自动读这些环境变量）
ENV SFT_HOST=0.0.0.0 \
    SFT_PORT=5001 \
    SFT_DATA_DIR=/data

VOLUME /data
EXPOSE 5001

# 健康检查：用 python 一行脚本探测端口，不依赖 curl
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import socket,sys; s=socket.socket(); sys.exit(0 if s.connect_ex(('127.0.0.1', 5001))==0 else 1)"

ENTRYPOINT ["python", "cli_server.py"]
