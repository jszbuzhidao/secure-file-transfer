PYTHON ?= python

.PHONY: install test run-server docker-build clean

# 安装开发依赖
install:
	$(PYTHON) -m pip install -r requirements.txt

# 跑测试套件
test:
	$(PYTHON) -m pytest -q

# 本地启动服务端（示例）
run-server:
	$(PYTHON) cli_server.py

# 构建 Docker 镜像
docker-build:
	docker build -t secure-file-transfer:latest .
