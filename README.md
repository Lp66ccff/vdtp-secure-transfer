# VDTP/2

《软件与系统安全》实验 1B 的实现：自定义应用层协议跑在 WebSocket 二进制帧上，浏览器是客户端。

协议规范在 [docs/协议.md](docs/协议.md)，课程要求与计划在 [../README.md](../README.md)。

## 现在能跑什么

- 后端：FastAPI 的 `/ws` 接受 WebSocket，解 16 字节帧，完成 HELLO/HELLO_ACK 握手，回 PONG，未知消息回 ERROR。
- 前端：连接、显示会话号与挑战、30 秒心跳与往返时延、帧日志。
- 单测：帧编解码 10 项，含半帧、粘帧、坏 magic、超长声明。

认证、目录、上传、续传、限速还没写，里程碑见上层 README。

## 结构

```
backend/
  app/frame.py     16 字节头与消息类型的编解码
  app/main.py      FastAPI 应用与 /ws 端点
  tests/           单元测试
  tools/smoke.py   对着真服务端跑一遍握手与心跳
frontend/
  src/protocol.js  浏览器端的同一套帧编解码
  src/App.vue      连接面板与帧日志
deploy/
  Dockerfile.backend / Dockerfile.frontend / nginx.conf / docker-compose.yml
docs/协议.md       协议规范
```

## 本地起

后端（用仓库里的 venv，装依赖走清华源）：

```bash
cd backend
python3 -m venv .venv
.venv/bin/pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt
.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
```

前端另开一个终端：

```bash
cd frontend
npm install
npm run dev        # http://127.0.0.1:5173，/ws 与 /api 由 vite 转到 8000
```

冒烟与单测：

```bash
cd backend
.venv/bin/python -m pytest -q
.venv/bin/python tools/smoke.py
```

## 容器起

```bash
cd deploy
docker compose up --build   # http://127.0.0.1:8080
```

`deploy/` 的 compose 还在草稿状态：TLS 与限流在里程碑 6 接上，现在只有 HTTP 转发。

## 提交前要做的

- 打包脚本按 `姓名_学号_ex1B_src/`、`_play.mp4`、`_report.pdf` 三个子项出包。
- 去掉 `.venv`、`node_modules`、`dist` 与 `.git`（`.gitignore` 已经挡了前三个）。
