# VDTP/2

《软件与系统安全》实验 1B 的实现：自定义应用层协议跑在 WebSocket 二进制帧上，浏览器是客户端。

协议规范在 [docs/协议.md](docs/协议.md)，课程要求与计划在 [../README.md](../README.md)。

## 现在能跑什么

- 注册：`POST /api/register` 收用户名与 ECDSA P-256 公钥，重复登记同钥返回 `created: false`，异钥返回 409。
- 协议：HELLO/HELLO_ACK → AUTH_CHALLENGE → AUTH_RESPONSE → AUTH_OK，之后 LIST/LIST_OK、PING/PONG，未知消息回 ERROR。
- 认证：浏览器 WebCrypto 生成密钥对，私钥以不可导出形态存 IndexedDB；服务端比对公钥指纹，验 `nonce‖sid` 的签名，发 HMAC 票据与档位。
- 目录：用户根目录内的列出与进入，`../` 与越界路径回 DENIED。
- 上传：256 KiB 分块，OPEN 先报 Merkle 根，每 4 MiB 一次 ACK，DONE 时比对大小、全文 SHA-256 与 Merkle 根，全对才把 `.part` 改名。
- 下载：服务端按窗口推 DATA，客户端回 ACK，DONE 带全文摘要，客户端校验后才落盘。
- 续传：断线后 `.part` 与偏移挂起 10 分钟，重连 RESUME 报 offset，从断点接着传，DONE 时按整份文件重算摘要与 Merkle 根。
- 限速：按用户档位配令牌桶，自由档 2 MiB/s、VIP 档 8 MiB/s，突发 256 KiB；下载在推流前扣额度，上传在落盘前扣。
- 单测：32 项，覆盖帧编解码、签名验签、票据、用户存储、路径越界与 Merkle。

防注入演示、ACL 脚本、容器验证还没做，里程碑见上层 README。

## 结构

```
backend/
  app/frame.py     16 字节头与消息类型的编解码
  app/auth.py      挑战签名、公钥指纹、票据
  app/store.py     SQLite 用户表与路径钉根
  app/merkle.py    Merkle 块树
  app/transfer.py  上传落盘、下载推流、收尾校验与续传重建
  app/bucket.py    令牌桶
  app/main.py      FastAPI 应用、/api/register 与 /ws 端点
  tests/           单元测试
  tools/smoke.py        注册、认证、列目录、上传下载、越权与心跳
  tools/resume_smoke.py 传一半掐线，重连续传并核对摘要
  tools/bench_rate.py   量一档的实际上传速率
  tools/tier.py         改用户档位（限速演示用）
frontend/
  src/protocol.js  浏览器端的同一套帧编解码
  src/identity.js  密钥对生成、IndexedDB 存取、签名
  src/api.js       注册接口
  src/merkle.js    浏览器端 Merkle
  src/transfer.js  上传与下载的分块、ACK 窗口与校验
  src/App.vue      登录、文件列表、身份与会话面板、帧日志
deploy/
  Dockerfile.backend / Dockerfile.frontend / nginx.conf / docker-compose.yml
docs/协议.md       协议规范
```

运行数据落在 `backend/data/`（`VDTP_DATA` 可改）：`vdtp.db`、`ticket.key`、`users/<用户名>/`。整个目录在 `.gitignore` 里。

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
