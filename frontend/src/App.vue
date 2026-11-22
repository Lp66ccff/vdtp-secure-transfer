<script setup>
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { Decoder, NAMES, T, VER, control, pack, parseControl } from './protocol.js'

const status = ref('idle') // idle | connecting | open | closed
const logs = ref([])
const info = reactive({
  sid: '—',
  nonce: '—',
  ver: VER,
  rtt: 0,
  framesIn: 0,
  framesOut: 0,
  since: '—',
})

let ws = null
const dec = new Decoder()
let seq = 0
let heartbeat = null
let pingSentAt = 0

const url = computed(() => {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  return `${proto}://${location.host}/ws`
})

const statusText = computed(() => ({
  idle: '未连接',
  connecting: '连接中',
  open: '已连接',
  closed: '已断开',
}[status.value]))

function log(dir, text) {
  const at = new Date().toLocaleTimeString('zh-CN', { hour12: false })
  logs.value.unshift({ at, dir, text })
  if (logs.value.length > 200) logs.value.pop()
}

function send(type, payload = new Uint8Array(0)) {
  if (!ws || ws.readyState !== WebSocket.OPEN) return
  seq += 1
  ws.send(pack(type, payload, { seq }))
  info.framesOut += 1
  log('out', `${NAMES[type] ?? type} seq=${seq} ${payload.length}B`)
}

function onFrame(frame) {
  info.framesIn += 1
  const name = NAMES[frame.type] ?? `UNKNOWN(${frame.type})`
  if (frame.type === T.HELLO_ACK) {
    const ack = parseControl(frame.payload)
    info.sid = ack.sid
    info.nonce = ack.nonce.slice(0, 16) + '…'
    info.ver = ack.ver
    log('in', `HELLO_ACK sid=${ack.sid} nonce=${ack.nonce.length / 2}B`)
    return
  }
  if (frame.type === T.PONG) {
    info.rtt = Math.round(performance.now() - pingSentAt)
    log('in', `PONG seq=${frame.seq} 往返 ${info.rtt}ms`)
    return
  }
  if (frame.type === T.ERROR) {
    const err = parseControl(frame.payload)
    log('err', `ERROR ${err.code} ${err.msg}`)
    return
  }
  log('in', `${name} seq=${frame.seq} ${frame.payload.length}B`)
}

function connect() {
  if (ws) return
  status.value = 'connecting'
  dec.buf = new Uint8Array(0)
  ws = new WebSocket(url.value)
  ws.binaryType = 'arraybuffer'
  ws.onopen = () => {
    status.value = 'open'
    info.since = new Date().toLocaleTimeString('zh-CN', { hour12: false })
    log('sys', `连上 ${url.value}`)
    send(T.HELLO, control({ ver: VER, user: 'guest', caps: ['ping', 'list'] }))
    heartbeat = setInterval(() => {
      if (ws && ws.readyState === WebSocket.OPEN) {
        pingSentAt = performance.now()
        send(T.PING)
      }
    }, 30000)
  }
  ws.onmessage = (event) => {
    let frames = []
    try {
      frames = dec.feed(event.data)
    } catch (err) {
      log('err', `帧错误：${err.message}`)
      ws.close()
      return
    }
    frames.forEach(onFrame)
  }
  ws.onclose = () => {
    status.value = 'closed'
    clearInterval(heartbeat)
    heartbeat = null
    ws = null
    log('sys', '连接关闭')
  }
  ws.onerror = () => log('err', '连接出错')
}

function disconnect() {
  if (!ws) return
  if (ws.readyState === WebSocket.OPEN) send(T.BYE, control({ reason: 'user' }))
  ws.close()
}

function ping() {
  if (!ws || ws.readyState !== WebSocket.OPEN) return
  pingSentAt = performance.now()
  send(T.PING)
}

onMounted(connect)

onBeforeUnmount(() => {
  clearInterval(heartbeat)
  if (ws) ws.close()
})
</script>

<template>
  <main class="page">
    <header class="head">
      <div>
        <h1>VDTP/2 文件传输</h1>
        <p class="sub">软件与系统安全 · 实验 1B · 自定义应用层协议跑在 WebSocket 上</p>
      </div>
      <div class="pill" :class="status">{{ statusText }}</div>
    </header>

    <section class="grid">
      <article class="card">
        <h2>连接</h2>
        <dl class="facts">
          <dt>地址</dt><dd class="mono">{{ url }}</dd>
          <dt>会话</dt><dd class="mono">{{ info.sid }}</dd>
          <dt>挑战</dt><dd class="mono">{{ info.nonce }}</dd>
          <dt>协议</dt><dd class="mono">VDTP/2 v{{ info.ver }} · 16 字节头</dd>
          <dt>往返</dt><dd class="mono">{{ info.rtt }} ms</dd>
          <dt>帧数</dt><dd class="mono">收 {{ info.framesIn }} · 发 {{ info.framesOut }}</dd>
          <dt>连上</dt><dd class="mono">{{ info.since }}</dd>
        </dl>
        <div class="actions">
          <button v-if="status !== 'open'" @click="connect" :disabled="status === 'connecting'">
            {{ status === 'connecting' ? '连接中…' : '连接' }}
          </button>
          <button v-else class="ghost" @click="disconnect">断开</button>
          <button class="ghost" @click="ping" :disabled="status !== 'open'">发一次心跳</button>
        </div>
      </article>

      <article class="card">
        <h2>传输</h2>
        <p class="hint">
          骨架先跑通握手与心跳。认证、目录、上传与断点续传在里程碑 2 和 3 接上，
          那时这块会变成文件列表与上传队列。
        </p>
        <ul class="todo">
          <li><span>认证</span>挑战签名，公钥登记</li>
          <li><span>目录</span>LIST 与用户根目录</li>
          <li><span>上传</span>256 KiB 分块，4 MiB 一次 ACK</li>
          <li><span>续传</span>断线后凭票据恢复</li>
        </ul>
      </article>
    </section>

    <section class="card log">
      <div class="log-head">
        <h2>帧日志</h2>
        <button class="ghost tiny" @click="logs = []">清空</button>
      </div>
      <ol class="lines">
        <li v-for="(row, i) in logs" :key="i" :class="row.dir">
          <span class="at mono">{{ row.at }}</span>
          <span class="dir mono">{{ { out: '→', in: '←', err: '!', sys: '·' }[row.dir] }}</span>
          <span class="text mono">{{ row.text }}</span>
        </li>
        <li v-if="!logs.length" class="empty">还没连过。点「连接」。</li>
      </ol>
    </section>
  </main>
</template>

<style>
:root {
  --bg: #0f1419;
  --panel: #161c23;
  --line: #232c36;
  --text: #d7dee6;
  --dim: #8494a4;
  --accent: #4aa8ff;
  --ok: #3ecf8e;
  --warn: #f0b429;
  --err: #ff6b6b;
}

* { box-sizing: border-box; }

body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font: 14px/1.6 -apple-system, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
}

.page {
  max-width: 980px;
  margin: 0 auto;
  padding: 32px 20px 48px;
}

.head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 24px;
}

h1 {
  margin: 0 0 4px;
  font-size: 22px;
  font-weight: 600;
}

.sub {
  margin: 0;
  color: var(--dim);
  font-size: 13px;
}

.pill {
  padding: 4px 12px;
  border: 1px solid var(--line);
  border-radius: 999px;
  font-size: 12px;
  color: var(--dim);
  white-space: nowrap;
}

.pill.open { color: var(--ok); border-color: #2c4a3c; }
.pill.connecting { color: var(--warn); border-color: #4a4029; }
.pill.closed { color: var(--err); border-color: #4a2c2c; }

.grid {
  display: grid;
  grid-template-columns: 1.2fr 1fr;
  gap: 16px;
  margin-bottom: 16px;
}

@media (max-width: 760px) {
  .grid { grid-template-columns: 1fr; }
}

.card {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 12px;
  padding: 18px 20px;
}

h2 {
  margin: 0 0 12px;
  font-size: 13px;
  font-weight: 600;
  letter-spacing: 0.04em;
  color: var(--dim);
  text-transform: uppercase;
}

.facts {
  display: grid;
  grid-template-columns: 52px 1fr;
  gap: 6px 10px;
  margin: 0 0 18px;
}

.facts dt { color: var(--dim); font-size: 13px; }
.facts dd { margin: 0; font-size: 13px; overflow-wrap: anywhere; }

.mono { font-family: ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace; }

.actions { display: flex; gap: 8px; }

button {
  padding: 7px 14px;
  border: 1px solid var(--accent);
  border-radius: 8px;
  background: var(--accent);
  color: #06121f;
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
}

button:disabled { opacity: 0.4; cursor: default; }

button.ghost {
  background: transparent;
  border-color: var(--line);
  color: var(--text);
  font-weight: 400;
}

button.tiny { padding: 3px 10px; font-size: 12px; }

.hint { margin: 0 0 14px; color: var(--dim); font-size: 13px; }

.todo { margin: 0; padding: 0; list-style: none; }

.todo li {
  display: flex;
  gap: 10px;
  padding: 6px 0;
  border-top: 1px solid var(--line);
  font-size: 13px;
  color: var(--dim);
}

.todo span {
  min-width: 40px;
  color: var(--text);
}

.log-head { display: flex; align-items: center; justify-content: space-between; }
.log-head h2 { margin: 0; }

.lines {
  margin: 12px 0 0;
  padding: 0;
  list-style: none;
  max-height: 260px;
  overflow: auto;
  font-size: 12.5px;
}

.lines li {
  display: flex;
  gap: 8px;
  padding: 3px 0;
  border-top: 1px solid #1c242d;
}

.lines .at { color: #56636f; }
.lines .dir { width: 12px; color: var(--dim); }
.lines.out .text { color: var(--accent); }
.lines.in .text { color: var(--text); }
.lines.err .text { color: var(--err); }
.lines.sys .text { color: var(--dim); }
.lines.empty { color: var(--dim); border: 0; }
</style>
