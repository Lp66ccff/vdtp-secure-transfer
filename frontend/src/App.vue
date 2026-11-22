<script setup>
import { computed, reactive, ref } from 'vue'
import { Decoder, NAMES, T, VER, control, pack, parseControl } from './protocol.js'
import { loadIdentity, sign } from './identity.js'
import { register } from './api.js'
import { download, prepareUpload, saveBlob, sendUpload } from './transfer.js'

const user = ref(localStorage.getItem('vdtp.user') || '')
const entered = ref(false)
const status = ref('idle')
const banner = ref('')
const logs = ref([])
const busy = ref(false)
const files = reactive({ path: '', entries: [] })
const queue = ref([])
const info = reactive({
  sid: '—', rtt: 0, framesIn: 0, framesOut: 0, since: '—',
  rate: 0, quota: 0, thumb: '', ticket: 0, bytesIn: 0, bytesOut: 0,
})

let ws = null
const dec = new Decoder()
let seq = 0
let streamSeq = 0
let heartbeat = null
let pingSentAt = 0
let identity = null
let lastTicket = ''
let resumeCtx = null
const resumable = ref(null)
const waiters = []
let itemSeq = 0
let activeItem = null

const url = computed(() => {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  return `${proto}://${location.host}/ws`
})

const statusText = computed(() => ({
  idle: '未连接', connecting: '认证中', open: '已认证', closed: '已断开',
}[status.value]))

const crumb = computed(() => files.path ? `/${files.path}` : '/')

function fmtSize(bytes) {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KiB`
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} MiB`
  return `${(bytes / 1024 ** 3).toFixed(2)} GiB`
}

function pct(done, total) {
  return total ? `${Math.min(100, Math.round((done / total) * 100))}%` : '100%'
}

function fmtTime(ts) {
  if (!ts) return '—'
  return new Date(ts * 1000).toLocaleString('zh-CN', { hour12: false }).slice(5, 16)
}

function b64u(bytes) {
  let raw = ''
  bytes.forEach((b) => { raw += String.fromCharCode(b) })
  return btoa(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}

function log(dir, text) {
  const at = new Date().toLocaleTimeString('zh-CN', { hour12: false })
  logs.value.unshift({ at, dir, text })
  if (logs.value.length > 200) logs.value.pop()
}

function send(type, payload = new Uint8Array(0), stream = 0) {
  if (!ws || ws.readyState !== WebSocket.OPEN) return
  seq += 1
  ws.send(pack(type, payload, { stream, seq }))
  info.framesOut += 1
  info.bytesOut += payload.length
  if (type !== T.DATA) log('out', `${NAMES[type] ?? type} seq=${seq} ${payload.length}B`)
}

function sendData(stream, offset, bytes) {
  const payload = new Uint8Array(8 + bytes.length)
  new DataView(payload.buffer).setBigUint64(0, BigInt(offset))
  payload.set(bytes, 8)
  send(T.DATA, payload, stream)
}

function nextStream() {
  streamSeq += 1
  return streamSeq
}

function waitFor(pred, timeout = 30000) {
  return new Promise((resolve, reject) => {
    const entry = { pred, resolve, reject }
    entry.timer = setTimeout(() => {
      const i = waiters.indexOf(entry)
      if (i >= 0) waiters.splice(i, 1)
      reject(new Error('等待超时'))
    }, timeout)
    waiters.push(entry)
  })
}

function failWaiters(err) {
  while (waiters.length) {
    const w = waiters.pop()
    clearTimeout(w.timer)
    w.reject(err)
  }
}

function dispatchWaiters(frame) {
  for (let i = waiters.length - 1; i >= 0; i -= 1) {
    const w = waiters[i]
    if (!w.pred(frame)) continue
    clearTimeout(w.timer)
    waiters.splice(i, 1)
    w.resolve(frame)
  }
}

const ch = {
  nextStream,
  sendJson: (type, obj, stream = 0) => send(type, control(obj), stream),
  sendData,
  waitFor,
}

async function enter() {
  const name = user.value.trim()
  if (!name || busy.value) return
  busy.value = true
  banner.value = ''
  try {
    identity = await loadIdentity(name)
    const resp = await register(name, identity.pub)
    if (!resp.ok) {
      banner.value = resp.body.detail || `登记失败（${resp.status}）`
      return
    }
    info.thumb = resp.body.thumbprint || ''
    localStorage.setItem('vdtp.user', name)
    entered.value = true
    connect()
  } catch (err) {
    banner.value = `进入失败：${err.message}`
  } finally {
    busy.value = false
  }
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
    send(T.HELLO, control({ ver: VER, user: user.value.trim(), caps: ['ping', 'list', 'xfer'] }))
    heartbeat = setInterval(() => {
      if (ws && ws.readyState === WebSocket.OPEN) ping()
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
    frames.forEach((frame) => { onFrame(frame) })
  }
  ws.onclose = () => {
    status.value = 'closed'
    clearInterval(heartbeat)
    heartbeat = null
    ws = null
    failWaiters(new Error('连接断开'))
    log('sys', '连接关闭')
  }
  ws.onerror = () => log('err', '连接出错')
}

async function onFrame(frame) {
  info.framesIn += 1
  info.bytesIn += frame.payload.length
  dispatchWaiters(frame)

  if (frame.type === T.DATA) return

  const name = NAMES[frame.type] ?? `UNKNOWN(${frame.type})`

  if (frame.type === T.HELLO_ACK) {
    const ack = parseControl(frame.payload)
    info.sid = ack.sid
    log('in', `HELLO_ACK sid=${ack.sid}`)
    return
  }
  if (frame.type === T.AUTH_CHALLENGE) {
    const { nonce } = parseControl(frame.payload)
    log('in', `AUTH_CHALLENGE nonce=${nonce.length / 2}B`)
    const message = new Uint8Array([...hexToBytes(nonce), ...new TextEncoder().encode(info.sid)])
    const sig = await sign(identity, message)
    send(T.AUTH_RESPONSE, control({ pub: identity.pub, sig: b64u(sig) }))
    return
  }
  if (frame.type === T.AUTH_OK) {
    const ok = parseControl(frame.payload)
    info.rate = ok.rate
    info.quota = ok.quota
    info.ticket = ok.ticket.length
    lastTicket = ok.ticket
    log('in', `AUTH_OK user=${ok.user} 票据=${ok.ticket.length}B`)
    if (resumeCtx) {
      // 用断线前那次的票据：新会话的 sid 上没有挂起的流
      send(T.RESUME, control({ ticket: resumeCtx.ticket }))
      return
    }
    ping()
    listFiles('')
    return
  }
  if (frame.type === T.LIST_OK) {
    const body = parseControl(frame.payload)
    files.path = body.path || ''
    files.entries = body.entries || []
    log('in', `LIST_OK ${files.entries.length} 项`)
    return
  }
  if (frame.type === T.RESUME_OK) {
    const body = parseControl(frame.payload)
    log('in', `RESUME_OK ${(body.streams || []).length} 条流`)
    continueResume(body.streams || [])
    return
  }
  if (frame.type === T.ACK) {
    const body = parseControl(frame.payload)
    if (activeItem) activeItem.acked = body.offset
    log('in', `ACK offset=${body.offset}`)
    return
  }
  if (frame.type === T.PONG) {
    info.rtt = Math.round(performance.now() - pingSentAt)
    log('in', `PONG 往返 ${info.rtt}ms`)
    return
  }
  if (frame.type === T.ERROR) {
    const err = parseControl(frame.payload)
    banner.value = `${err.code}：${err.msg}`
    log('err', `ERROR ${err.code} ${err.msg}`)
    return
  }
  log('in', `${name} seq=${frame.seq} ${frame.payload.length}B`)
}

function ping() {
  if (!ws || ws.readyState !== WebSocket.OPEN) return
  pingSentAt = performance.now()
  send(T.PING)
}

function listFiles(path) {
  send(T.LIST, control({ path }))
}

function pushItem(name, size, kind = 'up') {
  itemSeq += 1
  const item = reactive({
    id: itemSeq, name, size, kind, done: 0, acked: 0, status: '等待', error: '',
  })
  queue.value.unshift(item)
  return item
}

async function uploadOne(file) {
  const rel = files.path ? `${files.path}/${file.name}` : file.name
  const item = pushItem(file.name, file.size, 'up')
  item.status = '上传中'
  activeItem = item
  try {
    const { root } = await prepareUpload(file)
    let target = rel
    let stream = nextStream()
    ch.sendJson(T.OPEN, { path: target, mode: 'up', size: file.size, root }, stream)
    let opened = await ch.waitFor((f) => f.stream === stream && (f.type === T.OPEN_OK || f.type === T.ERROR))
    if (opened.type === T.ERROR) {
      const err = parseControl(opened.payload)
      if (!/同名文件已存在/.test(err.msg)) throw new Error(err.msg)
      // 撞名就加序号重开一条流，用户不用自己改名
      const m = /^(.*?)(\.[^.]+)?$/.exec(file.name)
      const stamp = new Date().toTimeString().slice(0, 8).replace(/:/g, '')
      const renamed = `${m[1]}-${stamp}${m[2] || ''}`
      target = files.path ? `${files.path}/${renamed}` : renamed
      item.name = renamed
      stream = nextStream()
      ch.sendJson(T.OPEN, { path: target, mode: 'up', size: file.size, root }, stream)
      opened = await ch.waitFor((f) => f.stream === stream && (f.type === T.OPEN_OK || f.type === T.ERROR))
      if (opened.type === T.ERROR) throw new Error(parseControl(opened.payload).msg)
    }
    await sendUpload(ch, { file, stream, offset: 0, onProgress: (done) => { item.done = done } })
    item.done = file.size
    item.acked = file.size
    item.status = '完成'
    activeItem = null
    listFiles(files.path)
  } catch (err) {
    if (status.value === 'closed' || /连接断开/.test(err.message)) {
      item.status = '中断'
      if (item.acked) item.done = item.acked
      resumeCtx = { file, rel, item, ticket: lastTicket }
      resumable.value = { name: file.name, size: file.size }
    } else {
      item.status = '失败'
      item.error = err.message
    }
  }
}

// 同时最多三条上传流：协议本来就支持多流，队列只是把并发压住。
async function handleFiles(event) {
  const picked = Array.from(event.target.files || [])
  event.target.value = ''
  const pool = picked.slice()
  const workers = Array.from({ length: Math.min(3, pool.length) }, async () => {
    while (pool.length) await uploadOne(pool.shift())
  })
  await Promise.all(workers)
}

function resume() {
  if (!resumeCtx) return
  banner.value = ''
  resumable.value = { name: resumeCtx.file.name, size: resumeCtx.file.size }
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    connect()
    return
  }
  send(T.RESUME, control({ ticket: resumeCtx.ticket }))
}

async function continueResume(streams) {
  const ctx = resumeCtx
  if (!ctx || !streams.length) {
    banner.value = '没有可续传的流，重新上传吧'
    resumeCtx = null
    resumable.value = null
    return
  }
  const found = streams.find((st) => st.path === ctx.rel) || streams[0]
  ctx.item.status = '上传中'
  ctx.item.done = found.offset
  resumeCtx = null
  resumable.value = null
  try {
    await sendUpload(ch, {
      file: ctx.file, stream: found.stream, offset: found.offset,
      onProgress: (done) => { ctx.item.done = done },
    })
    ctx.item.status = '完成'
    listFiles(files.path)
  } catch (err) {
    ctx.item.status = '失败'
    ctx.item.error = err.message
  }
}

async function fetchEntry(entry) {
  if (entry.dir) {
    listFiles(files.path ? `${files.path}/${entry.name}` : entry.name)
    return
  }
  const item = pushItem(entry.name, entry.size, 'down')
  item.status = '下载中'
  try {
    const rel = files.path ? `${files.path}/${entry.name}` : entry.name
    const buf = await download(ch, rel, (done) => { item.done = done })
    await saveBlob(buf, entry.name)
    item.status = '完成'
  } catch (err) {
    item.status = '失败'
    item.error = err.message
  }
}

function upOne() {
  const parts = files.path.split('/').filter(Boolean)
  parts.pop()
  listFiles(parts.join('/'))
}

// 开发期断线演示用：在控制台或自动化里调用 window.__vdtp.drop() 掐掉连接。
if (import.meta.env.DEV) {
  window.__vdtp = { drop: () => ws && ws.close() }
}

function leave() {
  if (ws) {
    if (ws.readyState === WebSocket.OPEN) send(T.BYE, control({ reason: 'user' }))
    ws.close()
  }
  entered.value = false
  files.path = ''
  files.entries = []
  queue.value = []
}
</script>

<template>
  <main class="page">
    <header class="head">
      <div>
        <h1>VDTP/2 文件传输</h1>
        <p class="sub">软件与系统安全 · 实验 1B · 自定义应用层协议跑在 WebSocket 上</p>
      </div>
      <div class="who">
        <span v-if="entered" class="chip mono">{{ user }}</span>
        <span class="pill" :class="status">{{ statusText }}</span>
      </div>
    </header>

    <p v-if="banner" class="banner">{{ banner }}</p>

    <section v-if="!entered" class="card login">
      <h2>身份</h2>
      <p class="hint">
        首次进入会在这台浏览器里生成一对 ECDSA P-256 密钥，私钥存 IndexedDB，公钥登记到服务端。
        登录不传密码，服务端发 32 字节挑战，你用私钥签名。
      </p>
      <form class="row" @submit.prevent="enter">
        <input v-model="user" placeholder="用户名，字母数字下划线连字符" maxlength="32" spellcheck="false" />
        <button :disabled="busy">{{ busy ? '准备中…' : '进入' }}</button>
      </form>
    </section>

    <template v-else>
      <section class="grid">
        <article class="card files">
          <div class="card-head">
            <h2>文件</h2>
            <div class="tools">
              <span class="crumb mono">{{ crumb }}</span>
              <button class="ghost tiny" @click="upOne" :disabled="!files.path">上一级</button>
              <button class="ghost tiny" @click="listFiles(files.path)">刷新</button>
              <label class="upload">
                上传
                <input type="file" multiple @change="handleFiles" />
              </label>
            </div>
          </div>
          <table v-if="files.entries.length" class="listing">
            <thead>
              <tr><th>名字</th><th class="num">大小</th><th class="num">修改</th></tr>
            </thead>
            <tbody>
              <tr v-for="entry in files.entries" :key="entry.name" :class="{ dir: entry.dir }" @click="fetchEntry(entry)">
                <td><span class="icon">{{ entry.dir ? '📁' : '📄' }}</span>{{ entry.name }}</td>
                <td class="num mono">{{ entry.dir ? '—' : fmtSize(entry.size) }}</td>
                <td class="num mono">{{ fmtTime(entry.mtime) }}</td>
              </tr>
            </tbody>
          </table>
          <p v-else class="hint empty">目录是空的，点右上角「上传」。</p>
          <p v-if="files.entries.length" class="hint note">点文件下载，点文件夹进入。</p>

          <ul v-if="queue.length" class="queue">
            <li v-for="item in queue" :key="item.id" :class="item.status">
              <div class="line">
                <span class="qname">{{ item.name }}</span>
                <span class="qmeta mono">
                  <template v-if="item.kind === 'up'">已确认 {{ fmtSize(item.acked) }} · 已发 {{ fmtSize(item.done) }} / {{ fmtSize(item.size) }}</template>
                  <template v-else>{{ fmtSize(item.done) }} / {{ fmtSize(item.size) }}</template>
                </span>
                <span class="qstatus">{{ item.status === '失败' ? item.error : item.status }}</span>
              </div>
              <div class="bar">
                <span class="sent" :style="{ width: pct(item.done, item.size) }" />
                <span v-if="item.kind === 'up'" class="acked" :style="{ width: pct(item.acked, item.size) }" />
              </div>
            </li>
          </ul>

          <div v-if="resumable" class="resume">
            <span>上次没传完：{{ resumable.name }}</span>
            <button class="tiny" @click="resume">续传</button>
          </div>
        </article>

        <aside class="side">
          <article class="card">
            <h2>身份</h2>
            <dl class="facts">
              <dt>用户</dt><dd class="mono">{{ user }}</dd>
              <dt>指纹</dt><dd class="mono">{{ info.thumb ? info.thumb.slice(0, 16) + '…' : '—' }}</dd>
              <dt>档位</dt><dd class="mono">{{ info.rate ? fmtSize(info.rate) + '/s' : '—' }}</dd>
              <dt>配额</dt><dd class="mono">{{ info.quota ? fmtSize(info.quota) : '—' }}</dd>
              <dt>票据</dt><dd class="mono">{{ info.ticket ? info.ticket + ' B' : '—' }}</dd>
            </dl>
            <button class="ghost tiny" @click="leave">退出</button>
          </article>

          <article class="card">
            <h2>会话</h2>
            <dl class="facts">
              <dt>会话</dt><dd class="mono">{{ info.sid }}</dd>
              <dt>往返</dt><dd class="mono">{{ info.rtt }} ms</dd>
              <dt>上下行</dt><dd class="mono">{{ fmtSize(info.bytesOut) }} / {{ fmtSize(info.bytesIn) }}</dd>
              <dt>帧数</dt><dd class="mono">收 {{ info.framesIn }} · 发 {{ info.framesOut }}</dd>
              <dt>连上</dt><dd class="mono">{{ info.since }}</dd>
            </dl>
          </article>
        </aside>
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
          <li v-if="!logs.length" class="empty">还没连过。</li>
        </ol>
      </section>
    </template>
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

.page { max-width: 1040px; margin: 0 auto; padding: 32px 20px 48px; }

.head { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; margin-bottom: 20px; }

h1 { margin: 0 0 4px; font-size: 22px; font-weight: 600; }
.sub { margin: 0; color: var(--dim); font-size: 13px; }

.who { display: flex; align-items: center; gap: 8px; }

.chip { padding: 4px 10px; border: 1px solid var(--line); border-radius: 8px; font-size: 12px; }

.pill { padding: 4px 12px; border: 1px solid var(--line); border-radius: 999px; font-size: 12px; color: var(--dim); white-space: nowrap; }
.pill.open { color: var(--ok); border-color: #2c4a3c; }
.pill.connecting { color: var(--warn); border-color: #4a4029; }
.pill.closed { color: var(--err); border-color: #4a2c2c; }

.banner { margin: 0 0 16px; padding: 10px 14px; border: 1px solid #4a2c2c; border-radius: 10px; background: #1e1416; color: #ffb4b4; font-size: 13px; }

.grid { display: grid; grid-template-columns: 1.55fr 1fr; gap: 16px; margin-bottom: 16px; align-items: start; }

@media (max-width: 820px) { .grid { grid-template-columns: 1fr; } }

.card { background: var(--panel); border: 1px solid var(--line); border-radius: 12px; padding: 18px 20px; }

h2 { margin: 0 0 12px; font-size: 12.5px; font-weight: 600; letter-spacing: 0.04em; color: var(--dim); text-transform: uppercase; }

.card-head { display: flex; align-items: baseline; justify-content: space-between; gap: 10px; margin-bottom: 10px; }
.card-head h2 { margin: 0; }
.tools { display: flex; align-items: center; gap: 8px; }
.crumb { color: var(--dim); font-size: 12px; }

.upload {
  position: relative; padding: 3px 10px; border: 1px solid var(--accent); border-radius: 8px;
  color: var(--accent); font-size: 12px; cursor: pointer;
}
.upload input { position: absolute; inset: 0; opacity: 0; cursor: pointer; }

.login .row { display: flex; gap: 8px; }
.login input {
  flex: 1; padding: 8px 12px; border: 1px solid var(--line); border-radius: 8px;
  background: #0f1419; color: var(--text); font-size: 13px;
}
.login input:focus { outline: 1px solid var(--accent); }

.listing { width: 100%; border-collapse: collapse; font-size: 13px; }
.listing th { text-align: left; font-weight: 500; color: var(--dim); font-size: 12px; padding: 6px 8px; border-bottom: 1px solid var(--line); }
.listing td { padding: 7px 8px; border-bottom: 1px solid #1c242d; }
.listing tbody tr { cursor: pointer; }
.listing tbody tr:hover { background: #1b232c; }
.listing .num { text-align: right; }
.icon { margin-right: 8px; }

.queue { list-style: none; margin: 14px 0 0; padding: 0; display: grid; gap: 10px; }
.queue .line { display: flex; align-items: baseline; gap: 10px; font-size: 12.5px; }
.qname { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.qmeta { color: var(--dim); }
.qstatus { min-width: 48px; text-align: right; color: var(--dim); }
.queue .完成 .qstatus { color: var(--ok); }
.queue .失败 .qstatus { color: var(--err); }
.bar { position: relative; margin-top: 4px; height: 4px; border-radius: 2px; background: #1c242d; overflow: hidden; }
.bar span { position: absolute; inset: 0 auto 0 0; height: 100%; transition: width 0.15s linear; }
.bar .sent { background: #2f4a66; }
.bar .acked { background: var(--accent); }
.queue .完成 .bar .sent { background: var(--ok); }
.queue .完成 .bar .acked { background: var(--ok); }
.queue .失败 .bar .sent { background: var(--err); }

.resume {
  display: flex; align-items: center; gap: 10px; margin-top: 14px; padding: 10px 12px;
  border: 1px dashed #4a4029; border-radius: 10px; background: #1a1811; font-size: 12.5px; color: var(--warn);
}

.side { display: grid; gap: 16px; }

.facts { display: grid; grid-template-columns: 52px 1fr; gap: 6px 10px; margin: 0 0 14px; }
.facts dt { color: var(--dim); font-size: 13px; }
.facts dd { margin: 0; font-size: 13px; overflow-wrap: anywhere; }

.mono { font-family: ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace; }

button { padding: 7px 14px; border: 1px solid var(--accent); border-radius: 8px; background: var(--accent); color: #06121f; font-size: 13px; font-weight: 600; cursor: pointer; }
button:disabled { opacity: 0.4; cursor: default; }
button.ghost { background: transparent; border-color: var(--line); color: var(--text); font-weight: 400; }
button.tiny { padding: 3px 10px; font-size: 12px; }

.hint { margin: 0 0 14px; color: var(--dim); font-size: 13px; }
.hint.empty { margin: 18px 0 6px; }
.hint.note { margin: 10px 0 0; font-size: 12px; }

.log-head { display: flex; align-items: center; justify-content: space-between; }
.log-head h2 { margin: 0; }

.lines { margin: 12px 0 0; padding: 0; list-style: none; max-height: 220px; overflow: auto; font-size: 12.5px; }
.lines li { display: flex; gap: 8px; padding: 3px 0; border-top: 1px solid #1c242d; }
.lines .at { color: #56636f; }
.lines .dir { width: 12px; color: var(--dim); }
.lines.out .text { color: var(--accent); }
.lines.in .text { color: var(--text); }
.lines.err .text { color: var(--err); }
.lines.sys .text { color: var(--dim); }
.lines.empty { color: var(--dim); border: 0; }
</style>
