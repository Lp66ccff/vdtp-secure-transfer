<script setup>
import { computed, reactive, ref } from 'vue'
import { Decoder, NAMES, T, VER, control, pack, parseControl } from './protocol.js'
import { loadIdentity, sign } from './identity.js'
import { register } from './api.js'
import { download, saveBlob, upload } from './transfer.js'

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
const waiters = []
let itemSeq = 0

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
    log('in', `AUTH_OK user=${ok.user} 票据=${ok.ticket.length}B`)
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

function pushItem(name, size) {
  itemSeq += 1
  const item = reactive({
    id: itemSeq, name, size, done: 0, status: '等待', error: '',
  })
  queue.value.unshift(item)
  return item
}

async function handleFiles(event) {
  const picked = Array.from(event.target.files || [])
  event.target.value = ''
  for (const file of picked) {
    const item = pushItem(file.name, file.size)
    item.status = '上传中'
    try {
      await upload(ch, file, files.path ? `${files.path}/${file.name}` : file.name,
        (done) => { item.done = done })
      item.status = '完成'
      item.done = file.size
      listFiles(files.path)
    } catch (err) {
      item.status = '失败'
      item.error = err.message
    }
  }
}

async function fetchEntry(entry) {
  if (entry.dir) {
    listFiles(files.path ? `${files.path}/${entry.name}` : entry.name)
    return
  }
  const item = pushItem(entry.name, entry.size)
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
                <span class="qmeta mono">{{ fmtSize(item.done) }} / {{ fmtSize(item.size) }}</span>
                <span class="qstatus">{{ item.status === '失败' ? item.error : item.status }}</span>
              </div>
              <div class="bar"><span :style="{ width: item.size ? `${Math.round((item.done / item.size) * 100)}%` : '100%' }" /></div>
            </li>
          </ul>
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
.bar { margin-top: 4px; height: 4px; border-radius: 2px; background: #1c242d; overflow: hidden; }
.bar span { display: block; height: 100%; background: var(--accent); transition: width 0.15s linear; }
.queue .完成 .bar span { background: var(--ok); }
.queue .失败 .bar span { background: var(--err); }

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
