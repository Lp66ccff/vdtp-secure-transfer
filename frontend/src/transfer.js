// 上传与下载：分块、Merkle 根、ACK 窗口、收尾校验，以及续传用的分段函数。
// ch 是小适配器：{ nextStream, sendJson, sendData, waitFor }。

import { T, control, parseControl } from './protocol.js'
import { leaf, rootOf, sha256 } from './merkle.js'

export const CHUNK = 256 << 10
const ACK_EVERY = 4 << 20

export function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

function errorOf(frame) {
  const body = parseControl(frame.payload)
  return new Error(`${body.code}：${body.msg}`)
}

// 只算 Merkle 根：分块流式算，不把整份文件读进内存。
// 全文摘要由服务端边写边算，DONE_OK 里回给客户端展示。
export async function prepareUpload(file) {
  const leaves = []
  for (let off = 0; off < file.size; off += CHUNK) {
    leaves.push(await leaf(new Uint8Array(await file.slice(off, off + CHUNK).arrayBuffer())))
  }
  return { root: toHex(await rootOf(leaves)) }
}

// 从 offset 起把剩下的块发完，DONE 收尾。续传时 offset 用服务端报的。
export async function sendUpload(ch, { file, stream, offset, onProgress }) {
  let lastAck = offset
  for (let off = offset; off < file.size; off += CHUNK) {
    const chunk = new Uint8Array(await file.slice(off, off + CHUNK).arrayBuffer())
    ch.sendData(stream, off, chunk)
    onProgress(Math.min(off + CHUNK, file.size), file.size)
    if (off + CHUNK - lastAck >= ACK_EVERY) {
      const ack = await ch.waitFor((f) => f.stream === stream && (f.type === T.ACK || f.type === T.ERROR))
      if (ack.type === T.ERROR) throw errorOf(ack)
      lastAck = parseControl(ack.payload).offset
    }
  }
  ch.sendJson(T.DONE, { size: file.size }, stream)
  const done = await ch.waitFor((f) => f.stream === stream && (f.type === T.DONE_OK || f.type === T.ERROR))
  if (done.type === T.ERROR) throw errorOf(done)
  return { stream }
}

export async function upload(ch, file, name, onProgress) {
  const { root } = await prepareUpload(file)
  const stream = ch.nextStream()
  ch.sendJson(T.OPEN, { path: name, mode: 'up', size: file.size, root }, stream)
  const opened = await ch.waitFor((f) => f.stream === stream && (f.type === T.OPEN_OK || f.type === T.ERROR))
  if (opened.type === T.ERROR) throw errorOf(opened)
  await sendUpload(ch, { file, stream, offset: 0, onProgress })
  return { stream, root }
}

// state 跨断线保留：{ buf, offset }。重连后带 offset 重开下载流，服务端从该偏移推。
export async function download(ch, path, onProgress, state = {}) {
  const stream = ch.nextStream()
  const ask = state.offset || 0
  const body = { path, mode: 'down' }
  if (ask > 0) body.offset = ask
  ch.sendJson(T.OPEN, body, stream)
  const opened = await ch.waitFor((f) => f.stream === stream && (f.type === T.OPEN_OK || f.type === T.ERROR))
  if (opened.type === T.ERROR) throw errorOf(opened)
  const { size } = parseControl(opened.payload)
  if (!state.buf || state.buf.length !== size) state.buf = new Uint8Array(size)
  const buf = state.buf

  while (true) {
    const fr = await ch.waitFor((f) => f.stream === stream
      && (f.type === T.DATA || f.type === T.DONE || f.type === T.ERROR))
    if (fr.type === T.ERROR) throw errorOf(fr)
    if (fr.type === T.DATA) {
      const offset = Number(new DataView(fr.payload.buffer, fr.payload.byteOffset, 8).getBigUint64(0))
      const chunk = fr.payload.subarray(8)
      buf.set(chunk, offset)
      state.offset = offset + chunk.length
      ch.sendJson(T.ACK, { offset: state.offset }, stream)
      onProgress(state.offset, size)
      continue
    }
    const body = parseControl(fr.payload)
    const digest = toHex(await sha256(buf))
    if (body.sha256 !== digest) throw new Error(`HASH_MISMATCH：服务端 ${body.sha256.slice(0, 12)}… 本地 ${digest.slice(0, 12)}…`)
    ch.sendJson(T.DONE_OK, { stream }, stream)
    return buf
  }
}

export async function saveBlob(buf, name) {
  const url = URL.createObjectURL(new Blob([buf]))
  const a = document.createElement('a')
  a.href = url
  a.download = name
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 4000)
}

export { control }
