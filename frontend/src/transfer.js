// 上传与下载：分块、Merkle 根、ACK 窗口、收尾校验。
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

export async function upload(ch, file, name, onProgress) {
  const leaves = []
  for (let off = 0; off < file.size; off += CHUNK) {
    leaves.push(await leaf(new Uint8Array(await file.slice(off, off + CHUNK).arrayBuffer())))
  }
  const root = toHex(await rootOf(leaves))
  const digest = toHex(await sha256(new Uint8Array(await file.arrayBuffer())))

  const stream = ch.nextStream()
  ch.sendJson(T.OPEN, { path: name, mode: 'up', size: file.size, root }, stream)
  const opened = await ch.waitFor((f) => f.stream === stream && (f.type === T.OPEN_OK || f.type === T.ERROR))
  if (opened.type === T.ERROR) throw errorOf(opened)

  let lastAck = 0
  for (let off = 0; off < file.size; off += CHUNK) {
    const chunk = new Uint8Array(await file.slice(off, off + CHUNK).arrayBuffer())
    ch.sendData(stream, off, chunk)
    onProgress(Math.min(off + CHUNK, file.size), file.size)
    if (off + CHUNK - lastAck >= ACK_EVERY) {
      const ack = await ch.waitFor((f) => f.stream === stream && (f.type === T.ACK || f.type === T.ERROR))
      if (ack.type === T.ERROR) throw errorOf(ack)
      lastAck = parseControl(ack.payload).offset
    }
  }

  ch.sendJson(T.DONE, { size: file.size, sha256: digest }, stream)
  const done = await ch.waitFor((f) => f.stream === stream && (f.type === T.DONE_OK || f.type === T.ERROR))
  if (done.type === T.ERROR) throw errorOf(done)
  return { stream, digest }
}

export async function download(ch, path, onProgress) {
  const stream = ch.nextStream()
  ch.sendJson(T.OPEN, { path, mode: 'down' }, stream)
  const opened = await ch.waitFor((f) => f.stream === stream && (f.type === T.OPEN_OK || f.type === T.ERROR))
  if (opened.type === T.ERROR) throw errorOf(opened)
  const { size } = parseControl(opened.payload)
  const buf = new Uint8Array(size)

  while (true) {
    const fr = await ch.waitFor((f) => f.stream === stream
      && (f.type === T.DATA || f.type === T.DONE || f.type === T.ERROR))
    if (fr.type === T.ERROR) throw errorOf(fr)
    if (fr.type === T.DATA) {
      const offset = Number(new DataView(fr.payload.buffer, fr.payload.byteOffset, 8).getBigUint64(0))
      const chunk = fr.payload.subarray(8)
      buf.set(chunk, offset)
      ch.sendJson(T.ACK, { offset: offset + chunk.length }, stream)
      onProgress(offset + chunk.length, size)
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
