// VDTP/2 的浏览器端帧编解码，与 backend/app/frame.py 一一对应。

export const MAGIC = 0x5654
export const VER = 1
export const HDR = 16
export const MAX_PAYLOAD = 1 << 20

export const T = {
  HELLO: 1,
  HELLO_ACK: 2,
  AUTH_CHALLENGE: 3,
  AUTH_RESPONSE: 4,
  AUTH_OK: 5,
  LIST: 6,
  LIST_OK: 7,
  OPEN: 8,
  OPEN_OK: 9,
  DATA: 10,
  ACK: 11,
  DONE: 12,
  DONE_OK: 13,
  RESUME: 14,
  RESUME_OK: 15,
  PING: 16,
  PONG: 17,
  ERROR: 18,
  BYE: 19,
}

export const NAMES = Object.fromEntries(Object.entries(T).map(([k, v]) => [v, k]))

function sortKeys(value) {
  if (Array.isArray(value)) return value.map(sortKeys)
  if (value && typeof value === 'object') {
    const out = {}
    for (const key of Object.keys(value).sort()) out[key] = sortKeys(value[key])
    return out
  }
  return value
}

// 控制消息的载荷：键排序、无空格的 JSON，和服务端的 control() 对齐。
export function control(obj) {
  return new TextEncoder().encode(JSON.stringify(sortKeys(obj)))
}

export function parseControl(bytes) {
  return JSON.parse(new TextDecoder().decode(bytes))
}

export function pack(type, payload = new Uint8Array(0), { stream = 0, seq = 0, flags = 0 } = {}) {
  if (payload.length > MAX_PAYLOAD) throw new Error('载荷超限')
  const buf = new ArrayBuffer(HDR + payload.length)
  const view = new DataView(buf)
  view.setUint16(0, MAGIC)
  view.setUint8(2, VER)
  view.setUint8(3, type)
  view.setUint8(4, flags)
  view.setUint8(5, 0)
  view.setUint16(6, stream)
  view.setUint32(8, seq)
  view.setUint32(12, payload.length)
  new Uint8Array(buf, HDR).set(payload)
  return new Uint8Array(buf)
}

export class Decoder {
  constructor() {
    this.buf = new Uint8Array(0)
  }

  feed(chunk) {
    const data = new Uint8Array(chunk)
    const buf = new Uint8Array(this.buf.length + data.length)
    buf.set(this.buf)
    buf.set(data, this.buf.length)
    const view = new DataView(buf.buffer)
    const frames = []
    let off = 0
    while (buf.length - off >= HDR) {
      const magic = view.getUint16(off)
      if (magic !== MAGIC) throw new Error(`magic 0x${magic.toString(16)} 不对`)
      const ver = view.getUint8(off + 2)
      if (ver !== VER) throw new Error(`版本 ${ver} 不支持`)
      const type = view.getUint8(off + 3)
      const flags = view.getUint8(off + 4)
      const stream = view.getUint16(off + 6)
      const seq = view.getUint32(off + 8)
      const length = view.getUint32(off + 12)
      if (length > MAX_PAYLOAD) throw new Error(`长度 ${length} 超过上限`)
      if (buf.length - off - HDR < length) break
      frames.push({ type, flags, stream, seq, payload: buf.slice(off + HDR, off + HDR + length) })
      off += HDR + length
    }
    this.buf = buf.slice(off)
    return frames
  }
}
