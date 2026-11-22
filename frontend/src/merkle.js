// 浏览器端的 Merkle 块树，与 backend/app/merkle.py 对应。

export async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))
}

export async function leaf(chunk) {
  const buf = new Uint8Array(chunk.length + 1)
  buf[0] = 0
  buf.set(chunk, 1)
  return sha256(buf)
}

export async function node(left, right) {
  const buf = new Uint8Array(65)
  buf[0] = 1
  buf.set(left, 1)
  buf.set(right, 33)
  return sha256(buf)
}

export async function rootOf(leaves) {
  if (!leaves.length) return new Uint8Array(32)
  let level = leaves.slice()
  while (level.length > 1) {
    if (level.length % 2) level.push(level[level.length - 1])
    const next = []
    for (let i = 0; i < level.length; i += 2) {
      next.push(await node(level[i], level[i + 1]))
    }
    level = next
  }
  return level[0]
}
