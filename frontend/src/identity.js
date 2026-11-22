// 浏览器端身份：ECDSA P-256 密钥对，私钥存 IndexedDB，导出公钥 JWK。

const ALG = { name: 'ECDSA', namedCurve: 'P-256' }
const SIGN = { name: 'ECDSA', hash: 'SHA-256' }
const DB_NAME = 'vdtp'
const STORE = 'keys'

function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1)
    req.onupgradeneeded = () => req.result.createObjectStore(STORE)
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
  })
}

function idbGet(db, key) {
  return new Promise((resolve, reject) => {
    const req = db.transaction(STORE, 'readonly').objectStore(STORE).get(key)
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
  })
}

function idbSet(db, key, value) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readwrite')
    tx.objectStore(STORE).put(value, key)
    tx.oncomplete = () => resolve()
    tx.onerror = () => reject(tx.error)
  })
}

export async function loadIdentity(user) {
  const db = await openDB()
  const saved = await idbGet(db, `identity:${user}`)
  if (saved) return saved

  // 先生成可导出的密钥对，导出公钥后再把私钥以不可导出的形态放回去。
  const pair = await crypto.subtle.generateKey(ALG, true, ['sign', 'verify'])
  const privJwk = await crypto.subtle.exportKey('jwk', pair.privateKey)
  const pubJwk = await crypto.subtle.exportKey('jwk', pair.publicKey)
  const priv = await crypto.subtle.importKey('jwk', privJwk, ALG, false, ['sign'])
  const identity = {
    priv,
    pub: { kty: pubJwk.kty, crv: pubJwk.crv, x: pubJwk.x, y: pubJwk.y },
  }
  await idbSet(db, `identity:${user}`, identity)
  return identity
}

export async function sign(identity, message) {
  const raw = await crypto.subtle.sign(SIGN, identity.priv, message)
  return new Uint8Array(raw)
}
