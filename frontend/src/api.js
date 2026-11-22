// 注册与其它 HTTP 接口。

export async function register(user, pub) {
  const resp = await fetch('/api/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user, pub }),
  })
  let body = {}
  try {
    body = await resp.json()
  } catch {
    body = {}
  }
  return { ok: resp.ok, status: resp.status, body }
}
