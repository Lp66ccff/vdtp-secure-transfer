"""改用户档位，给限速演示用。

    python3 tools/tier.py <用户名> free|vip
"""

import os
import sys

sys.path.insert(0, ".")

from app.store import Store  # noqa: E402

if len(sys.argv) != 3 or sys.argv[2] not in ("free", "vip"):
    print(__doc__.strip())
    raise SystemExit(2)

store = Store(os.environ.get("VDTP_DATA", "data"))
name, tier = sys.argv[1], sys.argv[2]
if not store.set_tier(name, tier):
    print(f"没有这个用户：{name}")
    raise SystemExit(1)
print(f"{name} -> {tier}")
