"""数据目录的位置：$VDTP_DATA，缺省 $XDG_DATA_HOME/vdtp（~/.local/share/vdtp）。

服务端与 tools/ 里的脚本都从这里取，避免各自写死一个相对的 data/。
"""

from __future__ import annotations

import os


def default_data_dir() -> str:
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(
        os.path.expanduser("~"), ".local", "share")
    return os.path.join(base, "vdtp")


def data_dir() -> str:
    return os.environ.get("VDTP_DATA") or default_data_dir()
