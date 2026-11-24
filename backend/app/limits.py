"""连接与流的上限。

按 IP、按用户、全局各一个计数，外加单连接的流数。计数在进程内存里，单实例
有效；多副本部署时每个副本各算一份，这点与令牌桶一样。

    L = Limits()
    L.open_conn("10.0.0.7")      # 到上限回 False
    L.open_user("liangpei")
    L.streams                   # 单连接的流数上限
"""

from __future__ import annotations


class Limits:
    def __init__(self, per_ip: int = 16, per_user: int = 4, total: int = 512,
                 streams: int = 8) -> None:
        self.per_ip = per_ip
        self.per_user = per_user
        self.total = total
        self.streams = streams
        self.live = 0
        self.by_ip: dict[str, int] = {}
        self.by_user: dict[str, int] = {}

    # ------------------------------------------------------------ 连接
    def open_conn(self, ip: str) -> bool:
        if self.live >= self.total:
            return False
        if self.by_ip.get(ip, 0) >= self.per_ip:
            return False
        self.live += 1
        self.by_ip[ip] = self.by_ip.get(ip, 0) + 1
        return True

    def close_conn(self, ip: str) -> None:
        have = self.by_ip.get(ip, 0)
        if have <= 0:
            return
        self.live = max(0, self.live - 1)
        if have == 1:
            del self.by_ip[ip]
        else:
            self.by_ip[ip] = have - 1

    # ------------------------------------------------------------ 用户
    def open_user(self, name: str) -> bool:
        if self.by_user.get(name, 0) >= self.per_user:
            return False
        self.by_user[name] = self.by_user.get(name, 0) + 1
        return True

    def close_user(self, name: str) -> None:
        left = self.by_user.get(name, 0) - 1
        if left <= 0:
            self.by_user.pop(name, None)
        else:
            self.by_user[name] = left

    def snapshot(self) -> dict:
        return {"live": self.live, "ips": len(self.by_ip), "users": len(self.by_user)}
