#!/usr/bin/env bash
# 服务端目录的访问控制：每个用户一个根目录，服务账号只拿读写权，其它人无权。
#
# 用法：sudo ./acl.sh <数据目录>
#   例：sudo ./acl.sh ../backend/data
#
# 做三件事：
#   1. 建 vdtp 组与用户目录，目录权限 750，属主是跑服务的账号；
#   2. 用 setfacl 给组 rwx，默认 ACL 让新建文件继承；
#   3. 用 mask 收口，把“其他人”的位全部清掉。
set -euo pipefail

data="${1:?用法：./acl.sh <数据目录>}"
svc_group="${VDTP_GROUP:-vdtp}"
svc_user="${VDTP_USER:-$(id -un)}"
base="$data/users"

mkdir -p "$base"
chmod 750 "$base"

if ! getent group "$svc_group" >/dev/null; then
	if [[ "$(id -u)" == "0" ]]; then
		groupadd "$svc_group"
	else
		svc_group="$(id -gn)"
		echo "（不是 root，组 ${VDTP_GROUP:-vdtp} 不存在，改用当前主组 $svc_group）"
	fi
fi

echo "== 目录 $base"
chown -R "$svc_user:$svc_group" "$base"
setfacl -m "u:$svc_user:rwx,g:$svc_group:rwx,o::---,m::rwx" "$base"
setfacl -d -m "u:$svc_user:rwx,g:$svc_group:rwx,o::---,m::rwx" "$base"

for dir in "$base"/*/; do
	[[ -d "$dir" ]] || continue
	chown -R "$svc_user:$svc_group" "$dir"
	setfacl -m "u:$svc_user:rwx,g:$svc_group:rwx,o::---,m::rwx" "$dir"
	setfacl -d -m "u:$svc_user:rwx,g:$svc_group:rwx,o::---,m::rwx" "$dir"
	echo "-- $(basename "$dir")"
	getfacl -cp "$dir" | sed 's/^/   /'
done

echo
echo "== 验证：其他人读不了"
probe="$(mktemp "$base/.acl-probe.XXXX")"
if getfacl -cp "$probe" | grep -qx 'other::---'; then
	echo "ok: 新建文件继承默认 ACL，other 位为空"
	rc=0
else
	echo "warn: 新建文件的 other 位不是 ---"
	getfacl -cp "$probe" | sed 's/^/   /'
	rc=1
fi
rm -f "$probe"
exit "$rc"
