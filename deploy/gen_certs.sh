#!/usr/bin/env bash
# 生成本地演示用的根证书与服务器证书。
# 用法：./gen_certs.sh [输出目录]，默认 ./certs
set -euo pipefail

dir="${1:-certs}"
mkdir -p "$dir"
cd "$dir"

if [[ -f ca.crt && -f server.crt ]]; then
	echo "证书已存在：$(pwd)"
	exit 0
fi

openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
	-keyout ca.key -out ca.crt -subj "/CN=VDTP Dev CA" 2>/dev/null

openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
	-subj "/CN=localhost" 2>/dev/null

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
	-out server.crt -days 365 \
	-extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1") 2>/dev/null

rm -f server.csr
chmod 600 ca.key server.key
echo "证书生成在 $(pwd)：ca.crt 给客户端信任，server.crt/server.key 给 nginx"
