"""
提示词:
编写Python代码app.py和requirements，https://github.com/SagerNet/sing-box/releases/download/v1.14.4/sing-box-1.14.4-linux-amd64-musl.tar.gz 部署在Python主机上，部署tuic和anytls协议节点，共用一个端口(用户填写)，共用密码(用户填写或自动生成)，openssl无法使用，只能Python库自签证书。app.py同目录下创建.tmp文件夹，二进制、节点链接等文件统一放进去
"""

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
app.py — 在 Python 主机上一键部署 sing-box（TUIC + AnyTLS 同端口共存）

要点：
  * TUIC 走 UDP(QUIC)、AnyTLS 走 TCP，两者可绑定同一端口号，互不冲突。
  * 证书用 cryptography 纯 Python 自签，不依赖 openssl 命令行。
  * 所有产物（二进制、配置、证书、节点链接）统一放在脚本同目录的 .tmp/ 下。

用法：
  python3 app.py --port 443
  python3 app.py --port 8443 --password 'MyPass' --host vps.example.com
  python3 app.py --port 443 --check        # 只生成并校验配置，不启动
"""

import argparse
import datetime
import ipaddress
import json
import os
import secrets
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request
import uuid as uuidlib
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

DOWNLOAD_URL = (
    "https://github.com/SagerNet/sing-box/releases/download/"
    "v1.14.4/sing-box-1.14.4-linux-amd64-musl.tar.gz"
)

BASE_DIR = Path(__file__).resolve().parent
TMP_DIR = BASE_DIR / ".tmp"
BIN_PATH = TMP_DIR / "sing-box"
ARCHIVE_PATH = TMP_DIR / "sing-box.tar.gz"
CONFIG_PATH = TMP_DIR / "config.json"
CLIENT_CONFIG_PATH = TMP_DIR / "client-config.json"
NODES_PATH = TMP_DIR / "nodes.txt"
CERT_PATH = TMP_DIR / "cert.pem"
KEY_PATH = TMP_DIR / "key.pem"
STATE_PATH = TMP_DIR / "state.json"

_child = None


def log(msg):
    print("[{}] {}".format(time.strftime("%H:%M:%S"), msg), flush=True)


def die(msg):
    log("错误: " + msg)
    sys.exit(1)


def ensure_tmp():
    TMP_DIR.mkdir(mode=0o700, exist_ok=True)
    try:
        os.chmod(TMP_DIR, 0o700)
    except OSError:
        pass


def write_private(path, data, binary=False):
    mode = "wb" if binary else "w"
    kwargs = {} if binary else {"encoding": "utf-8"}
    tmp = path.with_suffix(path.suffix + ".part")
    with open(tmp, mode, **kwargs) as f:
        f.write(data)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def load_state():
    if STATE_PATH.exists():
        try:
            return json.loads(STATE_PATH.read_text("utf-8"))
        except (OSError, ValueError):
            return {}
    return {}


def save_state(state):
    write_private(STATE_PATH, json.dumps(state, indent=2, ensure_ascii=False))


# --------------------------------------------------------------------------- #
# 二进制
# --------------------------------------------------------------------------- #
def download_archive(force=False):
    if ARCHIVE_PATH.exists() and ARCHIVE_PATH.stat().st_size > 0 and not force:
        log("复用已下载的压缩包: {}".format(ARCHIVE_PATH.name))
        return
    log("下载 sing-box: {}".format(DOWNLOAD_URL))
    req = urllib.request.Request(DOWNLOAD_URL, headers={"User-Agent": "curl/8"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        total = int(resp.headers.get("Content-Length") or 0)
        done = 0
        part = ARCHIVE_PATH.with_suffix(".part")
        with open(part, "wb") as f:
            while True:
                chunk = resp.read(256 * 1024)
                if not chunk:
                    break
                f.write(chunk)
                done += len(chunk)
                if total:
                    pct = done * 100 // total
                    print("\r    进度 {:>3}%  {}/{} KB".format(
                        pct, done // 1024, total // 1024), end="", flush=True)
        print()
    os.chmod(part, 0o600)
    os.replace(part, ARCHIVE_PATH)
    log("下载完成: {} KB".format(ARCHIVE_PATH.stat().st_size // 1024))


def install_binary(force=False):
    if BIN_PATH.exists() and not force:
        log("复用已有二进制: {}".format(BIN_PATH))
        return BIN_PATH

    download_archive(force)

    log("解压归档…")
    with tempfile.TemporaryDirectory(dir=str(TMP_DIR)) as workdir:
        with tarfile.open(ARCHIVE_PATH, "r:gz") as tf:
            if sys.version_info >= (3, 12):
                tf.extractall(path=workdir, filter="data")
            else:
                tf.extractall(path=workdir)
            member = None
            for m in tf.getmembers():
                if m.isfile() and os.path.basename(m.name) == "sing-box":
                    member = m
                    break
        if member is None:
            die("压缩包里找不到 sing-box 可执行文件")

        src = Path(workdir) / member.name
        shutil.copy2(src, BIN_PATH)

    os.chmod(BIN_PATH, 0o755)

    try:
        out = subprocess.run([str(BIN_PATH), "version"], capture_output=True,
                             text=True, timeout=30)
        log("二进制版本: " + (out.stdout or out.stderr).strip().splitlines()[0])
    except (OSError, subprocess.SubprocessError, IndexError) as exc:
        die("二进制无法执行: {}".format(exc))

    return BIN_PATH


# --------------------------------------------------------------------------- #
# 证书 / 主机信息
# --------------------------------------------------------------------------- #
def detect_public_ip():
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip",
                "https://ipv4.icanhazip.com"):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "curl/8"})
            with urllib.request.urlopen(req, timeout=6) as resp:
                value = resp.read().decode().strip()
            ipaddress.ip_address(value)
            return value
        except Exception:
            continue
    return None


def _key_usage():
    """兼容 cryptography 新老版本的 KeyUsage 构造。"""
    kwargs = dict(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=True,
        key_cert_sign=True,
        crl_sign=True,
    )
    try:
        return x509.KeyUsage(encipher_only=False, decipher_only=False, **kwargs)
    except TypeError:
        return x509.KeyUsage(**kwargs)


def make_cert(host):
    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        pass

    log("自签证书 (SAN: {})".format(host))
    key = ec.generate_private_key(ec.SECP256R1())

    san = [
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        x509.IPAddress(ipaddress.ip_address("::1")),
    ]
    if is_ip:
        san.append(x509.IPAddress(ipaddress.ip_address(host)))
    else:
        san.append(x509.DNSName(host))

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(_key_usage(), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                       critical=False)
        .sign(key, hashes.SHA256())
    )

    write_private(
        KEY_PATH,
        key.private_bytes(serialization.Encoding.PEM,
                          serialization.PrivateFormat.PKCS8,
                          serialization.NoEncryption()), binary=True)
    write_private(CERT_PATH, cert.public_bytes(serialization.Encoding.PEM), binary=True)
    log("证书已生成: {} / {}".format(CERT_PATH.name, KEY_PATH.name))


# --------------------------------------------------------------------------- #
# 配置
# --------------------------------------------------------------------------- #
def build_server_config(port, password, tuic_uuid, host, listen):
    tls_base = {
        "enabled": True,
        "server_name": host,
        "certificate_path": str(CERT_PATH),
        "key_path": str(KEY_PATH),
    }
    return {
        "log": {"level": "info", "timestamp": True},
        "inbounds": [
            {
                "type": "tuic",
                "tag": "tuic-in",
                "listen": listen,
                "listen_port": port,
                "users": [{"uuid": tuic_uuid, "password": password}],
                "congestion_control": "bbr",
                "tls": dict(tls_base, alpn=["h3"]),
            },
            {
                "type": "anytls",
                "tag": "anytls-in",
                "listen": listen,
                "listen_port": port,
                "users": [{"name": "user", "password": password}],
                "tls": dict(tls_base, alpn=["h2", "http/1.1"]),
            },
        ],
    }


def build_links(port, password, tuic_uuid, host):
    q = urllib.parse.quote
    name = "{}:{}".format(host, port)
    tuic = (
        "tuic://{}:{}@{}:{}?congestion_control=bbr&udp_relay_mode=native"
        "&alpn=h3&sni={}&allow_insecure=1&disable_sni=0#{}"
    ).format(tuic_uuid, q(password, safe=""), host, port, q(host), q("TUIC-" + name))
    anytls = (
        "anytls://{}@{}:{}?sni={}&insecure=1#{}"
    ).format(q(password, safe=""), host, port, q(host), q("AnyTLS-" + name))
    return tuic, anytls


def build_client_config(port, password, tuic_uuid, host):
    return {
        "log": {"level": "info", "timestamp": True},
        "inbounds": [
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1",
             "listen_port": 1080},
        ],
        "outbounds": [
            {
                "type": "tuic", "tag": "tuic-out",
                "server": host, "server_port": port,
                "uuid": tuic_uuid, "password": password,
                "congestion_control": "bbr", "udp_relay_mode": "native",
                "heartbeat": "10s",
                "tls": {"enabled": True, "server_name": host, "alpn": ["h3"],
                        "insecure": True},
            },
            {
                "type": "anytls", "tag": "anytls-out",
                "server": host, "server_port": port, "password": password,
                "tls": {"enabled": True, "server_name": host, "insecure": True},
            },
            {"type": "urltest", "tag": "auto", "outbounds": ["tuic-out", "anytls-out"],
             "url": "https://www.gstatic.com/generate_204", "interval": "5m"},
            {"type": "direct", "tag": "direct"},
        ],
        "route": {"rules": [{"action": "sniff"}], "final": "auto"},
    }


# --------------------------------------------------------------------------- #
# 运行
# --------------------------------------------------------------------------- #
def _on_signal(signum, _frame):
    log("收到信号 {}，正在停止 sing-box…".format(signum))
    if _child and _child.poll() is None:
        _child.terminate()
        try:
            _child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            _child.kill()


def run_server():
    global _child
    signal.signal(signal.SIGINT, _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)

    log("启动 sing-box…")
    _child = subprocess.Popen([str(BIN_PATH), "run", "-c", str(CONFIG_PATH)],
                              cwd=str(TMP_DIR))
    try:
        code = _child.wait()
    except KeyboardInterrupt:
        _on_signal(signal.SIGINT, None)
        code = _child.wait()
    log("sing-box 退出，返回码 {}".format(code))
    return code


# --------------------------------------------------------------------------- #
def main():
    parser = argparse.ArgumentParser(
        description="部署 sing-box（TUIC + AnyTLS 同端口共存）")
    parser.add_argument("--port", type=int, help="监听端口（TCP 给 AnyTLS，UDP 给 TUIC）")
    parser.add_argument("--password", help="共用密码，留空则自动生成")
    parser.add_argument("--host", help="节点域名或 IP，留空自动探测公网 IP")
    parser.add_argument("--listen", default="::", help="监听地址，默认 ::（双栈）")
    parser.add_argument("--check", action="store_true", help="只生成并校验配置，不启动")
    parser.add_argument("--force", action="store_true", help="强制重新下载/重新签证书")
    args = parser.parse_args()

    ensure_tmp()
    state = load_state()

    # 把 0 改成你的服务器端口号
    port = 0 or args.port or state.get("port")
    if not port:
        die("请用 --port 指定端口")
    if not (0 < port < 65536):
        die("端口非法: {}".format(port))

    password = args.password or state.get("password") or secrets.token_urlsafe(24)
    tuic_uuid = state.get("uuid") or str(uuidlib.uuid4())

    host = args.host or state.get("host")
    if not host:
        log("未指定 --host，尝试探测公网 IP…")
        host = detect_public_ip()
        if not host:
            die("探测公网 IP 失败，请用 --host 指定域名或 IP")
        log("探测到公网 IP: {}".format(host))

    save_state({"port": port, "password": password, "uuid": tuic_uuid, "host": host})

    install_binary(force=args.force)

    if args.force or not (CERT_PATH.exists() and KEY_PATH.exists()) \
            or state.get("cert_host") != host:
        make_cert(host)
        state["cert_host"] = host
        save_state(state)

    config = build_server_config(port, password, tuic_uuid, host, args.listen)
    write_private(CONFIG_PATH, json.dumps(config, indent=2, ensure_ascii=False))

    tuic_link, anytls_link = build_links(port, password, tuic_uuid, host)
    write_private(NODES_PATH, "TUIC:\n{}\n\nAnyTLS:\n{}\n".format(tuic_link, anytls_link))
    write_private(CLIENT_CONFIG_PATH,
                  json.dumps(build_client_config(port, password, tuic_uuid, host),
                             indent=2, ensure_ascii=False))

    log("配置已写入: {}".format(CONFIG_PATH))
    if port < 1024 and os.geteuid() != 0:
        log("提示: 端口 {} < 1024，需要 root 权限才能绑定".format(port))

    chk = subprocess.run([str(BIN_PATH), "check", "-c", str(CONFIG_PATH)],
                         capture_output=True, text=True)
    if chk.returncode != 0:
        die("配置校验失败:\n" + (chk.stderr or chk.stdout))
    log("配置校验通过")

    print("\n" + "=" * 72)
    print("  协议: TUIC (UDP) + AnyTLS (TCP)   端口: {}   密码: {}".format(port, password))
    print("  服务端 SNI: {}   UUID: {}".format(host, tuic_uuid))
    print("  TUIC  : {}".format(tuic_link))
    print("  AnyTLS: {}".format(anytls_link))
    print("  节点链接文件: {}".format(NODES_PATH))
    print("  客户端配置  : {}".format(CLIENT_CONFIG_PATH))
    print("  记得放行 TCP 与 UDP {} 端口".format(port))
    print("=" * 72 + "\n")

    if args.check:
        log("--check 已指定，不启动服务")
        return 0

    return run_server()


if __name__ == "__main__":
    sys.exit(main())
