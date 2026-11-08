#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sing-box + cloudflared(Argo) -> VLESS + WS 节点
所有文件落在 .cache/ 下, UUID 持久化, 重启复用
环境变量:
  ARGO_PORT    本地监听端口, 默认 8080
  ARGO_TOKEN   Cloudflare 隧道 token; 填了走固定隧道, 不填走临时隧道
  ARGO_DOMAIN  固定隧道对外域名(可选, 临时隧道自动解析)
固定隧道需在 Cloudflare 后台把 Public Hostname 的 Service 指向 http://localhost:8080
"""
import os, re, sys, json, time, uuid, shutil, tarfile, signal, platform, subprocess
from urllib.parse import quote
import requests

CACHE = ".cache"
PORT = int(os.getenv("ARGO_PORT") or os.getenv("SERVER_PORT") or 8080)
TOKEN = (os.getenv("ARGO_TOKEN") or "").strip()
DOMAIN = (os.getenv("ARGO_DOMAIN") or "").strip().replace("https://", "").strip("/")
ARCH = "arm64" if platform.machine().lower() in ("aarch64", "arm64") else "amd64"

os.makedirs(CACHE, exist_ok=True)
SB = os.path.join(CACHE, "sing-box")
CF = os.path.join(CACHE, "cloudflared")
CFG = os.path.join(CACHE, "config.json")
UUID_FILE = os.path.join(CACHE, "uuid")
CF_LOG = os.path.join(CACHE, "argo.log")
SB_LOG = os.path.join(CACHE, "sb.log")


def download(url, path):
    if os.path.exists(path) and os.path.getsize(path) > 0:
        return path
    headers = {"User-Agent": "Mozilla/5.0"}
    with requests.get(url, headers=headers, stream=True, timeout=120) as r:
        r.raise_for_status()
        tmp = path + ".part"
        with open(tmp, "wb") as f:
            for chunk in r.iter_content(1 << 16):
                f.write(chunk)
    os.replace(tmp, path)
    return path


def ensure_singbox():
    if os.path.exists(SB):
        return SB
    url = (f"https://github.com/SagerNet/sing-box/releases/download/"
           f"v1.11.4/sing-box-1.11.4-linux-{ARCH}.tar.gz")
    tgz = os.path.join(CACHE, "sb.tar.gz")
    print("[*] 下载 sing-box 1.11.4 ...")
    download(url, tgz)
    with tarfile.open(tgz, "r:gz") as t:
        for m in t.getmembers():
            if m.isfile() and m.name.endswith("sing-box"):
                with t.extractfile(m) as src, open(SB, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                break
    os.remove(tgz)
    os.chmod(SB, 0o755)
    return SB


def ensure_cloudflared():
    if os.path.exists(CF):
        return CF
    print("[*] 下载 cloudflared ...")
    download(f"https://github.com/cloudflare/cloudflared/releases/latest/download/"
             f"cloudflared-linux-{ARCH}", CF)
    os.chmod(CF, 0o755)
    return CF


def get_uuid():
    if os.path.exists(UUID_FILE):
        u = open(UUID_FILE).read().strip()
        if u:
            return u
    u = str(uuid.uuid4())
    open(UUID_FILE, "w").write(u)
    return u


def write_config(u):
    cfg = {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [{
            "type": "vless",
            "tag": "vless-ws",
            "listen": "127.0.0.1",
            "listen_port": PORT,
            "users": [{"uuid": u}],
            "transport": {
                "type": "ws",
                "path": "/",
                "max_early_data": 2048,
                "early_data_header_name": "Sec-WebSocket-Protocol"
            }
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}]
    }
    with open(CFG, "w") as f:
        json.dump(cfg, f, indent=2)


def spawn(cmd, log_path):
    log = open(log_path, "ab", buffering=0)
    return subprocess.Popen(cmd, stdout=log, stderr=log,
                            preexec_fn=os.setsid if hasattr(os, "setsid") else None)


def start_singbox():
    p = spawn([SB, "run", "-c", CFG], SB_LOG)
    print(f"[*] sing-box 已启动, 本地 127.0.0.1:{PORT} (pid {p.pid})")
    return p


def start_argo():
    if TOKEN:
        cmd = [CF, "tunnel", "--no-autoupdate", "run", "--token", TOKEN, "--url", f"http://127.0.0.1:{PORT}"]
    else:
        cmd = [CF, "tunnel", "--no-autoupdate", "--url", f"http://127.0.0.1:{PORT}"]
    print("[*] 启动 cloudflared ...")
    return spawn(cmd, CF_LOG)


def wait_domain(timeout=90):
    if DOMAIN:
        return DOMAIN
    print("[*] 等待临时隧道域名 ...")
    pat = re.compile(r"https://([a-z0-9-]+\.trycloudflare\.com)")
    end = time.time() + timeout
    while time.time() < end:
        if os.path.exists(CF_LOG):
            m = pat.search(open(CF_LOG, errors="ignore").read())
            if m:
                return m.group(1)
        time.sleep(2)
    return None


def show_node(u, host):
    link = (f"vless://{u}@{host}:443?encryption=none&security=tls"
            f"&sni={host}&fp=chrome&type=ws&host={host}"
            f"&path=%2F%3Fed%3D2048#{quote('vless-ws-argo')}")
    print("\n" + "=" * 60)
    print(f"  域名 : {host}")
    print(f"  UUID : {u}")
    print(f"  节点 : {link}")
    print("=" * 60 + "\n", flush=True)


def main():
    u = get_uuid()
    ensure_singbox()
    ensure_cloudflared()
    write_config(u)
    sb = start_singbox()
    cf = start_argo()
    host = wait_domain()
    if not host:
        print("[!] 未能获取域名, 查看 .cache/argo.log")
    else:
        show_node(u, host)

    def stop(*_):
        for p in (cf, sb):
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGTERM)
            except Exception:
                p.terminate()
        sys.exit(0)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    while True:
        time.sleep(10)
        if sb.poll() is not None:
            print("[!] sing-box 退出, 重启")
            sb = start_singbox()
        if cf.poll() is not None:
            print("[!] cloudflared 退出, 重启")
            cf = start_argo()


if __name__ == "__main__":
    main()