#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sing-box + cloudflared(Argo) -> VLESS+WS 节点, 可选 Hysteria2 节点
所有文件落在 .cache/ 下, UUID 持久化, 重启复用
环境变量:
  ARGO_PORT    本地监听端口, 默认 8080
  ARGO_TOKEN   Cloudflare 隧道 token; 填了走固定隧道, 不填走临时隧道
  ARGO_DOMAIN  固定隧道对外域名(可选, 临时隧道自动解析)
  HY2_PORT     Hysteria2 UDP 端口, 默认 0(关闭), 填了才启用
  HY2_HOST     Hysteria2 对外地址, 不填自动探测公网 IP
固定隧道需在 Cloudflare 后台把 Public Hostname 的 Service 指向 http://localhost:8080
"""
import os, re, sys, ssl, json, time, uuid, shutil, hashlib, tarfile, signal
import platform, subprocess
from urllib.parse import quote
import requests

CACHE = ".cache"
PORT = int(os.getenv("ARGO_PORT") or os.getenv("SERVER_PORT") or 8080)
TOKEN = (os.getenv("ARGO_TOKEN") or "").strip()
DOMAIN = (os.getenv("ARGO_DOMAIN") or "").strip().replace("https://", "").strip("/")
HY2_PORT = int(os.getenv("HY2_PORT") or 0)
HY2_HOST = (os.getenv("HY2_HOST") or "").strip()
ARCH = "arm64" if platform.machine().lower() in ("aarch64", "arm64") else "amd64"

os.makedirs(CACHE, exist_ok=True)
SB = os.path.join(CACHE, "sing-box")
CF = os.path.join(CACHE, "cloudflared")
CFG = os.path.join(CACHE, "config.json")
UUID_FILE = os.path.join(CACHE, "uuid")
CERT = os.path.join(CACHE, "cert.pem")
KEY = os.path.join(CACHE, "key.pem")
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


def _gen_cert_py(cert, key):
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    import datetime

    k = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "bing.com")])
    now = datetime.datetime.utcnow()
    crt = (x509.CertificateBuilder()
           .subject_name(name).issuer_name(name)
           .public_key(k.public_key())
           .serial_number(x509.random_serial_number())
           .not_valid_before(now - datetime.timedelta(days=1))
           .not_valid_after(now + datetime.timedelta(days=3650))
           .add_extension(x509.SubjectAlternativeName(
               [x509.DNSName("bing.com")]), critical=False)
           .sign(k, hashes.SHA256()))
    with open(key, "wb") as f:
        f.write(k.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.TraditionalOpenSSL,
                                serialization.NoEncryption()))
    with open(cert, "wb") as f:
        f.write(crt.public_bytes(serialization.Encoding.PEM))


def ensure_cert():
    if os.path.exists(CERT) and os.path.exists(KEY):
        return
    print("[*] 生成自签证书 ...")
    if shutil.which("openssl"):
        try:
            subprocess.run(["openssl", "ecparam", "-genkey", "-name",
                            "prime256v1", "-out", KEY], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["openssl", "req", "-new", "-x509", "-days", "3650",
                            "-key", KEY, "-out", CERT, "-subj", "/CN=bing.com",
                            "-addext", "subjectAltName=DNS:bing.com"], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return
        except Exception as e:
            print(f"[!] openssl 失败({e}), 改用 Python 库")
    _gen_cert_py(CERT, KEY)


def cert_pin():
    der = ssl.PEM_cert_to_DER_cert(open(CERT).read())
    h = hashlib.sha256(der).hexdigest().upper()
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))


def public_ip():
    if HY2_HOST:
        return HY2_HOST
    for url in ("https://api.ipify.org", "https://ipv4.icanhazip.com",
                "https://api64.ipify.org"):
        try:
            r = requests.get(url, timeout=8)
            ip = r.text.strip()
            if re.fullmatch(r"[0-9a-fA-F:.]+", ip):
                return ip
        except Exception:
            pass
    return "0.0.0.0"


def write_config(u, hy2):
    inbounds = [{
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
    }]
    if hy2:
        inbounds.append({
            "type": "hysteria2",
            "tag": "hy2",
            "listen": "::",
            "listen_port": HY2_PORT,
            "users": [{"password": u}],
            "masquerade": "https://bing.com",
            "tls": {
                "enabled": True,
                "server_name": "bing.com",
                "alpn": ["h3"],
                "certificate_path": CERT,
                "key_path": KEY
            }
        })
    cfg = {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": inbounds,
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
    print(f"[*] sing-box 已启动 (pid {p.pid})")
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


def show_vless(u, host):
    link = (f"vless://{u}@{host}:443?encryption=none&security=tls"
            f"&sni={host}&fp=chrome&type=ws&host={host}"
            f"&path=%2F%3Fed%3D2048#{quote('vless-ws-argo')}")
    print("\n" + "=" * 72)
    print(f"  [VLESS] 域名 : {host}")
    print(f"  [VLESS] UUID : {u}")
    print(f"  [VLESS] 节点 : {link}")
    print("=" * 72 + "\n", flush=True)


def show_hy2(u, pin):
    host = public_ip()
    link = (f"hysteria2://{u}@{host}:{HY2_PORT}/?sni=bing.com"
            f"&insecure=1&alpn=h3&pinSHA256={quote(pin)}#{quote('hy2-argo')}")
    print("\n" + "=" * 72)
    print(f"  [HY2] 地址   : {host}:{HY2_PORT}  (需放行 UDP)")
    print(f"  [HY2] 密码   : {u}")
    print(f"  [HY2] 指纹   : {pin}")
    print(f"  [HY2] 节点   : {link}")
    print("=" * 72 + "\n", flush=True)


def main():
    u = get_uuid()
    ensure_singbox()
    ensure_cloudflared()

    hy2 = HY2_PORT > 0
    pin = ""
    if hy2:
        ensure_cert()
        pin = cert_pin()

    write_config(u, hy2)
    sb = start_singbox()
    cf = start_argo()

    host = wait_domain()
    if not host:
        print("[!] 未能获取域名, 查看 .cache/argo.log")
    else:
        show_vless(u, host)
    if hy2:
        show_hy2(u, pin)

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