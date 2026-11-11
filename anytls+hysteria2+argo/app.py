#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""部署 sing-box：hysteria2 + anytls 共用端口/密码，可选 VLESS+WS 固定隧道(Argo)。"""

import hashlib
import ipaddress
import json
import os
import secrets
import shutil
import ssl
import subprocess
import tarfile
import tempfile
import urllib.parse
import urllib.request
import uuid as uuidlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

VERSION = "1.14.4"
BIN_URL = ("https://github.com/SagerNet/sing-box/releases/download/"
           f"v{VERSION}/sing-box-{VERSION}-linux-amd64-musl.tar.gz")

BASE = Path(__file__).resolve().parent
TMP = BASE / ".tmp"
BIN, CERT, KEY = TMP / "sing-box", TMP / "cert.pem", TMP / "key.pem"
CFG, NODES, FPFILE = TMP / "config.json", TMP / "nodes.txt", TMP / "fingerprint.txt"

PORT = int(os.environ.get("SERVER_PORT", "8443"))
PASSWORD = os.environ.get("SERVER_PASSWORD") or secrets.token_urlsafe(18)
SNI = os.environ.get("SERVER_SNI", "www.bing.com")

ARGO_TOKEN = os.environ.get("ARGO_TOKEN", "").strip()
ARGO_PORT = int(os.environ.get("ARGO_PORT", "8080"))
ARGO_DOMAIN = os.environ.get("ARGO_DOMAIN", "").strip().lower()
VLESS_UUID = os.environ.get("VLESS_UUID", "").strip() or str(uuidlib.uuid4())


def public_ip() -> str:
    for url in ("https://api.ipify.org", "https://ipv4.icanhazip.com", "https://ifconfig.me/ip"):
        try:
            with urllib.request.urlopen(url, timeout=6) as r:
                ip = r.read().decode().strip()
                ipaddress.ip_address(ip)
                return ip
        except Exception:
            continue
    return "127.0.0.1"


HOST = os.environ.get("SERVER_HOST") or public_ip()


def is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def ensure_bin() -> None:
    if BIN.is_file():
        return
    TMP.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=TMP) as td:
        tgz = Path(td) / "sb.tar.gz"
        urllib.request.urlretrieve(BIN_URL, tgz)
        with tarfile.open(tgz) as tf:
            m = next(m for m in tf.getmembers() if m.isfile() and m.name.endswith("/sing-box"))
            m.name = "sing-box"
            tf.extract(m, TMP)
    BIN.chmod(0o755)


def san_names():
    from cryptography import x509
    names = [x509.DNSName(SNI)]
    if HOST:
        if is_ip(HOST):
            names.append(x509.IPAddress(ipaddress.ip_address(HOST)))
        elif HOST != SNI:
            names.append(x509.DNSName(HOST))
    return names


def selfsign() -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, SNI)])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.SubjectAlternativeName(san_names()), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    KEY.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
    CERT.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def ensure_cert() -> None:
    if CERT.is_file() and KEY.is_file():
        return
    TMP.mkdir(parents=True, exist_ok=True)
    if shutil.which("openssl"):
        san = ",".join(f"{'IP' if is_ip(v) else 'DNS'}:{v}" for v in [SNI, HOST] if v)
        try:
            subprocess.run(
                ["openssl", "req", "-x509", "-newkey", "ec",
                 "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-sha256",
                 "-days", "3650", "-keyout", str(KEY), "-out", str(CERT),
                 "-subj", f"/CN={SNI}", "-addext", f"subjectAltName={san}"],
                check=True, capture_output=True)
            return
        except (subprocess.CalledProcessError, OSError):
            pass
    selfsign()


def fingerprint() -> str:
    der = ssl.PEM_cert_to_DER_cert(CERT.read_text())
    return ":".join(f"{b:02X}" for b in hashlib.sha256(der).digest())


def build_config() -> dict:
    tls = {"enabled": True, "server_name": SNI,
           "certificate_path": str(CERT), "key_path": str(KEY)}
    inbounds = [
        {"type": "hysteria2", "tag": "hy2", "listen": "::", "listen_port": PORT,
         "users": [{"password": PASSWORD}], "masquerade": "https://www.bing.com",
         "tls": {**tls, "alpn": ["h3"]}},
        {"type": "anytls", "tag": "anytls", "listen": "::", "listen_port": PORT,
         "users": [{"password": PASSWORD}],
         "tls": {**tls, "alpn": ["h2", "http/1.1"]}},
    ]
    outbounds = [{"type": "direct", "tag": "direct"}]
    rules = []

    if ARGO_TOKEN:
        inbounds.append({
            "type": "vless", "tag": "vless-ws", "listen": "127.0.0.1",
            "listen_port": ARGO_PORT,
            "users": [{"uuid": VLESS_UUID}],
            "transport": {"type": "ws", "path": "/"},
        })
        outbounds.append({
            "type": "vless", "tag": "vless-local",
            "server": "127.0.0.1", "server_port": ARGO_PORT,
            "uuid": VLESS_UUID,
            "transport": {"type": "ws", "path": "/"},
            "tls": {"enabled": False},
        })
        inbounds.append({
            "type": "cloudflared", "tag": "argo",
            "token": ARGO_TOKEN, "post_quantum": True,
        })
        rules.append({"inbound": ["argo"], "outbound": "vless-local"})

    cfg = {
        "log": {"level": "info", "timestamp": True},
        "inbounds": inbounds,
        "outbounds": outbounds,
    }
    if rules:
        cfg["route"] = {"rules": rules}
    return cfg


def links(fp: str) -> str:
    pw = urllib.parse.quote(PASSWORD, safe="")
    tag = f"{HOST}-{PORT}"
    lines = [
        f"hysteria2://{pw}@{HOST}:{PORT}/?sni={SNI}&insecure=1&pinSHA256={fp}#hy2-{tag}",
        (f"anytls://{pw}@{HOST}:{PORT}?security=tls&sni={SNI}"
         f"&insecure=1&allowInsecure=1&pinSHA256={fp}#anytls-{tag}"),
    ]
    if ARGO_TOKEN:
        domain = ARGO_DOMAIN or "YOUR-DOMAIN"
        lines.append(
            f"vless://{VLESS_UUID}@{domain}:443?encryption=none&security=tls"
            f"&sni={domain}&fp=chrome&type=ws&host={domain}&path=%2F"
            f"#vless-ws-argo-{domain}")
    return "\n".join(lines) + "\n"


def main() -> None:
    TMP.mkdir(parents=True, exist_ok=True)
    ensure_bin()
    ensure_cert()
    fp = fingerprint()

    CFG.write_text(json.dumps(build_config(), indent=2))
    FPFILE.write_text(fp + "\n")
    NODES.write_text(links(fp))

    print(f"host       : {HOST}")
    print(f"port       : {PORT} (udp=hysteria2, tcp=anytls)")
    print(f"password   : {PASSWORD}")
    print(f"cert-sha256: {fp}")
    if ARGO_TOKEN:
        print(f"argo       : enabled, local ws on 127.0.0.1:{ARGO_PORT}, uuid={VLESS_UUID}")
        print(f"argo domain: {ARGO_DOMAIN or '(未填写，链接中为占位符)'}")
        if not ARGO_DOMAIN:
            print("             → 在 CF 面板给隧道绑定 http://127.0.0.1:%d 后替换占位符" % ARGO_PORT)
    print(f"files      : {TMP}")
    print("--- nodes ---")
    print(NODES.read_text().strip())
    print("-------------")

    subprocess.run([str(BIN), "run", "-c", str(CFG)])


if __name__ == "__main__":
    main()