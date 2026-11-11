---

编写代码app.py、requirements.txt，https\://github.com/SagerNet/sing-box/releases/download/v1.14.4/sing-box-1.14.4-linux-amd64-musl.tar.gz 部署在python主机上，部署hysteria2和anytls协议节点，共用一个端口SERVER\_PORT，共用密码(用户填写或自动生成)，openssl无法使用时，cryptography库自签证书，计算证书sha-256，节点带上SHA-256，证书指纹格式要这种61:BC:FD:70:...，。app.py同目录下创建.tmp文件夹，二进制、节点链接等文件统一放进去，简洁代码

已运行 32s · 1 步

下面这套方案的核心思路先说清楚：hysteria2 走 **UDP/QUIC**，anytls 走 **TCP**，两者只是复用同一个端口号，sing-box 1.12+ 已支持同一端口的多 inbound；两种协议共用同一个密码和同一张自签证书。证书优先用 openssl 生成，失败则用 cryptography 自签，并把证书 DER 的 SHA-256 以 `61:BC:FD:70:...` 形式写进节点链接。

**app.py**


```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""部署 sing-box：hysteria2 + anytls 共用端口/密码，自签证书并附 SHA-256 指纹。"""

import hashlib
import ipaddress
import os
import secrets
import shutil
import ssl
import subprocess
import tarfile
import tempfile
import urllib.parse
import urllib.request
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
        san = ",".join(f"{'IP' if is_ip(v) else 'DNS'}:{v}"
                       for v in [SNI, HOST] if v)
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


def build_config(sni: str) -> dict:
    tls = {"enabled": True, "server_name": sni,
           "certificate_path": str(CERT), "key_path": str(KEY)}
    return {
        "log": {"level": "info", "timestamp": True},
        "inbounds": [
            {"type": "hysteria2", "tag": "hy2", "listen": "::", "listen_port": PORT,
             "users": [{"password": PASSWORD}], "masquerade": "https://www.bing.com",
             "tls": {**tls, "alpn": ["h3"]}},
            {"type": "anytls", "tag": "anytls", "listen": "::", "listen_port": PORT,
             "users": [{"password": PASSWORD}],
             "tls": {**tls, "alpn": ["h2", "http/1.1"]}},
        ],
        "outbounds": [{"type": "direct", "tag": "direct"}],
    }


def links(fp: str) -> str:
    pw = urllib.parse.quote(PASSWORD, safe="")
    tag = f"{HOST}-{PORT}"
    hy2 = (f"hysteria2://{pw}@{HOST}:{PORT}/?sni={SNI}&insecure=1&pinSHA256={fp}#hy2-{tag}")
    anytls = (f"anytls://{pw}@{HOST}:{PORT}?security=tls&sni={SNI}"
              f"&insecure=1&allowInsecure=1&pinSHA256={fp}#anytls-{tag}")
    return f"{hy2}\n{anytls}\n"


def main() -> None:
    TMP.mkdir(parents=True, exist_ok=True)
    ensure_bin()
    ensure_cert()
    fp = fingerprint()

    CFG.write_text(__import__("json").dumps(build_config(SNI), indent=2))
    FPFILE.write_text(fp + "\n")
    NODES.write_text(links(fp))

    print(f"host      : {HOST}")
    print(f"port      : {PORT} (udp=hysteria2, tcp=anytls)")
    print(f"password  : {PASSWORD}")
    print(f"cert-sha256: {fp}")
    print(f"files     : {TMP}")
    print("--- nodes ---")
    print(NODES.read_text().strip())
    print("-------------")

    subprocess.run([str(BIN), "run", "-c", str(CFG)])


if __name__ == "__main__":
    main()
```

**requirements.txt**


```
cryptography>=41.0.0
```

**用法**



```bash
pip install -r requirements.txt
SERVER_PORT=8443 SERVER_PASSWORD='你的密码' python3 app.py
# 或让脚本自动生成密码/探测公网 IP
SERVER_PORT=8443 python3 app.py
```

环境变量：`SERVER_PORT`（默认 8443）、`SERVER_PASSWORD`（不填则随机生成）、`SERVER_HOST`（不填自动探测公网 IP）、`SERVER_SNI`（默认 www\.bing.com，同时作为证书 CN/SAN）。所有产物（sing-box 二进制、证书、config.json、nodes.txt、fingerprint.txt）都落在同目录 `.tmp/` 内。

几点实操提醒：链接里带的是**证书 DER 的 SHA-256**，客户端靠它做 pinning，`insecure=1` 只是让首次握手不被证书链校验拦住；想换证书直接删掉 `.tmp/cert.pem` 和 `.tmp/key.pem` 重启即可，指纹会自动更新。若主机在云厂商安全组后面，记得放通该端口的 UDP 和 TCP；sing-box 以 root 或带 `CAP_NET_BIND_SERVICE` 的用户运行，低端口才绑得上。需要开机自启的话，把 `ExecStart` 指向 `python3 /path/app.py` 写成 systemd 单元即可。

增加vless+ws搭配固定隧道节点，ARGO\_TOKEN有填写时启用，ARGO\_PORT默认8080，ARGO\_DOMAIN可填写或不填写，不需要下载cloudflared，sing-box本身就支持隧道了

已运行 25s · 4 个步骤

已确认：sing-box 自 1.14.0 起内置 `cloudflared` inbound，无需外部 cloudflared 二进制。隧道进来的流量会走路由引擎，所以本地用一条路由规则把它转发到 127.0.0.1 上的 VLESS+WS 入站即可（TLS 由 Cloudflare 边缘终结）。

**app.py**


```python
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
```

**requirements.txt**


```
cryptography>=41.0.0
```

**用法**


```bash
pip install -r requirements.txt
SERVER_PORT=8443 ARGO_TOKEN='eyJhIjoi...' ARGO_DOMAIN='node.example.com' python3 app.py
```

新增环境变量：`ARGO_TOKEN`（填了才启用隧道）、`ARGO_PORT`（默认 8080）、`ARGO_DOMAIN`（可空）、`VLESS_UUID`（不填自动生成）。原有 hy2/anytls 节点逻辑不变，仍共用 `SERVER_PORT` 和同一个密码，走自签证书 + 指纹。

几个关键点：VLESS 入站只绑 `127.0.0.1:ARGO_PORT`，不直接暴露公网，只能经隧道访问；`cloudflared` 入站的流量被路由规则强制送到本地 `vless-local` 出站，所以隧道里只有 WS 明文到本地，边缘到客户端是 CF 的正规 TLS，因此这条链接不需要 `insecure`。在 Cloudflare Zero Trust 面板里把该隧道的 public hostname 指向 `http://127.0.0.1:8080`（或你设的 ARGO\_PORT），若留空 ARGO\_DOMAIN 就等绑好域名后把链接里的 `YOUR-DOMAIN` 替换掉。`post_quantum` 已开，边缘控制连接走 PQ 密钥交换。
