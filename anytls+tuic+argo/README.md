
编写代码app.py、requirements.txt，https://github.com/SagerNet/sing-box/releases/download/v1.14.4/sing-box-1.14.4-linux-amd64-musl.tar.gz 部署在python主机上，部署tuic和anytls协议节点，共用一个端口SERVER_PORT，共用密码(用户填写或自动生成)，openssl无法使用时，cryptography库自签证书，计算证书sha-256，节点带上SHA-256，证书指纹格式要这种61:BC:FD:70:...，。app.py同目录下创建.tmp文件夹，二进制、节点链接等文件统一放进去，简洁代码

已运行 21s · 1 步

下面是可直接部署的实现。核心思路是：**TUIC 走 UDP、AnyTLS 走 TCP，所以两者可以共用同一个 `SERVER_PORT`**，并且共用同一张自签证书与同一个密码（密码可自动生成）。证书 SHA-256 指纹会写入节点链接。

`requirements.txt`


```
cryptography>=42.0.0
```

`app.py`


```python
#!/usr/bin/env python3
"""sing-box 一键部署：TUIC(UDP) + AnyTLS(TCP) 共用端口、共用密码、共用自签证书。"""
import ipaddress
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tarfile
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone

VER = "1.14.4"
URL = (f"https://github.com/SagerNet/sing-box/releases/download/v{VER}/"
       f"sing-box-{VER}-linux-amd64-musl.tar.gz")

BASE = os.path.dirname(os.path.abspath(__file__))
TMP = os.path.join(BASE, ".tmp")
BIN = os.path.join(TMP, "sing-box")
CONF = os.path.join(TMP, "config.json")
CERT = os.path.join(TMP, "cert.pem")
KEY = os.path.join(TMP, "key.pem")
NODES = os.path.join(TMP, "nodes.txt")

DAYS = 3650


def log(msg):
    print(f"[*] {msg}", flush=True)


def is_ip(h):
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def public_ip():
    for url in ("https://api.ipify.org", "https://ipv4.icanhazip.com"):
        try:
            with urllib.request.urlopen(url, timeout=6) as r:
                ip = r.read().decode().strip()
            if ip:
                return ip
        except Exception:
            pass
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return "127.0.0.1"


def fetch_binary():
    if os.path.isfile(BIN) and os.access(BIN, os.X_OK):
        return
    log(f"下载 sing-box {VER} ...")
    tgz = os.path.join(TMP, "sb.tar.gz")
    urllib.request.urlretrieve(URL, tgz)
    with tarfile.open(tgz, "r:gz") as tar:
        for m in tar.getmembers():
            if m.name.endswith("sing-box") and m.isfile():
                with tar.extractfile(m) as f, open(BIN, "wb") as out:
                    out.write(f.read())
                break
    os.chmod(BIN, 0o755)
    os.remove(tgz)
    log("二进制就绪")


def make_cert(host):
    if os.path.isfile(CERT) and os.path.isfile(KEY):
        return
    san = f"IP:{host}" if is_ip(host) else f"DNS:{host}"

    if shutil.which("openssl"):
        try:
            subprocess.run(
                ["openssl", "req", "-x509", "-newkey", "ec",
                 "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                 "-keyout", KEY, "-out", CERT, "-days", str(DAYS),
                 "-subj", f"/CN={host}", "-addext", f"subjectAltName={san}"],
                check=True, capture_output=True)
            log("已用 openssl 生成自签证书")
            return
        except Exception as e:
            log(f"openssl 不可用（{e}），改用 cryptography")

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    alt = [x509.IPAddress(ipaddress.ip_address(host))] if is_ip(host) \
        else [x509.DNSName(host)]
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=DAYS))
            .add_extension(x509.SubjectAlternativeName(alt), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                           critical=True)
            .sign(key, hashes.SHA256()))
    with open(KEY, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    with open(CERT, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    os.chmod(KEY, 0o600)
    log("已用 cryptography 生成自签证书")


def fingerprint():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    with open(CERT, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    return ":".join(f"{b:02X}" for b in cert.fingerprint(hashes.SHA256()))


def build_config(port, uid, pw):
    return {
        "log": {"level": "info", "timestamp": True},
        "inbounds": [
            {
                "type": "tuic", "tag": "tuic-in",
                "listen": "::", "listen_port": port,
                "users": [{"name": "user", "uuid": uid, "password": pw}],
                "congestion_control": "bbr",
                "tls": {"enabled": True, "alpn": ["h3"],
                        "certificate_path": CERT, "key_path": KEY},
            },
            {
                "type": "anytls", "tag": "anytls-in",
                "listen": "::", "listen_port": port,
                "users": [{"name": "user", "password": pw}],
                "tls": {"enabled": True, "alpn": ["h2", "http/1.1"],
                        "certificate_path": CERT, "key_path": KEY},
            },
        ],
        "outbounds": [{"type": "direct", "tag": "direct"}],
    }


def build_nodes(host, port, uid, pw, sni, fp):
    p = urllib.parse.quote(pw, safe="")
    tag = host.replace(":", "-")
    return [
        f"tuic://{uid}:{p}@{host}:{port}?congestion_control=bbr"
        f"&udp_relay_mode=native&alpn=h3&sni={sni}&allow_insecure=1"
        f"&pinSHA256={fp}#tuic-{tag}",
        f"anytls://{p}@{host}:{port}?sni={sni}&insecure=1&fp=chrome"
        f"&pinSHA256={fp}#anytls-{tag}",
    ]


def main():
    os.makedirs(TMP, exist_ok=True)

    port = int(os.environ.get("SERVER_PORT") or 443)
    host = os.environ.get("SERVER_HOST") or public_ip()
    sni = os.environ.get("SNI") or host
    pw = os.environ.get("PASSWORD") or secrets.token_hex(16)
    uid = os.environ.get("TUIC_UUID") or str(uuid.uuid4())

    fetch_binary()
    make_cert(host)

    fp = fingerprint()
    cfg = build_config(port, uid, pw)
    with open(CONF, "w") as f:
        json.dump(cfg, f, indent=2)

    nodes = build_nodes(host, port, uid, pw, sni, fp)
    with open(NODES, "w") as f:
        f.write("\n".join(nodes) + "\n")

    subprocess.run([BIN, "check", "-c", CONF], check=True)

    log(f"地址 {host}:{port}（TUIC/UDP + AnyTLS/TCP 共用）")
    log(f"密码 {pw}")
    log(f"证书 SHA-256 {fp}")
    for n in nodes:
        log(n)
    log(f"节点已写入 {NODES}，启动 sing-box")

    proc = subprocess.Popen([BIN, "run", "-c", CONF])
    try:
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        proc.wait()
    sys.exit(proc.returncode)


if __name__ == "__main__":
    main()
```

用法：


```bash
pip install -r requirements.txt
SERVER_PORT=443 PASSWORD='yourpass' python3 app.py
```

可选环境变量：`SERVER_HOST`（对外地址，默认自动探测公网 IP）、`SNI`（默认同 host）、`TUIC_UUID`。

要点：

+ TUIC 用 UDP/QUIC、AnyTLS 用 TCP，同端口不冲突，sing-box 分别绑定。
+ 证书、密钥、二进制、`config.json`、`nodes.txt` 全部落在 `.tmp/`，不污染目录。
+ 先尝试 `openssl`，失败才用 `cryptography` 生成 P-256 自签证书；指纹按 `61:BC:FD:70:...` 大写冒号格式输出。
+ 节点带 `pinSHA256` 指纹，客户端可做证书固定校验（`allow_insecure=1` 便于首次连通）。
+ 想换端口/密码直接改环境变量重跑即可；`.tmp` 里已有证书会复用，删掉即重新签发。

main函数要输入的参数改成全局变量

已运行 5s · 1 步


```python
#!/usr/bin/env python3
"""sing-box 一键部署：TUIC(UDP) + AnyTLS(TCP) 共用端口、共用密码、共用自签证书。"""
import ipaddress
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tarfile
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone

VER = "1.14.4"
URL = (f"https://github.com/SagerNet/sing-box/releases/download/v{VER}/"
       f"sing-box-{VER}-linux-amd64-musl.tar.gz")

BASE = os.path.dirname(os.path.abspath(__file__))
TMP = os.path.join(BASE, ".tmp")
BIN = os.path.join(TMP, "sing-box")
CONF = os.path.join(TMP, "config.json")
CERT = os.path.join(TMP, "cert.pem")
KEY = os.path.join(TMP, "key.pem")
NODES = os.path.join(TMP, "nodes.txt")

DAYS = 3650


def log(msg):
    print(f"[*] {msg}", flush=True)


def is_ip(h):
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def public_ip():
    for url in ("https://api.ipify.org", "https://ipv4.icanhazip.com"):
        try:
            with urllib.request.urlopen(url, timeout=6) as r:
                ip = r.read().decode().strip()
            if ip:
                return ip
        except Exception:
            pass
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return "127.0.0.1"


def fetch_binary():
    if os.path.isfile(BIN) and os.access(BIN, os.X_OK):
        return
    log(f"下载 sing-box {VER} ...")
    tgz = os.path.join(TMP, "sb.tar.gz")
    urllib.request.urlretrieve(URL, tgz)
    with tarfile.open(tgz, "r:gz") as tar:
        for m in tar.getmembers():
            if m.name.endswith("sing-box") and m.isfile():
                with tar.extractfile(m) as f, open(BIN, "wb") as out:
                    out.write(f.read())
                break
    os.chmod(BIN, 0o755)
    os.remove(tgz)
    log("二进制就绪")


def make_cert(host):
    if os.path.isfile(CERT) and os.path.isfile(KEY):
        return
    san = f"IP:{host}" if is_ip(host) else f"DNS:{host}"

    if shutil.which("openssl"):
        try:
            subprocess.run(
                ["openssl", "req", "-x509", "-newkey", "ec",
                 "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                 "-keyout", KEY, "-out", CERT, "-days", str(DAYS),
                 "-subj", f"/CN={host}", "-addext", f"subjectAltName={san}"],
                check=True, capture_output=True)
            log("已用 openssl 生成自签证书")
            return
        except Exception as e:
            log(f"openssl 不可用（{e}），改用 cryptography")

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    alt = [x509.IPAddress(ipaddress.ip_address(host))] if is_ip(host) \
        else [x509.DNSName(host)]
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=DAYS))
            .add_extension(x509.SubjectAlternativeName(alt), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                           critical=True)
            .sign(key, hashes.SHA256()))
    with open(KEY, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    with open(CERT, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    os.chmod(KEY, 0o600)
    log("已用 cryptography 生成自签证书")


def fingerprint():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    with open(CERT, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    return ":".join(f"{b:02X}" for b in cert.fingerprint(hashes.SHA256()))


def build_config(port, uid, pw):
    return {
        "log": {"level": "info", "timestamp": True},
        "inbounds": [
            {
                "type": "tuic", "tag": "tuic-in",
                "listen": "::", "listen_port": port,
                "users": [{"name": "user", "uuid": uid, "password": pw}],
                "congestion_control": "bbr",
                "tls": {"enabled": True, "alpn": ["h3"],
                        "certificate_path": CERT, "key_path": KEY},
            },
            {
                "type": "anytls", "tag": "anytls-in",
                "listen": "::", "listen_port": port,
                "users": [{"name": "user", "password": pw}],
                "tls": {"enabled": True, "alpn": ["h2", "http/1.1"],
                        "certificate_path": CERT, "key_path": KEY},
            },
        ],
        "outbounds": [{"type": "direct", "tag": "direct"}],
    }


def build_nodes(host, port, uid, pw, sni, fp):
    p = urllib.parse.quote(pw, safe="")
    tag = host.replace(":", "-")
    return [
        f"tuic://{uid}:{p}@{host}:{port}?congestion_control=bbr"
        f"&udp_relay_mode=native&alpn=h3&sni={sni}&allow_insecure=1"
        f"&pinSHA256={fp}#tuic-{tag}",
        f"anytls://{p}@{host}:{port}?sni={sni}&insecure=1&fp=chrome"
        f"&pinSHA256={fp}#anytls-{tag}",
    ]


# ---------------- 全局参数 ----------------
SERVER_PORT = int(os.environ.get("SERVER_PORT") or 443)
SERVER_HOST = os.environ.get("SERVER_HOST") or public_ip()
SNI = os.environ.get("SNI") or SERVER_HOST
PASSWORD = os.environ.get("PASSWORD") or secrets.token_hex(16)
TUIC_UUID = os.environ.get("TUIC_UUID") or str(uuid.uuid4())
# ----------------------------------------


def main():
    os.makedirs(TMP, exist_ok=True)

    fetch_binary()
    make_cert(SERVER_HOST)

    fp = fingerprint()
    with open(CONF, "w") as f:
        json.dump(build_config(SERVER_PORT, TUIC_UUID, PASSWORD), f, indent=2)

    nodes = build_nodes(SERVER_HOST, SERVER_PORT, TUIC_UUID, PASSWORD, SNI, fp)
    with open(NODES, "w") as f:
        f.write("\n".join(nodes) + "\n")

    subprocess.run([BIN, "check", "-c", CONF], check=True)

    log(f"地址 {SERVER_HOST}:{SERVER_PORT}（TUIC/UDP + AnyTLS/TCP 共用）")
    log(f"密码 {PASSWORD}")
    log(f"证书 SHA-256 {fp}")
    for n in nodes:
        log(n)
    log(f"节点已写入 {NODES}，启动 sing-box")

    proc = subprocess.Popen([BIN, "run", "-c", CONF])
    try:
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        proc.wait()
    sys.exit(proc.returncode)


if __name__ == "__main__":
    main()
```

参数已全部提到模块级全局变量（`SERVER_PORT` / `SERVER_HOST` / `SNI` / `PASSWORD` / `TUIC_UUID`），`main()` 不再接收任何参数，直接读取全局值；仍可用同名环境变量覆盖，不填则自动生成密码和 UUID、自动探测公网 IP。

`requirements.txt` 不变：



```
cryptography>=42.0.0
```

增加vless+ws搭配固定隧道节点，ARGO_TOKEN有填写时启用，ARGO_PORT默认8080，ARGO_DOMAIN可填写或不填写，WS_PATH路径默认/vless，不需要下载cloudflared，sing-box本身就支持隧道了

已运行 31s · 6 个步骤

`cloudflared` 在 sing-box 1.14 里是 **inbound**（内嵌 tunnel 客户端，把隧道流量交给路由引擎），所以要配一个本地 VLESS+WS 入站加一条回环出站把流量转给它。以下为完整文件：

python



```python
#!/usr/bin/env python3
"""sing-box 一键部署：TUIC(UDP) + AnyTLS(TCP) 共用端口、共用密码、共用自签证书。
ARGO_TOKEN 存在时追加 VLESS+WS 固定隧道节点。"""
import ipaddress
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tarfile
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone

VER = "1.14.4"
URL = (f"https://github.com/SagerNet/sing-box/releases/download/v{VER}/"
       f"sing-box-{VER}-linux-amd64-musl.tar.gz")

BASE = os.path.dirname(os.path.abspath(__file__))
TMP = os.path.join(BASE, ".tmp")
BIN = os.path.join(TMP, "sing-box")
CONF = os.path.join(TMP, "config.json")
CERT = os.path.join(TMP, "cert.pem")
KEY = os.path.join(TMP, "key.pem")
NODES = os.path.join(TMP, "nodes.txt")

DAYS = 3650


def log(msg):
    print(f"[*] {msg}", flush=True)


def is_ip(h):
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def public_ip():
    for url in ("https://api.ipify.org", "https://ipv4.icanhazip.com"):
        try:
            with urllib.request.urlopen(url, timeout=6) as r:
                ip = r.read().decode().strip()
            if ip:
                return ip
        except Exception:
            pass
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return "127.0.0.1"


def fetch_binary():
    if os.path.isfile(BIN) and os.access(BIN, os.X_OK):
        return
    log(f"下载 sing-box {VER} ...")
    tgz = os.path.join(TMP, "sb.tar.gz")
    urllib.request.urlretrieve(URL, tgz)
    with tarfile.open(tgz, "r:gz") as tar:
        for m in tar.getmembers():
            if m.name.endswith("sing-box") and m.isfile():
                with tar.extractfile(m) as f, open(BIN, "wb") as out:
                    out.write(f.read())
                break
    os.chmod(BIN, 0o755)
    os.remove(tgz)
    log("二进制就绪")


def make_cert(host):
    if os.path.isfile(CERT) and os.path.isfile(KEY):
        return
    san = f"IP:{host}" if is_ip(host) else f"DNS:{host}"

    if shutil.which("openssl"):
        try:
            subprocess.run(
                ["openssl", "req", "-x509", "-newkey", "ec",
                 "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                 "-keyout", KEY, "-out", CERT, "-days", str(DAYS),
                 "-subj", f"/CN={host}", "-addext", f"subjectAltName={san}"],
                check=True, capture_output=True)
            log("已用 openssl 生成自签证书")
            return
        except Exception as e:
            log(f"openssl 不可用（{e}），改用 cryptography")

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    alt = [x509.IPAddress(ipaddress.ip_address(host))] if is_ip(host) \
        else [x509.DNSName(host)]
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=DAYS))
            .add_extension(x509.SubjectAlternativeName(alt), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                           critical=True)
            .sign(key, hashes.SHA256()))
    with open(KEY, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    with open(CERT, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    os.chmod(KEY, 0o600)
    log("已用 cryptography 生成自签证书")


def fingerprint():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    with open(CERT, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    return ":".join(f"{b:02X}" for b in cert.fingerprint(hashes.SHA256()))


def build_config():
    inbounds = [
        {
            "type": "tuic", "tag": "tuic-in",
            "listen": "::", "listen_port": SERVER_PORT,
            "users": [{"name": "user", "uuid": TUIC_UUID, "password": PASSWORD}],
            "congestion_control": "bbr",
            "tls": {"enabled": True, "alpn": ["h3"],
                    "certificate_path": CERT, "key_path": KEY},
        },
        {
            "type": "anytls", "tag": "anytls-in",
            "listen": "::", "listen_port": SERVER_PORT,
            "users": [{"name": "user", "password": PASSWORD}],
            "tls": {"enabled": True, "alpn": ["h2", "http/1.1"],
                    "certificate_path": CERT, "key_path": KEY},
        },
    ]
    outbounds = [{"type": "direct", "tag": "direct"}]
    rules = []

    if ARGO_TOKEN:
        inbounds.append({
            "type": "vless", "tag": "vless-ws-in",
            "listen": "127.0.0.1", "listen_port": ARGO_PORT,
            "users": [{"name": "user", "uuid": VLESS_UUID}],
            "transport": {"type": "ws", "path": WS_PATH},
        })
        inbounds.append({
            "type": "cloudflared", "tag": "argo-in", "token": ARGO_TOKEN,
        })
        outbounds.append({
            "type": "vless", "tag": "argo-out",
            "server": "127.0.0.1", "server_port": ARGO_PORT,
            "uuid": VLESS_UUID,
            "transport": {"type": "ws", "path": WS_PATH},
        })
        rules.append({"inbound": ["argo-in"], "outbound": "argo-out"})

    return {
        "log": {"level": "info", "timestamp": True},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {"rules": rules, "final": "direct"},
    }


def build_nodes(host, port, uid, pw, sni, fp):
    p = urllib.parse.quote(pw, safe="")
    tag = host.replace(":", "-")
    nodes = [
        f"tuic://{uid}:{p}@{host}:{port}?congestion_control=bbr"
        f"&udp_relay_mode=native&alpn=h3&sni={sni}&allow_insecure=1"
        f"&pinSHA256={fp}#tuic-{tag}",
        f"anytls://{p}@{host}:{port}?sni={sni}&insecure=1&fp=chrome"
        f"&pinSHA256={fp}#anytls-{tag}",
    ]
    if ARGO_TOKEN:
        d = ARGO_DOMAIN or "YOUR-ARGO-DOMAIN"
        nodes.append(
            f"vless://{VLESS_UUID}@{d}:443?encryption=none&security=tls"
            f"&type=ws&host={d}&sni={d}&fp=chrome"
            f"&path={urllib.parse.quote(WS_PATH, safe='')}#vless-ws-{d}")
    return nodes


# ---------------- 全局参数 ----------------
SERVER_PORT = int(os.environ.get("SERVER_PORT") or 443)
SERVER_HOST = os.environ.get("SERVER_HOST") or public_ip()
SNI = os.environ.get("SNI") or SERVER_HOST
PASSWORD = os.environ.get("PASSWORD") or secrets.token_hex(16)
TUIC_UUID = os.environ.get("TUIC_UUID") or str(uuid.uuid4())

ARGO_TOKEN = (os.environ.get("ARGO_TOKEN") or "").strip()
ARGO_PORT = int(os.environ.get("ARGO_PORT") or 8080)
ARGO_DOMAIN = (os.environ.get("ARGO_DOMAIN") or "").strip().rstrip("/")
WS_PATH = os.environ.get("WS_PATH") or "/vless"
VLESS_UUID = os.environ.get("VLESS_UUID") or TUIC_UUID
if not WS_PATH.startswith("/"):
    WS_PATH = "/" + WS_PATH
# ----------------------------------------


def main():
    os.makedirs(TMP, exist_ok=True)

    fetch_binary()
    make_cert(SERVER_HOST)

    fp = fingerprint()
    with open(CONF, "w") as f:
        json.dump(build_config(), f, indent=2)

    nodes = build_nodes(SERVER_HOST, SERVER_PORT, TUIC_UUID, PASSWORD, SNI, fp)
    with open(NODES, "w") as f:
        f.write("\n".join(nodes) + "\n")

    subprocess.run([BIN, "check", "-c", CONF], check=True)

    log(f"地址 {SERVER_HOST}:{SERVER_PORT}（TUIC/UDP + AnyTLS/TCP 共用）")
    log(f"密码 {PASSWORD}")
    log(f"证书 SHA-256 {fp}")
    for n in nodes:
        log(n)
    if ARGO_TOKEN:
        log(f"Argo 隧道已启用，本地 WS 127.0.0.1:{ARGO_PORT}{WS_PATH}")
        log("请在 Cloudflare Zero Trust 的隧道 Public Hostname 里指向"
            f" http://localhost:{ARGO_PORT}（路径无需改写）")
        if not ARGO_DOMAIN:
            log("未填 ARGO_DOMAIN，节点域名以 YOUR-ARGO-DOMAIN 占位，请自行替换")
    log(f"节点已写入 {NODES}，启动 sing-box")

    proc = subprocess.Popen([BIN, "run", "-c", CONF])
    try:
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        proc.wait()
    sys.exit(proc.returncode)


if __name__ == "__main__":
    main()
```

用法：


```bash
ARGO_TOKEN='eyJhIjoi...' ARGO_DOMAIN='t.example.com' SERVER_PORT=443 python3 app.py
```

要点：

+ `cloudflared` 入站把隧道流量丢进路由，`route.rules` 只把 `argo-in` 的流量转给 `argo-out`（指向本地 `127.0.0.1:8080` 的 VLESS+WS 出站），其余流量仍走 `direct`，不会成环。
+ 本地 WS 入站只监听 `127.0.0.1`，公网入口只有 Cloudflare 边缘；`ARGO_PORT`、`WS_PATH`、`VLESS_UUID` 均可改。
+ `ARGO_DOMAIN` 不填也能跑，只是节点链接域名留占位符，需要你按隧道里的 Public Hostname 补上；隧道侧回源填 `http://localhost:8080`。
+ 只有 `ARGO_TOKEN` 非空才生成 VLESS 入站、隧道入站与第三条节点，未填时配置与之前完全一致。
