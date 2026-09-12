import base64
import json
import os
import random
import re
import socket
import subprocess
import tempfile
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests


OWNER = "igareck"
REPO = "vpn-configs-for-russia"

API = f"https://api.github.com/repos/{OWNER}/{REPO}/contents"

SING_BOX = "./sing-box"

# Сколько серверов проверять одновременно
MAX_WORKERS = 8

# Сколько секунд максимум ждать один сервер
CHECK_TIMEOUT = 8

# Сайт для проверки реального выхода через VPN
TEST_URL = "https://www.gstatic.com/generate_204"

ALLOWED = (
    "vless://",
    "vmess://",
    "ss://",
    "trojan://",
    "hysteria2://",
    "hy2://",
    "tuic://",
)


# ============================================================
# GitHub
# ============================================================

def get_files():
    response = requests.get(
        API,
        headers={"Accept": "application/vnd.github+json"},
        timeout=30,
    )

    response.raise_for_status()

    return response.json()


def download_configs(files):
    configs = set()

    for file in files:

        name = file.get("name", "")
        url = file.get("download_url")

        if not name.lower().endswith(".txt"):
            continue

        if not url:
            continue

        print(f"Скачиваем: {name}")

        try:
            response = requests.get(
                url,
                timeout=30,
            )

            response.raise_for_status()

            for line in response.text.splitlines():

                line = line.strip()

                if not line:
                    continue

                if line.startswith("#"):
                    continue

                if line.startswith(ALLOWED):
                    configs.add(line)

        except Exception as e:
            print(f"Ошибка {name}: {e}")

    return sorted(configs)


# ============================================================
# Base64
# ============================================================

def b64decode(text):

    try:
        text = text.strip()

        text += "=" * (-len(text) % 4)

        return base64.urlsafe_b64decode(
            text
        ).decode(
            "utf-8",
            errors="ignore"
        )

    except Exception:
        return ""


def b64encode(text):

    return base64.urlsafe_b64encode(
        text.encode()
    ).decode()


# ============================================================
# VLESS
# ============================================================

def parse_vless(uri):

    parsed = urllib.parse.urlparse(uri)

    query = urllib.parse.parse_qs(
        parsed.query
    )

    server = parsed.hostname
    port = parsed.port
    uuid = parsed.username

    if not server or not port or not uuid:
        return None

    outbound = {
        "type": "vless",
        "tag": "proxy",
        "server": server,
        "server_port": port,
        "uuid": uuid,
    }

    # flow
    flow = query.get("flow", [None])[0]

    if flow:
        outbound["flow"] = flow

    # network
    network = query.get(
        "type",
        query.get("network", ["tcp"])
    )[0]

    if network:
        outbound["network"] = network

    # TLS
    security = query.get(
        "security",
        [""]
    )[0]

    if security == "tls":

        tls = {
            "enabled": True
        }

        sni = query.get("sni", [None])[0]

        if sni:
            tls["server_name"] = sni

        fp = query.get("fp", [None])[0]

        if fp:
            tls["utls"] = {
                "enabled": True,
                "fingerprint": fp,
            }

        outbound["tls"] = tls

    # Reality
    if security == "reality":

        tls = {
            "enabled": True
        }

        sni = query.get("sni", [None])[0]

        if sni:
            tls["server_name"] = sni

        fp = query.get("fp", [None])[0]

        if fp:
            tls["utls"] = {
                "enabled": True,
                "fingerprint": fp,
            }

        pbk = query.get("pbk", [None])[0]

        sid = query.get("sid", [None])[0]

        reality = {
            "enabled": True
        }

        if pbk:
            reality["public_key"] = pbk

        if sid:
            reality["short_id"] = sid

        tls["reality"] = reality

        outbound["tls"] = tls

    # Transport
    transport_type = network

    if transport_type == "ws":

        transport = {
            "type": "ws"
        }

        path = query.get(
            "path",
            ["/"]
        )[0]

        transport["path"] = path

        host = query.get(
            "host",
            [None]
        )[0]

        if host:
            transport["headers"] = {
                "Host": host
            }

        outbound["transport"] = transport

    elif transport_type == "grpc":

        service_name = query.get(
            "serviceName",
            [""]
        )[0]

        outbound["transport"] = {
            "type": "grpc",
            "service_name": service_name,
        }

    return outbound


# ============================================================
# VMESS
# ============================================================

def parse_vmess(uri):

    encoded = uri[len("vmess://"):]

    encoded = encoded.split("#")[0]

    decoded = b64decode(encoded)

    if not decoded:
        return None

    try:
        data = json.loads(decoded)
    except Exception:
        return None

    server = data.get("add")
    port = data.get("port")
    uuid = data.get("id")

    if not server or not port or not uuid:
        return None

    outbound = {
        "type": "vmess",
        "tag": "proxy",
        "server": server,
        "server_port": int(port),
        "uuid": uuid,
        "security": data.get("scy", "auto"),
    }

    network = data.get(
        "net",
        "tcp"
    )

    outbound["network"] = network

    if data.get("tls"):

        tls = {
            "enabled": True
        }

        if data.get("sni"):
            tls["server_name"] = data["sni"]

        outbound["tls"] = tls

    if network == "ws":

        transport = {
            "type": "ws",
            "path": data.get(
                "path",
                "/"
            )
        }

        host = data.get("host")

        if host:
            transport["headers"] = {
                "Host": host
            }

        outbound["transport"] = transport

    elif network == "grpc":

        outbound["transport"] = {
            "type": "grpc",
            "service_name": data.get(
                "path",
                ""
            )
        }

    return outbound


# ============================================================
# TROJAN
# ============================================================

def parse_trojan(uri):

    parsed = urllib.parse.urlparse(uri)

    query = urllib.parse.parse_qs(
        parsed.query
    )

    server = parsed.hostname
    port = parsed.port
    password = parsed.username

    if not server or not port or not password:
        return None

    outbound = {
        "type": "trojan",
        "tag": "proxy",
        "server": server,
        "server_port": port,
        "password": urllib.parse.unquote(
            password
        ),
    }

    tls = {
        "enabled": True
    }

    sni = query.get(
        "sni",
        [None]
    )[0]

    if sni:
        tls["server_name"] = sni

    fp = query.get(
        "fp",
        [None]
    )[0]

    if fp:

        tls["utls"] = {
            "enabled": True,
            "fingerprint": fp,
        }

    outbound["tls"] = tls

    network = query.get(
        "type",
        ["tcp"]
    )[0]

    if network == "ws":

        outbound["transport"] = {
            "type": "ws",
            "path": query.get(
                "path",
                ["/"]
            )[0],
        }

    elif network == "grpc":

        outbound["transport"] = {
            "type": "grpc",
            "service_name": query.get(
                "serviceName",
                [""]
            )[0],
        }

    return outbound


# ============================================================
# SHADOWSOCKS
# ============================================================

def parse_ss(uri):

    value = uri[len("ss://"):]

    value = value.split("#")[0]

    # SIP002:
    # ss://base64(method:password)@host:port
    if "@" in value:

        encoded_user, server_part = value.rsplit(
            "@",
            1
        )

        decoded = b64decode(
            encoded_user
        )

        if ":" not in decoded:
            return None

        method, password = decoded.split(
            ":",
            1
        )

        parsed = urllib.parse.urlparse(
            "dummy://" + server_part
        )

    else:

        decoded = b64decode(value)

        if "@" not in decoded:
            return None

        credentials, server_part = decoded.rsplit(
            "@",
            1
        )

        if ":" not in credentials:
            return None

        method, password = credentials.split(
            ":",
            1
        )

        parsed = urllib.parse.urlparse(
            "dummy://" + server_part
        )

    host = parsed.hostname
    port = parsed.port

    if not host or not port:
        return None

    return {
        "type": "shadowsocks",
        "tag": "proxy",
        "server": host,
        "server_port": port,
        "method": method,
        "password": password,
    }


# ============================================================
# HYSTERIA2
# ============================================================

def parse_hysteria2(uri):

    parsed = urllib.parse.urlparse(uri)

    query = urllib.parse.parse_qs(
        parsed.query
    )

    server = parsed.hostname
    port = parsed.port

    password = parsed.username

    if not server or not port or not password:
        return None

    outbound = {
        "type": "hysteria2",
        "tag": "proxy",
        "server": server,
        "server_port": port,
        "password": urllib.parse.unquote(
            password
        ),
    }

    tls = {
        "enabled": True
    }

    sni = query.get(
        "sni",
        [None]
    )[0]

    if sni:
        tls["server_name"] = sni

    outbound["tls"] = tls

    return outbound


# ============================================================
# TUIC
# ============================================================

def parse_tuic(uri):

    parsed = urllib.parse.urlparse(uri)

    query = urllib.parse.parse_qs(
        parsed.query
    )

    server = parsed.hostname
    port = parsed.port

    uuid = parsed.username
    password = parsed.password

    if (
        not server
        or not port
        or not uuid
        or not password
    ):
        return None

    outbound = {
        "type": "tuic",
        "tag": "proxy",
        "server": server,
        "server_port": port,
        "uuid": uuid,
        "password": password,
    }

    tls = {
        "enabled": True
    }

    sni = query.get(
        "sni",
        [None]
    )[0]

    if sni:
        tls["server_name"] = sni

    outbound["tls"] = tls

    return outbound


# ============================================================
# URI → sing-box
# ============================================================

def convert_config(uri):

    try:

        if uri.startswith("vless://"):
            return parse_vless(uri)

        if uri.startswith("vmess://"):
            return parse_vmess(uri)

        if uri.startswith("trojan://"):
            return parse_trojan(uri)

        if uri.startswith("ss://"):
            return parse_ss(uri)

        if uri.startswith(
            ("hysteria2://", "hy2://")
        ):
            return parse_hysteria2(uri)

        if uri.startswith("tuic://"):
            return parse_tuic(uri)

    except Exception:
        return None

    return None


# ============================================================
# Проверка
# ============================================================

def check_server(uri):

    outbound = convert_config(uri)

    if not outbound:
        return uri, False

    # Уникальный порт для локального SOCKS
    socks_port = random.randint(
        20000,
        50000
    )

    config = {
        "log": {
            "level": "error"
        },

        "inbounds": [
            {
                "type": "mixed",
                "tag": "local",
                "listen": "127.0.0.1",
                "listen_port": socks_port,
            }
        ],

        "outbounds": [
            outbound,
            {
                "type": "direct",
                "tag": "direct"
            }
        ],

        "route": {
            "final": "proxy"
        }
    }

    process = None

    try:

        with tempfile.TemporaryDirectory() as temp:

            config_path = os.path.join(
                temp,
                "config.json"
            )

            with open(
                config_path,
                "w",
                encoding="utf-8"
            ) as f:
                json.dump(
                    config,
                    f,
                    ensure_ascii=False
                )

            # Проверяем конфигурацию
            check = subprocess.run(
                [
                    SING_BOX,
                    "check",
                    "-c",
                    config_path,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
            )

            if check.returncode != 0:
                return uri, False

            # Запускаем sing-box
            process = subprocess.Popen(
                [
                    SING_BOX,
                    "run",
                    "-c",
                    config_path,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            # Даём прокси запуститься
            time.sleep(1.2)

            # Проверяем именно запрос ЧЕРЕЗ VPN
            result = subprocess.run(
                [
                    "curl",
                    "-4",
                    "-L",
                    "--max-time",
                    str(CHECK_TIMEOUT),
                    "--proxy",
                    f"socks5h://127.0.0.1:{socks_port}",
                    "-o",
                    "/dev/null",
                    "-s",
                    "-w",
                    "%{http_code}",
                    TEST_URL,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=CHECK_TIMEOUT + 3,
            )

            code = result.stdout.strip()

            if code in (
                "200",
                "204",
                "301",
                "302",
            ):
                return uri, True

    except Exception:
        pass

    finally:

        if process:

            try:
                process.terminate()

                process.wait(
                    timeout=2
                )

            except Exception:

                try:
                    process.kill()
                except Exception:
                    pass

    return uri, False


# ============================================================
# Проверка всех
# ============================================================

def check_all(configs):

    working = []

    total = len(configs)

    print()
    print("=" * 60)
    print("РЕАЛЬНАЯ ПРОВЕРКА VPN")
    print("=" * 60)
    print(f"Конфигов: {total}")
    print(f"Параллельно: {MAX_WORKERS}")
    print("=" * 60)

    completed = 0

    with ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:

        futures = [
            executor.submit(
                check_server,
                config
            )
            for config in configs
        ]

        for future in as_completed(futures):

            completed += 1

            try:

                config, status = future.result()

                if status:

                    working.append(config)

                    print(
                        f"[{completed}/{total}] OK"
                    )

                else:

                    print(
                        f"[{completed}/{total}] DEAD"
                    )

            except Exception:

                print(
                    f"[{completed}/{total}] ERROR"
                )

    print()
    print("=" * 60)
    print(f"Всего:   {total}")
    print(f"Рабочих: {len(working)}")
    print(f"Мёртвых: {total - len(working)}")
    print("=" * 60)

    return sorted(
        set(working)
    )


# ============================================================
# Сохранение
# ============================================================

def save_subscription(configs):

    with open(
        "unified.txt",
        "w",
        encoding="utf-8",
        newline="\n"
    ) as f:

        f.write(
            "#profile-title: VolkovVPN\n"
        )

        f.write(
            "#profile-update-interval: 6\n"
        )

        for config in configs:

            f.write(
                config + "\n"
            )


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 60)
    print("VOLKOVVPN")
    print("=" * 60)

    files = get_files()

    configs = download_configs(
        files
    )

    print(
        f"\nПолучено конфигов: {len(configs)}"
    )

    if not configs:

        print(
            "Конфиги не найдены."
        )

        return

    working = check_all(
        configs
    )

    save_subscription(
        working
    )

    print()
    print(
        f"VolkovVPN: {len(working)} рабочих серверов"
    )


if __name__ == "__main__":
    main()
