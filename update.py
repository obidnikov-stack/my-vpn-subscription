import requests
import socket
import urllib.parse
import base64
import re
from concurrent.futures import ThreadPoolExecutor, as_completed


OWNER = "igareck"
REPO = "vpn-configs-for-russia"

API = f"https://api.github.com/repos/{OWNER}/{REPO}/contents"

ALLOWED = (
    "vless://",
    "vmess://",
    "ss://",
    "trojan://",
    "hysteria2://",
    "hy2://",
    "tuic://",
)

# Сколько секунд ждать подключения к одному серверу
TIMEOUT = 3

# Одновременно проверяем столько серверов
MAX_WORKERS = 50


def get_files():
    print("Получаем список файлов...")

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
        download_url = file.get("download_url")

        if not name.lower().endswith(".txt"):
            continue

        if not download_url:
            continue

        print(f"Скачиваем: {name}")

        try:
            response = requests.get(
                download_url,
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


def decode_base64_url(data):
    """
    Пытаемся декодировать base64 для ss://
    """

    try:
        data += "=" * (-len(data) % 4)

        decoded = base64.urlsafe_b64decode(data).decode(
            "utf-8",
            errors="ignore"
        )

        return decoded

    except Exception:
        return ""


def extract_host_port(config):
    """
    Извлекает host и port из популярных VPN-ссылок.
    """

    try:

        # -------------------------
        # VLESS / TROJAN / HY2
        # -------------------------

        if config.startswith(
            (
                "vless://",
                "trojan://",
                "hysteria2://",
                "hy2://",
            )
        ):
            parsed = urllib.parse.urlparse(config)

            host = parsed.hostname
            port = parsed.port

            if host and port:
                return host, port

        # -------------------------
        # VMESS
        # -------------------------

        if config.startswith("vmess://"):

            encoded = config[8:].split("#")[0]

            decoded = decode_base64_url(encoded)

            if not decoded:
                return None

            match = re.search(
                r'"add"\s*:\s*"([^"]+)"',
                decoded
            )

            port_match = re.search(
                r'"port"\s*:\s*(\d+)',
                decoded
            )

            if match and port_match:
                host = match.group(1)
                port = int(port_match.group(1))

                return host, port

        # -------------------------
        # Shadowsocks
        # -------------------------

        if config.startswith("ss://"):

            data = config[5:].split("#")[0]

            # ss://base64@host:port
            if "@" in data:

                server_part = data.rsplit("@", 1)[1]

                parsed = urllib.parse.urlparse(
                    "dummy://" + server_part
                )

                host = parsed.hostname
                port = parsed.port

                if host and port:
                    return host, port

            # ss://base64
            decoded = decode_base64_url(data)

            if decoded and "@" in decoded:

                server_part = decoded.rsplit("@", 1)[1]

                parsed = urllib.parse.urlparse(
                    "dummy://" + server_part
                )

                host = parsed.hostname
                port = parsed.port

                if host and port:
                    return host, port

    except Exception:
        pass

    return None


def check_server(config):
    """
    Проверяет TCP-доступность сервера.
    """

    result = extract_host_port(config)

    if not result:
        return config, False

    host, port = result

    try:

        with socket.create_connection(
            (host, port),
            timeout=TIMEOUT
        ):
            return config, True

    except Exception:
        return config, False


def check_all_configs(configs):

    print()
    print("======================================")
    print("НАЧИНАЕМ ПРОВЕРКУ СЕРВЕРОВ")
    print("======================================")
    print()

    working = []
    dead = []

    total = len(configs)

    with ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:

        futures = {
            executor.submit(
                check_server,
                config
            ): config
            for config in configs
        }

        completed = 0

        for future in as_completed(futures):

            config = futures[future]

            try:
                config, status = future.result()

            except Exception:
                status = False

            completed += 1

            if status:
                working.append(config)

                print(
                    f"[{completed}/{total}] OK"
                )

            else:
                dead.append(config)

                print(
                    f"[{completed}/{total}] DEAD"
                )

    print()
    print("--------------------------------------")
    print(f"Всего:       {total}")
    print(f"Рабочих:     {len(working)}")
    print(f"Недоступных: {len(dead)}")
    print("--------------------------------------")
    print()

    return sorted(working)


def save_subscription(configs):

    with open(
        "unified.txt",
        "w",
        encoding="utf-8",
        newline="\n"
    ) as f:

        # Название подписки INCY
        f.write("#profile-title: VolkovVPN\n")

        # Автообновление профиля
        f.write("#profile-update-interval: 6\n")

        for config in configs:
            f.write(config + "\n")

    print("unified.txt сохранён.")
    print(f"Рабочих конфигов: {len(configs)}")


def main():

    print("======================================")
    print("        VOLKOVVPN UPDATER")
    print("======================================")
    print()

    # Получаем список файлов
    files = get_files()

    # Скачиваем конфиги
    configs = download_configs(files)

    print()
    print(f"Получено уникальных конфигов: {len(configs)}")

    # Проверяем серверы
    working_configs = check_all_configs(configs)

    # Сохраняем только рабочие
    save_subscription(working_configs)

    print()
    print("======================================")
    print("VOLKOVVPN ГОТОВ")
    print("======================================")


if __name__ == "__main__":
    main()
