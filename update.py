import requests

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

configs = set()

response = requests.get(API, timeout=30)
response.raise_for_status()

files = response.json()

for file in files:
    name = file["name"]

    if not name.lower().endswith(".txt"):
        continue

    try:
        text = requests.get(
            file["download_url"],
            timeout=30
        ).text

        for line in text.splitlines():
            line = line.strip()

            if line.startswith(ALLOWED):
                configs.add(line)

    except Exception as e:
        print(f"Ошибка {name}: {e}")

configs = sorted(configs)

with open("unified.txt", "w", encoding="utf-8") as f:
    for config in configs:
        f.write(config + "\n")

print(f"Готово. Конфигов собрано: {len(configs)}")
