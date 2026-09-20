import base64
import hashlib
import json
import os
import re
import socket
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

import requests

OWNER = "igareck"
REPO = "vpn-configs-for-russia"
BRANCH = "main"

ALLOWED = (
    "vless://", "vmess://", "ss://", "trojan://",
    "hysteria2://", "hy2://", "tuic://"
)

SING_BOX = "./sing-box"
SOCKS_BASE_PORT = 18080
MAX_WORKERS = 16
PROXY_TIMEOUT = 7
TCP_TIMEOUT = 3
TOP_FOR_DEEP_TEST = 80
TOP_FASTEST = 20
SPEED_TEST_CANDIDATES = 40
SPEED_TEST_BYTES = 512_000
STATE_FILE = Path("server_state.json")
FAILED_FILE = Path("failed.txt")
UNIFIED_FILE = Path("unified.txt")
FASTEST_FILE = Path("fastest.txt")

TEST_URLS = [
    "https://www.gstatic.com/generate_204",
    "https://www.google.com/generate_204",
]

session = requests.Session()
session.headers.update({"User-Agent": "VolkovVPN-Updater/2.0"})


def cfg_id(url: str) -> str:
    return hashlib.sha256(url.strip().encode()).hexdigest()[:16]


def collect_txt_files():
    """Collect all .txt files from the locally cloned upstream repository."""
    root = Path("source_repo")
    if not root.exists():
        raise RuntimeError("source_repo not found. Clone the upstream repository first.")

    files = []
    for path in root.rglob("*.txt"):
        if path.is_file():
            files.append(path)

    files.sort()
    return files


def extract_configs(files):
    """Extract supported VPN URLs from locally downloaded source files."""
    configs = []
    by_file = {}
    seen = set()

    for path in files:
        rel = str(path.relative_to("source_repo")).replace("\\", "/")
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            by_file[rel] = f"read_error: {e}"
            continue

        count = 0
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            m = re.search(
                r"(?:vless|vmess|ss|trojan|hysteria2|hy2|tuic)://\S+",
                line,
                re.I,
            )
            if not m:
                continue

            u = m.group(0).rstrip("'\"),;]")
            if not u.lower().startswith(ALLOWED):
                continue

            # Keep the URI fragment (usually the server name), but do not
            # accidentally include a plain text comment after the URL.
            if u not in seen:
                seen.add(u)
                configs.append((u, rel))
                count += 1

        by_file[rel] = count

    return configs, by_file

def q1(qs, key, default=""):
    v = qs.get(key, [default])
    return v[0] if v else default


def tls_obj(qs):
    sec = q1(qs, "security", "")
    if sec not in ("tls", "reality"):
        return None
    tls = {"enabled": True}
    sni = q1(qs, "sni") or q1(qs, "serverName") or q1(qs, "host")
    if sni:
        tls["server_name"] = sni
    fp = q1(qs, "fp") or q1(qs, "fingerprint")
    if fp:
        tls["utls"] = {"enabled": True, "fingerprint": fp}
    if sec == "reality":
        pbk = q1(qs, "pbk") or q1(qs, "publicKey")
        sid = q1(qs, "sid") or q1(qs, "shortId")
        reality = {"enabled": True}
        if pbk:
            reality["public_key"] = pbk
        if sid:
            reality["short_id"] = sid
        tls["reality"] = reality
    return tls


def transport_obj(qs):
    net = q1(qs, "type") or q1(qs, "network", "tcp")
    net = net.lower()
    if net in ("tcp", "none", ""):
        return None
    if net == "ws":
        tr = {"type": "ws"}
        path = q1(qs, "path")
        host = q1(qs, "host")
        if path:
            tr["path"] = unquote(path)
        if host:
            tr["headers"] = {"Host": host}
        return tr
    if net == "grpc":
        tr = {"type": "grpc"}
        service = q1(qs, "serviceName") or q1(qs, "service_name")
        if service:
            tr["service_name"] = service
        return tr
    if net == "http":
        tr = {"type": "http"}
        host = q1(qs, "host")
        path = q1(qs, "path")
        if host:
            tr["host"] = [host]
        if path:
            tr["path"] = unquote(path)
        return tr
    return None


def parse_vless(url):
    p = urlparse(url)
    if not p.hostname or not p.port or not p.username:
        raise ValueError("invalid_vless")
    qs = parse_qs(p.query, keep_blank_values=True)
    out = {
        "type": "vless", "tag": "proxy",
        "server": p.hostname, "server_port": p.port,
        "uuid": unquote(p.username),
        "network": q1(qs, "type", "tcp"),
    }
    flow = q1(qs, "flow")
    if flow:
        out["flow"] = flow
    tls = tls_obj(qs)
    if tls:
        out["tls"] = tls
    tr = transport_obj(qs)
    if tr:
        out["transport"] = tr
    return out


def parse_vmess(url):
    raw = url.split("//", 1)[1]
    raw += "=" * (-len(raw) % 4)
    data = json.loads(base64.urlsafe_b64decode(raw).decode("utf-8"))
    host = data.get("add") or data.get("host")
    port = int(data.get("port"))
    uuid = data.get("id")
    if not host or not port or not uuid:
        raise ValueError("invalid_vmess")
    out = {
        "type": "vmess", "tag": "proxy", "server": host,
        "server_port": port, "uuid": uuid,
        "security": data.get("scy") or "auto",
        "alter_id": int(data.get("aid") or 0),
        "network": data.get("net") or "tcp",
    }
    if str(data.get("tls", "")).lower() in ("tls", "true", "1"):
        tls = {"enabled": True}
        sni = data.get("sni") or data.get("host")
        if sni:
            tls["server_name"] = sni
        if data.get("fp"):
            tls["utls"] = {"enabled": True, "fingerprint": data["fp"]}
        out["tls"] = tls
    qs = {k: [v] for k, v in data.items()}
    tr = transport_obj(qs)
    if tr:
        out["transport"] = tr
    return out


def parse_trojan(url):
    p = urlparse(url)
    if not p.hostname or not p.port or not p.username:
        raise ValueError("invalid_trojan")
    qs = parse_qs(p.query, keep_blank_values=True)
    out = {
        "type": "trojan", "tag": "proxy",
        "server": p.hostname, "server_port": p.port,
        "password": unquote(p.username),
    }
    tls = tls_obj({**qs, "security": ["tls"]})
    out["tls"] = tls or {"enabled": True}
    tr = transport_obj(qs)
    if tr:
        out["transport"] = tr
    return out


def parse_ss(url):
    p = urlparse(url)
    if not p.hostname or not p.port:
        raise ValueError("invalid_ss")
    user = unquote(p.username or "")
    if ":" in user:
        method, password = user.split(":", 1)
    else:
        # ss://base64(method:password)@host:port OR ss://base64(method:password)
        token = url.split("ss://", 1)[1].split("#", 1)[0]
        if "@" in token:
            encoded_user = token.split("@", 1)[0]
            encoded_user += "=" * (-len(encoded_user) % 4)
            try:
                dec_user = base64.urlsafe_b64decode(encoded_user).decode()
                method, password = dec_user.split(":", 1)
            except Exception:
                raise ValueError("invalid_ss_base64_userinfo")
        else:
            token += "=" * (-len(token) % 4)
            try:
                dec = base64.urlsafe_b64decode(token).decode()
                user, hostpart = dec.rsplit("@", 1)
                method, password = user.split(":", 1)
                hp = hostpart.rsplit(":", 1)
                host, port = hp[0], int(hp[1])
            except Exception:
                raise ValueError("invalid_ss_base64")
    return {
        "type": "shadowsocks", "tag": "proxy",
        "server": p.hostname, "server_port": p.port,
        "method": method, "password": password,
    }


def parse_hy2(url):
    p = urlparse(url)
    if not p.hostname or not p.port:
        raise ValueError("invalid_hysteria2")
    qs = parse_qs(p.query, keep_blank_values=True)
    password = unquote(p.username or "")
    if p.password:
        password += ":" + unquote(p.password)
    if not password:
        password = q1(qs, "password")
    out = {
        "type": "hysteria2", "tag": "proxy",
        "server": p.hostname, "server_port": p.port,
        "password": password,
        "tls": {"enabled": True},
    }
    sni = q1(qs, "sni") or q1(qs, "peer")
    if sni:
        out["tls"]["server_name"] = sni
    insecure = q1(qs, "insecure", "0")
    if insecure in ("1", "true"):
        out["tls"]["insecure"] = True
    obfs = q1(qs, "obfs")
    obfs_password = q1(qs, "obfs-password") or q1(qs, "obfs_password")
    if obfs:
        out["obfs"] = {"type": obfs}
        if obfs_password:
            out["obfs"]["password"] = obfs_password
    return out


def parse_tuic(url):
    p = urlparse(url)
    if not p.hostname or not p.port or not p.username:
        raise ValueError("invalid_tuic")
    qs = parse_qs(p.query, keep_blank_values=True)
    password = unquote(p.password or "")
    out = {
        "type": "tuic", "tag": "proxy",
        "server": p.hostname, "server_port": p.port,
        "uuid": unquote(p.username), "password": password,
        "tls": {"enabled": True},
    }
    sni = q1(qs, "sni")
    if sni:
        out["tls"]["server_name"] = sni
    if q1(qs, "insecure", "0") in ("1", "true"):
        out["tls"]["insecure"] = True
    return out


def to_singbox(url):
    low = url.lower()
    if low.startswith("vless://"):
        return parse_vless(url)
    if low.startswith("vmess://"):
        return parse_vmess(url)
    if low.startswith("ss://"):
        return parse_ss(url)
    if low.startswith("trojan://"):
        return parse_trojan(url)
    if low.startswith("hysteria2://") or low.startswith("hy2://"):
        return parse_hy2(url)
    if low.startswith("tuic://"):
        return parse_tuic(url)
    raise ValueError("unsupported_protocol")


def tcp_prefilter(url):
    try:
        p = urlparse(url)
        if p.scheme == "vmess":
            # VMess host/port are encoded, so parse it.
            obj = parse_vmess(url)
            host, port = obj["server"], obj["server_port"]
        else:
            obj = to_singbox(url)
            host, port = obj["server"], obj["server_port"]
        with socket.create_connection((host, int(port)), timeout=TCP_TIMEOUT):
            return True, "tcp_ok"
    except Exception as e:
        return False, f"tcp_failed:{type(e).__name__}"


def run_proxy_test(item, deep=False):
    url, source = item
    sid = cfg_id(url)
    port = SOCKS_BASE_PORT + (int(sid[:4], 16) % 2000)
    work = Path(tempfile.mkdtemp(prefix="volkov_"))
    conf = work / "config.json"
    log = work / "singbox.log"
    try:
        outbound = to_singbox(url)
        config = {
            "log": {"level": "error", "output": str(log)},
            "inbounds": [{"type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": port}],
            "outbounds": [outbound],
            "route": {"final": "proxy"},
        }
        conf.write_text(json.dumps(config, ensure_ascii=False), encoding="utf-8")
        proc = subprocess.Popen([SING_BOX, "run", "-c", str(conf)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        start = time.perf_counter()
        ok = False
        latency = None
        for _ in range(20):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                    break
            except Exception:
                time.sleep(0.1)
        for test_url in TEST_URLS:
            try:
                t0 = time.perf_counter()
                r = requests.get(test_url, proxies={"http": f"socks5h://127.0.0.1:{port}", "https": f"socks5h://127.0.0.1:{port}"}, timeout=PROXY_TIMEOUT, allow_redirects=False)
                dt = (time.perf_counter() - t0) * 1000
                if r.status_code in (200, 204, 301, 302):
                    ok = True
                    latency = dt if latency is None else min(latency, dt)
                    break
            except Exception:
                pass
        if not ok:
            return {"id": sid, "url": url, "source": source, "ok": False, "reason": "proxy_test_failed"}
        score = latency
        if deep:
            # A second independent request reduces false positives from transient success.
            success2 = False
            for test_url in TEST_URLS:
                try:
                    r = requests.get(test_url, proxies={"http": f"socks5h://127.0.0.1:{port}", "https": f"socks5h://127.0.0.1:{port}"}, timeout=PROXY_TIMEOUT, allow_redirects=False)
                    if r.status_code in (200, 204, 301, 302):
                        success2 = True
                        break
                except Exception:
                    pass
            if not success2:
                return {"id": sid, "url": url, "source": source, "ok": False, "reason": "second_test_failed"}
        return {"id": sid, "url": url, "source": source, "ok": True, "latency": round(score, 1)}
    except Exception as e:
        return {"id": sid, "url": url, "source": source, "ok": False, "reason": f"{type(e).__name__}:{e}"}
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=1)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        for f in work.glob("*"):
            try:
                f.unlink()
            except Exception:
                pass
        try:
            work.rmdir()
        except Exception:
            pass


def benchmark_speed(result):
    """Measure a small download through the proxy for the already-good candidates."""
    url = result["url"]
    sid = result["id"]
    port = SOCKS_BASE_PORT + (int(sid[:4], 16) % 2000)
    work = Path(tempfile.mkdtemp(prefix="volkov_speed_"))
    conf = work / "config.json"
    try:
        outbound = to_singbox(url)
        config = {
            "log": {"level": "error"},
            "inbounds": [{"type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": port}],
            "outbounds": [outbound],
            "route": {"final": "proxy"},
        }
        conf.write_text(json.dumps(config), encoding="utf-8")
        proc = subprocess.Popen([SING_BOX, "run", "-c", str(conf)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(20):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                    break
            except Exception:
                time.sleep(0.1)
        t0 = time.perf_counter()
        r = requests.get(
            "https://speed.cloudflare.com/__down?bytes=" + str(SPEED_TEST_BYTES),
            proxies={"http": f"socks5h://127.0.0.1:{port}", "https": f"socks5h://127.0.0.1:{port}"},
            timeout=8,
            stream=True,
            headers={"Range": f"bytes=0-{SPEED_TEST_BYTES-1}"},
        )
        total = 0
        for chunk in r.iter_content(64 * 1024):
            total += len(chunk)
            if total >= SPEED_TEST_BYTES:
                break
        elapsed = max(time.perf_counter() - t0, 0.001)
        if total < 50_000:
            raise RuntimeError("too_little_data")
        result["speed_mbps"] = round((total * 8) / elapsed / 1_000_000, 2)
        return result
    except Exception as e:
        result["speed_mbps"] = 0
        result["speed_error"] = type(e).__name__
        return result
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=1)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        for f in work.glob("*"):
            try:
                f.unlink()
            except Exception:
                pass
        try:
            work.rmdir()
        except Exception:
            pass


def load_state():
    if not STATE_FILE.exists():
        return {}
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_state(state):
    STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


def main():
    deep = os.getenv("DEEP_CHECK", "false").lower() == "true"
    print("=== VolkovVPN updater 2.0 ===")
    print(f"Deep check: {deep}")

    files = collect_txt_files()
    print(f"TXT файлов найдено: {len(files)}")
    configs, by_file = extract_configs(files)
    print(f"Конфигов найдено: {len(configs)}")
    for path, count in sorted(by_file.items()):
        print(f"  {path}: {count}")

    # Parse + TCP prefilter first. This prevents wasting a sing-box process on obviously dead endpoints.
    parsed = []
    failed = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(tcp_prefilter, item[0]): item for item in configs}
        for fut in as_completed(futures):
            item = futures[fut]
            try:
                ok, reason = fut.result()
            except Exception as e:
                ok, reason = False, f"prefilter_exception:{e}"
            if ok:
                parsed.append(item)
            else:
                failed.append({"id": cfg_id(item[0]), "url": item[0], "source": item[1], "reason": reason})
    print(f"После TCP-проверки: {len(parsed)}")

    state = load_state()
    results = []
    # Deep mode tests all candidates. Normal mode tests all candidates too, but only ranks the best 80;
    # this keeps the list fresh while avoiding a large download benchmark for every server.
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(run_proxy_test, item, deep): item for item in parsed}
        for fut in as_completed(futures):
            item = futures[fut]
            try:
                res = fut.result()
            except Exception as e:
                res = {"id": cfg_id(item[0]), "url": item[0], "source": item[1], "ok": False, "reason": f"exception:{e}"}
            results.append(res)

    alive = [r for r in results if r.get("ok")]
    dead = [r for r in results if not r.get("ok")]
    print(f"Proxy-тест прошли: {len(alive)}")
    print(f"Не прошли: {len(dead) + len(failed)}")

    # 3-strike quarantine. A server is removed only after 3 consecutive failed proxy tests.
    current_ids = {r["id"] for r in alive}
    all_results = results + failed
    for r in all_results:
        sid = r["id"]
        entry = state.get(sid, {"failures": 0, "last_latency": None, "url": r["url"], "source": r["source"]})
        entry["url"] = r["url"]
        entry["source"] = r["source"]
        if r.get("ok"):
            entry["failures"] = 0
            entry["last_latency"] = r.get("latency")
            entry["last_ok"] = int(time.time())
        else:
            entry["failures"] = int(entry.get("failures", 0)) + 1
            entry["last_error"] = r.get("reason", "unknown")
        state[sid] = entry

    stable = []
    quarantine = []
    for r in alive:
        e = state.get(r["id"], {})
        if e.get("failures", 0) < 3:
            stable.append(r)
    for r in all_results:
        e = state.get(r["id"], {})
        if e.get("failures", 0) >= 3:
            quarantine.append(r)

    # Keep old stable entries only if they were not checked in this run; this protects against transient runner issues.
    checked_ids = {r["id"] for r in all_results}
    for sid, e in state.items():
        if sid not in checked_ids and e.get("failures", 0) < 3 and e.get("url"):
            stable.append({"id": sid, "url": e["url"], "source": e.get("source", "state"), "latency": e.get("last_latency", 99999)})

    # Deduplicate and sort: measured latency first, then stable historical latency.
    unique = {}
    for r in stable:
        unique[r["url"]] = r
    stable = list(unique.values())
    stable.sort(key=lambda r: (r.get("latency") is None, r.get("latency") if r.get("latency") is not None else 99999))

    # Benchmark only the fastest latency candidates. This is much cheaper than downloading through all servers.
    speed_candidates = stable[:SPEED_TEST_CANDIDATES]
    if speed_candidates:
        print(f"Замер скорости для {len(speed_candidates)} лучших по latency...")
        with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, 8)) as ex:
            futures = [ex.submit(benchmark_speed, r) for r in speed_candidates]
            for fut in as_completed(futures):
                fut.result()

        # Prefer throughput, with latency as a tie-breaker. Servers without a successful speed test go after tested ones.
        stable.sort(key=lambda r: (-r.get("speed_mbps", 0), r.get("latency") if r.get("latency") is not None else 99999))

    # Write unified and fastest.
    header = "#profile-title: VolkovVPN\n#profile-update-interval: 6\n"
    UNIFIED_FILE.write_text(header + "\n".join(r["url"] for r in stable) + ("\n" if stable else ""), encoding="utf-8")
    FASTEST_FILE.write_text(header + "\n".join(r["url"] for r in stable[:TOP_FASTEST]) + ("\n" if stable else ""), encoding="utf-8")

    with FAILED_FILE.open("w", encoding="utf-8") as f:
        f.write("# VolkovVPN failed/quarantine report\n")
        for r in sorted(quarantine, key=lambda x: state.get(x["id"], {}).get("failures", 0), reverse=True):
            e = state.get(r["id"], {})
            f.write(f"# failures={e.get('failures', 0)} reason={e.get('last_error', r.get('reason', 'unknown'))} source={r.get('source', '')}\n")
            f.write(r["url"] + "\n")

    save_state(state)
    print(f"Стабильных в unified.txt: {len(stable)}")
    print(f"Топ-{TOP_FASTEST} записан в fastest.txt")
    print(f"Карантин (3+ ошибок): {len(quarantine)}")
    print("Топ-10:")
    for i, r in enumerate(stable[:10], 1):
        print(f"  {i}. {r.get('speed_mbps', 0)} Mbps | {r.get('latency', '?')} ms | {r['url'][:100]}")


if __name__ == "__main__":
    main()
