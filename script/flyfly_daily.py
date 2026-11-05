#!/usr/bin/env python3
"""Filter the existing FlyFly IP list and replace it with verified nodes."""

import csv
import hashlib
import http.cookiejar
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


BASE_URL = os.environ.get("FLYFLY_URL", "https://flyfly.kdns.fr").rstrip("/")
PASSWORD = os.environ.get("FLYFLY_ADMIN_PASSWORD", "")
LATENCY_LIMIT_MS = 200
PING_WORKERS = 200
SING_BOX_VERSION = "1.14.4"
SING_BOX_URL = (
    "https://github.com/SagerNet/sing-box/releases/download/"
    f"v{SING_BOX_VERSION}/sing-box-{SING_BOX_VERSION}-linux-amd64.tar.gz"
)
SING_BOX_SHA256 = "699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968"
SING_BOX_WINDOWS_URL = (
    "https://github.com/SagerNet/sing-box/releases/download/"
    f"v{SING_BOX_VERSION}/sing-box-{SING_BOX_VERSION}-windows-amd64.zip"
)
SING_BOX_WINDOWS_SHA256 = "99185d75d314a07dbba4a130c8ad986cbeb629a07927975636b341ca61f991df"
MAX_CANDIDATES = 5000
BATCH_SIZE = 25
YOUTUBE_URL = "https://www.youtube.com/generate_204"
TIKTOK_URL = "https://www.tiktok.com/robots.txt"
TEST_URLS = (YOUTUBE_URL, TIKTOK_URL)

COLO_COUNTRIES = {
    "TPE": "台湾", "KHH": "台湾", "TSA": "台湾",
    "HKG": "香港", "MFM": "澳门", "NRT": "日本", "KIX": "日本",
    "NGO": "日本", "FUK": "日本", "ICN": "韩国", "GMP": "韩国",
    "SIN": "新加坡", "BKK": "泰国", "KUL": "马来西亚", "CGK": "印度尼西亚",
    "MNL": "菲律宾", "SGN": "越南", "HAN": "越南", "DEL": "印度",
    "BOM": "印度", "DXB": "阿联酋", "LHR": "英国", "MAN": "英国",
    "FRA": "德国", "MUC": "德国", "CDG": "法国", "AMS": "荷兰",
    "ZRH": "瑞士", "VIE": "奥地利", "MAD": "西班牙", "BCN": "西班牙",
    "FCO": "意大利", "MXP": "意大利", "ARN": "瑞典", "CPH": "丹麦",
    "OSL": "挪威", "HEL": "芬兰", "WAW": "波兰", "PRG": "捷克",
    "ATH": "希腊", "IST": "土耳其", "JNB": "南非", "GRU": "巴西",
    "EZE": "阿根廷", "SCL": "智利", "MEX": "墨西哥", "YYZ": "加拿大",
    "YVR": "加拿大", "YUL": "加拿大", "SYD": "澳大利亚", "MEL": "澳大利亚",
    "BNE": "澳大利亚", "PER": "澳大利亚", "AKL": "新西兰",
    "LAX": "美国", "SJC": "美国", "SFO": "美国", "SEA": "美国",
    "PDX": "美国", "LAS": "美国", "PHX": "美国", "DEN": "美国",
    "DFW": "美国", "AUS": "美国", "ORD": "美国", "ATL": "美国",
    "MIA": "美国", "IAD": "美国", "JFK": "美国", "EWR": "美国",
    "BOS": "美国", "PHL": "美国", "DTW": "美国", "MSP": "美国",
    "HNL": "美国", "YTO": "加拿大",
}


class FlyFlyClient:
    def __init__(self, base_url, password):
        self.base_url = base_url
        self.password = password
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookies)
        )

    def request(self, path, method="GET", body=None, content_type=None):
        headers = {"User-Agent": "FlyFly-IP-Monitor/1.0"}
        if content_type:
            headers["Content-Type"] = content_type
        request = urllib.request.Request(
            self.base_url + path, data=body, headers=headers, method=method
        )
        try:
            with self.opener.open(request, timeout=30) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            raise RuntimeError(
                f"FlyFly request failed: {method} {path} returned HTTP {error.code}"
            ) from None
        except (urllib.error.URLError, TimeoutError) as error:
            raise RuntimeError(
                f"FlyFly request failed: {method} {path}: {error.reason if isinstance(error, urllib.error.URLError) else error}"
            ) from None

    def login(self):
        body = urllib.parse.urlencode({"password": self.password}).encode()
        _, response = self.request(
            "/login", method="POST", body=body,
            content_type="application/x-www-form-urlencoded",
        )
        try:
            data = json.loads(response)
        except json.JSONDecodeError:
            raise RuntimeError("FlyFly login did not return JSON; check the password and URL") from None
        if not data.get("success"):
            raise RuntimeError("FlyFly login was rejected")

    def get_config(self):
        _, response = self.request("/admin/config.json")
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            raise RuntimeError("FlyFly returned invalid admin configuration") from None

    def get_ip_list(self):
        _, response = self.request("/admin/ADD.txt")
        return response.decode("utf-8").splitlines()

    def replace_ip_list(self, lines):
        payload = ("\n".join(lines) + "\n").encode("utf-8")
        self.request(
            "/admin/ADD.txt", method="POST", body=payload,
            content_type="text/plain; charset=utf-8",
        )
        saved = self.get_ip_list()
        if saved != lines:
            raise RuntimeError("FlyFly did not save the complete replacement IP list")


def parse_candidate(line):
    endpoint = line.split("#", 1)[0].strip()
    if endpoint.startswith("["):
        match = re.fullmatch(r"\[([0-9a-fA-F:]+)\]:(\d+)", endpoint)
        if not match:
            raise ValueError(f"invalid endpoint: {endpoint}")
        address, port = match.group(1), int(match.group(2))
    else:
        address, separator, port_text = endpoint.rpartition(":")
        if not separator or not port_text.isdigit():
            raise ValueError(f"invalid endpoint: {endpoint}")
        port = int(port_text)
    parsed_ip = ipaddress.ip_address(address)
    if not 1 <= port <= 65535:
        raise ValueError(f"invalid port in endpoint: {endpoint}")
    return str(parsed_ip), port


def install_sing_box(destination):
    is_windows = sys.platform == "win32"
    if sys.platform != "linux" and not is_windows:
        raise RuntimeError(f"Unsupported operating system: {sys.platform}")
    url = SING_BOX_WINDOWS_URL if is_windows else SING_BOX_URL
    expected_hash = SING_BOX_WINDOWS_SHA256 if is_windows else SING_BOX_SHA256
    with urllib.request.urlopen(url, timeout=120) as response:
        archive_bytes = response.read()
    if hashlib.sha256(archive_bytes).hexdigest() != expected_hash:
        raise RuntimeError("sing-box release checksum verification failed")

    with tempfile.TemporaryFile() as archive_file:
        archive_file.write(archive_bytes)
        archive_file.seek(0)
        if is_windows:
            with zipfile.ZipFile(archive_file) as archive:
                binary_name = next(
                    (
                        name for name in archive.namelist()
                        if Path(name).name == "sing-box.exe"
                    ),
                    None,
                )
                if binary_name is None:
                    raise RuntimeError("sing-box release archive has no executable")
                with archive.open(binary_name) as source, open(destination, "wb") as target:
                    shutil.copyfileobj(source, target)
        else:
            archive_file.seek(0)
            with tarfile.open(fileobj=archive_file, mode="r:gz") as archive:
                binary = next(
                    (
                        member for member in archive.getmembers()
                        if Path(member.name).name == "sing-box" and member.isfile()
                    ),
                    None,
                )
                if binary is None:
                    raise RuntimeError("sing-box release archive has no executable")
                source = archive.extractfile(binary)
                if source is None:
                    raise RuntimeError("Could not read sing-box executable")
                with source, open(destination, "wb") as target:
                    shutil.copyfileobj(source, target)
            os.chmod(destination, 0o755)
    return str(destination)


def read_node_settings(config):
    protocol = str(config.get("协议类型", "")).lower()
    transport = str(config.get("传输协议", "")).lower()
    host = str(config.get("HOST", "")).strip()
    uuid = str(config.get("UUID", "")).strip()
    path = str(config.get("PATH", "")).strip() or "/"
    if protocol != "vless" or transport != "ws":
        raise RuntimeError(
            "The FlyFly node is not VLESS over WebSocket; refusing to test with a mismatched protocol"
        )
    if not host or not uuid:
        raise RuntimeError("FlyFly config is missing the VLESS host or UUID")
    if not path.startswith("/"):
        path = "/" + path
    return {
        "host": host,
        "uuid": uuid,
        "path": path,
        "insecure": bool(config.get("跳过证书验证", False)),
        "fingerprint": str(config.get("Fingerprint", "")).lower(),
    }


def run_latency_test(root, candidates, port, workdir):
    candidate_file = workdir / f"candidates-{port}.txt"
    result_file = workdir / f"latency-{port}.csv"
    candidate_file.write_text(
        "".join(f"{address}\n" for address in candidates), encoding="utf-8"
    )
    command = [
        "go", "run", ".", "-n", str(PING_WORKERS), "-t", "1",
        "-tl", str(LATENCY_LIMIT_MS), "-tp", str(port),
        "-httping", "-httping-code", "200",
        "-url", f"{BASE_URL}/login",
        "-f", str(candidate_file), "-o", str(result_file),
        "-dd", "-p", "0",
    ]
    subprocess.run(command, cwd=root, check=True)
    if not result_file.exists():
        return {}

    results = {}
    with result_file.open(encoding="utf-8-sig", newline="") as stream:
        for row in csv.DictReader(stream):
            try:
                address = str(ipaddress.ip_address(row["IP 地址"]))
                delay = float(row["平均延迟"])
            except (KeyError, ValueError):
                raise RuntimeError("CFST produced a malformed result row") from None
            if delay <= LATENCY_LIMIT_MS:
                results[address] = {
                    "delay": delay,
                    "colo": row.get("地区码", "").strip().upper(),
                }
    return results


def reserve_local_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def make_sing_box_config(candidates, settings):
    inbounds, outbounds, rules = [], [], []
    for candidate in candidates:
        index = candidate["index"]
        inbound_tag = f"socks-{index}"
        outbound_tag = f"node-{index}"
        inbounds.append({
            "type": "socks",
            "tag": inbound_tag,
            "listen": "127.0.0.1",
            "listen_port": candidate["local_port"],
        })
        tls = {
            "enabled": True,
            "server_name": settings["host"],
            "insecure": settings["insecure"],
        }
        if settings["fingerprint"] in {"chrome", "firefox", "safari", "edge"}:
            tls["utls"] = {
                "enabled": True,
                "fingerprint": settings["fingerprint"],
            }
        outbounds.append({
            "type": "vless",
            "tag": outbound_tag,
            "server": candidate["ip"],
            "server_port": candidate["port"],
            "uuid": settings["uuid"],
            "tls": tls,
            "transport": {
                "type": "ws",
                "path": settings["path"],
                "headers": {"Host": settings["host"]},
            },
        })
        rules.append({"inbound": [inbound_tag], "outbound": outbound_tag})
    return {
        "log": {"level": "error"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {"rules": rules, "final": outbounds[0]["tag"]},
    }


def wait_for_inbounds(process, ports, timeout=15):
    deadline = time.monotonic() + timeout
    pending = set(ports)
    while pending and time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("sing-box stopped before its local proxy listeners became ready")
        for port in tuple(pending):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                    pending.remove(port)
            except OSError:
                pass
        if pending:
            time.sleep(0.1)
    if pending:
        raise RuntimeError("sing-box did not open all local proxy listeners")


def probe_url(port, url):
    try:
        result = subprocess.run(
            [
                "curl", "--silent", "--show-error", "--output", os.devnull,
                "--connect-timeout", "8", "--max-time", "12",
                "--proxy", f"socks5h://127.0.0.1:{port}",
                "--write-out", "%{http_code}", url,
            ],
            check=False, capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    if result.returncode != 0:
        return False
    try:
        status = int(result.stdout.strip())
    except ValueError:
        return False
    return 200 <= status < 400


def test_through_nodes(sing_box, candidates, settings, workdir):
    verified = []
    for start in range(0, len(candidates), BATCH_SIZE):
        batch = candidates[start:start + BATCH_SIZE]
        for index, candidate in enumerate(batch):
            candidate["index"] = index
            candidate["local_port"] = reserve_local_port()
        config_path = workdir / "sing-box.json"
        config_path.write_text(
            json.dumps(make_sing_box_config(batch, settings)),
            encoding="utf-8",
        )
        check = subprocess.run(
            [sing_box, "check", "-c", str(config_path)],
            capture_output=True, text=True, check=False,
        )
        if check.returncode != 0:
            raise RuntimeError("sing-box rejected the generated FlyFly proxy configuration")

        process = subprocess.Popen(
            [sing_box, "run", "-c", str(config_path)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            wait_for_inbounds(process, [candidate["local_port"] for candidate in batch])
            with ThreadPoolExecutor(
                max_workers=BATCH_SIZE * len(TEST_URLS)
            ) as executor:
                futures = []
                for candidate in batch:
                    candidate["site_results"] = [
                        executor.submit(probe_url, candidate["local_port"], url)
                        for url in TEST_URLS
                    ]
                for candidate in batch:
                    if all(future.result() for future in candidate["site_results"]):
                        verified.append(candidate)
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        print(
            f"Proxy checks complete: {min(start + len(batch), len(candidates))}/"
            f"{len(candidates)} candidates; {len(verified)} passed so far"
        )
    return verified


def country_name(colo):
    if len(colo) == 2:
        return {
            "TW": "台湾", "US": "美国", "JP": "日本", "HK": "香港",
            "SG": "新加坡", "KR": "韩国", "GB": "英国", "DE": "德国",
            "FR": "法国", "CA": "加拿大", "AU": "澳大利亚",
        }.get(colo, "其他")
    return COLO_COUNTRIES.get(colo, "其他")


def chinese_number(number):
    digits = "零一二三四五六七八九"
    units = ("", "十", "百", "千")
    if not 0 < number < 10000:
        raise ValueError("node sequence is outside the supported range")
    parts = []
    zero_pending = False
    for position in range(3, -1, -1):
        divisor = 10 ** position
        digit, number = divmod(number, divisor)
        if digit:
            if zero_pending:
                parts.append("零")
                zero_pending = False
            if not (position == 1 and digit == 1 and not parts):
                parts.append(digits[digit])
            parts.append(units[position])
        elif parts and number:
            zero_pending = True
    return "".join(parts)


def format_import_lines(candidates):
    counters = {}
    lines = []
    for candidate in sorted(candidates, key=lambda item: (item["colo"], item["delay"], item["ip"])):
        country = country_name(candidate["colo"])
        counters[country] = counters.get(country, 0) + 1
        address = candidate["ip"]
        if ":" in address:
            address = f"[{address}]"
        lines.append(
            f"{address}:{candidate['port']}#{country}{chinese_number(counters[country])}"
        )
    return lines


def main():
    if not PASSWORD:
        raise RuntimeError("Set the FLYFLY_ADMIN_PASSWORD environment variable")
    if not shutil.which("go") or not shutil.which("curl"):
        raise RuntimeError("Go and curl are required")

    client = FlyFlyClient(BASE_URL, PASSWORD)
    client.login()
    config = client.get_config()
    settings = read_node_settings(config)
    raw_candidates = client.get_ip_list()
    if not raw_candidates:
        raise RuntimeError("FlyFly's current candidate list is empty; refusing to replace it")
    if len(raw_candidates) > MAX_CANDIDATES:
        raise RuntimeError(
            f"Candidate list has {len(raw_candidates)} entries; limit is {MAX_CANDIDATES}"
        )

    candidates = []
    seen = set()
    for line in raw_candidates:
        if not line.strip():
            continue
        try:
            ip, port = parse_candidate(line)
        except ValueError as error:
            raise RuntimeError(f"Invalid entry in FlyFly candidate list: {error}") from None
        key = (ip, port)
        if key not in seen:
            seen.add(key)
            candidates.append({"ip": ip, "port": port})
    if not candidates:
        raise RuntimeError("FlyFly's candidate list contains no valid IP addresses")

    print(f"Testing {len(candidates)} existing FlyFly candidate IPs")
    with tempfile.TemporaryDirectory(prefix="flyfly-ip-test-") as temp_dir:
        workdir = Path(temp_dir)
        sing_box_name = "sing-box.exe" if sys.platform == "win32" else "sing-box"
        sing_box = install_sing_box(workdir / sing_box_name)
        passing_latency = []
        by_port = {}
        for candidate in candidates:
            by_port.setdefault(candidate["port"], []).append(candidate)
        for port, port_candidates in by_port.items():
            results = run_latency_test(
                Path(__file__).resolve().parent.parent,
                [item["ip"] for item in port_candidates],
                port,
                workdir,
            )
            for candidate in port_candidates:
                result = results.get(candidate["ip"])
                if result:
                    passing_latency.append({**candidate, **result})
        print(
            f"Latency <= {LATENCY_LIMIT_MS} ms: "
            f"{len(passing_latency)}/{len(candidates)}"
        )
        if not passing_latency:
            raise RuntimeError("No candidates passed latency; the existing FlyFly list was kept")

        verified = test_through_nodes(
            sing_box, passing_latency, settings, workdir
        )
        if not verified:
            raise RuntimeError(
                "No candidate passed both website checks; the existing FlyFly list was kept"
            )

        replacement = format_import_lines(verified)
        client.replace_ip_list(replacement)
        print(f"FlyFly list replaced with {len(replacement)} verified nodes")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"Daily FlyFly IP check failed: {error}", file=sys.stderr)
        sys.exit(1)
