import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
from pathlib import Path

from flyfly_daily import (
    FlyFlyClient,
    format_import_lines,
    make_sing_box_config,
    parse_candidate,
    probe_url,
    read_node_settings,
    reserve_local_ports,
    start_sing_box_batch,
)


class CandidateTests(unittest.TestCase):
    def test_parse_ipv4_candidate_with_comment(self):
        self.assertEqual(
            parse_candidate("104.24.0.232:443#old label"),
            ("104.24.0.232", 443),
        )

    def test_parse_bracketed_ipv6_candidate(self):
        self.assertEqual(
            parse_candidate("[2606:4700::1]:8443#old label"),
            ("2606:4700::1", 8443),
        )

    def test_rejects_hostnames_and_invalid_ports(self):
        with self.assertRaises(ValueError):
            parse_candidate("example.com:443#not an IP")
        with self.assertRaises(ValueError):
            parse_candidate("104.24.0.232:70000")

    def test_names_use_arabic_numbers_and_global_latency_order(self):
        lines = format_import_lines([
            {"ip": "104.24.0.3", "port": 443, "colo": "TPE", "delay": 12.5},
            {"ip": "104.24.0.2", "port": 443, "colo": "LAX", "delay": 10.1},
            {"ip": "104.24.0.1", "port": 443, "colo": "KHH", "delay": 8.2},
        ])
        self.assertEqual(lines, [
            "104.24.0.1:443#台湾 1",
            "104.24.0.2:443#美国 1",
            "104.24.0.3:443#台湾 2",
        ])
        self.assertNotIn("ms", "\n".join(lines))
        self.assertNotIn("MB/s", "\n".join(lines))

    @patch("flyfly_daily.subprocess.run")
    def test_site_probe_uses_platform_null_device(self, run):
        run.return_value.returncode = 0
        run.return_value.stdout = "204"
        self.assertTrue(probe_url(1080, "https://example.com"))
        self.assertEqual(run.call_args.args[0][4], os.devnull)

    @patch("flyfly_daily.reserve_local_port", side_effect=[31001, 31001, 31002, 31003])
    def test_batch_ports_are_unique(self, reserve_port):
        self.assertEqual(reserve_local_ports(3), [31001, 31002, 31003])
        self.assertEqual(reserve_port.call_count, 4)

    @patch("flyfly_daily.reserve_local_ports", side_effect=[[31001], [31002]])
    @patch("flyfly_daily.stop_sing_box")
    @patch("flyfly_daily.wait_for_inbounds", side_effect=[RuntimeError("startup failed"), None])
    @patch("flyfly_daily.subprocess.Popen")
    @patch("flyfly_daily.subprocess.run")
    def test_batch_start_retries_with_fresh_ports(
        self, run, popen, wait_for_inbounds, stop_sing_box, reserve_ports
    ):
        run.return_value.returncode = 0
        batch = [{"ip": "104.24.0.1", "port": 443}]
        settings = {
            "host": "flyfly.kdns.fr",
            "uuid": "00000000-0000-4000-8000-000000000000",
            "path": "/ws",
            "insecure": False,
            "fingerprint": "chrome",
        }
        with tempfile.TemporaryDirectory() as directory:
            process, error_log = start_sing_box_batch(
                "sing-box", batch, settings, Path(directory) / "config.json"
            )
            error_log.close()

        self.assertIs(process, popen.return_value)
        self.assertEqual(popen.call_count, 2)
        self.assertEqual(batch[0]["local_port"], 31002)
        stop_sing_box.assert_called_once_with(process)
        self.assertEqual(reserve_ports.call_count, 2)


class FlyFlyConfigTests(unittest.TestCase):
    def test_requires_the_observed_vless_websocket_protocol(self):
        settings = read_node_settings({
            "HOST": "flyfly.kdns.fr",
            "UUID": "00000000-0000-4000-8000-000000000000",
            "PATH": "/ws",
            "协议类型": "vless",
            "传输协议": "ws",
        })
        self.assertEqual(settings["host"], "flyfly.kdns.fr")
        self.assertEqual(settings["path"], "/ws")

        with self.assertRaises(RuntimeError):
            read_node_settings({
                "HOST": "flyfly.kdns.fr",
                "UUID": "00000000-0000-4000-8000-000000000000",
                "协议类型": "trojan",
                "传输协议": "ws",
            })

    def test_sing_box_config_routes_each_local_proxy_to_its_candidate(self):
        config = make_sing_box_config([{
            "index": 0,
            "local_port": 31001,
            "ip": "104.24.0.1",
            "port": 443,
        }], {
            "host": "flyfly.kdns.fr",
            "uuid": "00000000-0000-4000-8000-000000000000",
            "path": "/ws",
            "insecure": False,
            "fingerprint": "chrome",
        })
        self.assertEqual(config["outbounds"][0]["server"], "104.24.0.1")
        self.assertEqual(config["inbounds"][0]["listen_port"], 31001)
        self.assertEqual(config["route"]["rules"][0]["outbound"], "node-0")
        self.assertEqual(config["outbounds"][0]["transport"]["path"], "/ws")


class FlyFlyClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                if self.path == "/login":
                    self.send_response(200)
                    self.send_header("Set-Cookie", "auth=ok; Path=/")
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"success":true}')
                    return
                if self.path == "/admin/ADD.txt" and "auth=ok" in self.headers.get("Cookie", ""):
                    self.server.ip_list = body.decode("utf-8").splitlines()
                    self.send_response(200)
                    self.end_headers()
                    return
                self.send_error(403)

            def do_GET(self):
                if "auth=ok" not in self.headers.get("Cookie", ""):
                    self.send_error(403)
                    return
                if self.path == "/admin/ADD.txt":
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write("\n".join(self.server.ip_list).encode("utf-8"))
                    return
                if self.path == "/admin/config.json":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"协议类型": "vless"}).encode("utf-8"))
                    return
                self.send_error(404)

            def log_message(self, _format, *_args):
                pass

        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.server.ip_list = ["104.24.0.1:443#old"]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join()
        cls.server.server_close()

    def test_login_read_and_verified_replacement(self):
        client = FlyFlyClient(self.base_url, "test-password")
        client.login()
        self.assertEqual(client.get_config(), {"协议类型": "vless"})
        self.assertEqual(client.get_ip_list(), ["104.24.0.1:443#old"])
        replacement = ["104.24.0.2:443#台湾一"]
        client.replace_ip_list(replacement)
        self.assertEqual(client.get_ip_list(), replacement)


if __name__ == "__main__":
    unittest.main()
