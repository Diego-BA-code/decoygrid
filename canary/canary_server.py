import json
import os
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

LOG = "/var/tmp/canary.log"
PORT = int(os.environ.get("CANARY_PORT", "9000"))


class Handler(BaseHTTPRequestHandler):
    def _log(self, method: str) -> None:
        ev = {
            "utc_time": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f"),
            "src_host": self.client_address[0],
            "src_port": self.client_address[1],
            "dst_port": PORT,
            "logtype": 3100,
            "logdata": {
                "METHOD": method,
                "PATH": self.path,
                "USERAGENT": self.headers.get("User-Agent", ""),
            },
            "node_id": "decoygrid-canary",
        }
        with open(LOG, "a") as f:
            f.write(json.dumps(ev) + "\n")
        body = b"GIF89a"
        self.send_response(200)
        self.send_header("Content-Type", "image/gif")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._log("GET")

    def do_POST(self):
        self._log("POST")

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
