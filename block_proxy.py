"""
python -m proxy --plugins block_proxy.DomainBlockerPlugin --hostname 127.0.0.1 --port 3128
"""

from pathlib import Path
from typing import List

from proxy.http.proxy import HttpProxyBasePlugin
from proxy.http.exception import HttpRequestRejected
from proxy.http.codes import httpStatusCodes


class DomainBlockerPlugin(HttpProxyBasePlugin):
    BLOCK_FILE = Path(__file__).with_name("blocked_domains.txt")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._load_blocklist()

    # connection to the site passes through here
    def before_upstream_connection(self, request):
        host = (request.host or "").split(":")[0].lower()
        if self._is_blocked(host):
            raise HttpRequestRejected(
                status=403,
                reason=httpStatusCodes[403],
                headers={b"Content-Type": b"text/html"},
                body=(
                    b"<h1>403 Forbidden</h1>"
                    b"<p>This domain has blocked by your local proxy.</p>"
                ),
            )
        return request  # allow anything not on the list



    def _load_blocklist(self) -> None:
        self.blocked: List[str] = []
        if self.BLOCK_FILE.exists():
            self.blocked = [
                d.strip().lower()
                for d in self.BLOCK_FILE.read_text().splitlines()
                if d.strip() and not d.startswith("#")
            ]

    def _is_blocked(self, host: str) -> bool:
        self._load_blocklist()  # live-edit file
        return any(
            host == d or host.endswith("." + d)  # matches sub-domains
            for d in self.blocked
        )

