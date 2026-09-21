"""IPv6 字面量做主机名、又不显式写端口时的边界面板：池、直连、代理隧道三条入口
递给水层的 (host, port) 与上线的 Host / CONNECT 各是什么。

用法（仓库根目录）：timeout 200 env PYTHONPATH=src .venv/bin/python repro/ipv6-hostport.py
"""
import io
import socket
import sys
import threading
from unittest import mock

from urllib3 import HTTPConnectionPool, HTTPSConnectionPool, ProxyManager
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.util.connection import create_connection as _cc

RESULTS = []


def check(name, ok, note=""):
    RESULTS.append((name, bool(ok)))
    print("%-4s %-56s %s" % ("PASS" if ok else "FAIL", name, note))


def target_of(factory):
    """Return the (host, port) tuple handed to create_connection by a connection."""
    with mock.patch("urllib3.util.connection.create_connection") as m:
        try:
            conn = factory()
            conn.connect()
        except Exception:  # noqa: BLE001 - we only care about the requested target
            pass
    if not m.call_args_list:
        return None
    return m.call_args_list[0][0][0]


def cap_request(conn):
    """Return the first request line + Host header emitted by conn.request()."""
    buf = bytearray()

    class Sock(io.RawIOBase):
        def settimeout(self, *a):
            pass

        def sendall(self, data):
            buf.extend(data)

        def send(self, data):
            buf.extend(data)
            return len(data)

    conn.sock = Sock()
    conn.request("GET", "/")
    head = bytes(buf).split(b"\r\n")
    return head[0].decode(), head[1].decode()


# ---- P1/P2/P3/P4: pool -> connection -> socket target
p1 = target_of(lambda: HTTPConnectionPool("::1")._new_conn())
check("P1 HTTP pool '::1' no port -> ('::1', 80)", p1 == ("::1", 80), repr(p1))

p2 = target_of(lambda: HTTPSConnectionPool("[::1]")._new_conn())
check("P2 HTTPS pool '[::1]' no port -> ('::1', 443)", p2 == ("::1", 443), repr(p2))

p3 = target_of(lambda: HTTPConnectionPool("[::1]", 8080)._new_conn())
check("P3 HTTP pool '[::1]' port 8080 (guard)", p3 == ("::1", 8080), repr(p3))

p4 = target_of(lambda: HTTPConnectionPool("[fe80::1%25eth0]")._new_conn())
check("P4 scoped pool no port -> ('fe80::1%eth0', 80)", p4 == ("fe80::1%eth0", 80), repr(p4))

# ---- P5: existing sibling contract (PoolManager path) must not regress
def p5_factory():
    from urllib3 import PoolManager

    pool = PoolManager().connection_from_url("http://[a::b%zone]")
    return pool._get_conn()


p5 = target_of(p5_factory)
check("P5 PoolManager url -> ('a::b%zone', 80) (guard)", p5 == ("a::b%zone", 80), repr(p5))

# ---- P6: ProxyManager built from a pool object (typed public input)
try:
    pm = ProxyManager(HTTPConnectionPool("[::1]", 8080))
    tgt = target_of(lambda: pm.connection_from_host("example.com", 443, "https")._new_conn())
    ok6 = tgt == ("::1", 8080)
    note6 = "proxy target=%r" % (tgt,)
except Exception as e:  # noqa: BLE001
    ok6 = False
    note6 = "ProxyManager(pool) raised %s(%s)" % (type(e).__name__, e)
check("P6 ProxyManager(HTTPConnectionPool('[::1]',8080))", ok6, note6)

# ---- P7: direct public connection classes
try:
    c7a = HTTPConnection("::1")
    c7b = HTTPSConnection("[::1]")
    ok7 = (c7a.host, c7a.port, c7b.host, c7b.port) == ("::1", 80, "::1", 443)
    note7 = "HTTPConnection=%r/%r HTTPSConnection=%r/%r" % (c7a.host, c7a.port, c7b.host, c7b.port)
except Exception as e:  # noqa: BLE001
    ok7, note7 = False, "raised %s(%s)" % (type(e).__name__, e)
check("P7 HTTPConnection('::1')/HTTPSConnection('[::1]')", ok7, note7)

# ---- P8: what actually goes on the wire as the Host header
try:
    line, host_hdr = cap_request(HTTPConnectionPool("::1")._new_conn())
    check("P8 Host header for '::1' pool, default port", host_hdr == "Host: [::1]", host_hdr)
except Exception as e:  # noqa: BLE001
    check("P8 Host header for '::1' pool, default port", False, "raised %s(%s)" % (type(e).__name__, e))

# ---- P9: tunnel host keeps brackets (declared by existing test) and the
#          CONNECT authority seen by the proxy is the bracketed literal.
proxy_lines = []


def start_proxy():
    l = socket.socket()
    l.bind(("127.0.0.1", 0))
    l.listen(4)
    port = l.getsockname()[1]

    def run():
        while True:
            try:
                c, _ = l.accept()
            except OSError:
                return
            with c:
                buf = b""
                while b"\r\n\r\n" not in buf:
                    b = c.recv(4096)
                    if not b:
                        break
                    buf += b
                if buf.startswith(b"CONNECT"):
                    proxy_lines.append(buf.split(b"\r\n")[0])
                    try:
                        c.sendall(b"HTTP/1.1 502 No\r\ncontent-length: 0\r\n\r\n")
                    except OSError:
                        pass
                else:
                    proxy_lines.append(buf.split(b"\r\n")[0])

    threading.Thread(target=run, daemon=True).start()
    return l, port


pool = HTTPSConnectionPool("[::1]", 443, _proxy=None)
check("P9 _tunnel_host keeps brackets", pool._tunnel_host == "[::1]", repr(pool._tunnel_host))

l, pport = start_proxy()
try:
    pm = ProxyManager("http://127.0.0.1:%d" % pport)
    tgt_pool = pm.connection_from_host("::1", 443, "https")
    try:
        tgt_pool.urlopen("GET", "/", retries=0, timeout=3)
    except Exception as e:  # noqa: BLE001
        connect_line = proxy_lines[0] if proxy_lines else b"<none>"
        check(
            "P10 CONNECT authority is bracketed",
            connect_line.startswith(b"CONNECT [::1]:443"),
            connect_line.decode(errors="replace"),
        )
finally:
    l.close()

# ---- P11: real end-to-end request against an in-process ::1 server
try:
    ls = socket.socket(socket.AF_INET6)
    ls.bind(("::1", 0))
    ls.listen(4)
    srv_port = ls.getsockname()[1]
    seen = []

    def serve():
        while True:
            try:
                c, _ = ls.accept()
            except OSError:
                return
            with c:
                try:
                    data = c.recv(65536)
                except OSError:
                    return
                seen.append(data.split(b"\r\n")[1].decode())
                c.sendall(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")

    threading.Thread(target=serve, daemon=True).start()
    pool = HTTPConnectionPool("[::1]", srv_port, timeout=5)
    r = pool.urlopen("GET", "/", retries=0)
    check(
        "P11 e2e to ::1 server, Host on wire",
        r.status == 200 and seen and seen[0] == "Host: [::1]:%d" % srv_port,
        "status=%s wire=%r" % (r.status, seen[:1]),
    )
    pool.close()
except OSError as e:
    check("P11 e2e to ::1 server, Host on wire", False, "no ipv6 loopback: %s" % e)
finally:
    try:
        ls.close()
    except Exception:  # noqa: BLE001
        pass

# ---- P12: the tunnel a pool sets up for a *bare* IPv6 literal with no port
from urllib3.connection import ProxyConfig  # noqa: E402
from urllib3.util.url import parse_url  # noqa: E402

tun_pool = HTTPSConnectionPool(
    "::1",
    _proxy=parse_url("http://127.0.0.1:9"),
    _proxy_headers={},
    _proxy_config=ProxyConfig(None, False, None, None),
)
conn12 = tun_pool._new_conn()
with mock.patch.object(type(conn12), "connect", lambda self: None):
    tun_pool._prepare_proxy(conn12)
stored_host = conn12._tunnel_host
renderable = stored_host if stored_host.startswith("[") else "[%s]" % stored_host
check(
    "P12 tunnel state from bare '::1' w/o port",
    (renderable, conn12._tunnel_port) == ("[::1]", 443),
    "_tunnel_host=%r _tunnel_port=%r" % (conn12._tunnel_host, conn12._tunnel_port),
)

# Same path, but observed as the CONNECT request line the proxy actually receives.
l12, p12port = start_proxy()
try:
    wire_pool = HTTPSConnectionPool(
        "::1",
        _proxy=parse_url("http://127.0.0.1:%d" % p12port),
        _proxy_headers={},
        _proxy_config=ProxyConfig(None, False, None, None),
    )
    try:
        wire_pool.urlopen(
            "GET", "https://[::1]/", retries=0, timeout=3, assert_same_host=False
        )
    except Exception:  # noqa: BLE001 the fake proxy refuses the tunnel
        pass
    line12 = proxy_lines[-1] if len(proxy_lines) > 0 else b"<none>"
    check(
        "P13 CONNECT on the wire for bare '::1' w/o port",
        line12.startswith(b"CONNECT [::1]:443"),
        line12.decode(errors="replace"),
    )
finally:
    l12.close()

print("\n%d/%d cells pass" % (sum(1 for _, ok in RESULTS if ok), len(RESULTS)))
sys.exit(0)

