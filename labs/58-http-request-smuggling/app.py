"""
Lab 58 -- HTTP request smuggling (CL.TE desync).

A front-end proxy frames each request by Content-Length; the backend behind
it frames by Transfer-Encoding instead. A request carrying both headers,
with a body the two disagree about, splits their view of where one request
ends and the next begins -- CWE-444, Inconsistent Interpretation of HTTP
Requests -- the exact class Nullock's active `smuggle` probe times out to
confirm: forward only the Content-Length-declared prefix of a chunked body
and the backend blocks reading a chunk continuation that will never arrive.

In Nullock:
    1. nullock scope add http://localhost:5058/*
    2. nullock smuggle http://localhost:5058/
       -- times a CL.TE and a TE.CL desync probe against a baseline. The
       CL.TE probe's dangling chunk (forwarded whole by Content-Length,
       parsed short by Transfer-Encoding) leaves the backend blocked
       mid-read; Nullock reports it CONFIRMED once the delay reproduces on
       a resend with the connection held open and silent, not reset.
    3. Turn the confirmed desync into a real response-queue-poisoning
       hijack. Send one raw request whose declared Content-Length covers a
       complete (empty) chunked body PLUS a second, fully-formed request
       for /admin-secret -- a path the front-end's own allow-list would
       otherwise refuse outright, since it only ever inspects the request
       line of the ONE request it thinks it is forwarding:
         python3 -c "
         import socket
         tail = b'GET /admin-secret HTTP/1.1\r\nHost: x\r\n\r\n'
         body = b'0\r\n\r\n' + tail
         req = (b'POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: '
                + str(len(body)).encode()
                + b'\r\nTransfer-Encoding: chunked\r\n\r\n' + body)
         c = socket.create_connection(('127.0.0.1', 5058))
         c.sendall(req); c.close()"
       The backend answers the visible request fast and normally -- then,
       still on that same pooled backend connection, answers the smuggled
       /admin-secret request too. Nobody has claimed that second response.
    4. Open a brand new connection and send any ordinary request (even a
       plain GET /). It reuses that same pooled backend connection and
       receives the QUEUED response meant for the smuggled request instead
       of its own -- the flag surfaces on a request that never asked for
       it: curl -s http://127.0.0.1:5058/ (run right after step 3).
    5. Confirm success: GET /flag -- solved only once the backend itself
       recorded serving /admin-secret from a request it parsed out of
       another connection's forwarded body, never one the front-end's
       allow-list saw and let through directly.

Fix: never let a front-end and back-end disagree on request framing --
reject any request carrying both Content-Length and Transfer-Encoding
(RFC 7230 3.3.3), or terminate and completely re-frame every request at
the edge instead of tunneling raw bytes through to a pooled backend
connection.
"""

import hashlib
import queue
import socket
import threading

FRONT_PORT = 5058
BACK_PORT = 15058
BACK_IDLE_TIMEOUT = 20.0
FRONT_BACKEND_TIMEOUT = 25.0

FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-58-http-request-smuggling").hexdigest()[:16]
SOLVED = threading.Event()


def _content_length(head_lines):
    for line in head_lines:
        if line.lower().startswith(b"content-length:"):
            try:
                return int(line.split(b":", 1)[1].strip() or 0)
            except ValueError:
                return 0
    return 0


def _has_chunked(head_lines):
    for line in head_lines:
        if line.lower().startswith(b"transfer-encoding:") and b"chunked" in line.lower():
            return True
    return False


# ------------------------------------------------------------------ backend
# Trusts Transfer-Encoding over Content-Length -- the opposite priority from
# the front-end below, which is the whole desync.

def _read_chunked(conn, buf):
    body = b""
    while True:
        while b"\r\n" not in buf:
            chunk = conn.recv(4096)
            if not chunk:
                return None, b""
            buf += chunk
        size_line, _, buf = buf.partition(b"\r\n")
        try:
            size = int(size_line.split(b";")[0].strip(), 16)
        except ValueError:
            return None, b""
        while len(buf) < size + 2:
            chunk = conn.recv(4096)
            if not chunk:
                return None, b""
            buf += chunk
        body += buf[:size]
        buf = buf[size + 2:]
        if size == 0:
            return body, buf


def _backend_handle(path, body):
    if path == "/admin-secret":
        SOLVED.set()
        return b"internal admin: " + FLAG.encode() + b"\n"
    return b"OK\n"


def _backend_serve(conn):
    conn.settimeout(BACK_IDLE_TIMEOUT)
    buf = b""
    try:
        while True:
            while b"\r\n\r\n" not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                buf += chunk
            head, _, rest = buf.partition(b"\r\n\r\n")
            lines = head.split(b"\r\n")
            try:
                _, path, _ = lines[0].decode().split(" ", 2)
            except ValueError:
                return
            if _has_chunked(lines[1:]):
                body, rest = _read_chunked(conn, rest)
                if body is None:
                    return
            else:
                cl = _content_length(lines[1:])
                while len(rest) < cl:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    rest += chunk
                body, rest = rest[:cl], rest[cl:]
            buf = rest
            resp_body = _backend_handle(path.split("?")[0], body)
            resp = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
                    + str(len(resp_body)).encode() + b"\r\n\r\n" + resp_body)
            conn.sendall(resp)
    except (OSError, ValueError):
        return
    finally:
        conn.close()


def _backend_main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", BACK_PORT))
    srv.listen(128)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=_backend_serve, args=(conn,), daemon=True).start()


# ------------------------------------------------------------------ front-end
# Trusts Content-Length only -- ignores Transfer-Encoding entirely when
# deciding how many body bytes belong to THIS request -- and pools its
# connections to the backend, exactly like a real reverse proxy / load
# balancer that keeps its own upstream connections alive independent of
# whatever a given client connection does.

class _BackendConn:
    def __init__(self, sock):
        self.sock = sock
        self.buf = b""

    def send_and_read(self, raw):
        self.sock.sendall(raw)
        while b"\r\n\r\n" not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                return None
            self.buf += chunk
        head, _, rest = self.buf.partition(b"\r\n\r\n")
        cl = _content_length(head.split(b"\r\n")[1:])
        while len(rest) < cl:
            chunk = self.sock.recv(4096)
            if not chunk:
                return None
            rest += chunk
        self.buf = rest[cl:]
        return head + b"\r\n\r\n" + rest[:cl]


_pool = queue.Queue()


def _get_backend():
    try:
        return _pool.get_nowait()
    except queue.Empty:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", BACK_PORT))
        return _BackendConn(s)


def _front_serve(conn):
    conn.settimeout(30.0)
    try:
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = conn.recv(4096)
            if not chunk:
                return
            buf += chunk
        head, _, rest = buf.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        try:
            _, path, _ = lines[0].decode().split(" ", 2)
        except ValueError:
            return
        cl = _content_length(lines[1:])
        while len(rest) < cl:
            chunk = conn.recv(4096)
            if not chunk:
                return
            rest += chunk
        body = rest[:cl]   # CL-primary: anything past the declared length isn't ours to send

        clean_path = path.split("?")[0]
        if clean_path == "/flag":
            solved = SOLVED.is_set()
            payload = ('{"solved": true, "flag": "%s"}' % FLAG) if solved else '{"solved": false}'
            payload = payload.encode()
            conn.sendall(("HTTP/1.1 %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n"
                          % (("200 OK" if solved else "403 Forbidden"), len(payload))).encode() + payload)
            return
        if clean_path != "/":
            body_403 = b"forbidden\n"
            conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: " + str(len(body_403)).encode()
                         + b"\r\n\r\n" + body_403)
            return

        raw = head + b"\r\n\r\n" + body
        backend = _get_backend()
        ok = False
        try:
            backend.sock.settimeout(FRONT_BACKEND_TIMEOUT)
            resp = backend.send_and_read(raw)
            if resp is None:
                conn.sendall(b"HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\n\r\n")
            else:
                conn.sendall(resp)
                ok = True
        except OSError:
            pass
        finally:
            if ok:
                _pool.put(backend)
            else:
                try:
                    backend.sock.close()
                except OSError:
                    pass
    except OSError:
        return
    finally:
        conn.close()


def _front_main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", FRONT_PORT))
    srv.listen(128)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=_front_serve, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    threading.Thread(target=_backend_main, daemon=True).start()
    _front_main()
