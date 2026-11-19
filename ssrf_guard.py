"""Pengaman SSRF untuk Cyber Web Scanner.

Pemindai mengambil URL dari pengguna, jadi ia tidak boleh dipakai untuk menghubungi jaringan
internal: alamat privat, loopback, link-local (termasuk metadata cloud 169.254.169.254), CGNAT,
dan sejenisnya. Pemeriksaan dilakukan di tiga lapis:
1. sebelum setiap permintaan HTTP, termasuk setiap lompatan redirect;
2. setelah koneksi terbuka, terhadap IP yang benar-benar dihubungi (menutup celah DNS rebinding);
3. untuk koneksi TLS langsung (pemeriksaan sertifikat dan TLS lama).
"""
import ipaddress
import socket
from urllib.parse import urlparse

import requests
import urllib3.util.connection as _u3conn
from requests.adapters import HTTPAdapter

ALLOWED_SCHEMES = ("http", "https")
ALLOWED_PORTS = (None, 80, 443, 8080, 8443)
MAX_REDIRECTS = 5
MAX_BYTES = 5 * 1024 * 1024
BLOCKED_SUFFIXES = (".localhost", ".local", ".internal", ".lan", ".home.arpa")


class BlockedTarget(requests.exceptions.RequestException):
    """Tujuan ditolak demi keamanan (jaringan internal, skema, atau port tidak diizinkan)."""


class ResponseTooLarge(requests.exceptions.RequestException):
    """Respons melebihi batas ukuran."""


def is_public_ip(ip):
    """True hanya untuk alamat yang dapat dirutekan di internet publik."""
    try:
        addr = ipaddress.ip_address(str(ip).split("%")[0])
    except ValueError:
        return False
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return addr.is_global and not addr.is_multicast


def resolve_public(host):
    """Resolusi DNS; tolak bila SATU saja alamatnya bukan alamat publik."""
    host = (host or "").strip().strip("[]").rstrip(".").lower()
    if not host:
        raise BlockedTarget("Alamat tujuan kosong.")
    if host == "localhost" or host.endswith(BLOCKED_SUFFIXES):
        raise BlockedTarget(f"Alamat {host} adalah jaringan lokal; pemindaian ditolak.")
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise requests.exceptions.ConnectionError(f"Nama domain {host} tidak dapat ditemukan ({e}).")
    ips = sorted({info[4][0] for info in infos})
    for ip in ips:
        if not is_public_ip(ip):
            raise BlockedTarget(f"Alamat {host} mengarah ke jaringan privat atau internal ({ip}); pemindaian ditolak.")
    return ips


def check_url(url):
    """Validasi satu URL sebelum dihubungi."""
    p = urlparse(url)
    if p.scheme.lower() not in ALLOWED_SCHEMES:
        raise BlockedTarget("Hanya alamat http:// dan https:// yang dapat dipindai.")
    try:
        port = p.port
    except ValueError:
        raise BlockedTarget("Port pada alamat tidak valid.")
    if port not in ALLOWED_PORTS:
        raise BlockedTarget(f"Port {port} tidak diizinkan; hanya port web standar (80, 443, 8080, 8443).")
    if p.username or p.password:
        raise BlockedTarget("Alamat yang berisi nama pengguna atau kata sandi tidak dapat dipindai.")
    return resolve_public(p.hostname)


# --- Lapis 2: periksa IP yang benar-benar dihubungi ---
_original_create_connection = _u3conn.create_connection
_installed = False


def _guarded_create_connection(address, *args, **kwargs):
    sock = _original_create_connection(address, *args, **kwargs)
    try:
        peer = sock.getpeername()[0]
    except OSError:
        peer = None
    if peer is None or not is_public_ip(peer):
        sock.close()
        raise BlockedTarget(f"Koneksi ke alamat internal ({peer}) diblokir.")
    return sock


def install_connection_guard():
    global _installed
    if not _installed:
        _u3conn.create_connection = _guarded_create_connection
        _installed = True


# --- Lapis 3: koneksi soket langsung (TLS) ---
def connect_public(address, timeout=None):
    host, port = address
    resolve_public(host)
    sock = socket.create_connection(address, timeout=timeout)
    peer = sock.getpeername()[0]
    if not is_public_ip(peer):
        sock.close()
        raise BlockedTarget(f"Koneksi ke alamat internal ({peer}) diblokir.")
    return sock


# --- Lapis 1: setiap permintaan, termasuk setiap redirect, plus batas ukuran ---
class GuardedAdapter(HTTPAdapter):
    def send(self, request, stream=False, **kwargs):
        check_url(request.url)
        resp = super().send(request, stream=True, **kwargs)
        if stream:
            return resp
        data = resp.raw.read(MAX_BYTES + 1, decode_content=True)
        if len(data) > MAX_BYTES:
            resp.close()
            raise ResponseTooLarge(f"Respons lebih dari {MAX_BYTES // (1024 * 1024)} MB; pengambilan dihentikan.")
        resp._content = data
        resp._content_consumed = True
        try:
            resp.raw.release_conn()
        except Exception:
            pass
        return resp


def guard_session(session, max_redirects=MAX_REDIRECTS):
    """Pasang semua pengaman pada sebuah requests.Session."""
    install_connection_guard()
    adapter = GuardedAdapter(max_retries=0)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.max_redirects = max_redirects
    session.trust_env = False  # abaikan proxy dari environment agar pemeriksaan IP akurat
    return session
