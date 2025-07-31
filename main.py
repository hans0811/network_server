import os
import ssl
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler, TLS_FTPHandler
from pyftpdlib.servers import FTPServer
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta

# Manually define Telnet protocol bytes (since telnetlib is removed in Python 3.13)
IAC = 255
WILL = 251
DO = 253
ECHO = 1
SUPPRESS_GO_AHEAD = 3
TERMINAL_TYPE = 24

# ===================== FTP =====================
def start_ftp_server():
    authorizer = DummyAuthorizer()
    authorizer.add_user("user", "12345", os.getcwd(), perm="elradfmwMT")
    handler = FTPHandler
    handler.authorizer = authorizer
    server = FTPServer(("0.0.0.0", 21), handler)
    print("🟢 FTP server running on port 2121 (user: user / pass: 12345)")
    server.serve_forever()

# ===================== FTPS =====================
def start_ftps_server():
    authorizer = DummyAuthorizer()
    authorizer.add_user("secure", "12345", os.getcwd(), perm="elradfmwMT")
    handler = TLS_FTPHandler
    handler.certfile = "cert.pem"
    handler.keyfile = "key.pem"
    handler.tls_control_required = True
    handler.tls_data_required = True
    handler.authorizer = authorizer
    server = FTPServer(("0.0.0.0", 2122), handler)
    print("🟢 FTPS server running on port 2122 (secure FTP with TLS)")
    server.serve_forever()

# ===================== Telnet =====================
class TelnetHandler(StreamRequestHandler):
    def handle(self):
        self.send_telnet_negotiation()
        self.send_telnet_banner()
        try:
            self.wfile.write(b"login: ")
            username = self.rfile.readline().strip()
            self.wfile.write(b"password: ")
            password = self.rfile.readline().strip()
            self.wfile.write(b"\r\nLogin incorrect\r\n")
            self.wfile.write(b"Connection closed by foreign host.\r\n")
        except Exception as e:
            print(f"[!] Telnet error: {e}")

    def send_telnet_negotiation(self):
        try:
            self.wfile.write(bytes([
                IAC, WILL, ECHO,
                IAC, WILL, SUPPRESS_GO_AHEAD,
                IAC, DO, TERMINAL_TYPE
            ]))
        except Exception as e:
            print(f"[!] Telnet negotiation failed: {e}")

    def send_telnet_banner(self):
        self.wfile.write(b"\r\nFake SunOS 5.10 telnetd\r\n")
        self.wfile.write(b"Escape character is '^]'.\r\n")

def start_telnet_server():
    with TCPServer(("0.0.0.0", 23), TelnetHandler) as server:
        print("🟢 Telnet server running on port 2323")
        server.serve_forever()

# ===================== HTTP =====================
def start_http_server():
    handler = SimpleHTTPRequestHandler
    httpd = HTTPServer(("0.0.0.0", 8080), handler)
    print("🟢 HTTP server running on port 8080")
    httpd.serve_forever()

# ===================== HTTPS =====================
class ThreadedHTTPSServer(ThreadingMixIn, HTTPServer):
    pass

def start_https_server():
    handler = SimpleHTTPRequestHandler
    httpd = ThreadedHTTPSServer(("0.0.0.0", 8443), handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    print("🟢 HTTPS server running on port 8443")
    httpd.serve_forever()

# ===================== Certificate Generator =====================
def generate_cert():
    if not os.path.exists("cert.pem") or not os.path.exists("key.pem"):
        print("🔧 Generating self-signed certificate...")
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u'localhost'),
        ])
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            key.public_key()).serial_number(
            x509.random_serial_number()).not_valid_before(
            datetime.utcnow()).not_valid_after(
            datetime.utcnow() + timedelta(days=365)).sign(key, hashes.SHA256())
        with open("key.pem", "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()))
        with open("cert.pem", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        print("✅ Certificate and key generated.")

# =====================
import paramiko
from socket import socket as Socket

class SimpleSSHServer(paramiko.ServerInterface):
    def check_auth_password(self, username, password):
        if username == "sshuser" and password == "makebigmoney":
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

def start_ssh_server():
    host_key = paramiko.RSAKey.generate(2048)
    sock = Socket()
    sock.bind(("0.0.0.0", 22))
    sock.listen(100)
    print("🟢 SSH server running on port 2222 (user: sshuser / pass: makebigmoney)")

    while True:
        client, addr = sock.accept()
        transport = paramiko.Transport(client)
        transport.add_server_key(host_key)
        server = SimpleSSHServer()
        try:
            transport.start_server(server=server)
            chan = transport.accept(20)
            if chan:
                chan.send(b"Welcome to fake SSH server!\n")
                chan.close()
        except Exception as e:
            print(f"[!] SSH error: {e}")
        finally:
            transport.close()


# ===================== Main =====================
if __name__ == "__main__":
    generate_cert()

    services = [
        threading.Thread(target=start_ftp_server),
        threading.Thread(target=start_ftps_server),
        threading.Thread(target=start_telnet_server),
        threading.Thread(target=start_http_server),
        threading.Thread(target=start_https_server),
        threading.Thread(target=start_ssh_server)
    ]

    for t in services:
        t.daemon = True
        t.start()

    print("🚀 All test servers are running... Press Ctrl+C to stop.")
    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("\n🛑 Shutting down servers.")
