import os
import ssl
import threading
import argparse
from http.server import HTTPServer, SimpleHTTPRequestHandler
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler, TLS_FTPHandler
from pyftpdlib.servers import FTPServer


# ===================== FTP =====================
def start_ftp_server():
    authorizer = DummyAuthorizer()
    authorizer.add_user("user", "12345", os.getcwd(), perm="elradfmwMT")
    handler = FTPHandler
    handler.authorizer = authorizer
    server = FTPServer(("0.0.0.0", 2121), handler)
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
        self.wfile.write(b"Welcome to Test Telnet Server!\nType something:\n")
        while True:
            data = self.rfile.readline().strip()
            if not data:
                break
            response = b"Echo: " + data + b"\n"
            self.wfile.write(response)

def start_telnet_server():
    with TCPServer(("0.0.0.0", 2323), TelnetHandler) as server:
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
        print("🔧 Generating self-signed certificate using cryptography...")
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import serialization, hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from datetime import datetime, timedelta

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


# ===================== Argument Parser =====================
def parse_args():
    parser = argparse.ArgumentParser(description="Test Multi-Service Server")
    parser.add_argument("--all", action="store_true", help="Start all services")
    parser.add_argument("--ftp", action="store_true", help="Start FTP server")
    parser.add_argument("--ftps", action="store_true", help="Start FTPS server")
    parser.add_argument("--http", action="store_true", help="Start HTTP server")
    parser.add_argument("--https", action="store_true", help="Start HTTPS server")
    parser.add_argument("--telnet", action="store_true", help="Start Telnet server")
    return parser.parse_args()


# ===================== Main =====================
if __name__ == "__main__":
    args = parse_args()
    generate_cert()

    services = []

    if args.all or args.ftp:
        services.append(threading.Thread(target=start_ftp_server))
    if args.all or args.ftps:
        services.append(threading.Thread(target=start_ftps_server))
    if args.all or args.telnet:
        services.append(threading.Thread(target=start_telnet_server))
    if args.all or args.http:
        services.append(threading.Thread(target=start_http_server))
    if args.all or args.https:
        services.append(threading.Thread(target=start_https_server))

    for t in services:
        t.daemon = True
        t.start()

    if services:
        print("🚀 Selected test servers are running... Press Ctrl+C to stop.")
        try:
            while True:
                pass
        except KeyboardInterrupt:
            print("\n🛑 Shutting down servers.")
    else:
        print("⚠️ No service selected. Use --help for options.")
