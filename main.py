from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs
from pathlib import Path
import ssl
import os

# optioneel: cryptography voor auto cert
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

# ---------- CONFIG ----------
class Config:
    HOST = "0.0.0.0"
    PORT = 8443
    USERNAME = "admin"
    PASSWORD = "admin123"
    HTML_DIR = Path("html")
    CERT_FILE = "cert.pem"
    KEY_FILE = "key.pem"

# ---------- HTML Loader ----------
class HtmlLoader:
    @staticmethod
    def load(page: str) -> bytes:
        return (Config.HTML_DIR / page).read_bytes()

# ---------- Authenticatie ----------
class AuthService:
    @staticmethod
    def validate(username: str, password: str) -> bool:
        return username == Config.USERNAME and password == Config.PASSWORD

# ---------- Request Handler ----------
class RequestHandler(BaseHTTPRequestHandler):
    server_version = "SecureServer"
    sys_version = ""

    def do_GET(self):
        self._respond(200, HtmlLoader.load("login.html"))

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        data = parse_qs(self.rfile.read(length).decode())

        username = data.get("username", [""])[0]
        password = data.get("password", [""])[0]

        if AuthService.validate(username, password):
            self._respond(200, HtmlLoader.load("success.html"))
        else:
            self._respond(401, HtmlLoader.load("failed.html"))

    def _respond(self, status: int, content: bytes):
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

# ---------- Auto-certificaat genereren ----------
def generate_self_signed_cert(cert_file, key_file):
    if os.path.exists(cert_file) and os.path.exists(key_file):
        return
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "NL"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Nederland"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Stad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MijnOrganisatie"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)\
        .public_key(key.public_key())\
        .serial_number(x509.random_serial_number())\
        .not_valid_before(datetime.datetime.utcnow())\
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))\
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)\
        .sign(key, hashes.SHA256(), default_backend())

    # schrijf key
    with open(key_file, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # schrijf cert
    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

# ---------- Webserver ----------
class WebServer:
    def __init__(self):
        generate_self_signed_cert(Config.CERT_FILE, Config.KEY_FILE)
        self.server = HTTPServer((Config.HOST, Config.PORT), RequestHandler)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=Config.CERT_FILE, keyfile=Config.KEY_FILE)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)

    def run(self):
        print(f"Server draaiend op https://{Config.HOST}:{Config.PORT}")
        self.server.serve_forever()

# ---------- Start ----------
if __name__ == "__main__":
    WebServer().run()
