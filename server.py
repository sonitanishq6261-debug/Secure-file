"""Local SecureFS service. Encrypted binary records are stored in uploaded_files/."""

from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
import base64
import json
import re


PROJECT_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = PROJECT_DIR / "uploaded_files"
FOLDER_DIR = UPLOAD_DIR / ".folders"
MAX_REQUEST_BYTES = 16 * 1024 * 1024
RECORD_MAGIC = b"SFS1"
UUID_PATTERN = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)


def valid_uuid(value):
    return isinstance(value, str) and UUID_PATTERN.fullmatch(value) is not None


def encrypted_bytes(payload):
    try:
        iv = base64.b64decode(payload["iv"], validate=True)
        ciphertext = base64.b64decode(payload["data"], validate=True)
    except (KeyError, ValueError, TypeError):
        raise ValueError("Encrypted payload is malformed.")
    if len(iv) != 12 or len(ciphertext) < 16:
        raise ValueError("Encrypted payload is malformed.")
    return RECORD_MAGIC + iv + ciphertext


def record_from_disk(path, folder_id=None):
    raw = path.read_bytes()
    if raw.startswith(RECORD_MAGIC) and len(raw) >= 32:
        record = {
            "id": path.stem,
            "payload": {
                "iv": base64.b64encode(raw[4:16]).decode("ascii"),
                "data": base64.b64encode(raw[16:]).decode("ascii"),
            },
        }
        if folder_id is not None:
            record["folderId"] = folder_id
        return record

    # Rewrite the earlier JSON wrapper as the compact binary format in place.
    legacy = json.loads(raw.decode("utf-8"))
    binary = encrypted_bytes(legacy["payload"])
    temporary = path.with_suffix(".tmp")
    temporary.write_bytes(binary)
    temporary.replace(path)
    legacy["id"] = path.stem
    if folder_id is not None:
        legacy["folderId"] = folder_id
    return legacy


def records_in(directory):
    records = []
    if not directory.exists():
        return records
    for child in directory.iterdir():
        if not child.is_dir() or child.name == ".folders":
            continue
        for path in child.glob("*.sfs"):
            try:
                records.append(record_from_disk(path, child.name))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError, KeyError):
                continue
    return records


def is_local_preview_origin(origin):
    if not origin:
        return False
    return bool(re.fullmatch(r"http://(?:127\.0\.0\.1|localhost)(?::\d+)?", origin))


class SecureFSHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(PROJECT_DIR), **kwargs)

    def add_cors_headers(self):
        origin = self.headers.get("Origin", "")
        if is_local_preview_origin(origin):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def send_json(self, status, value):
        body = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.add_cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        if not is_local_preview_origin(self.headers.get("Origin", "")):
            return self.send_json(403, {"error": "Only local preview origins are allowed."})
        self.send_response(204)
        self.add_cors_headers()
        self.end_headers()

    def read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ValueError("Invalid request size.")
        if length < 1 or length > MAX_REQUEST_BYTES:
            raise ValueError("Request is empty or larger than the 16 MB limit.")
        try:
            value = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ValueError("Request must contain valid JSON.")
        if not isinstance(value, dict):
            raise ValueError("Request must be a JSON object.")
        return value

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/files":
            return self.send_json(200, records_in(UPLOAD_DIR))
        if path == "/api/folders":
            records = []
            if FOLDER_DIR.exists():
                for item in FOLDER_DIR.glob("*.sfs"):
                    try:
                        records.append(record_from_disk(item))
                    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError, KeyError):
                        continue
            return self.send_json(200, records)
        if path.startswith("/api/"):
            return self.send_json(404, {"error": "API route not found."})
        if path == "/uploaded_files" or path.startswith("/uploaded_files/"):
            self.send_error(404)
            return
        return super().do_GET()

    def do_POST(self):
        path = urlparse(self.path).path
        if path not in ("/api/files", "/api/folders"):
            return self.send_json(404, {"error": "API route not found."})
        try:
            record = self.read_json()
            record_id = record.get("id")
            payload = record.get("payload")
            if not valid_uuid(record_id) or not isinstance(payload, dict):
                raise ValueError("Record is missing a valid ID or encrypted payload.")
            binary = encrypted_bytes(payload)
            if path == "/api/files":
                folder_id = record.get("folderId", "root")
                if folder_id != "root" and not valid_uuid(folder_id):
                    raise ValueError("Folder ID is invalid.")
                target_dir = UPLOAD_DIR / folder_id
            else:
                target_dir = FOLDER_DIR
            target_dir.mkdir(parents=True, exist_ok=True)
            target = target_dir / f"{record_id}.sfs"
            temporary = target.with_suffix(".tmp")
            temporary.write_bytes(binary)
            temporary.replace(target)
            return self.send_json(201, {"ok": True, "id": record_id})
        except ValueError as error:
            return self.send_json(400, {"error": str(error)})
        except OSError:
            return self.send_json(500, {"error": "Could not save the encrypted record to the project folder."})

    def do_DELETE(self):
        parsed = urlparse(self.path)
        parts = parsed.path.strip("/").split("/")
        if len(parts) != 3 or parts[0] != "api" or parts[1] not in ("files", "folders") or not valid_uuid(parts[2]):
            return self.send_json(404, {"error": "Record not found."})
        if parts[1] == "files":
            folder_id = parse_qs(parsed.query).get("folderId", ["root"])[0]
            if folder_id != "root" and not valid_uuid(folder_id):
                return self.send_json(400, {"error": "Folder ID is invalid."})
            target = UPLOAD_DIR / folder_id / f"{parts[2]}.sfs"
        else:
            target = FOLDER_DIR / f"{parts[2]}.sfs"
        try:
            target.unlink()
            return self.send_json(200, {"ok": True})
        except FileNotFoundError:
            return self.send_json(404, {"error": "Record not found."})
        except OSError:
            return self.send_json(500, {"error": "Could not remove the record from the project folder."})

    def log_message(self, message, *args):
        print("SecureFS: " + message % args)


if __name__ == "__main__":
    UPLOAD_DIR.mkdir(exist_ok=True)
    service = ThreadingHTTPServer(("127.0.0.1", 8000), SecureFSHandler)
    print("SecureFS is running at http://127.0.0.1:8000")
    print(f"Encrypted uploads are saved in: {UPLOAD_DIR}")
    try:
        service.serve_forever()
    except KeyboardInterrupt:
        print("\nSecureFS server stopped.")
    finally:
        service.server_close()
