import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from core.secure_channel_server import EncryptorServer

if __name__ == "__main__":
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))

    server = EncryptorServer()
    server.start_server(host=host, port=port)
