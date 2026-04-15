"""
Utility to integrate the encryptor server into an existing FastAPI application.
Use integrate_encryptor(app) instead of wiring the router and middleware manually.
"""

from fastapi import FastAPI, Request, Response

from encryptor.crypto.encryptor import Encryptor
from encryptor.server.router import router as handshake_router


def integrate_encryptor(app: FastAPI, prefix: str = "/crypto") -> None:
    """
    Mount the handshake endpoint and response-encryption middleware onto an
    existing FastAPI application.

    The app gains:
      - POST {prefix}/handshake  — DH key exchange; returns a session token
      - HTTP middleware           — encrypts response bodies per session token

    State added to app.state:
      - encryptor:    shared Encryptor instance (DH + AES-256-GCM)
      - session_keys: dict[session_token -> shared_key], one entry per client
    """
    app.state.encryptor = Encryptor()
    app.state.session_keys = {}  # dict[session_token: str -> shared_key: bytes]

    app.include_router(handshake_router, prefix=prefix, tags=["crypto"])

    @app.middleware("http")
    async def encrypt_response_middleware(request: Request, call_next):
        """Encrypt API response bodies with the requesting client's shared key."""
        response = await call_next(request)

        # Never encrypt the handshake endpoint itself
        if request.url.path.startswith(prefix):
            return response

        session_token = request.headers.get("X-Session-Token")
        shared_key = app.state.session_keys.get(session_token) if session_token else None

        if shared_key is None:
            return response

        body = b""
        async for chunk in response.body_iterator:
            body += chunk

        try:
            encrypted = app.state.encryptor.encrypt(body, shared_key)
            headers = dict(response.headers)
            headers["X-Encrypted"] = "true"
            headers["Content-Length"] = str(len(encrypted))
            return Response(
                content=encrypted,
                status_code=response.status_code,
                headers=headers,
                media_type="application/octet-stream",
            )
        except Exception as exc:
            import logging
            logging.getLogger(__name__).warning(
                "Response encryption failed, returning plaintext: %s", exc
            )
            return Response(
                content=body,
                status_code=response.status_code,
                headers=dict(response.headers),
            )
