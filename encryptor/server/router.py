"""
This should be responsible for exposing the endpoints needed for the key exchange
"""

from fastapi import APIRouter, Depends, HTTPException, Request
from encryptor.server.schemas import HandshakeRequest, HandshakeResponse
from encryptor.crypto.encryptor import Encryptor

router = APIRouter(tags=["Handshake"])


def get_encryptor(request: Request) -> Encryptor:
    return request.app.state.encryptor


@router.post("/handshake", response_model=HandshakeResponse)
async def handshake(
    body: HandshakeRequest,
    request: Request,
    encryptor: Encryptor = Depends(get_encryptor),
) -> HandshakeResponse:
    try:
        client_salt: bytes = bytes.fromhex(body.salt)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid salt: must be a hex-encoded string")

    try:
        client_pub_pem: bytes = body.public_key.encode()
        shared_key: bytes = encryptor.derive_shared_key(client_pub_pem, client_salt)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid public key: {e}")
    request.app.state.shared_key = shared_key

    return HandshakeResponse(
        public_key=encryptor.get_public_key().decode(),
        salt=body.salt,
    )
