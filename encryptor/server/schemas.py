from pydantic import BaseModel


class HandshakeRequest(BaseModel):
    public_key: str  # PEM
    salt: str        # hex


class HandshakeResponse(BaseModel):
    public_key: str     # PEM
    salt: str           # hex — echoed from client's request
    session_token: str  # UUID identifying this client's shared key
