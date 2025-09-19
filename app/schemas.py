from pydantic import BaseModel, Field
from typing import Optional, List, Dict
from datetime import datetime

class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_]+$")
    email: Optional[str] = None

class UserCreate(UserBase):
    password: str = Field(..., min_length=6)
    public_key: str = Field(..., description="Public key for encryption")  # Добавлено

class UserLogin(BaseModel):
    username: str
    password: str

class User(UserBase):
    id: int
    public_key: str  # Только для чтения

    class Config:
        from_attributes = True

class PublicKeyResponse(BaseModel):
    username: str
    public_key: str
    key_fingerprint: str

class Token(BaseModel):
    access_token: str
    token_type: str

class MessageBase(BaseModel):
    text: str

class MessageCreate(BaseModel):
    text: str = Field(..., description="Encrypted message text")
    receiver_username: str
    encrypted_key: str = Field(..., description="Encrypted AES key")
    iv: str = Field(..., description="Initialization vector for AES")
    signature: str = Field(..., description="Message signature")

    class Config:
        json_schema_extra = {
            "example": {
                "text": "base64-encrypted-text",
                "receiver_username": "username",
                "encrypted_key": "base64-encrypted-aes-key",
                "iv": "base64-iv",
                "signature": "base64-signature"
            }
        }

class Message(BaseModel):
    id: int
    sender_id: int
    receiver_id: int
    encrypted_text: str
    encrypted_key: str
    iv: str
    signature: str
    timestamp: datetime
    sender: "User"
    receiver: "User"

    class Config:
        from_attributes = True

class DecryptedMessage(BaseModel):
    id: int
    text: str
    sender: User
    receiver: User
    timestamp: datetime

class KeyVerification(BaseModel):
    username: str
    fingerprint: str
    verified: bool

class Conversation(BaseModel):
    user: User
    last_message: Optional[Message] = None
    unread_count: int = 0
    last_message_time: Optional[datetime] = None

class RecentMessage(BaseModel):
    id: int
    encrypted_text: str
    sender: User
    receiver: User
    timestamp: datetime
    is_own: bool

class UnreadCount(BaseModel):
    total: int
    by_conversation: Dict[str, int] = {}

Message.update_forward_refs()