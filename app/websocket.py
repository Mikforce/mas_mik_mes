from fastapi import WebSocket, WebSocketDisconnect, Depends
from sqlalchemy.orm import Session
from .database import get_db
from . import crud, models
import json
from typing import Dict, List


class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[int, WebSocket] = {}
        self.user_connections: Dict[int, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, user_id: int):
        await websocket.accept()
        if user_id not in self.user_connections:
            self.user_connections[user_id] = []
        self.user_connections[user_id].append(websocket)
        self.active_connections[id(websocket)] = user_id
        print(f"User {user_id} connected. Total connections: {len(self.user_connections.get(user_id, []))}")

    def disconnect(self, websocket: WebSocket):
        user_id = self.active_connections.get(id(websocket))
        if user_id and user_id in self.user_connections:
            self.user_connections[user_id] = [conn for conn in self.user_connections[user_id] if conn != websocket]
            if not self.user_connections[user_id]:
                del self.user_connections[user_id]
        if id(websocket) in self.active_connections:
            del self.active_connections[id(websocket)]
        print(f"User {user_id} disconnected. Remaining connections: {len(self.user_connections.get(user_id, []))}")

    async def send_personal_message(self, message: dict, user_id: int):
        if user_id in self.user_connections:
            for connection in self.user_connections[user_id]:
                try:
                    await connection.send_json(message)
                except Exception as e:
                    print(f"Error sending message to user {user_id}: {e}")
                    self.disconnect(connection)

    async def broadcast(self, message: dict):
        for user_id in self.user_connections:
            await self.send_personal_message(message, user_id)


manager = ConnectionManager()


async def websocket_endpoint(websocket: WebSocket, token: str, db: Session = Depends(get_db)):
    from .auth import verify_token

    try:
        # Verify JWT token
        credentials_exception = Exception("Invalid token")

        # Remove "Bearer " prefix if present
        if token.startswith('Bearer '):
            token = token[7:]

        token_data = verify_token(token, credentials_exception)
        user = crud.get_user_by_username(db, username=token_data["username"])

        if not user:
            await websocket.close(code=1008)
            return

        await manager.connect(websocket, user.id)

        try:
            while True:
                # Client can send ping messages
                data = await websocket.receive_text()
                if data == "ping":
                    await websocket.send_text("pong")

        except WebSocketDisconnect:
            manager.disconnect(websocket)

    except Exception as e:
        print(f"WebSocket connection failed: {e}")
        await websocket.close(code=1008)


# Function to notify users about new messages
async def notify_new_message(message: models.Message, db: Session):
    message_data = {
        "type": "new_message",
        "message": {
            "id": message.id,
            "encrypted_text": message.encrypted_text,
            "encrypted_key": message.encrypted_key,
            "iv": message.iv,
            "signature": message.signature,
            "sender_id": message.sender_id,
            "receiver_id": message.receiver_id,
            "timestamp": message.timestamp.isoformat(),
            "sender_username": message.sender.username,
            "receiver_username": message.receiver.username
        }
    }

    # Notify sender and receiver
    await manager.send_personal_message(message_data, message.sender_id)
    await manager.send_personal_message(message_data, message.receiver_id)


async def notify_message_read(user_id: int, sender_id: int, db: Session):
    message_data = {
        "type": "messages_read",
        "data": {
            "reader_id": user_id,
            "sender_id": sender_id
        }
    }
    await manager.send_personal_message(message_data, sender_id)



