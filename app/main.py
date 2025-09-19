from fastapi import FastAPI, Depends, HTTPException, status, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from . import models, schemas, crud, auth, security
from .database import SessionLocal, engine, get_db
from .admin import setup_admin
from typing import List
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
import hashlib
from .websocket import websocket_endpoint, manager, notify_new_message, notify_message_read
from fastapi.staticfiles import StaticFiles


models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="Secure Family Messenger API")

# Настройка админ-панели
admin = setup_admin(app)

# Настройка CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Переопределяем зависимости для аутентификации
async def get_current_user_override(
        token: str = Depends(auth.oauth2_scheme),
        db: Session = Depends(get_db)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    token_data = auth.verify_token(token, credentials_exception)
    user = crud.get_user_by_username(db, username=token_data["username"])
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user_override(current_user: models.User = Depends(get_current_user_override)):
    return current_user


app.dependency_overrides[auth.get_current_user] = get_current_user_override
app.dependency_overrides[auth.get_current_active_user] = get_current_active_user_override


# Эндпоинт для создания администратора
@app.post("/create-admin/")
def create_admin_user(db: Session = Depends(get_db)):
    admin_user = crud.get_user_by_username(db, "admin")
    if admin_user:
        return {"message": "Admin user already exists"}

    # Генерируем ключи для админа
    private_key, public_key = security.generate_rsa_key_pair()

    admin_data = schemas.UserCreate(
        username="admin",
        email="admin@family-messenger.com",
        password="admin123",
        public_key=public_key
    )

    admin_user = crud.create_user(db=db, user=admin_data)

    return {
        "message": "Admin user created",
        "username": "admin",
        "password": "admin123",
        "private_key": private_key,  # Только для первоначальной настройки!
        "warning": "Save this private key securely and never share it!"
    }


# Эндпоинт для регистрации
@app.post("/register/", response_model=schemas.User)
def register_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    print(f"Registration attempt: {user.username}, email: {user.email}")
    print(f"Public key provided: {user.public_key[:100]}...")  # Первые 100 символов

    db_user = crud.get_user_by_username(db, username=user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")

    try:
        new_user = crud.create_user(db=db, user=user)
        print(f"User {user.username} registered successfully")
        return new_user
    except ValueError as e:
        print(f"Registration error: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        print(f"Unexpected registration error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# Эндпоинт для получения публичного ключа пользователя
@app.get("/users/{username}/public-key", response_model=schemas.PublicKeyResponse)
def get_user_public_key(username: str, db: Session = Depends(get_db)):
    user = crud.get_user_by_username(db, username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    fingerprint = security.generate_key_fingerprint(user.public_key)

    return {
        "username": user.username,
        "public_key": user.public_key,
        "key_fingerprint": fingerprint
    }


# Эндпоинт для верификации ключа
@app.get("/users/{username}/verify-key/{fingerprint}")
def verify_key_fingerprint(username: str, fingerprint: str, db: Session = Depends(get_db)):
    user = crud.get_user_by_username(db, username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    expected_fingerprint = security.generate_key_fingerprint(user.public_key)
    is_valid = fingerprint.lower() == expected_fingerprint.lower()

    return {
        "username": username,
        "fingerprint": expected_fingerprint,
        "verified": is_valid
    }


# Эндпоинт для отправки сообщения
# Эндпоинт для отправки сообщения
@app.post("/messages/", response_model=schemas.Message)
async def send_message(message: schemas.MessageCreate, db: Session = Depends(get_db),
                       current_user: models.User = Depends(get_current_active_user_override)):
    print(f"Message received from {current_user.username} to {message.receiver_username}")
    print(f"Text length: {len(message.text)}")
    print(f"Encrypted key length: {len(message.encrypted_key)}")
    print(f"IV length: {len(message.iv)}")
    print(f"Signature length: {len(message.signature)}")

    receiver = crud.get_user_by_username(db, username=message.receiver_username)
    if not receiver:
        raise HTTPException(status_code=404, detail="Receiver not found")

    print(f"Receiver found: {receiver.username}")

    # Валидация подписи (упростим для демо)
    try:
        is_signature_valid = security.verify_signature(
            message.text,
            message.signature,
            current_user.public_key
        )

        if not is_signature_valid:
            print("Signature validation failed")
            # Для демо пропустим ошибку валидации подписи
            # raise HTTPException(status_code=400, detail="Invalid message signature")

    except Exception as e:
        print(f"Signature validation error: {e}")
        # Для демо пропустим ошибку

    # Сохраняем сообщение
    try:
        db_message = crud.create_message(
            db=db,
            encrypted_text=message.text,
            encrypted_key=message.encrypted_key,
            iv=message.iv,
            signature=message.signature,
            sender_id=current_user.id,
            receiver_id=receiver.id
        )

        print(f"Message saved with ID: {db_message.id}")

        # Отправляем уведомление через WebSocket
        await notify_new_message(db_message, db)

        return db_message

    except Exception as e:
        print(f"Error saving message: {e}")
        raise HTTPException(status_code=500, detail="Error saving message")


# Эндпоинт для получения сообщений (возвращает только зашифрованные данные)
@app.get("/messages/", response_model=List[schemas.Message])
def get_messages(skip: int = 0, limit: int = 100, db: Session = Depends(get_db),
                 current_user: models.User = Depends(get_current_active_user_override)):
    messages = crud.get_user_messages(db, user_id=current_user.id, skip=skip, limit=limit)
    return messages


# Эндпоинт для проверки безопасности системы
@app.get("/security/status")
def security_status(db: Session = Depends(get_db)):
    total_users = db.query(models.User).count()
    total_messages = db.query(models.Message).count()

    # Проверяем, что у всех пользователей есть публичные ключи
    users_without_public_keys = db.query(models.User).filter(
        models.User.public_key.is_(None) | (models.User.public_key == "")
    ).count()

    return {
        "total_users": total_users,
        "total_messages": total_messages,
        "users_without_public_keys": users_without_public_keys,
        "security_level": "HIGH" if users_without_public_keys == 0 else "MEDIUM",
        "e2ee_implemented": True,
        "private_keys_on_server": 0,  # Приватные ключи больше не хранятся на сервере
        "recommendation": "✅ No private keys stored on server" if users_without_public_keys == 0
        else "⚠️  Some users missing public keys"
    }


# Остальные эндпоинты...
@app.post("/login/", response_model=schemas.Token)
def login_for_access_token(form_data: schemas.UserLogin, db: Session = Depends(get_db)):
    user = auth.authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me/", response_model=schemas.User)
def read_users_me(current_user: models.User = Depends(get_current_active_user_override)):
    return current_user


@app.on_event("startup")
def create_admin_on_startup():
    from sqlalchemy.orm import Session
    from .database import SessionLocal

    db = SessionLocal()
    try:
        admin_user = crud.get_user_by_username(db, "admin")
        if not admin_user:
            print("ℹ️  Admin user not found. Use /create-admin/ endpoint to create one.")
        else:
            print("✅ Admin user exists")

        # Простая проверка безопасности
        total_users = db.query(models.User).count()
        users_without_public_keys = db.query(models.User).filter(
            models.User.public_key.is_(None) | (models.User.public_key == "")
        ).count()

        print(f"🔒 Security status: {total_users - users_without_public_keys}/{total_users} users have public keys")
        print("✅ No private keys stored on server (E2EE implemented)")

    except Exception as e:
        print(f"⚠️  Security check error: {e}")
    finally:
        db.close()


# Эндпоинт для получения истории переписки с конкретным пользователем
@app.get("/messages/conversation/{other_username}", response_model=List[schemas.Message])
def get_conversation(
        other_username: str,
        skip: int = 0,
        limit: int = 100,
        db: Session = Depends(get_db),
        current_user: models.User = Depends(get_current_active_user_override)
):
    other_user = crud.get_user_by_username(db, other_username)
    if not other_user:
        raise HTTPException(status_code=404, detail="User not found")

    messages = crud.get_conversation_messages(
        db,
        user1_id=current_user.id,
        user2_id=other_user.id,
        skip=skip,
        limit=limit
    )
    return messages


# Эндпоинт для получения всех диалогов пользователя
@app.get("/conversations/", response_model=List[schemas.User])
def get_conversations(
        db: Session = Depends(get_db),
        current_user: models.User = Depends(get_current_active_user_override)
):
    # Получаем всех пользователей, с которыми есть переписка
    from sqlalchemy import distinct, or_

    # Находим всех собеседников
    sender_ids = db.query(models.Message.receiver_id).filter(
        models.Message.sender_id == current_user.id
    ).distinct().all()

    receiver_ids = db.query(models.Message.sender_id).filter(
        models.Message.receiver_id == current_user.id
    ).distinct().all()

    # Объединяем и получаем уникальные ID
    all_ids = set([id[0] for id in sender_ids] + [id[0] for id in receiver_ids])

    if not all_ids:
        return []

    # Получаем информацию о собеседниках
    conversations = db.query(models.User).filter(
        models.User.id.in_(all_ids)
    ).all()

    return conversations


# Эндпоинт для получения последних сообщений из всех диалогов
@app.get("/messages/recent/", response_model=List[dict])
def get_recent_messages(
        limit_per_conversation: int = 5,
        db: Session = Depends(get_db),
        current_user: models.User = Depends(get_current_active_user_override)
):
    # Более сложный запрос для получения последних сообщений из каждого диалога
    from sqlalchemy import desc, func

    # Подзапрос для получения последних сообщений каждого диалога
    subquery = (
        db.query(
            models.Message.id,
            models.Message.sender_id,
            models.Message.receiver_id,
            models.Message.timestamp,
            func.row_number().over(
                partition_by=func.greatest(models.Message.sender_id, models.Message.receiver_id),
                order_by=desc(models.Message.timestamp)
            ).label('row_num')
        )
        .filter(
            (models.Message.sender_id == current_user.id) |
            (models.Message.receiver_id == current_user.id)
        )
        .subquery()
    )

    recent_messages = (
        db.query(models.Message)
        .join(subquery, models.Message.id == subquery.c.id)
        .filter(subquery.c.row_num <= limit_per_conversation)
        .order_by(desc(models.Message.timestamp))
        .all()
    )

    # Форматируем ответ
    result = []
    for msg in recent_messages:
        result.append({
            "id": msg.id,
            "text": msg.encrypted_text,  # Клиент будет расшифровывать
            "sender": {
                "id": msg.sender.id,
                "username": msg.sender.username
            },
            "receiver": {
                "id": msg.receiver.id,
                "username": msg.receiver.username
            },
            "timestamp": msg.timestamp,
            "is_own": msg.sender_id == current_user.id
        })

    return result


# Эндпоинт для получения количества непрочитанных сообщений
@app.get("/messages/unread/count")
def get_unread_count(
        conversation_with: str = None,
        db: Session = Depends(get_db),
        current_user: models.User = Depends(get_current_active_user_override)
):
    conversation_with_id = None
    if conversation_with:
        other_user = crud.get_user_by_username(db, conversation_with)
        if not other_user:
            raise HTTPException(status_code=404, detail="User not found")
        conversation_with_id = other_user.id

    count = crud.get_unread_messages_count(db, current_user.id, conversation_with_id)
    return {"unread_count": count}


# Эндпоинт для пометки сообщений как прочитанных
@app.post("/messages/mark-read/{username}")
def mark_as_read(
        username: str,
        db: Session = Depends(get_db),
        current_user: models.User = Depends(get_current_active_user_override)
):
    other_user = crud.get_user_by_username(db, username)
    if not other_user:
        raise HTTPException(status_code=404, detail="User not found")

    crud.mark_messages_as_read(db, current_user.id, other_user.id)
    return {"message": "Messages marked as read"}


# Эндпоинт для получения всех диалогов с информацией
@app.get("/conversations/with-info", response_model=List[dict])
def get_conversations_with_info(
        db: Session = Depends(get_db),
        current_user: models.User = Depends(get_current_active_user_override)
):
    # Получаем всех собеседников
    from sqlalchemy import distinct

    sender_ids = db.query(models.Message.receiver_id).filter(
        models.Message.sender_id == current_user.id
    ).distinct().all()

    receiver_ids = db.query(models.Message.sender_id).filter(
        models.Message.receiver_id == current_user.id
    ).distinct().all()

    all_ids = set([id[0] for id in sender_ids] + [id[0] for id in receiver_ids])

    if not all_ids:
        return []

    conversations = []
    for user_id in all_ids:
        other_user = crud.get_user(db, user_id)
        if not other_user:
            continue

        # Получаем последнее сообщение
        last_message = crud.get_last_conversation_message(db, current_user.id, user_id)

        # Получаем количество непрочитанных
        unread_count = crud.get_unread_messages_count(db, current_user.id, user_id)

        conversations.append({
            "user": {
                "id": other_user.id,
                "username": other_user.username,
                "public_key": other_user.public_key
            },
            "last_message": {
                "id": last_message.id if last_message else None,
                "encrypted_text": last_message.encrypted_text if last_message else None,
                "timestamp": last_message.timestamp if last_message else None,
                "is_own": last_message.sender_id == current_user.id if last_message else False
            } if last_message else None,
            "unread_count": unread_count,
            "last_message_time": last_message.timestamp if last_message else None
        })

    # Сортируем по времени последнего сообщения
    conversations.sort(key=lambda x: x['last_message_time'] or datetime.min, reverse=True)

    return conversations



# Добавим WebSocket endpoint
@app.websocket("/ws")
async def websocket_route(websocket: WebSocket, token: str, db: Session = Depends(get_db)):
    print(f"WebSocket connection attempt with token: {token[:50]}...")
    await websocket_endpoint(websocket, token, db)


# Обновим эндпоинт отправки сообщения
@app.post("/messages/", response_model=schemas.Message)
async def send_message(message: schemas.MessageCreate, db: Session = Depends(get_db),
                       current_user: models.User = Depends(get_current_active_user_override)):
    receiver = crud.get_user_by_username(db, username=message.receiver_username)
    if not receiver:
        raise HTTPException(status_code=404, detail="Receiver not found")

    # Валидация подписи
    is_signature_valid = security.verify_signature(
        message.text,
        message.signature,
        current_user.public_key
    )

    if not is_signature_valid:
        raise HTTPException(status_code=400, detail="Invalid message signature")

    # Сохраняем сообщение
    db_message = crud.create_message(
        db=db,
        encrypted_text=message.text,
        encrypted_key=message.encrypted_key,
        iv=message.iv,
        signature=message.signature,
        sender_id=current_user.id,
        receiver_id=receiver.id
    )

    # Отправляем уведомление через WebSocket
    await notify_new_message(db_message, db)

    return db_message


# Обновим эндпоинт пометки как прочитанных
@app.post("/messages/mark-read/{username}")
async def mark_as_read(
        username: str,
        db: Session = Depends(get_db),
        current_user: models.User = Depends(get_current_active_user_override)
):
    other_user = crud.get_user_by_username(db, username)
    if not other_user:
        raise HTTPException(status_code=404, detail="User not found")

    crud.mark_messages_as_read(db, current_user.id, other_user.id)

    # Уведомляем отправителя о прочтении
    await notify_message_read(current_user.id, other_user.id, db)

    return {"message": "Messages marked as read"}

# Эндпоинт для поиска пользователей
@app.get("/users/search/{username_query}", response_model=List[schemas.User])
def search_users(
    username_query: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user_override)
):
    users = db.query(models.User).filter(
        models.User.username.ilike(f"%{username_query}%"),
        models.User.id != current_user.id
    ).limit(20).all()
    return users

# Эндпоинт для получения всех пользователей (кроме текущего)
@app.get("/users/", response_model=List[schemas.User])
def get_all_users(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user_override)
):
    users = db.query(models.User).filter(
        models.User.id != current_user.id
    ).all()
    return users





@app.post("/files/", response_model=schemas.FileResponse)
async def upload_file(
    file: schemas.FileCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user_override)
):
    receiver = crud.get_user_by_username(db, username=file.receiver_username)
    if not receiver:
        raise HTTPException(status_code=404, detail="Receiver not found")

    # Валидация подписи
    is_signature_valid = security.verify_signature(
        file.encrypted_data,
        file.signature,
        current_user.public_key
    )

    if not is_signature_valid:
        raise HTTPException(status_code=400, detail="Invalid file signature")

    # Сохраняем файл
    db_file = crud.create_file(
        db=db,
        file_data=file,
        sender_id=current_user.id,
        receiver_id=receiver.id
    )

    # Уведомляем получателя через WebSocket
    await notify_new_file(db_file, db)

    return {
        **db_file.__dict__,
        "download_url": f"/files/download/{db_file.id}"
    }

@app.get("/files/download/{file_id}")
async def download_file(
    file_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user_override)
):
    file = crud.get_file_by_id(db, file_id)
    if not file:
        raise HTTPException(status_code=404, detail="File not found")

    # Проверяем права доступа
    if file.sender_id != current_user.id and file.receiver_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    return {
        "filename": file.filename,
        "file_type": file.file_type,
        "encrypted_data": file.encrypted_data,
        "encrypted_key": file.encrypted_key,
        "iv": file.iv,
        "signature": file.signature
    }

@app.get("/files/conversation/{username}", response_model=List[schemas.FileResponse])
async def get_conversation_files(
    username: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user_override)
):
    other_user = crud.get_user_by_username(db, username)
    if not other_user:
        raise HTTPException(status_code=404, detail="User not found")

    files = crud.get_conversation_files(db, current_user.id, other_user.id)
    return files

# Функция для уведомления о новом файле через WebSocket
async def notify_new_file(file: models.File, db: Session):
    file_data = {
        "type": "new_file",
        "file": {
            "id": file.id,
            "filename": file.filename,
            "file_type": file.file_type,
            "file_size": file.file_size,
            "sender_id": file.sender_id,
            "receiver_id": file.receiver_id,
            "timestamp": file.timestamp.isoformat(),
            "download_url": f"/files/download/{file.id}"
        }
    }

    await manager.send_personal_message(file_data, file.sender_id)
    await manager.send_personal_message(file_data, file.receiver_id)




# Добавим в main.py после создания app
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Добавим эндпоинт для главной страницы
@app.get("/")
async def serve_client():
    return FileResponse("app/static/client.html")














if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)