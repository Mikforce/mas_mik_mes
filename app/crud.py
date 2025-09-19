from sqlalchemy.orm import Session
from . import models, schemas
from typing import Optional, List
from passlib.context import CryptContext
import hashlib

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


# User operations
def get_user(db: Session, user_id: int) -> Optional[models.User]:
    return db.query(models.User).filter(models.User.id == user_id).first()


def get_user_by_username(db: Session, username: str) -> Optional[models.User]:
    return db.query(models.User).filter(models.User.username == username).first()


def get_user_by_email(db: Session, email: str) -> Optional[models.User]:
    return db.query(models.User).filter(models.User.email == email).first()


def get_users(db: Session, skip: int = 0, limit: int = 100) -> List[models.User]:
    return db.query(models.User).offset(skip).limit(limit).all()


def create_user(db: Session, user: schemas.UserCreate) -> models.User:
    # Проверяем, что публичный ключ валидный
    if not user.public_key.strip() or "PUBLIC KEY" not in user.public_key:
        raise ValueError("Invalid public key format")

    hashed_password = get_password_hash(user.password)

    db_user = models.User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password,
        public_key=user.public_key
    )

    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def update_user_public_key(db: Session, user_id: int, public_key: str) -> models.User:
    user = get_user(db, user_id)
    if user:
        user.public_key = public_key
        db.commit()
        db.refresh(user)
    return user


# Message operations
def create_message(db: Session, encrypted_text: str, encrypted_key: str,
                   iv: str, signature: str, sender_id: int, receiver_id: int) -> models.Message:
    db_message = models.Message(
        encrypted_text=encrypted_text,
        encrypted_key=encrypted_key,
        iv=iv,
        signature=signature,
        sender_id=sender_id,
        receiver_id=receiver_id
    )

    db.add(db_message)
    db.commit()
    db.refresh(db_message)
    return db_message


def get_message(db: Session, message_id: int) -> Optional[models.Message]:
    return db.query(models.Message).filter(models.Message.id == message_id).first()


def get_user_messages(db: Session, user_id: int, skip: int = 0, limit: int = 100) -> List[models.Message]:
    return (db.query(models.Message)
            .filter((models.Message.sender_id == user_id) | (models.Message.receiver_id == user_id))
            .order_by(models.Message.timestamp.desc())
            .offset(skip)
            .limit(limit)
            .all())


def get_conversation_messages(db: Session, user1_id: int, user2_id: int, skip: int = 0, limit: int = 100) -> List[
    models.Message]:
    return (db.query(models.Message)
            .filter(
        ((models.Message.sender_id == user1_id) & (models.Message.receiver_id == user2_id)) |
        ((models.Message.sender_id == user2_id) & (models.Message.receiver_id == user1_id))
    )
            .order_by(models.Message.timestamp.desc())
            .offset(skip)
            .limit(limit)
            .all())


# Добавим метод для получения последнего сообщения в диалоге
def get_last_conversation_message(db: Session, user1_id: int, user2_id: int) -> Optional[models.Message]:
    return (
        db.query(models.Message)
        .filter(
            ((models.Message.sender_id == user1_id) & (models.Message.receiver_id == user2_id)) |
            ((models.Message.sender_id == user2_id) & (models.Message.receiver_id == user1_id))
        )
        .order_by(models.Message.timestamp.desc())
        .first()
    )


# Метод для получения непрочитанных сообщений
def get_unread_messages_count(db: Session, user_id: int, conversation_with_id: int = None) -> int:
    query = db.query(models.Message).filter(
        models.Message.receiver_id == user_id,
        models.Message.is_read == False  # Добавим поле is_read в модель
    )

    if conversation_with_id:
        query = query.filter(models.Message.sender_id == conversation_with_id)

    return query.count()


# Метод для пометки сообщений как прочитанных
def mark_messages_as_read(db: Session, user_id: int, sender_id: int):
    db.query(models.Message).filter(
        models.Message.receiver_id == user_id,
        models.Message.sender_id == sender_id,
        models.Message.is_read == False
    ).update({"is_read": True})
    db.commit()