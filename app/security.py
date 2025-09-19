from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hmac
from cryptography.exceptions import InvalidSignature
import os
import base64
import time
import hashlib


# --- Генерация ключей ---
def generate_rsa_key_pair():
    """Генерирует пару RSA приватный/публичный ключ"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b'strong-password')  # Защита паролем
    )

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem.decode('utf-8'), public_pem.decode('utf-8')


def generate_aes_key():
    """Генерирует случайный 256-битный ключ для AES-GCM"""
    return AESGCM.generate_key(bit_length=256)


def generate_key_fingerprint(public_key_pem: str) -> str:
    """Генерирует отпечаток публичного ключа"""
    return hashlib.sha256(public_key_pem.encode()).hexdigest()[:16]


# --- Шифрование / Расшифровка ---
def encrypt_message_aes(plaintext: str, aes_key: bytes, iv: bytes = None) -> tuple:
    """Шифрует сообщение с помощью AES-GCM"""
    if iv is None:
        iv = os.urandom(12)

    aesgcm = AESGCM(aes_key)

    # Добавляем timestamp для защиты от replay-атак
    timestamp = int(time.time()).to_bytes(8, 'big')
    data_to_encrypt = timestamp + plaintext.encode('utf-8')

    ciphertext = aesgcm.encrypt(iv, data_to_encrypt, None)

    return base64.b64encode(iv).decode('utf-8'), base64.b64encode(ciphertext).decode('utf-8')


def decrypt_message_aes(encrypted_data_b64: str, iv_b64: str, aes_key: bytes) -> str:
    """Расшифровывает сообщение, зашифрованное AES-GCM"""
    iv = base64.b64decode(iv_b64)
    ciphertext = base64.b64decode(encrypted_data_b64)

    aesgcm = AESGCM(aes_key)

    try:
        decrypted_data = aesgcm.decrypt(iv, ciphertext, None)
        # Извлекаем timestamp и сообщение
        timestamp = int.from_bytes(decrypted_data[:8], 'big')
        plaintext = decrypted_data[8:].decode('utf-8')

        # Проверяем timestamp (защита от replay)
        current_time = int(time.time())
        if abs(current_time - timestamp) > 300:  # 5 минут допустимого расхождения
            raise ValueError("Message timestamp is invalid")

        return plaintext
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")


def encrypt_aes_key_with_rsa(aes_key: bytes, public_key_pem: str) -> str:
    """Шифрует симметричный AES ключ с помощью публичного RSA ключа получателя"""
    public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))

    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return base64.b64encode(encrypted_key).decode('utf-8')


def decrypt_aes_key_with_rsa(encrypted_aes_key_b64: str, private_key_pem: str, password: bytes = None) -> bytes:
    """Расшифровывает AES ключ с помощью приватного RSA ключа"""
    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=password,
        )

        encrypted_key = base64.b64decode(encrypted_aes_key_b64)

        decrypted_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return decrypted_key
    except Exception as e:
        raise ValueError(f"Failed to decrypt AES key: {str(e)}")


# --- Цифровые подписи ---
def sign_message(message: str, private_key_pem: str, password: bytes = None) -> str:
    """Создает цифровую подпись сообщения"""
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=password,
    )

    signature = private_key.sign(
        message.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return base64.b64encode(signature).decode('utf-8')


def verify_signature(message: str, signature_b64: str, public_key_pem: str) -> bool:
    """Проверяет цифровую подпись сообщения"""
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
        signature = base64.b64decode(signature_b64)

        public_key.verify(
            signature,
            message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return True
    except InvalidSignature:
        return False
    except Exception:
        return False