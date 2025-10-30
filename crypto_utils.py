import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

# 🔑 کلید رمزنگاری سرور (برای Encryption at Rest)
SERVER_ENCRYPTION_KEY = b"0123456789ABCDEF0123456789ABCDEF"  # دقیقا 32 بایت


# ۱) تولید کلید متقارن تصادفی (AES-256)
def generate_symmetric_key():
    return os.urandom(32)  # 32 بایت = 256 بیت

# ۲) رمزنگاری با کلید عمومی (RSA)
def encrypt_with_public_key(public_key_pem, data):
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    encrypted = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

# ۳) رمزگشایی با کلید خصوصی (RSA)
def decrypt_with_private_key(private_key_pem, encrypted_data):
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    decrypted = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted

# ۴) رمزنگاری پیام با AES (CFB mode, با IV تصادفی)
def encrypt_message(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    # IV را به ابتدای ciphertext اضافه می‌کنیم
    return iv + ciphertext

# ۵) رمزگشایی پیام با AES (CFB mode)
def decrypt_message(key, encrypted_data):
    if len(encrypted_data) < 16:
        raise ValueError("Encrypted data is too short to contain IV.")
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode()

# ۶) رمزنگاری فایل (Encryption at Rest)
def encrypt_file(file_data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(file_data) + encryptor.finalize()
    return iv + ciphertext

# ۷) رمزگشایی فایل
def decrypt_file(encrypted_data, key):
    if len(encrypted_data) < 16:
        raise ValueError("Encrypted file data is too short to contain IV.")
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext
