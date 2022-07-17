from Crypto.Cipher import AES as CryptoAES
from Crypto.Util.Padding import pad, unpad
import Crypto.Random as Random
import base64
from hashlib import sha256

def rsa_cipher(data, x, n):
    return pow(data, x, n)

def i_to_b(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

def aes_encrypt(data: bytes, AESkey) -> bytes:
    iv = Random.new().read(CryptoAES.block_size)
    cipher = CryptoAES.new(AESkey, CryptoAES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(pad(data, CryptoAES.block_size)))

def aes_decrypt(enc: bytes, AESkey) -> bytes:
    enc = base64.b64decode(enc)
    iv = enc[:CryptoAES.block_size]
    cipher = CryptoAES.new(AESkey, CryptoAES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[CryptoAES.block_size:]), CryptoAES.block_size)

def create_digest(data: bytes, d, n):
    digest = int.from_bytes(sha256(data).digest(), 'big')
    encr_digest = rsa_cipher(digest, d, n)
    return encr_digest

def verify_digest(data: bytes, digest, e, n) -> bool:
    ver_digest = rsa_cipher(digest, e, n)
    sig = int.from_bytes(sha256(data).digest(), 'big')
    return ver_digest == sig % n