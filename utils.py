from random import randrange, choice
from base64 import urlsafe_b64encode, urlsafe_b64decode
from time import time
import json

ID_LENGTH = 6
SALT_LENGTH = 16
ALPHABET = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'


def gen_id() -> int:
    return randrange(10 ** (ID_LENGTH - 1), 10 ** ID_LENGTH)


def gen_salt() -> str:
    return ''.join(choice(ALPHABET) for i in range(16))


def encrypt_password(password: str, salt: str) -> int:
    return hash(password + salt)


def validate_password(input: str, salt: str, password_hash: str) -> bool:
    return encrypt_password(input, salt) == password_hash


def gen_expiry(duration: int) -> int:
    return int(time()) + duration


def is_expired(ts: int) -> bool:
    return time() > ts


def urlsafe_b64encode_str(s: str) -> str:
    return urlsafe_b64encode(bytes(s, 'UTF-8')).decode('UTF-8')


def dict_to_b64(d: dict) -> str:
    return urlsafe_b64encode_str(json.dumps(d)).rstrip('=')

def urlsafe_b64decode_with_padding(s: str) -> str:
    s = bytes(s, 'UTF-8')
    padding = b'=' * (4 - (len(s) % 4))
    return urlsafe_b64decode(s + padding).decode('UTF-8')
