from utils import gen_id, gen_salt, encrypt_password, gen_expiry, is_expired, dict_to_b64
from typing import List


class User:

    def __init__(self, username: str, password: str) -> None:
        self.id = gen_id()
        # To simplify, usernames are case-insensitive and are converted to lower case in storage
        self.username = username.strip().lower()
        self.roles = set()
        self.password_salt = gen_salt()
        self.password_hash = encrypt_password(password, self.password_salt)

    def add_role(self, role_name: str) -> None:
        self.roles.add(role_name)

    def remove_role(self, role_name: str) -> None:
        if role_name in self.roles:
            self.roles.remove(role_name)

    def has_role(self, role_name: str) -> bool:
        return role_name in self.roles

    def get_roles(self) -> List[str]:
        return list(self.roles)

    # def validate_password(self, input: str) -> bool:
    #     return encrypt_password(input, self.password_salt) == self.password_hash


class Role:

    def __init__(self, name: str) -> None:
        # To simplify, the "name" attribute is a unique identifier. Role name is also case-insensitive and are converted to lower case in storage
        self.name = name.strip().lower()


class Token:
    def __init__(self, user: 'User', duration: int) -> None:
        self.header = {
            "alg": "none",
            "typ": "JWT"
        }
        self.payload = {
            "sub": user.id,
            "name": user.username,
            "exp": gen_expiry(duration)
        }
        self.signature = None

    def to_string(self) -> str:
        return dict_to_b64(self.header) + '.' + dict_to_b64(self.payload) + '.'

    def is_valid(self) -> bool:
        return not is_expired(self.payload["exp"])

    def get_user_id(self) -> int:
        return self.payload["sub"]

    def set_exp(self, ts: int) -> None:
        self.payload["exp"] = ts
