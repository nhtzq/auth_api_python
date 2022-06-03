from typing import Dict, List
from entities import User, Role, Token
from exceptions import UsernameAlreadyExistsError, UsernameNotFoundError, RoleAlreadyExistsError, RoleNotFoundError, InvalidPasswordError, InvalidTokenError
from utils import validate_password

TOKEN_DURATION = 2 * 60 * 60  # 2 hours in seconds


class Auth:
    def __init__(self) -> None:
        # Storage for users, key is user ID, value is a User object
        self.users: Dict[int, User] = {}
        # Storage for roles, key is role name, value a Role object
        self.roles: Dict[str, Role] = {}
        # Storage for issueed tokens, key is token string, value is a Token object
        self.tokens: Dict[str, Token] = {}
        # Username - user ID map
        self.username_id_map: Dict[str, int] = {}
        # Role - users map, key is role name, value is a set of user IDs
        self.role_users_map: Dict[str, set[int]] = {}
        # User ID - token string map
        self.user_token_map: Dict[int, str] = {}

    def create_user(self, username: str, password: str) -> User:
        username = username.strip().lower()

        if username in self.username_id_map:
            raise UsernameAlreadyExistsError(username)

        user = User(username, str(password))
        self.users[user.id] = user
        self.username_id_map[username] = user.id

        return user

    def delete_user(self, username: str) -> None:
        username = username.strip().lower()

        self.check_if_username_exists(username)

        user_id = self.username_id_map[username]
        user = self.users[user_id]
        for role_name in user.roles:
            self.role_users_map[role_name].remove(user_id)
        del self.username_id_map[username]
        del self.users[user_id]

    def create_role(self, role_name: str) -> Role:
        role_name = role_name.strip().lower()

        if role_name in self.roles:
            raise RoleAlreadyExistsError(role_name)

        role = Role(role_name)
        self.roles[role_name] = role
        self.role_users_map[role_name] = set()

        return role

    def delete_role(self, role_name: str) -> None:
        role_name = role_name.strip().lower()

        self.check_if_role_exists(role_name)

        for user_id in self.role_users_map[role_name]:
            self.users[user_id].remove_role(role_name)

        del self.role_users_map[role_name]
        del self.roles[role_name]

    def add_role_to_user(self, username: str, role_name: str) -> None:
        username = username.strip().lower()
        role_name = role_name.strip().lower()

        self.check_if_username_exists(username)
        self.check_if_role_exists(role_name)

        user_id = self.username_id_map[username]
        self.users[user_id].add_role(role_name)
        self.role_users_map[role_name].add(user_id)

    def check_if_username_exists(self, username: str) -> None:
        if username not in self.username_id_map:
            raise UsernameNotFoundError(username)

    def check_if_role_exists(self, role_name: str) -> None:
        if role_name not in self.roles:
            raise RoleNotFoundError(role_name)

    def authenticate(self, username: str, password: str) -> str:
        username = username.strip().lower()
        password = str(password)

        self.check_if_username_exists(username)

        user_id = self.username_id_map[username]
        user = self.users[user_id]

        if not validate_password(password, user.password_salt, user.password_hash):
            raise InvalidPasswordError()

        # Purges previously issued token for this user
        self.invalidate_token_by_user_id(user_id)

        token = Token(user, TOKEN_DURATION)
        token_string = token.to_string()
        self.tokens[token_string] = token
        self.user_token_map[user_id] = token_string

        return token_string

    def invalidate_token_by_user_id(self, user_id: int) -> None:
        """
        Invalidates and purges a token by user ID
        """
        if user_id in self.user_token_map:
            token_string = self.user_token_map[user_id]
            del self.user_token_map[user_id]
            del self.tokens[token_string]

    def validate_token(self, token_str: str) -> None:
        """
        Returns nothing is token is valid. Otherwise, raises InvalidTokenError
        """
        if token_str not in self.tokens:
            raise InvalidTokenError()

        token = self.tokens[token_str]
        # Token expires, purges it and raises error
        if not token.is_valid():
            self.invalidate_token_by_user_id(token.get_user_id())
            raise InvalidTokenError()

    def invalidate_token(self, token_str: str) -> None:
        self.validate_token(token_str)

        token = self.tokens[token_str]
        self.invalidate_token_by_user_id(token.get_user_id())

    def check_role(self, token_str: str, role_name: str) -> bool:
        user = self.get_user_from_token(token_str)

        role_name = role_name.strip().lower()
        self.check_if_role_exists(role_name)

        return user.has_role(role_name)

    def get_roles(self, token_str: str) -> List[str]:
        user = self.get_user_from_token(token_str)
        return user.get_roles()

    def get_user_from_token(self, token_str: str) -> User:
        self.validate_token(token_str)

        token = self.tokens[token_str]
        user_id = token.get_user_id()
        return self.users[user_id]
