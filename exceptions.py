class AuthError(Exception):
    """
    Base class for all exceptions
    """

    pass

class UsernameAlreadyExistsError(AuthError):
    def __init__(self, username):
        self.username = username

    def __str__(self):
        return f'Username "{self.username}" already exists.'

class UsernameNotFoundError(AuthError):
    def __init__(self, username):
        self.username = username

    def __str__(self):
        return f'Username "{self.username}" does not exists.'

class RoleAlreadyExistsError(AuthError):
    def __init__(self, role_name):
        self.role_name = role_name

    def __str__(self):
        return f'Role "{self.role_name}" already exists.'

class RoleNotFoundError(AuthError):
    def __init__(self, role_name):
        self.role_name = role_name

    def __str__(self):
        return f'Role "{self.role_name}" does not exists.'

class InvalidPasswordError(AuthError):
    def __str__(self):
        return 'The entered password is not correct.'

class InvalidTokenError(AuthError):
    def __str__(self):
        return 'Auth token is invalid.'