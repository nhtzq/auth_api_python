from auth import Auth
from exceptions import UsernameAlreadyExistsError, UsernameNotFoundError, RoleAlreadyExistsError, RoleNotFoundError, InvalidPasswordError, InvalidTokenError
from unittest.mock import Mock, patch
import unittest


class TestAuth(unittest.TestCase):

    def setUp(self):
        self.auth = Auth()
        self.username = 'jackt'
        self.password = '123456'
        self.role_name_1 = 'admin'
        self.role_name_2 = 'customer'
        # self.mocked_now_ts = 1654041600  # 2022-06-01 12:00:00 AM GMT

    def test_create_user(self):
        user = self.auth.create_user(self.username, self.password)
        self.assertEqual(self.auth.users[user.id].username, self.username)

    def test_create_existing_user(self):
        self.auth.create_user(self.username, self.password)
        with self.assertRaises(UsernameAlreadyExistsError):
            self.auth.create_user(self.username, self.password)

    def test_delete_user(self):
        self.auth.create_user(self.username, self.password)
        self.auth.delete_user(self.username)
        with self.assertRaises(UsernameNotFoundError):
            self.auth.check_if_username_exists(self.username)

    def test_delete_nonexistent_user(self):
        with self.assertRaises(UsernameNotFoundError):
            self.auth.delete_user(self.username)

    def test_create_role(self):
        role = self.auth.create_role(self.role_name_1)
        self.assertEqual(self.auth.roles[role.name].name, self.role_name_1)

    def test_create_existing_role(self):
        self.auth.create_role(self.role_name_1)
        with self.assertRaises(RoleAlreadyExistsError):
            self.auth.create_role(self.role_name_1)

    def test_delete_role(self):
        self.auth.create_role(self.role_name_1)
        self.auth.delete_role(self.role_name_1)
        with self.assertRaises(RoleNotFoundError):
            self.auth.check_if_role_exists(self.role_name_1)

    def test_delete_nonexistent_role(self):
        with self.assertRaises(RoleNotFoundError):
            self.auth.delete_role(self.role_name_1)

    def test_add_role_to_user(self):
        user = self.auth.create_user(self.username, self.password)
        self.auth.create_role(self.role_name_1)
        self.auth.add_role_to_user(self.username, self.role_name_1)
        self.assertTrue(user.has_role(self.role_name_1))
        self.assertTrue(user.id in self.auth.role_users_map[self.role_name_1])

    def test_authenticate(self):
        self.auth.create_user(self.username, self.password)
        token_str = self.auth.authenticate(self.username, self.password)
        try:
            self.auth.validate_token(token_str)
        except InvalidTokenError:
            self.fail('InvalidTokenError is raised.')

    def test_authenticate_wrong_username(self):
        self.auth.create_user(self.username, self.password)
        with self.assertRaises(UsernameNotFoundError):
            self.auth.authenticate('wrong-name', self.password)

    def test_authenticate_wrong_password(self):
        self.auth.create_user(self.username, self.password)
        with self.assertRaises(InvalidPasswordError):
            self.auth.authenticate(self.username, 'wrong-password')

    # TODO: Need to figure out how to mock time.time() in utils.is_expired
    def test_token_expiry(self):
        pass

    def test_invalidate_token(self):
        self.auth.create_user(self.username, self.password)
        token_str = self.auth.authenticate(self.username, self.password)
        self.auth.invalidate_token(token_str)
        with self.assertRaises(InvalidTokenError):
            self.auth.validate_token(token_str)

    def test_check_role(self):
        self.auth.create_user(self.username, self.password)
        self.auth.create_role(self.role_name_1)
        self.auth.add_role_to_user(self.username, self.role_name_1)
        token_str = self.auth.authenticate(self.username, self.password)
        self.assertTrue(self.auth.check_role(token_str, self.role_name_1))

    def test_get_roles(self):
        self.auth.create_user(self.username, self.password)
        self.auth.create_role(self.role_name_1)
        self.auth.create_role(self.role_name_2)
        self.auth.add_role_to_user(self.username, self.role_name_1)
        self.auth.add_role_to_user(self.username, self.role_name_2)
        token_str = self.auth.authenticate(self.username, self.password)
        roles = {self.role_name_1, self.role_name_2}
        get_roles_results = self.auth.get_roles(token_str)
        self.assertTrue(not set(get_roles_results).difference(roles))


if __name__ == '__main__':
    unittest.main()
