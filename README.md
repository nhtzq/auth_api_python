# auth_api_python
A Python authentication and authorization service API

## Prerequisites

- Python >= 3.8

## Setup

Grab the repo.

```bash
git clone https://github.com/nhtzq/auth_api_python.git
cd auth_api_python
```

## Running the test

```console
python3 test.py
```

## Contents

| Script | Description |
| ------ | ----------- |
| `auth.py` | The Auth service API |
| `entities.py` | Entity classes of User, Role, Token |
| `exception.py` | Exception classes |
| `test.py` | Test cases |
| `utils.py` | Utility functions |

## Conclusion

I wanted to mock time.time() method so that I can test token expiry but I didn't succeed.