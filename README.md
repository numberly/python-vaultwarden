# python-vaultwarden

[![PyPI Version][pypi-v-image]][pypi-v-link]
[![Build Status][GHAction-image]][GHAction-link]

A python client library for [vaultwarden](https://github.com/dani-garcia/vaultwarden).

## Rationale

While there are numerous [clients for bitwarden](https://bitwarden.com/download/), its low-level Python client libraries ecosystem is not well stuffed yet.

We at [Numberly](https://numberly.com) are strong users (and supporters) of [vaultwarden](https://github.com/dani-garcia/vaultwarden) and needed a way to integrate admin operations into our automation stack.

We took inspiration from [bitwardentools](https://github.com/corpusops/bitwardentools) and leverage from it internally while adding some admin related features so that we can automate vaultwarden administration tasks.

Contributions welcomed!

## Clients

There are 2 types of clients:

- One for the vaultwarden admin API, that needs to be authenticated with an admin token.
- One for the bitwarden API, that needs to be authenticated with the user api keys or user's mail and password. An Owner or Admin user is required to perform admin operations.

The `reset_account` and `transfer_account_rights` from the Admin client needs a valid Bitwarden client to re-invite the
target user.

## Installation
```bash
pip install python-vaultwarden
```
## Usage

### Admin client

```python
from vaultwarden.clients.vaultwarden import VaultwardenAdminClient

client = VaultwardenAdminClient(url="https://vaultwarden.example.com", admin_secret_token="admin_token", preload_users=True)

client.invite("john.doe@example.com")

# Get all users
all_users = client.users()

# Get a specific user by email
user = client.user(email="example@example.com")

# Delete/Disable/Enable a user by ID
client.delete(user.Id)
client.disable(user.Id)
client.enable(user.Id)

# Set enabled status of a user
client.set_user_enabled(user.Id, enabled=True)
```

### Bitwarden client

#### Login/… creation & lookup
```python
import urllib.parse
import secrets
from vaultwarden.models.bitwarden import Login, LoginData, UriMatch, UriMatchDetection
from vaultwarden.clients.bitwarden import BitwardenAPIClient

bitwarden_client = BitwardenAPIClient(url="http://127.0.0.1",
                                      email="test-account@example.com",
                                      password="test-account",
                                      client_id="user.a8be340c-856b-481f-8183-2b7712995da2",
                                      client_secret="ag66paVUq4h7tBLbCbJOY5tJkQvUuT",
                                      device_id="e54ba5f5-7d58-4830-8f2b-99194c70c14f")
bitwarden_client.sync()

# create
uri = urllib.parse.urlparse(url:="http://username:password@login.example.org")
key = secrets.token_bytes(64)

data = LoginData.model_construct(
    name=uri.hostname,
    password=uri.username,
    username=uri.password,
    uris = [UriMatch.model_construct(match = UriMatchDetection.HOST, uri=url)]
)
item = Login.model_construct(
    name=f"{uri.username}@{uri.hostname}",
    login=data,
    data=data,
    key=key,
)

bitwarden_client.create_item(item, None, None)

# refresh cache
bitwarden_client.sync(force_refresh=True)

# lookup
print(list(bitwarden_client.search_items(name="login.example.")))
print(list(bitwarden_client.search_items(uri="http://login.example.org")))
```

#### User / Org / Collection Management
```python
from vaultwarden.clients.bitwarden import BitwardenAPIClient
from vaultwarden.models.bitwarden import Organization, OrganizationCollection, get_organization

bitwarden_client = BitwardenAPIClient(url="https://vaultwarden.example.com", email="admin@example", password="admin_password", client_id="client_id", client_secret="client_secret")

org_uuid = "550e8400-e29b-41d4-a716-446655440000"

orga= get_organization(bitwarden_client, org_uuid)

collection_id_list = ["666e8400-e29b-41d4-a716-446655440000", "888e8400-e29b-41d4-a716-446655440000", "770e8400-e29b-41d4-a716-446655440000" ]
orga.invite(email="new@example.com", collections=collection_id_list, default_readonly=True, default_hide_passwords=True)
org_users = orga.users()
org_collections: list[OrganizationCollection] = orga.collections()
org_collections_by_name: dict[str: OrganizationCollection] = orga.collections(as_dict=True)
new_coll = orga.create_collection("new_collection")
orga.delete_collection(new_coll.Id)

my_coll = orga.collection("my_collection")
if new_coll:
    users_coll = my_coll.users()

my_coll_2 = org_collections_by_name["my_coll_2"]

my_user = orga.users(search="john.doe@example.com")
if my_user:
    my_user = my_user[0]
    print(my_user.Collections)
    my_user.add_collections([my_coll_2.Id])

```


## Compatibility

This library is compatible with vaultwarden 1.32.0 and above.
It is tested against vaultwarden 1.32.5, 1.33.2, and 1.34.3.

python-vaultwarden <= v1.0.2 is compatible with vaultwarden from v1.30.0 up to v1.33.2.

## Credits

The [crypto part](src/vaultwarden/utils/crypto.py) originates from [bitwardentools](https://github.com/corpusops/bitwardentools).


<!-- Badges -->

[pypi-v-image]: https://img.shields.io/pypi/v/python-vaultwarden.svg

[pypi-v-link]: https://pypi.org/project/python-vaultwarden/

[GHAction-image]: https://github.com/numberly/python-vaultwarden/workflows/CI/badge.svg?branch=main&event=push

[GHAction-link]: https://github.com/numberly/python-vaultwarden/actions?query=event%3Apush+branch%3Amain
<!-- Links -->


## Contributing
Thank you for being interested in contributing to `python-vaultwarden`. There are many ways you can contribute to the project:
  - Try and report bugs/issues you find
  - Implement new features
  - Review Pull Requests of others
  - Write documentation
  - Participate in discussions

### Development
To start developing create a fork of the python-vaultwarden repository on GitHub.

Then clone your fork with the following command replacing YOUR-USERNAME with your GitHub username:

```bash
git clone https://github.com/YOUR-USERNAME/python-vaultwarden
```

You can now install the project and its dependencies using:
```bash
pip install -e .[test]
```

### Pre-commit hooks

Install [pre-commit](https://pre-commit.com/) hooks to run the same checks as CI before each commit:
```bash
pip install pre-commit
pre-commit install
```

Run all hooks manually:
```bash
pre-commit run --all-files
```

### Testing
To run the tests, use:

```bash
bash tests/e2e/run_tests.sh
```

Or using hatch:
```bash
hatch run test:test
```

## License

Python-vaultwarden is distributed under the terms of the [Apache-2.0](https://spdx.org/licenses/Apache-2.0.html) license.
