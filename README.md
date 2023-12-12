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

## Usage

### Admin client

```python
from vaultwarden.clients.vaultwarden import VaultwardenAdminClient

client = VaultwardenAdminClient(url="https://vaultwarden.example.com", admin_secret_token="admin_token")

client.invite("john.doe@example.com")

all_users = client.get_all_users()

client.delete(all_users[0].id)

```

### Bitwarden client

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

## TODO
- [ ] Add tests form Vaultwarden admin client
- [ ] Rewrite crypto part to remove dependency on bitwardentools and add argon2id support
- [ ] Support email + password authentication
- [ ] Support end user operations
- [ ] Ciphers management support
- [ ] Many other things I didn't think of yet


## Credits

The [crypto part](src/vaultwarden/utils/crypto.py) originates from [bitwardentools](https://github.com/corpusops/bitwardentools).


<!-- Badges -->

[pypi-v-image]: https://img.shields.io/pypi/v/python-vaultwarden.svg

[pypi-v-link]: https://pypi.org/project/python-vaultwarden/

[GHAction-image]: https://github.com/numberly/python-vaultwarden/workflows/CI/badge.svg?branch=main&event=push

[GHAction-link]: https://github.com/numberly/python-vaultwarden/actions?query=event%3Apush+branch%3Amain
<!-- Links -->

## License

Python-vaultwarden is distributed under the terms of the [Apache-2.0](https://spdx.org/licenses/Apache-2.0.html) license.
