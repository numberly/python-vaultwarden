# python-vaultwarden

A python library for vaultwarden

## Clients

There is 2 clients:

- One for the vaultwarden admin API, that needs to be authenticated with the admin token
- One for the bitwarden API, that needs to be authenticated with the user api keys, mail and password.

The `reset_account` and `transfer_account_rights` from the Admin client needs a valid Bitwarden client to re-invite the
target user.

## Credits

The cryptographic part is handled by the [bitwardentools library](https://github.com/corpusops/bitwardentools).


## License

Python-vaultwarden is distributed under the terms of the [Apache](https://spdx.org/licenses/Apache-2.0.html) license.
