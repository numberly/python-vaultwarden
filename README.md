# python-vaultwarden

[![PyPI Version][pypi-v-image]][pypi-v-link]
[![Build Status][GHAction-image]][GHAction-link]

A python library for vaultwarden

## Clients

There is 2 clients:

- One for the vaultwarden admin API, that needs to be authenticated with the admin token
- One for the bitwarden API, that needs to be authenticated with the user api keys, mail and password.

The `reset_account` and `transfer_account_rights` from the Admin client needs a valid Bitwarden client to re-invite the
target user.

## Credits

The cryptographic part is handled by the [bitwardentools library](https://github.com/corpusops/bitwardentools).


<!-- Badges -->

[pypi-v-image]: https://img.shields.io/pypi/v/python-vaultwarden.svg

[pypi-v-link]: https://pypi.org/project/python-vaultwarden/

[GHAction-image]: https://github.com/numberly/python-vaultwarden/workflows/CI/badge.svg?branch=main&event=push

[GHAction-link]: https://github.com/numberly/python-vaultwarden/actions?query=event%3Apush+branch%3Amain
<!-- Links -->

[Issue]: https://github.com/numberly/python-vaultwarden/issues

[Discussions]: https://github.com/numberly/python-vaultwarden/discussions

[PyPA Code of Conduct]: https://www.pypa.io/en/latest/code-of-conduct/

## License

Python-vaultwarden is distributed under the terms of the [Apache](https://spdx.org/licenses/Apache-2.0.html) license.
