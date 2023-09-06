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
- One for the bitwarden API, that needs to be authenticated with the user api keys or user's mail and password.

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

Python-vaultwarden is distributed under the terms of the [Apache-2.0](https://spdx.org/licenses/Apache-2.0.html) license.
