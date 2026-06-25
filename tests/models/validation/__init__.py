from typing import Any

from vaultwarden.models.crypto import CryptoContext


def default_ctx(account: str = "test-account") -> Any:
    import json
    from pathlib import Path

    from vaultwarden.clients.bitwarden import BitwardenAPIClient
    from vaultwarden.models.sync import ConnectToken

    client = BitwardenAPIClient(
        url=".",
        email=f"{account}@example.com",
        password=account,
        client_id=".",
        device_id=".",
        client_secret=".",
    )
    ctx = CryptoContext(client)

    payload = json.loads(
        Path(f"tests/fixtures/{account}/sync_camel.json").read_text()
    )

    ct = {
        "Kdf": 0,
        "KdfIterations": 600000,
        "Key": payload["profile"]["key"],
        "PrivateKey": payload["profile"]["privateKey"],
        "access_token": "",
        "expires_in": 3600,
        "token_type": "",
        "scope": "",
    }

    client._connect_token = ConnectToken.model_validate(ct, context=ctx)

    client._sync_step(payload)
    return ctx
