import os
import random
import secrets
import string
import urllib.parse

import pytest
from vaultwarden.clients.bitwarden import BitwardenAPIClient
from vaultwarden.clients.vaultwarden import VaultwardenAdminClient
from vaultwarden.models.bitwarden import (
    Card,
    CardData,
    CipherDetails,
    Identity,
    IdentityData,
    Kdf,
    Login,
    LoginData,
    Organization,
    OrganizationCollection,
    SecureNote,
    SecureNoteData,
    SSHKeyData,
    UriMatch,
    UriMatchDetection,
)


@pytest.fixture
def test_account():
    from . import env_from_ci

    env_from_ci()

    # Get Bitwarden credentials from environment variables
    url = os.environ.get("BITWARDEN_URL", None)
    email = os.environ.get("BITWARDEN_EMAIL", None)
    password = os.environ.get("BITWARDEN_PASSWORD", None)
    client_id = os.environ.get("BITWARDEN_CLIENT_ID", None)
    client_secret = os.environ.get("BITWARDEN_CLIENT_SECRET", None)
    device_id = os.environ.get("BITWARDEN_DEVICE_ID", None)

    # Get test organization id from environment variables
    # test_organization = os.environ.get("BITWARDEN_TEST_ORGANIZATION", None)

    c = BitwardenAPIClient(
        url,
        email,
        password,
        client_id,
        client_secret,
        device_id,
    )

    c.sync()
    yield c
    c.close()


@pytest.fixture
def admin(test_account):
    admin_secret_token = os.environ.get("VAULTWARDEN_ADMIN_TOKEN", None)
    c = VaultwardenAdminClient(
        test_account.url, admin_secret_token, preload_users=False
    )
    yield c
    c.close()


@pytest.fixture
def user() -> dict:
    u = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
    email = f"{u}@example.org"
    return dict(email=email, password=u, name=u, kdf=Kdf.argon2id())


@pytest.fixture
def organization(test_account: BitwardenAPIClient, user: dict) -> Organization:
    return test_account.create_organization(
        name=f'Org {user["email"].partition("@")[0]}', email=user["email"]
    )


@pytest.fixture
def login() -> "Login":
    uri = urllib.parse.urlparse(
        url := "http://username:password@login.example.org"
    )
    key = secrets.token_bytes(64)

    data = LoginData.model_construct(
        name=uri.hostname,
        password=uri.username,
        username=uri.password,
        uris=[UriMatch.model_construct(match=UriMatchDetection.HOST, uri=url)],
    )
    item = Login.model_construct(
        name=f"{uri.username}@{uri.hostname}",
        login=data,
        data=data,
        key=key,
    )
    return item


@pytest.fixture
def securenote() -> "SecureNote":
    uri = urllib.parse.urlparse(
        url := "http://username:password@securenote.example.org"
    )
    key = secrets.token_bytes(64)

    data = SecureNoteData.model_construct(
        Notes="".join(random.choices(string.ascii_letters, k=10)),
        uris=[UriMatch.model_construct(match=UriMatchDetection.HOST, uri=url)],
    )
    item = SecureNote.model_construct(
        Name=f"{uri.username}@{uri.hostname}",
        SecureNote=data,
        Data=data,
        Key=key,
    )
    return item


@pytest.fixture
def card():
    key = secrets.token_bytes(64)
    data = CardData.model_construct(
        cardholderName="user",
        brand="VISA",
        code="123",
        expMonth="11",
        expYear="2020",
        number="1204391293",
    )
    item = Card.model_construct(
        Name="user@VISA",
        Card=data,
        Data=data,
        Key=key,
    )
    return item


@pytest.fixture
def identity():
    key = secrets.token_bytes(64)
    data = IdentityData.model_construct(
        title="Mrs.",
        firstName="A",
        middleName="B",
        lastName="C",
        username="abc",
        company="Z",
        ssn="1",
        passportNumber="2",
        licenseNumber="3",
        email="abc@Z.org",
        phone="112",
        address1="a1",
        address2="a2",
        address3="a3",
        city="City",
        state="State",
        postalCode="1",
        country="X",
    )
    item = Identity.model_construct(
        Name="user@Z",
        Identity=data,
        Data=data,
        Key=key,
    )
    return item


@pytest.fixture
def sshkey():
    fp = "SHA256:0uYSZPry8sa7UC/sfjLZCgjggJ12KhHHeD+BP0hew50"
    priv = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBMlizY/9+h3pZlH9ADEGOaL/aRnBA0XveKurHXW66oAwAAAIgdq/EQHavx
EAAAAAtzc2gtZWQyNTUxOQAAACBMlizY/9+h3pZlH9ADEGOaL/aRnBA0XveKurHXW66oAw
AAAEAjVrd/TKd20aXb5qdh15Jjqw3GNEhQ+dLBx0nfV7X29UyWLNj/36HelmUf0AMQY5ov
9pGcEDRe94q6sddbrqgDAAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----
    """
    pub = (
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEyWLNj"
        "/36HelmUf0AMQY5ov9pGcEDRe94q6sddbrqgD"
    )

    data = SSHKeyData.model_construct(
        keyFingerprint=fp, privateKey=priv, publicKey=pub
    )
    item = SSHKeyData.model_construct(sshKey=data)
    return item


@pytest.fixture
def collection(organization: Organization) -> OrganizationCollection:
    return organization.create_collection("Test Collection")


@pytest.fixture
def ciphers(login, securenote, card, identity) -> list[CipherDetails]:
    return [login, securenote, card, identity]


def test_user(
    test_account: BitwardenAPIClient,
    admin: VaultwardenAdminClient,
    user: dict,
    organization: Organization,
    collection: OrganizationCollection,
    ciphers,
):
    # create
    test_account.create_user(**user)

    # invite
    organization.invite(user["email"])

    # confirm
    users = organization.users(force_refresh=True, search=user["email"])
    assert len(users) == 1
    u = users[0]
    organization.confirm(u)

    # add to collection
    u.add_collections([collection.Id])

    # cleanup
    organization.delete()
    admin.delete(u.Id)


def test_ciphers(
    test_account: BitwardenAPIClient,
    organization: Organization,
    collection: OrganizationCollection,
    ciphers,
):
    for c in ciphers:
        test_account.create_item(c, organization, [collection])

    organization.delete()


def test_cleanup_users(admin: VaultwardenAdminClient):
    for i in admin.users():
        if i.Email.endswith("@example.org"):
            admin.delete(i.Id)


SEARCH_ITEMS = [
    #            ("http://default.com", "http://default.com", None),
    (
        "http://sub.basedomain.com",
        "http://basedomain.com",
        UriMatchDetection.BASEDOMAIN,
    ),
    ("http://host.com/a", "http://host.com", UriMatchDetection.HOST),
    (
        "http://startswith.com/a/b",
        "http://startswith.com/a",
        UriMatchDetection.STARTSWITH,
    ),
    ("http://re.com", r"^http://re\.c.m", UriMatchDetection.RE),
    ("http://exact.com", "http://exact.com", UriMatchDetection.EXACT),
]


@pytest.fixture(
    params=SEARCH_ITEMS,
    ids=[urllib.parse.urlparse(url).hostname for url, *_ in SEARCH_ITEMS],
)
def logins(request, test_account, organization, collection):
    url, uri, match = request.param
    name = urllib.parse.urlparse(url).hostname
    data = LoginData.model_construct(
        name=name,
        password="test123",
        username="test",
        Uris=[UriMatch.model_construct(match=match, uri=uri)],
    )
    item = Login.model_construct(
        name=name,
        login=data,
        data=data,
        key=secrets.token_bytes(64),
    )
    test_account.create_item(item, organization, [collection])
    return url, uri, match


def test_search(
    test_account: BitwardenAPIClient,
    organization: Organization,
    collection: OrganizationCollection,
    logins,
):
    test_account.sync(force_refresh=True)
    url, uri, match = logins

    r = list(
        test_account.search_items(
            url, organisations=[organization], collections=[collection]
        )
    )
    assert len(r) == 1, url
    assert r[0].Name == urllib.parse.urlparse(url).hostname


def test_edit(
    test_account: BitwardenAPIClient,
    organization: Organization,
    collection: OrganizationCollection,
    logins,
):
    test_account.sync(force_refresh=True)
    url, uri, match = logins

    r = list(
        test_account.search_items(
            url, organisations=[organization], collections=[collection]
        )
    )
    assert len(r) == 1, url
    assert r[0].Name == urllib.parse.urlparse(url).hostname
    lo: Login = r[0]
    assert lo.Login.username == "test"
    lo.Login.username = lo.Login.password = "edit"
    lo.save()
    test_account.sync(force_refresh=True)
    r = list(
        test_account.search_items(
            url, organisations=[organization], collections=[collection]
        )
    )
    assert len(r) == 1, url
    lo: Login = r[0]
    assert lo.Login.username == lo.Login.password == "edit"
