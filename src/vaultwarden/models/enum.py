from enum import IntEnum


class OrganizationUserStatus(IntEnum):
    Revoked = -1
    Invited = 0
    Accepted = 1
    Confirmed = 2


class OrganizationUserType(IntEnum):
    Owner = 0
    Admin = 1
    User = 2
    Manager = 3


class CipherType(IntEnum):
    Login = 1
    SecureNote = 2
    Card = 3
    Identity = 4


class VaultwardenUserStatus(IntEnum):
    Enabled = 0
    Invited = 1
    Disabled = 2
