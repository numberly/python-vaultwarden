from enum import Enum


class OrganizationUserStatus(Enum):
    Revoked = -1
    Invited = 0
    Accepted = 1
    Confirmed = 2


class OrganizationUserType(Enum):
    Owner = 0
    Admin = 1
    User = 2
    Manager = 3


class CipherType(Enum):
    Login = 1
    SecureNote = 2
    Card = 3
    Identity = 4


class VaultwardenUserStatus(Enum):
    Enabled = 0
    Invited = 1
    Disabled = 2
