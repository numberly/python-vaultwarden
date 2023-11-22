from pydantic import BaseModel


class VaultWardenOrg(BaseModel):
    Id: str
    Name: str
    Object: str


class VaultWardenUser(BaseModel):
    CreatedAt: str
    SecurityStamp: str
    _Status: int
    Key: str
    Email: str
    EmailVerified: bool
    ForcePasswordReset: bool
    Id: str
    Name: str
    Organizations: list[VaultWardenOrg]
    UserEnabled: bool
    TwoFactorEnabled: bool
