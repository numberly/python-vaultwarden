from pydantic import BaseModel

from vaultwarden.utils.string_cases import pascal_case_to_camel_case


class PermissiveBaseModel(
    BaseModel,
    extra="allow",
    alias_generator=pascal_case_to_camel_case,
    populate_by_name=True,
    arbitrary_types_allowed=True,
):
    pass
