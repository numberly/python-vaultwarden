def pascal_case_to_camel_case(pascal: str) -> str:
    """Convert a PascalCase string to camelCase.

    Args:
        pascal: The string to convert.

    Returns:
        The converted camelCase string.
    """
    return pascal[0].lower() + pascal[1:]
