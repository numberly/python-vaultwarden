from .logger import logger


def get_collection_id_from_ditcs(collections_names, collection_name):
    if collections_names.get(collection_name) is not None:
        return collections_names[collection_name][-1].get("Id")
    return None


def get_matching_ids_from_ditcs(collections_names, collection_name):
    res = []
    for name, ids in collections_names.items():
        if name == collection_name or name.startswith(f"{collection_name}/"):
            res.append(ids[-1].get("Id"))
    return res


def log_raise_for_status(response) -> None:
    if response.status_code == 403:
        logger.error(
            "Error: 403 Forbidden. Given Account has not access the data."
        )
    if response.status_code >= 400:
        logger.error(f"Error: {response.status_code}")
    response.raise_for_status()
