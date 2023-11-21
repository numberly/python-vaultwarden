import logging

logging.basicConfig()
logger = logging.getLogger(__name__)


def log_raise_for_status(response) -> None:
    if response.status_code == 403:
        logger.error(
            "Error: 403 Forbidden. Given Account has not access the data."
        )
    if response.status_code >= 400:
        logger.error(f"Error: {response.status_code}")
    response.raise_for_status()
