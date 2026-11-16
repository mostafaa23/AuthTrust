"""Read runtime settings from .env / environment variables / an optional
config file.

TODO: switch to pydantic-settings for stronger validation if needed.
"""

import os
from dataclasses import dataclass


@dataclass
class WilyConfig:
    log_level: str = os.getenv("WILY_LOG_LEVEL", "INFO")
    rate_limit_rps: int = int(os.getenv("WILY_RATE_LIMIT_RPS", "10"))
    wordlists_dir: str = os.getenv("WILY_WORDLISTS_DIR", "./wordlists")
    aws_region: str = os.getenv("AWS_REGION", "us-east-1")
    ses_sender_email: str = os.getenv("SES_SENDER_EMAIL", "")


def load_config() -> WilyConfig:
    return WilyConfig()
