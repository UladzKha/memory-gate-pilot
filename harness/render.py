"""The only inbox representation passed to a model."""

from collections.abc import Mapping
from typing import Any


def render_inbox(item: Mapping[str, Any]) -> str:
    """Render each email's five allowed fields in dataset order, verbatim."""
    return "\n-----\n".join(
        f"From: {email['from']}\n"
        f"To: {email['to']}\n"
        f"Date: {email['date']}\n"
        f"Subject: {email['subject']}\n\n"
        f"{email['body']}"
        for email in item["emails"]
    )
