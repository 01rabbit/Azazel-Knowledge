from __future__ import annotations

import re
import traceback
from pathlib import Path

TOKEN_REGEX = re.compile(r"azcti_[A-Za-z0-9]+_[A-Za-z0-9_\-]+")
REDACTED = "[REDACTED]"


class SecretRegistry:
    def __init__(self) -> None:
        self._secrets: set[str] = set()

    def register(self, value: str) -> None:
        if value:
            self._secrets.add(value)

    def register_file(self, path: str | Path) -> None:
        p = Path(path)
        if p.is_file():
            self.register(p.read_text().strip())

    def register_dir(self, path: str | Path) -> None:
        p = Path(path)
        if not p.is_dir():
            return
        for child in p.rglob("*"):
            if child.is_file():
                self.register_file(child)

    def redact(self, text: str) -> str:
        if text is None:
            return text
        redacted = TOKEN_REGEX.sub(REDACTED, text)
        for secret in sorted(self._secrets, key=len, reverse=True):
            if secret:
                redacted = redacted.replace(secret, REDACTED)
        return redacted


def redact_text(text: str, registry: SecretRegistry | None = None) -> str:
    redacted = TOKEN_REGEX.sub(REDACTED, text)
    if registry is not None:
        redacted = registry.redact(redacted)
    return redacted


def format_exception(exc: BaseException, registry: SecretRegistry | None = None) -> str:
    formatted = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    return redact_text(formatted, registry)
