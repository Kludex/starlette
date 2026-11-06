from __future__ import annotations

import re


class AcceptEncoding:
    def __init__(self, value: str | None) -> None:
        self.value = value
        self.qualities: dict[str, float] = {}
        for item in (value or "").lower().split(","):
            coding, separator, weight = item.strip().partition(";")
            quality = 1.0
            if separator:
                match = re.fullmatch(r"\s*q\s*=\s*(0(?:\.\d{0,3})?|1(?:\.0{0,3})?)\s*", weight)
                quality = float(match[1]) if match else 0.0
            self.qualities[coding.strip()] = quality

    def accepts(self, encoding: str) -> bool:
        if encoding == "identity":
            return self.qualities.get("identity", self.qualities.get("*", 1.0)) > 0
        return self.value is None or self.qualities.get(encoding, self.qualities.get("*", 0.0)) > 0

    def select(self, encodings: tuple[str, ...]) -> str | None:
        selected = "identity" if self.accepts("identity") else None
        best = 0.0
        for encoding in encodings:
            quality = self.qualities.get(encoding, self.qualities.get("*", 0.0))
            if quality > best:
                selected, best = encoding, quality
        if self.qualities.get("identity", 0.0) > best:
            return "identity"
        return selected
