from __future__ import annotations

import base64
import hashlib
import hmac
import time

from starlette.datastructures import Secret


class TimestampSigner:
    """
    Signs and unsigns data with HMAC-SHA256 and timestamp validation.

    Format: <b64(payload+timestamp)><b64(signature)>_
    """

    def __init__(self, secret: str | Secret) -> None:
        """
        Initialize signer with a secret key.

        Args:
            secret: Secret key for HMAC signing
        """
        self._secret = str(secret).encode("utf-8")

    def sign(self, data: bytes) -> bytes:
        """
        Sign data with current timestamp.

        Args:
            data: Raw data to sign

        Returns:
            Signed token as bytes
        """
        timestamp_bytes = int(time.time()).to_bytes(5, "big")

        combined = data + timestamp_bytes
        combined_encoded = _b64_encode(combined)

        signature = hmac.HMAC(self._secret, combined_encoded, hashlib.sha256).digest()[:16]
        signature_encoded = _b64_encode(signature)

        return combined_encoded + (signature_encoded + b"_")

    def unsign(self, signed_data: bytes, max_age: int | None = None) -> bytes | None:
        """
        Verify and extract data from signed token.

        Args:
            signed_data: Signed token
            max_age: Maximum age in seconds (optional)

        Returns:
            Payload bytes on success, None on failure
        """
        # Quick pre-checks
        if len(signed_data) < 30 or signed_data[-1] != 95:
            return None

        signature_encoded = signed_data[-23:-1]
        signature = _b64_decode(signature_encoded)
        if signature is None or len(signature) != 16:
            return None

        combined_encoded = signed_data[:-23]
        expected_signature = hmac.HMAC(self._secret, combined_encoded, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(signature, expected_signature):
            return None

        combined = _b64_decode(combined_encoded)
        if combined is None:  # pragma: no cover
            return None

        # Check timestamp age if max_age is set
        if max_age is not None:
            timestamp_bytes = combined[-5:]
            timestamp = int.from_bytes(timestamp_bytes, "big")
            if time.time() - timestamp > max_age:
                return None

        data = combined[:-5]
        return data


def _b64_encode(data: bytes) -> bytes:
    """Encode bytes to base64url format without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def _b64_decode(data: bytes) -> bytes | None:
    """Decode base64url format, adding padding if needed. Returns None on error."""
    # Add padding if needed
    padding = 4 - (len(data) % 4)
    if padding != 4:
        data = data + b"=" * padding

    try:
        return base64.urlsafe_b64decode(data)
    except Exception:
        return None
