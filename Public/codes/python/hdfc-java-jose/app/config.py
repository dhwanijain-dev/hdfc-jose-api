from __future__ import annotations

import os
from dataclasses import dataclass
from dotenv import load_dotenv


# Load project .env when present; existing server environment variables take priority.
load_dotenv()


@dataclass(frozen=True)
class Settings:
    partner_private_key_path: str
    hdfc_public_key_path: str
    partner_public_cert_path: str | None
    partner_private_key_password: bytes | None
    max_request_bytes: int

    @classmethod
    def from_environment(cls) -> "Settings":
        password = os.getenv("PARTNER_PRIVATE_KEY_PASSWORD")
        try:
            max_request_bytes = int(os.getenv("MAX_REQUEST_BYTES", "1048576"))
        except ValueError as exc:
            raise RuntimeError("MAX_REQUEST_BYTES must be an integer") from exc
        if max_request_bytes < 1:
            raise RuntimeError("MAX_REQUEST_BYTES must be greater than zero")

        return cls(
            partner_private_key_path=os.getenv(
                "PARTNER_PRIVATE_KEY_PATH", "/run/secrets/partner-private-key.pem"
            ),
            hdfc_public_key_path=os.getenv(
                "HDFC_PUBLIC_KEY_PATH", "/run/secrets/hdfc-jose-public.pem"
            ),
            partner_public_cert_path=os.getenv("PARTNER_PUBLIC_CERT_PATH") or None,
            partner_private_key_password=password.encode() if password else None,
            max_request_bytes=max_request_bytes,
        )
