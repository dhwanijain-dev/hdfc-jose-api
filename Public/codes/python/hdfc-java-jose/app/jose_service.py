from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from jwcrypto import jwe, jws, jwk

from app.config import Settings


class JoseConfigurationError(RuntimeError):
    pass


class JosePayloadError(ValueError):
    pass


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _read_public_key(path: str) -> rsa.RSAPublicKey:
    raw = Path(path).read_bytes()
    try:
        if b"BEGIN CERTIFICATE" in raw:
            key = x509.load_pem_x509_certificate(raw).public_key()
        elif b"BEGIN PUBLIC KEY" in raw:
            key = serialization.load_pem_public_key(raw)
        elif b"BEGIN RSA PUBLIC KEY" in raw:
            key = serialization.load_pem_public_key(raw)
        elif raw.startswith(b"ssh-rsa "):
            key = serialization.load_ssh_public_key(raw)
        else:
            raise JoseConfigurationError("Unsupported public key format")
    except JoseConfigurationError:
        raise
    except Exception as exc:
        raise JoseConfigurationError(f"Cannot read configured public key: {path}") from exc

    if not isinstance(key, rsa.RSAPublicKey):
        raise JoseConfigurationError("Configured JOSE public key must be RSA")
    return key


def _read_partner_private_key(settings: Settings) -> rsa.RSAPrivateKey:
    try:
        key = serialization.load_pem_private_key(
            Path(settings.partner_private_key_path).read_bytes(),
            password=settings.partner_private_key_password,
        )
    except Exception as exc:
        raise JoseConfigurationError(
            f"Cannot read configured partner private key: {settings.partner_private_key_path}"
        ) from exc
    if not isinstance(key, rsa.RSAPrivateKey):
        raise JoseConfigurationError("Configured partner private key must be RSA")
    return key


def _read_certificates(path: str) -> list[x509.Certificate]:
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise JoseConfigurationError(
            f"Cannot read configured partner certificate file: {path}"
        ) from exc

    loaders = (
        x509.load_pem_x509_certificate,
        x509.load_der_x509_certificate,
        pkcs7.load_pem_pkcs7_certificates,
        pkcs7.load_der_pkcs7_certificates,
    )
    for loader in loaders:
        try:
            result = loader(raw)
            certificates = result if isinstance(result, list) else [result]
            if certificates:
                return certificates
        except (ValueError, TypeError):
            continue
    raise JoseConfigurationError(
        f"Configured partner certificate is not a supported PEM/DER X.509 or PKCS#7 file: {path}"
    )


def _kid(public_key: rsa.RSAPublicKey) -> str:
    # HDFC specifies BASE64URL(SHA256(publicKey.getEncoded())). In Java, getEncoded()
    # is the DER SubjectPublicKeyInfo representation.
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return _b64url(hashlib.sha256(der).digest())


def _key_as_jwk(key: rsa.RSAPrivateKey | rsa.RSAPublicKey) -> jwk.JWK:
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ) if isinstance(key, rsa.RSAPrivateKey) else key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return jwk.JWK.from_pem(pem)


class JoseService:
    def __init__(self, settings: Settings):
        self.partner_private_key = _read_partner_private_key(settings)
        self.hdfc_public_key = _read_public_key(settings.hdfc_public_key_path)

        if settings.partner_public_cert_path:
            certificates = _read_certificates(settings.partner_public_cert_path)
            partner_public_key = next(
                (
                    cert.public_key()
                    for cert in certificates
                    if isinstance(cert.public_key(), rsa.RSAPublicKey)
                    and cert.public_key().public_numbers()
                    == self.partner_private_key.public_key().public_numbers()
                ),
                None,
            )
            if partner_public_key is None:
                raise JoseConfigurationError(
                    "Configured partner certificate contains no RSA public key matching the private key"
                )
        else:
            partner_public_key = self.partner_private_key.public_key()

        if not isinstance(partner_public_key, rsa.RSAPublicKey):
            raise JoseConfigurationError("Partner certificate must contain an RSA public key")
        if partner_public_key.public_numbers() != self.partner_private_key.public_key().public_numbers():
            raise JoseConfigurationError("Partner certificate does not match the private key")

        self.partner_kid = _kid(partner_public_key)
        self.hdfc_kid = _kid(self.hdfc_public_key)
        self._partner_private_jwk = _key_as_jwk(self.partner_private_key)
        self._hdfc_public_jwk = _key_as_jwk(self.hdfc_public_key)

    def encrypt_request(self, payload: dict[str, Any]) -> str:
        try:
            payload_bytes = json.dumps(
                payload, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")

            signed = jws.JWS(payload_bytes)
            signed.add_signature(
                self._partner_private_jwk,
                protected={"alg": "RS256", "typ": "JWT", "kid": self.partner_kid},
            )

            encrypted = jwe.JWE(
                signed.serialize(compact=True).encode("ascii"),
                protected={
                    "alg": "RSA-OAEP-256",
                    "enc": "A256GCM",
                    "typ": "JWE",
                    "kid": self.hdfc_kid,
                },
            )
            encrypted.add_recipient(self._hdfc_public_jwk)
            return encrypted.serialize(compact=True)
        except Exception as exc:
            raise JosePayloadError("Unable to sign and encrypt the JSON payload") from exc

    def decrypt_response(self, compact_jwe: str) -> dict[str, Any]:
        try:
            encrypted = jwe.JWE()
            encrypted.deserialize(compact_jwe)
            header = encrypted.jose_header
            if header.get("alg") != "RSA-OAEP-256" or header.get("enc") != "A256GCM":
                raise JosePayloadError("Unexpected JWE algorithms")
            if header.get("typ") != "JWE":
                raise JosePayloadError("Unexpected JWE type")
            if header.get("kid") != self.partner_kid:
                raise JosePayloadError("JWE KID does not identify the partner key")
            encrypted.decrypt(self._partner_private_jwk)

            signed = jws.JWS()
            signed.deserialize(encrypted.payload.decode("ascii"))
            protected = signed.jose_header
            if protected.get("alg") != "RS256":
                raise JosePayloadError("Unexpected JWS algorithm")
            if protected.get("typ") != "JWT":
                raise JosePayloadError("Unexpected JWS type")
            if protected.get("kid") != self.hdfc_kid:
                raise JosePayloadError("JWS KID does not identify the configured HDFC key")
            signed.verify(self._hdfc_public_jwk)
            payload = json.loads(signed.payload.decode("utf-8"))
            if not isinstance(payload, dict):
                raise JosePayloadError("Verified response payload must be a JSON object")
            return payload
        except JosePayloadError:
            raise
        except Exception as exc:
            # Keep crypto/parser detail out of the caller response.
            raise JosePayloadError("Unable to decrypt and verify the JOSE response") from exc
