from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


@dataclass(frozen=True, slots=True)
class Identity:
    cert: Path
    key: Path
    certificate: x509.Certificate


@dataclass(frozen=True, slots=True)
class CertificateBundle:
    ca_cert: Path
    crl_path: Path
    ca_certificate: x509.Certificate
    ca_key: rsa.RSAPrivateKey
    server: Identity
    enrolled_node: Identity
    unenrolled_node: Identity
    self_signed_node: Identity


def _new_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65_537, key_size=2048)


def _write_key(path: Path, key: rsa.RSAPrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def _write_cert(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _issue_identity(
    directory: Path,
    *,
    common_name: str,
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
    usage: ExtendedKeyUsageOID,
) -> Identity:
    key = _new_key()
    now = datetime.now(UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(x509.ExtendedKeyUsage([usage]), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    cert_path = directory / f"{common_name}.crt"
    key_path = directory / f"{common_name}.key"
    _write_cert(cert_path, cert)
    _write_key(key_path, key)
    return Identity(cert=cert_path, key=key_path, certificate=cert)


def _self_signed_identity(directory: Path, common_name: str) -> Identity:
    key = _new_key()
    now = datetime.now(UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = directory / f"{common_name}.crt"
    key_path = directory / f"{common_name}.key"
    _write_cert(cert_path, cert)
    _write_key(key_path, key)
    return Identity(cert=cert_path, key=key_path, certificate=cert)


def write_crl(
    certificates: CertificateBundle,
    revoked_identities: tuple[Identity, ...] = (),
) -> None:
    """Write a test CRL containing the supplied identities."""
    now = datetime.now(UTC)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(certificates.ca_certificate.subject)
        .last_update(now - timedelta(minutes=1))
        .next_update(now + timedelta(days=1))
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                certificates.ca_key.public_key()
            ),
            critical=False,
        )
    )
    for identity in revoked_identities:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(identity.certificate.serial_number)
            .revocation_date(now)
            .build()
        )
    certificates.crl_path.write_bytes(
        builder.sign(certificates.ca_key, hashes.SHA256()).public_bytes(
            serialization.Encoding.PEM
        )
    )


@pytest.fixture
def certificates(tmp_path: Path) -> CertificateBundle:
    """Generate a complete, throwaway PKI without repository certificate scripts."""
    ca_key = _new_key()
    now = datetime.now(UTC)
    ca_subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Vestrix pytest CA")]
    )
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_path = tmp_path / "ca.crt"
    _write_cert(ca_path, ca_cert)

    bundle = CertificateBundle(
        ca_cert=ca_path,
        crl_path=tmp_path / "ca.crl",
        ca_certificate=ca_cert,
        ca_key=ca_key,
        server=_issue_identity(
            tmp_path,
            common_name="collector-test",
            ca_cert=ca_cert,
            ca_key=ca_key,
            usage=ExtendedKeyUsageOID.SERVER_AUTH,
        ),
        enrolled_node=_issue_identity(
            tmp_path,
            common_name="node-01",
            ca_cert=ca_cert,
            ca_key=ca_key,
            usage=ExtendedKeyUsageOID.CLIENT_AUTH,
        ),
        unenrolled_node=_issue_identity(
            tmp_path,
            common_name="node-99",
            ca_cert=ca_cert,
            ca_key=ca_key,
            usage=ExtendedKeyUsageOID.CLIENT_AUTH,
        ),
        self_signed_node=_self_signed_identity(tmp_path, "rogue-node"),
    )
    write_crl(bundle)
    return bundle
