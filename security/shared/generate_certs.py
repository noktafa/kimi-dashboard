#!/usr/bin/env python3
"""
Certificate generation script for the Kimi ecosystem.

Generates a self-signed CA and service certificates for all components.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID


# Service definitions
SERVICES = {
    "security-auditor": {
        "hostname": "security-auditor.kimi.local",
        "port": 8000,
        "alt_names": ["localhost", "127.0.0.1", "::1"],
    },
    "sysadmin-ai": {
        "hostname": "sysadmin-ai.kimi.local",
        "port": 8001,
        "alt_names": ["localhost", "127.0.0.1", "::1"],
    },
    "convergence-loop": {
        "hostname": "convergence-loop.kimi.local",
        "port": 8002,
        "alt_names": ["localhost", "127.0.0.1", "::1"],
    },
    "dashboard": {
        "hostname": "dashboard.kimi.local",
        "port": 8766,
        "alt_names": ["localhost", "127.0.0.1", "::1"],
    },
}


def generate_private_key(key_size: int = 2048) -> rsa.RSAPrivateKey:
    """Generate an RSA private key."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )


def generate_ca_certificate(
    output_dir: Path,
    validity_days: int = 3650,
    key_size: int = 4096,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Generate a self-signed CA certificate."""
    print("Generating CA certificate...")
    
    private_key = generate_private_key(key_size)
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Kimi Ecosystem"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Certificate Authority"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Kimi Ecosystem CA"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=validity_days)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    ).add_extension(
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
    ).sign(private_key, hashes.SHA256())
    
    # Save CA certificate
    ca_cert_path = output_dir / "ca.crt"
    with open(ca_cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"  CA certificate: {ca_cert_path}")
    
    # Save CA private key
    ca_key_path = output_dir / "ca.key"
    with open(ca_key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    print(f"  CA private key: {ca_key_path}")
    
    return private_key, cert


def generate_service_certificate(
    service_name: str,
    hostname: str,
    alt_names: list[str],
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    output_dir: Path,
    validity_days: int = 365,
    key_size: int = 2048,
) -> tuple[Path, Path]:
    """Generate a service certificate signed by the CA."""
    print(f"Generating certificate for {service_name}...")
    
    private_key = generate_private_key(key_size)
    
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Kimi Ecosystem"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, service_name),
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
    ])
    
    # Build SAN list
    san_list = [x509.DNSName(hostname)]
    for alt in alt_names:
        try:
            # Try to parse as IP address
            ip = ipaddress.ip_address(alt)
            san_list.append(x509.IPAddress(ip))
        except ValueError:
            # Treat as DNS name
            san_list.append(x509.DNSName(alt))
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=validity_days)
    ).add_extension(
        x509.SubjectAlternativeName(san_list),
        critical=False,
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).add_extension(
        x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.SERVER_AUTH,
            ExtendedKeyUsageOID.CLIENT_AUTH,
        ]),
        critical=False,
    ).sign(ca_key, hashes.SHA256())
    
    # Save service certificate
    service_dir = output_dir / service_name
    service_dir.mkdir(exist_ok=True)
    
    cert_path = service_dir / "tls.crt"
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"  Certificate: {cert_path}")
    
    # Save service private key
    key_path = service_dir / "tls.key"
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    print(f"  Private key: {key_path}")
    
    return cert_path, key_path


def generate_client_certificate(
    client_name: str,
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    output_dir: Path,
    validity_days: int = 365,
) -> tuple[Path, Path]:
    """Generate a client certificate for mutual TLS."""
    print(f"Generating client certificate for {client_name}...")
    
    private_key = generate_private_key(2048)
    
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Kimi Ecosystem"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Clients"),
        x509.NameAttribute(NameOID.COMMON_NAME, client_name),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=validity_days)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).add_extension(
        x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.CLIENT_AUTH,
        ]),
        critical=False,
    ).sign(ca_key, hashes.SHA256())
    
    # Save client certificate
    client_dir = output_dir / "clients"
    client_dir.mkdir(exist_ok=True)
    
    cert_path = client_dir / f"{client_name}.crt"
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"  Certificate: {cert_path}")
    
    # Save client private key
    key_path = client_dir / f"{client_name}.key"
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    print(f"  Private key: {key_path}")
    
    return cert_path, key_path


def generate_dh_params(output_dir: Path, key_size: int = 2048) -> Path:
    """Generate Diffie-Hellman parameters for perfect forward secrecy."""
    print("Generating DH parameters...")
    
    from cryptography.hazmat.primitives.asymmetric import dh
    
    parameters = dh.generate_parameters(generator=2, key_size=key_size)
    dh_path = output_dir / "dhparam.pem"
    
    with open(dh_path, "wb") as f:
        f.write(parameters.parameter_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.ParameterFormat.PKCS3,
        ))
    print(f"  DH parameters: {dh_path}")
    
    return dh_path


def main():
    parser = argparse.ArgumentParser(
        description="Generate TLS certificates for the Kimi ecosystem"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="./certs",
        help="Output directory for certificates (default: ./certs)",
    )
    parser.add_argument(
        "--ca-validity-days",
        type=int,
        default=3650,
        help="CA certificate validity in days (default: 3650)",
    )
    parser.add_argument(
        "--service-validity-days",
        type=int,
        default=365,
        help="Service certificate validity in days (default: 365)",
    )
    parser.add_argument(
        "--key-size",
        type=int,
        default=2048,
        help="RSA key size in bits (default: 2048)",
    )
    parser.add_argument(
        "--ca-key-size",
        type=int,
        default=4096,
        help="CA RSA key size in bits (default: 4096)",
    )
    parser.add_argument(
        "--skip-dh",
        action="store_true",
        help="Skip DH parameters generation",
    )
    parser.add_argument(
        "--clients",
        type=str,
        nargs="+",
        default=["dashboard-client"],
        help="Client names for mTLS (default: dashboard-client)",
    )
    
    args = parser.parse_args()
    
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"Generating certificates in: {output_dir.absolute()}")
    print()
    
    # Generate CA
    ca_key, ca_cert = generate_ca_certificate(
        output_dir,
        validity_days=args.ca_validity_days,
        key_size=args.ca_key_size,
    )
    print()
    
    # Generate service certificates
    for service_name, config in SERVICES.items():
        generate_service_certificate(
            service_name=service_name,
            hostname=config["hostname"],
            alt_names=config["alt_names"],
            ca_key=ca_key,
            ca_cert=ca_cert,
            output_dir=output_dir,
            validity_days=args.service_validity_days,
            key_size=args.key_size,
        )
        print()
    
    # Generate client certificates
    for client_name in args.clients:
        generate_client_certificate(
            client_name=client_name,
            ca_key=ca_key,
            ca_cert=ca_cert,
            output_dir=output_dir,
            validity_days=args.service_validity_days,
        )
        print()
    
    # Generate DH parameters
    if not args.skip_dh:
        generate_dh_params(output_dir, key_size=args.key_size)
        print()
    
    print("Certificate generation complete!")
    print()
    print("To use these certificates:")
    print("  1. Distribute the CA certificate (ca.crt) to all clients")
    print("  2. Configure services with their respective tls.crt and tls.key")
    print("  3. For mTLS, configure clients with their client certificate and key")
    print()
    print("Environment variables:")
    for service_name, config in SERVICES.items():
        service_dir = output_dir / service_name
        print(f"  {service_name.upper().replace('-', '_')}_TLS_CERT={service_dir}/tls.crt")
        print(f"  {service_name.upper().replace('-', '_')}_TLS_KEY={service_dir}/tls.key")
        print(f"  {service_name.upper().replace('-', '_')}_TLS_CA={output_dir}/ca.crt")


if __name__ == "__main__":
    main()