from cryptography import x509
from cryptography.x509.oid import ExtensionOID, ObjectIdentifier


def test_bootstrap_creates_four_tier_hierarchy(ca_manager):
    result = ca_manager.bootstrap_hierarchy(
        name_prefix="corp",
        common_name_prefix="Corp",
        organization="Example Corp",
        country="US",
        root_validity_years=20,
        intermediate_validity_years=10,
        issuing_validity_years=5,
        key_size_or_curve=2048,
    )

    assert result["success"] is True
    assert [item["ca_type"] for item in result["hierarchy"]] == [
        "root", "intermediate", "intermediate", "issuing"
    ]
    assert [item["path_length"] for item in result["hierarchy"]] == [3, 2, 1, 0]
    assert result["issuing_ca_id"] == result["hierarchy"][-1]["id"]
    assert result["chain_pem"].count("-----BEGIN CERTIFICATE-----") == 4


def test_pkinit_client_profile_has_rfc4556_eku_and_principal(tmp_path):
    from ca.private_ca import CertificateType, PrivateCAManager

    manager = PrivateCAManager(tmp_path)
    root = manager.create_root_ca("Root", key_size_or_curve=2048)
    leaf = manager.issue_certificate(
        "alice@EXAMPLE.COM",
        root["cert_pem"],
        root["key_pem"],
        cert_type=CertificateType.PKINIT_CLIENT,
        pkinit_principal="alice@EXAMPLE.COM",
    )
    cert = x509.load_pem_x509_certificate(leaf["cert_pem"].encode())

    eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
    assert ObjectIdentifier("1.3.6.1.5.2.3.4") in eku
    usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
    assert usage.digital_signature is True
    san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    principal = next(value for value in san if isinstance(value, x509.OtherName))
    assert principal.type_id == ObjectIdentifier("1.3.6.1.5.2.2")
    assert b"EXAMPLE.COM" in principal.value
    assert b"alice" in principal.value


def test_pkinit_kdc_profile_has_kdc_eku_and_tgs_principal(tmp_path):
    from ca.private_ca import CertificateType, PrivateCAManager

    manager = PrivateCAManager(tmp_path)
    root = manager.create_root_ca("Root", key_size_or_curve=2048)
    leaf = manager.issue_certificate(
        "kdc1.example.com",
        root["cert_pem"],
        root["key_pem"],
        cert_type=CertificateType.PKINIT_KDC,
        pkinit_principal="krbtgt/EXAMPLE.COM@EXAMPLE.COM",
        san_dns=["kdc1.example.com"],
    )
    cert = x509.load_pem_x509_certificate(leaf["cert_pem"].encode())

    eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
    assert ObjectIdentifier("1.3.6.1.5.2.3.5") in eku
    san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    other_name = next(value for value in san if isinstance(value, x509.OtherName))
    assert b"krbtgt" in other_name.value
    assert b"EXAMPLE.COM" in other_name.value


def test_pkinit_profile_requires_principal(tmp_path):
    import pytest
    from ca.private_ca import CertificateType, PrivateCAManager

    manager = PrivateCAManager(tmp_path)
    root = manager.create_root_ca("Root", key_size_or_curve=2048)

    with pytest.raises(ValueError, match="pkinit_principal"):
        manager.issue_certificate(
            "alice", root["cert_pem"], root["key_pem"],
            cert_type=CertificateType.PKINIT_CLIENT,
        )
