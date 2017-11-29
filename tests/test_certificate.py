import pytest
import os
from cryptography import x509
from cryptography.x509.oid import NameOID

import cergen
from cergen import manifest
from cergen.certificate import Certificate

from fixtures import *


def test_init(certificate):
    """
    Test that a self signed Certificate is instantiated from kwargs.
    """
    assert certificate.name == 'temp', \
        'Certificate name should be temp'
    assert certificate.crt_file.endswith('temp.crt.pem'), \
        'Certificate crt_file should be temp.crt.pem'
    assert not certificate.exists(), \
        'Certificate has not been generated, so it should not exist'
    assert certificate.cert is None, \
        'Certificate has not been generate, so cert() should return None'


def test_generate(certificate):
    """
    Test that generate() generates all expected files.
    """
    certificate.generate()
    assert certificate.exists(), \
        'Certficicate has been generated, so it should exist'

    # assert that all generated files exist
    assert os.path.exists(certificate.crt_file), \
        'crt_file should exist'
    assert os.path.exists(certificate.csr_file), \
        'csr_file should exist'
    assert os.path.exists(certificate.p12_file), \
        'p12_file should exist'
    assert os.path.exists(certificate.jks_file), \
        'jks_file should exist'
    assert os.path.exists(certificate.truststore_jks_file), \
        'truststore_jks_file should exist'

def test_authority_methods(certificate):
    """
    Test that provided and implemented methods from
    AbstractSigner do what they should.
    """
    certificate.generate()
    # certificate is a self signed certificate
    assert certificate.parent == certificate, \
        'parent certificate should be self'
    assert certificate.root == certificate, \
        'root certificate should be self'
    assert certificate.is_root, \
        'self signed certificate should be a root in authority chain'
    assert list(certificate.chain(include_self=False)) == [], \
        'self signed certificate authority chain without self should be empty'
    assert list(certificate.chain(include_self=True)) == [certificate], \
        'self signed certificate authority chain with self should contain only self'
    assert list(certificate.chain_names(include_self=True)) == [certificate.name], \
        'certificate chain names with self should only include this certificate\'s name'
    assert certificate.verify(certificate.cert), \
        'self signed certificate should be able to verify itself'
    assert certificate.cert_file == certificate.crt_file, \
        'cert_file() should return path to generated crt_file'


def test_cert(certificate):
    """
    Test that cert() returns a cryptography x509 certificate with the correct values
    """
    certificate.generate()
    x509_cert = certificate.cert
    assert x509_cert.subject.get_attributes_for_oid(
        NameOID.COMMON_NAME
    )[0].value == certificate.name, \
        'common_name in x509_cert subject should be the same as certicicate\'s name'


def test_load(certificate, certificate_kwargs):
    """
    Test that a x509 pem cert file is can be loaded from dist
    """
    #  generate the cert
    certificate.generate()
    # create a new Certificate instance with same kwargs.
    # It should automatically load() since the crt_file exists.
    c = Certificate(**certificate_kwargs)
    assert c.exists(), \
        'crt_file exists, so new Certificate should load it from file'
    # Run test_cert() with this loaded certificate to ensure
    # it is loaded properly
    test_cert(c)


def test_should_generate_read_only(certificate):
    """
    A read_only Certificate should not be able to generate
    """
    certificate.read_only = True
    assert not certificate.should_generate(), \
        'should_generate on read_only Certficate should return False'

    assert not certificate.should_generate(force=True), \
        'should_generate(force=True) on read_only Certficate should return False'


def test_should_generate(certificate):
    """
    Test that should_generate does the right thing based on state of certificate file
    """
    assert certificate.should_generate(), \
        'Non existent Certificate should generate'
    assert certificate.should_generate(force=True), \
        'Non existent Certificate should generate with force=True'

    certificate.generate()
    assert certificate.should_generate(force=True), \
        'Existent certificate should generate with force=True'
    assert not certificate.should_generate(path=certificate.crt_file), \
        'Existent certificate should not generate crt_file'
    assert certificate.should_generate(path=certificate.crt_file, force=True), \
        'Existent certficiate should genearte crt_file with force=True'


def test_dict_to_x509_name():
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    subject = {
        # Eitehr lower and upper case should work
        'country_name': 'US',
        'STATE_OR_PROVINCE_NAME': 'CA'
    }
    x509_name = cergen.certificate.dict_to_x509_name(subject)
    assert x509_name.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value == 'US', \
        'COUNTRY_NAME should be US'
    assert x509_name.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value == 'CA', \
        'STATE_OR_PROVINCE_NAME should be CA'

    subject = {
        'not_a_name_OID': 'NOPE',
    }
    with pytest.raises(AttributeError):
        cergen.certificate.dict_to_x509_name(subject)


def test_dns_names_to_x509_san():
    from cryptography import x509

    alt_names = ['me.you.org', '*.example.com']
    san = cergen.certificate.dns_names_to_x509_san(alt_names)
    assert san.get_values_for_type(x509.DNSName) == alt_names, \
        'DNS names should match provided alt_names'


def test_is_in_p12_keystore(certificate):
    certificate.generate()
    assert cergen.certificate.is_in_keystore(
        'temp', certificate.p12_file, 'temp_password', storetype='PKCS12'
    ), 'temp should be in the pkcs12 keystore'

    assert not cergen.certificate.is_in_keystore(
        'NONYA', certificate.p12_file, 'temp_password', storetype='PKCS12'
    ), 'NONYA should not be in the pkcs12 keystore'


def test_is_in_java_keystore(certificate):
    certificate.generate()
    assert cergen.certificate.is_in_keystore(
        'temp', certificate.jks_file, 'temp_password'
    ), 'temp should be in the java keystore'

    assert not cergen.certificate.is_in_keystore(
        'NONYA', certificate.jks_file, 'temp_password'
    ), 'NONYA should not be in the java keystore'

