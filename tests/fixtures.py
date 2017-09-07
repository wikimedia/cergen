from pytest import fixture

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


@fixture
def manifest_path():
    """
    Path to manifest yaml files.
    """
    return 'tests/fixtures/manifests'


@fixture
def manifest_dict(manifest_path, scope='session'):
    """
    Loaded manifest dict without defaults set.
    """
    from cergen.yamlreader import yaml_load
    return yaml_load(manifest_path)


@fixture
def manifest_entry(manifest_dict, scope='session'):
    """
    Single manifest entry from manifest without defaults set
    """
    return manifest_dict['hostname1.example.org']


@fixture
def manifest(manifest_path, tmpdir, scope='session'):
    """
    loaded manifest dict with defaults set.
    """
    from cergen import manifest
    return manifest.load_manifests(
        manifest_path, base_path=str(tmpdir), base_private_path=str(tmpdir)
    )


@fixture
def signer_graph(manifest):
    """
    SignerGraph instantiated from manifest fixture
    """
    from cergen.signer import SignerGraph
    return SignerGraph(manifest)


@fixture
def certificate_kwargs(tmpdir, scope='session'):
    """
    kwargs for instantiating Certificate
    """
    return {
        'name': 'temp',
        'subject': {
            # Both lower and upper case should work
            'country_name': 'US',
            'STATE_OR_PROVINCE_NAME': 'CA'
        },
        'key': {'password': 'temp_password'},
        'path': str(tmpdir),
    }

@fixture
def certificate(certificate_kwargs, scope='function'):
    """
    Certificate instance in temp directory
    """
    from cergen.certificate import Certificate
    return Certificate(**certificate_kwargs)


@fixture
def key_kwargs(tmpdir, scope='function'):
    """
    kwargs suitable for instantiating a cergen.key.Key
    """
    return {
        'name': 'temp',
        'path': str(tmpdir),
        'private_path': str(tmpdir),
        'password': 'temp_password',
        'algorithm': 'rsa',
        'key_size': 2048
    }


@fixture
def key(key_kwargs, scope='function'):
    """
    Instantiated cergen.key.Key
    """
    from cergen.key import Key
    return Key(**key_kwargs)


@fixture
def csr(key):
    """
    cryptography x509 CSR
    """
    subject = {
        # Both lower and upper case should work
        'country_name': 'US',
        'STATE_OR_PROVINCE_NAME': 'CA'
    }
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        util.dict_to_x509_name(subject)
    ).add_extension(
        util.dns_names_to_x509_san(['me.you.org', '*.example.com']), critical=False
    )

    # Sign the CSR with our private key
    csr = csr.sign(key.key, hashes.SHA256(), default_backend())
    return csr


