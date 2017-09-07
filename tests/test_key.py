import pytest
import os

from cryptography.hazmat.primitives.asymmetric import rsa

from cergen.key import Key


from fixtures import *

def test_init(key):
    assert key.name == 'temp'
    assert key.private_key_file.endswith('temp.key.private.pem'), \
        'Key private_key_file should be temp.key.private.pem'

    assert not key.exists(), \
        'non existent key should not exist'
    assert key.key is None, \
        'non existent key.key should be none'


def test_init_bad_algorthm(key_kwargs):
    from cergen.key import UnsupportedKeyAlgorithmException
    key_kwargs['algorithm'] = 'not a key alg'

    with pytest.raises(UnsupportedKeyAlgorithmException):
        Key(**key_kwargs)


def test_generate(key):
    key.generate()
    assert key.exists()
    assert os.path.exists(key.private_key_file)
    assert os.path.exists(key.public_key_file)


def test_load(key, key_kwargs):
    key.generate()
    k = Key(**key_kwargs)
    assert k.exists(), \
        'New key with existent private key file should load on init'
    assert isinstance(k.key, rsa.RSAPrivateKey), \
        'k.key should be an instance of RSAPrivateKey'


def test_generate_force(key):
    key.generate()
    key.generate(force=True)
    assert key.exists()


def test_generate_no_force(key):
    key.generate()
    assert not key.generate(force=False), \
        'Key generate should not overwrite anything if force=False'

