import pytest

from cergen.signer import AbstractSigner, instantiate

class NonSignerSubclass(object):
    def __init__(self, name):
        self._name = name

    @property
    def name(self):
        return self._name
    @property
    def cert(self):
        return 'cert'
    @property
    def parent(self):
        return None
    def sign(self, csr, expiry):
        return 'sign'


class SignerSubclass(AbstractSigner):
    def __init__(self, name):
        self._name = name

    @property
    def name(self):
        return self._name
    @property
    def cert(self):
        return 'cert'
    @property
    def parent(self):
        return None
    def sign(self, csr, expiry):
        return 'sign'


def test_signer_instantiate():
    a = instantiate(
        class_name='tests.test_signer.SignerSubclass',
        name='a1'
    )
    assert isinstance(a, AbstractSigner), \
        'instantiate should work with class_name string as kwarg'
    assert a.name == 'a1'

    a = instantiate(**{
        'class_name': 'tests.test_signer.SignerSubclass',
        'name': 'a2'
    })
    assert isinstance(a, AbstractSigner), \
        'instantiate should work with class_name string in kwargs dict'
    assert a.name == 'a2'

    with pytest.raises(RuntimeError):
        instantiate(
            **{'class_name': 'tests.test_signer.NonSignerSubclass', 'name': 'a3'}
        )
