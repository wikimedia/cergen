"""
A Key class for asymmetric key pair generation using the cryptography library.
This class is useful for abstracting key file generation and loading.
"""

import importlib
import logging
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

SUPPORTED_ALGORITHMS = ('rsa', 'dsa', 'ec')
"""list of str:  Supported asymmetric key algorithms.
These should match names of modules in the cryptography.hazmat.primitives.asymmetric module.
Currently: rsa, dsa, ec
"""


class Key(object):
    """
    Represents an asymmetric private key locally stored in .key.pem and .pub.pem files.

    Example:
        >>> key = Key(
            name='client_a', path='./keys', algorithm='rsa', password='qwerty', key_size=4096
        )
        >>> key.generate()

    """
    def __init__(self, name, path, private_path=None, algorithm='rsa', password=None, **kwargs):
        """
        Args:
            name (str): name of key

            path (str): path of directory in which to store public key file

            private_path (str): path in which to store private key file.
                Defaults to path if not given.

            algorithm (str):  This must match one of {}.  Defaults to 'rsa'.

            password (str): private key password.  Defaults to None.

            kwargs (dict): Any remaining kwargs will be passed to <algorithm>.generate_private_key
                (from the cryptography.hazmat.primitives.asymmetric module). Some defaults may be
                filled in by _get_algorithm_kwargs.
        """.format(', '.join(SUPPORTED_ALGORITHMS))

        self.name = name

        # Use a logger that is named module.ClassName, but has an extra
        # entry in the logging record that is ClassName(instance_name).
        self.log = logging.LoggerAdapter(
            logging.getLogger('{}.{}'.format(self.__module__, self.__class__.__name__)),
            {'instance_name': '{}({})'.format(self.__class__.__name__, self.name)}
        )

        self.path = os.path.abspath(path)
        if private_path:
            self.private_path = os.path.abspath(private_path)
        else:
            self.private_path = self.path

        if algorithm not in SUPPORTED_ALGORITHMS:
            raise UnsupportedKeyAlgorithmException(algorithm)

        self.algorithm = algorithm
        self.password = password

        self.module_name = 'cryptography.hazmat.primitives.asymmetric.{}'.format(self.algorithm)
        self.cryptography_module = importlib.import_module(self.module_name)

        # key files in .pem format
        self.private_key_file = os.path.join(
            self.private_path, '{}.key.private.pem'.format(self.name)
        )
        self.public_key_file = os.path.join(
            self.path, '{}.key.public.pem'.format(self.name)
        )

        # Set default kwargs for this algorithm, then update
        # with provided kwargs.
        self.algorithm_kwargs = _get_algorithm_defaults(self.algorithm)
        self.algorithm_kwargs.update(kwargs)

        if self.exists():
            self.load()
        else:
            self.key = None

    def exists(self):
        """
        Checks that this Key exists at the expected key file path.

        Returns:
            bool
        """
        return os.path.exists(self.private_key_file)

    def load(self):
        """
        Loads private_key_file into self.key
        """
        with open(self.private_key_file, 'rb') as f:
            self.key = serialization.load_pem_private_key(
                f.read(), bytes(self.password, 'utf-8'), backend=default_backend()
            )

    def write(self):
        """
        Writes out private and public key files in .pem format.
        """
        if self.password:
            encryption = serialization.BestAvailableEncryption(bytes(self.password, 'utf-8'))
        else:
            encryption = serialization.NoEncryption()

        private_bytes = self.key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )

        public_bytes = self.key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        os.makedirs(self.path, exist_ok=True)
        if self.private_path != self.path:
            print('making private path', self.private_path)
            os.makedirs(self.private_path, exist_ok=True, mode=0o750)

        with open(self.private_key_file, 'w') as f:
            f.write(str(private_bytes, 'utf-8'))

        with open(self.public_key_file, 'w') as f:
            f.write(str(public_bytes, 'utf-8'))

    def should_generate(self, force=False):
        """
        Check if generate should be allowed even if the key file already exists.

        Args:
            force (bool):  if True, this always returns True.  Defaults to False.

        Returns:
            bool: if generation should be allowed
        """
        if self.exists() and not force:
            self.log.warn('%s already exists, skipping key generation...', self.private_key_file)
            return False
        else:
            return True

    def generate(self, force=False):
        """
        Generates a new assymetric key, and writes out private and public key files.

        Args:
            force (bool): If true, this will write a new key, even if the private key
                files exists.  Defaults to False.
        """
        if not self.should_generate(force):
            return False

        self.key = self.cryptography_module.generate_private_key(
            **self.algorithm_kwargs
        )
        self.write()

    def __repr__(self):
        return 'Key {} ({})'.format(self.name, self.algorithm)


class UnsupportedKeyAlgorithmException(Exception):
    def __init__(self, algorithm):
        super().__init__('\'{}\' is not a supported algorithm, must be one of {}'.format(
            algorithm, ', '.join(SUPPORTED_ALGORITHMS)
        ))


def _get_algorithm_defaults(algorithm):
    """
    Creates kwargs defaults suitable for passing to cryptography asymmetric key
    generate_private_key methods with defaults for specific algorithms.

    Args:
        algorithm (str): name of asymmetric key algorthim, must be one of {}

    Returns:
        dict: kwargs
    """.format(', '.join(SUPPORTED_ALGORITHMS))

    defaults = {
        # All algorithms use the default cryptography backend.
        'backend': default_backend()
    }

    if algorithm == 'rsa':
        defaults['public_exponent'] = 65537
        defaults['key_size'] = 2048

    elif algorithm == 'dsa':
        defaults['key_size'] = 2048

    elif algorithm == 'ec':
        # Default EC key curves to SECP256R1 AKA prime256v1 AKA NIST P-256
        defaults['curve'] = ec.SECP256R1()

    return defaults
