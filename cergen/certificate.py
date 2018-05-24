import datetime
import ipaddress
import os
import shutil

from inspect import signature

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization

from cergen.command import run_command
from cergen.key import Key
from cergen.signer import AbstractSigner

OPENSSL = os.getenv('OPENSSL_BIN', 'openssl')
"""str: Path to openssl CLI.
Defaults to 'openssl', or the value of the environment variable OPENSSL_BIN
"""

KEYTOOL = os.getenv('KEYTOOL_BIN', 'keytool')
"""str: Path to java keytool CLI.
Defaults to 'keytool', or the environment variable KEYTOOL_BIN
"""

X509_KEY_USAGES = signature(x509.KeyUsage).parameters.keys()
"""list: All allowed key usages,
They're extracted from cryptography.x509.KeyUsage's constructor
"""


class Certificate(AbstractSigner):
    """
    Represents a local x509 certificate.  Handles generation of various file formats.

    A Certificate inherits from the abstract AbstractSigner class, since a Certificate itself
    can sign other Certificates as their authority.  This allows for an arbitrary
    chain of local Certificate authorities made up of local certificate files to be generated.

    The canonical source of data for this Certificate is self.crt_file, a .pem formatted
    x509 local certficiate file.  If this file exists, it will be loaded into a
    cryptography.x509.Certificate object.

    key is an instance of Key representing this Certificate's asymmetric Key. The private key
    will either be generated, or loaded from self.key.private_key_file if that file exists when
    the Key is instantiated.
    """
    def __init__(
        self,
        name,
        key,
        path,
        subject=None,
        key_usage=None,
        private_path=None,
        alt_names=None,
        expiry=365,
        authority=None,
        is_authority=False,
        path_length=None,
        read_only=False
    ):
        """
        Certificate constructor.

        Args:
            name (str): Name of this Certificate. This will be the common_name.

            key (dict or Key):
                An instance of a Key, or kwargs to pass to the Key constructor.

            path (str):
                Path to directory where files are generated and stored.

            subject (dict):
                x509 subject names to values.  Keys should match symbol
                names in the cryptography.x509.oid.NameOID module.
                COMMON_NAME will be set to name.
                Defaults to None (empty subject).

            key_usage (list, optional):
                If not None, a list of key usages that the certificate should be authorized for.
                Valid values can be found at `pydoc crypotgraphy.x509.KeyUsage`

            private_path (str, optional):
                Path to directory where private key files are generated and stored.
                Defaults to path.

            alt_names (list of str, optional):
                List of subject alternate names to include.  Defaults to None.

            expiry (datetime or int, optional):
                Expiry datetime, or expiry int days from now.  Defaults to 365.

            authority (AbstractSigner, optional):
                An instance of AbstractSigner that is this Certificate's direct CA.
                Defaults to None, meaning this will be a self signed certificate.

            is_authority (bool, optional):
                If false, this Certificate should not be used to sign other certificates.
                This will be set in BasicConstraints.  Defaults to False.

            path_length (int, optional):
                If is_authority, this is used to set the path length BasicConstraint.
                Defaults to None.

            read_only (bool, optional):
                If true, then any call to generate() will fail, as this is meant to be a
                read only Certificate.  This is useful if you want to use this class to
                refer to certificate .pem files (perhaps to sign other certificates),
                but want to be sure you won't accidentally overwrite those files by
                calling generate(force=True).  Defaults to False.
        """
        self._name = name
        super().__init__()

        self.path = os.path.abspath(path)
        if private_path:
            self.private_path = os.path.abspath(private_path)
        else:
            self.private_path = self.path

        # If key is is a Key, then just use it
        if isinstance(key, Key):
            self.key = key
        # Else assume it is a dict of kwargs and instantiate a new Key with it.
        else:
            # Set defaults for new Key.
            key.setdefault('name', self.name)
            key.setdefault('path', self.path)
            key.setdefault('private_path', self.private_path)
            self.key = Key(**key)

        if subject is None:
            subject = {}

        # Use the name of this cert as the subject common name
        subject['COMMON_NAME'] = name
        self.x509_name = dict_to_x509_name(subject)

        # Key usage: default is no key usage.
        self.x509_key_usage = None

        # If we are given alt_names, convert them an x509.SubjectAlternativeName.
        if alt_names:
            self.x509_san = names_to_x509_san(alt_names)
        else:
            self.x509_san = None

        # If expiry was given as an int, assume it is days from now
        if isinstance(expiry, int):
            self.expiry = datetime.datetime.utcnow() + datetime.timedelta(days=expiry)
        # Else it should be an expiration datetime.
        else:
            self.expiry = expiry

        # If we are given an authority, then use it.
        # The authority must be a sublcass of AbstractSigner.
        if authority:
            self.authority = authority
        # Else this will be a self signed certificate.  Use self as the authority.
        else:
            self.authority = self

        # If is_authority, then this certificate should be allowed to sign other certificates.
        self.is_authority = is_authority
        if self.is_authority:
            self.x509_constraints = x509.BasicConstraints(ca=True, path_length=path_length)
            key_usage = ['key_cert_sign', 'crl_sign']
        # Else ensure that this certificate will not be allowed to sign other certificates.
        else:
            self.x509_constraints = x509.BasicConstraints(ca=False, path_length=None)

        # Also save the key usage in this case
        if key_usage is not None:
            spurious = set(key_usage) - set(X509_KEY_USAGES)
            if spurious:
                raise ValueError("{}: Invalid key usages: {}"
                                 .format(self.name, ', '.join(spurious)))
            self.x509_key_usage = x509.KeyUsage(*[(k in key_usage) for k in X509_KEY_USAGES])

        # Certificate Signing Request file in .pem format.
        self.csr_file = os.path.join(self.path, '{}.csr.pem'.format(self.name))
        # x509 Certificate file in .pem format
        self.crt_file = os.path.join(self.path, '{}.crt.pem'.format(self.name))
        # Authority's x509 Certificate file in .pem format
        self.ca_crt_file = os.path.join(self.path, 'ca.crt.pem')
        # PKCS#12 'keystore' file
        self.p12_file = os.path.join(self.path, '{}.keystore.p12'.format(self.name))
        # Java Keystore file
        self.jks_file = os.path.join(self.path, '{}.keystore.jks'.format(self.name))
        # Java 'truststore' Keystore file.  This is a Java keystore
        # with this Certificate's authority certificate only.
        self.truststore_jks_file = os.path.join(self.path, 'truststore.jks')

        self.read_only = read_only

        # This is the crypotgraphy.x509.Certificate object.
        # It will either be set by load() or generate_crt()
        self.x509_cert = None

        if self.exists():
            self.log.debug('%s exists, loading', self.crt_file)
            self.load()

    def exists(self):
        """
        Returns:
            bool: True if self.crt_file exists, False otherwise.
        """
        return os.path.exists(self.crt_file)

    def load(self):
        """
        Loads self.crt_file into a cryptography.x509.Certificate object at self.x509_cert.
        Make sure self.crt_file exists before you call this.
        """
        with open(self.crt_file, 'rb') as f:
            self.x509_cert = x509.load_pem_x509_certificate(
                f.read(), backend=default_backend()
            )

    # TODO: rename this since we are removing paths, and clean up conditional logic.
    def should_generate(self, path=None, force=False):
        """
        Given a file path and its existance, a force arg, and the value of self.read_only,
        this will determine of the file path should be generated.  If self.read_only is True,
        this will always return false.

        Args:
            path (str, optional): Path of file to generate.  If not given, this will only
                check for self.read_only.

            force (bool, optional): If true, file will be overwritten if it exists.
                Defaults to False.

        Returns:
            bool
        """
        should_generate = True
        if self.read_only:
            self.log.warn(
                'Cannot call any generate method on a read_only Certificate.  Skipping generation.'
            )
            should_generate = False
        elif path and os.path.exists(path):
            if force:
                self.log.debug(
                    '%s exists, but force is True.  Removing before '
                    'continuing with generation.', path
                )
                if os.path.isdir(path):
                    shutil.rmtree(path)
                else:
                    os.remove(path)
                should_generate = True
            else:
                self.log.warn(
                    '%s exists, skipping generation.', path
                )
                should_generate = False
        else:
            should_generate = True

        return should_generate

    def generate(self, force=False):
        """
        Starting with keys and crt_file, generates various files and keystore formats for
        this Certificate and its CA chain.

        Args:
            force (bool, optional):
                If true, and a given file currently exists, the file will be removed
                before being written.  Otherwise, the file will not be written at all.

                This gets a little tricky.  If you manually remove a key file or the
                canonical crt_file, then it makes no sense to not regeneerate all
                subordinate files.  However, if you manually remove a subordinate file,
                it is fine to automatically regenerate that file (e.g. jks_file)
                from the canonical crt_file and CA chain.

        Returns:
            bool
        """
        self.log.info('Generating all files, force={}...'.format(force))
        os.makedirs(self.path, exist_ok=True)

        self.key.generate(force=force)
        self.generate_crt(force=force)
        # TODO: maybe rename these subordinate generate methods?
        self.generate_ca_crt(force=force)
        self.generate_p12(force=force)
        self.generate_keystore(force=force)
        self.generate_truststore(force=force)

    def generate_crt(self, force=False):
        """
        Uses self.authority to sign and output a .pem formatted x509 certificate file.
        This method generates the x509 CSR (and also outputs it as a .csr file),
        and then calls self.authority.sign(csr, self.expiry).  self.authority may be another
        Certificate instance (or even a reference to this one!), or any object
        that implements a sign(csr, expiry) and verify(x509_cert) methods.

        Args:
            force (bool, optional)

        Raises:
            RuntimeError: if a a new certificate cannot be signed by the authority
                or verified by the authority chain.

        """
        if not self.should_generate(self.crt_file, force):
            return False

        self.log.info('Generating certificate file')

        csr = self.generate_csr()
        self.log.debug('Sending CSR to %s to be signed', self.authority)

        self.x509_cert = self.authority.sign(csr, self.expiry)

        # Write our certificate crt_file out in .pem format.
        with open(self.crt_file, "wb") as f:
            f.write(self.cert.public_bytes(serialization.Encoding.PEM))

        # Verify that the cert is properly signed by self.authority.
        self.log.debug('Verifying signed certificate with %s', self.authority)
        self.authority.verify(self.cert)

        # Verify that crt_file was created.
        if not self.exists():
            raise RuntimeError(
                '{} does not exist even though {} signed and generated a '
                'certificate.  This should not happen.'.format(self.crt_file, self.authority)
            )

    def generate_csr(self):
        """
        This generates an x509.CertificateSigningRequest instance
        from this Certificate instance's attributes (like self.x509_name, etc.).
        The CSR bytes are written out to self.csr_file, and the x509.CertificateSigningRequest
        instance is then returned.  CSR files are ephemeral, so there is no check
        for should_generate here.

        Returns:
            cryptography.x509.CertificateSigningRequest
        """

        # NOTE: it is always safe to re-generate a CSR file, since it is
        # a temporary file that is might be used to submit signing requests.
        # This method doesn't take a force argument like other generate_* methods.

        csr = x509.CertificateSigningRequestBuilder().subject_name(
            self.x509_name
        )
        # Add any SubjectAlternateNames
        if self.x509_san:
            csr = csr.add_extension(
                self.x509_san, critical=False
            )
        # Add any BasicConstraints
        if self.x509_constraints:
            csr = csr.add_extension(
                self.x509_constraints, critical=True
            )

        # Add keyUsage extensions
        if self.x509_key_usage:
            csr = csr.add_extension(self.x509_key_usage, critical=False)

        # Add SubjectKeyIdentifier from this Certificate's public key
        subject_key_identifier = x509.SubjectKeyIdentifier.from_public_key(
            self.key.key.public_key()
        )
        csr = csr.add_extension(subject_key_identifier, critical=False)

        # If this is not a self signed certificate, add the AuthorityKeyIdentifier of the CA too.
        if not self.is_root:
            auth_key_identifier = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                self.authority.cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
            )
            csr = csr.add_extension(auth_key_identifier, critical=False)

        # Sign the CSR with our private key
        csr = csr.sign(self.key.key, hashes.SHA256(), default_backend())
        # Write the CSR out to a file.
        with open(self.csr_file, "wb") as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))

        return csr

    def generate_ca_crt(self, force=False):
        """
        Copies the authority's certificate in .pem format
        into this certificate's path under the name 'ca.crt.pem'.
        This is useful so the CA certificate can be easily distributed.

        Args:
            force (bool, optional)

        Raises:
            RuntimeError: if a a new certificate cannot be signed by the authority
                or verified by the authority chain.

        """
        if not self.should_generate(self.ca_crt_file, force):
            return False

        self.log.info('Generating CA certificate file')

        # The authority has a local cert_file.  Copy it to this Certificate's path.
        shutil.copyfile(self.authority.cert_file, self.ca_crt_file)

        # Verify that crt_file was created.
        if not os.path.exists(self.ca_crt_file):
            raise RuntimeError(
                '{} does not exist even though we copied it from {}. '
                ' This should not happen.'.format(self.ca_crt_file, self.authority.cert_file)
            )

    def generate_p12(self, force=False):
        """
        Uses openssl CLI to output a PKCS12 keystore file containing
        this x509 certificate and its private key.

        Args:
            force (bool, optional)
        """
        if not self.should_generate(self.p12_file, force):
            return False

        command = [
            OPENSSL,
            'pkcs12',
            '-export',
            '-name', self.name,
            # private key
            '-inkey', self.key.private_key_file,
            #  Public certificate
            '-in', self.crt_file,
            # output p12 keystore with password
            '-passout', 'pass:{}'.format(self.key.password),
            '-out', self.p12_file,
        ]
        if self.key.password:
            command += ['-passin', 'pass:{}'.format(self.key.password)]

        if self.authority and self.authority != self:
            command += ['-certfile', self.authority.cert_file]

        self.log.info('Generating PKCS12 keystore file')
        if not run_command(command, creates=self.p12_file):
            raise RuntimeError('PKCS12 file generation failed', self)

        # Verify that the certificate is in the P12 file.
        if not is_in_keystore(self.name, self.p12_file, self.key.password, storetype='PKCS12'):
            raise RuntimeError(
                'Generation of PKCS12 keystore succeeded, but a key for '
                '{} is not in {}. This should not happen'.format(self.name, self.p12_file)
            )
        # TODO: do we need to import the ca_cert into the PKS12 keystore too?

    def generate_keystore(self, force=False):
        """
        Uses the Java keytool CLI to output a Java Keystore .jks file
        containing this x509 certificate, its private key, and, if this
        certificate is not self signed, the CA's x509 certificate too.

        Args:
            force (bool, optional)

        Raises:
            RuntimeError
        """
        if not self.should_generate(self.jks_file, force):
            return False

        command = [
            KEYTOOL,
            '-importkeystore',
            '-noprompt',
            '-alias', self.name,
            '-srcstoretype', 'PKCS12',
            '-srcstorepass', self.key.password,
            '-srckeystore', self.p12_file,
            '-deststorepass', self.key.password,
            '-destkeystore', self.jks_file
        ]
        if self.key.password:
            command += ['-srckeypass', self.key.password, '-destkeypass', self.key.password]

        self.log.info('Generating Java keystore file')
        if not run_command(command, creates=self.jks_file):
            raise RuntimeError(
                'Java Keystore generation and import of certificate failed', self
            )

        # Verify that the cert is in the Java Keystore.
        if not is_in_keystore(self.name, self.jks_file, self.key.password):
            raise RuntimeError(
                'Java Keystore generation and import of certificate '
                'succeeded, but a key for {} is not in {}.  This should not happen'.format(
                    self.name, self.jks_file
                )
            )

        # If this certificate was signed by a CA, then also
        # import the CA certificate into the keystore.
        # TODO: Should we recursively import any CA certs in the chain
        # into the keystore?
        if self.authority and self.authority != self:
            command = [
                KEYTOOL,
                '-importcert',
                '-noprompt',
                "-alias",     self.authority.name,
                '-file', self.authority.cert_file,
                '-storepass', self.key.password,
                '-keystore', self.jks_file
            ]
            self.log.info('Importing %s cert into Java keystore', self.authority)
            if not run_command(command):
                raise RuntimeError(
                    'Import of {} cert into Java Keystore failed'.format(self.authority), self
                )
            # Verify that the ca_cert is in the Java Keystore.
            if not is_in_keystore(self.authority.name, self.jks_file, self.key.password):
                raise RuntimeError(
                    'Import of {} certificate into Java Keystore succeeded, but a key for '
                    '{} is not in {}. This should not happen'.format(
                        self.authority, self.authority.name, self.jks_file
                    )
                )

    def generate_truststore(self, force=False):
        if not self.should_generate(self.truststore_jks_file, force):
            return False

        # keytool -keystore puppet_ca.truststore.jks
        # -alias puppet_ca -import -file /var/lib/puppet/ssl/certs/ca.pem
        command = [
            KEYTOOL,
            '-import',
            '-noprompt',
            '-alias', self.authority.name,
            '-file', self.authority.crt_file,
            '-storepass', self.key.password,
            '-keystore', self.truststore_jks_file
        ]

        self.log.info(
            'Generating Java truststore file with CA certificate {}'.format(self.authority)
        )
        if not run_command(command, creates=self.truststore_jks_file):
            raise RuntimeError(
                'Java truststore generation and import of CA certificate failed', self
            )

        # Verify that the CA cert is in the Java truststore.
        if not is_in_keystore(self.authority.name, self.truststore_jks_file, self.key.password):
            raise RuntimeError(
                'Java truststore generation and import of CA certificate '
                'succeeded, but a certificate for {} is not in {}.  '
                'This should not happen'.format(
                    self.authority.name, self.truststore_jks_file
                )
            )

    # TODO: generate other concatenated formats of .pem files and keystores:
    #  “cert chain”, “key + cert”, and “key + cert chain”. ?
    # "key + all but root chain"?

    def status_string(self):
        """
        Returns:
            str: representing the existance status of all the files that
                this Certificate can generate.
        """
        file_statuses = []
        for p in [
            self.key.private_key_file,
            self.key.public_key_file,
            self.crt_file,
            self.ca_crt_file,
            self.p12_file,
            self.jks_file,
            self.truststore_jks_file
        ]:
            if os.path.exists(p):
                mtime = datetime.datetime.fromtimestamp(os.path.getmtime(p)).isoformat()
                file_statuses += ['\t{}: PRESENT (mtime: {})'.format(p, mtime)]

            else:
                file_statuses += ['\t{}: ABSENT'.format(p)]

        return '{}:\n{}'.format(self, '\n'.join(file_statuses))

    # --- Implement AbstractSigner methods

    def sign(self, csr, expiry):
        """
        Signs a CSR with this Certificate's key to create a new x509 Certificate.

        Args:
            csr (cryptographyx509.CertificateSigningRequest):
                CSR to sign.

            expiry (datetime):
                expiration time

        Returns
            cryptography.x509.Certificate
        """

        cert_builder = x509.CertificateBuilder().issuer_name(
            self.x509_name
        ).subject_name(
            csr.subject
        ).public_key(
            csr.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            expiry
        )

        # Add all extensions in the csr to the cert.
        for extension in csr.extensions:
            cert_builder = cert_builder.add_extension(
                extension.value, critical=extension.critical
            )

        self.log.debug('Signing CSR %s with %s', csr, self)

        # Sign the new x509_cert with self.key.key
        return cert_builder.sign(
            self.key.key, csr.signature_hash_algorithm, default_backend()
        )

    @property
    def name(self):
        return self._name

    @property
    def cert(self):
        return self.x509_cert

    @property
    def parent(self):
        return self.authority

    @property
    def cert_file(self):
        """
        Override AbstractSigner cert_file(), since this is a local file Certificate.
        If another Certificate is using this instance as its own CA, they will call
        cert_file() when generating keystores, etc.
        """
        return self.crt_file


def dict_to_x509_name(d):
    """
    Given a dict of NameOID string keys to values,
    create a new x509.Name object made up of x509.NameAttributes.
    This will sort the name by the NameOID item tuples in d, to ensure that
    the same subject dict will always result in the same ordered x509.Name.

    Args:
        d (dict): NameOID string keys to values.

    Returns:
        x509.Name
    """
    return x509.Name(
        [
            x509.NameAttribute(getattr(NameOID, key.upper()), value) for
            key, value in sorted(d.items())
        ]
    )


def names_to_x509_san(names):
    """
    Given a list of subject alternate names,
    create a new x509.SubjectAlternativeName object made up of x509.DNSName/ x509.IPAddress objects.

    Args:
        names (list of str): list of SAN strings.

    Returns:
        x509.SubjectAlternativeName
    """
    altnames = []
    for name in names:
        try:
            ip = ipaddress.ip_address(name)
            altnames.append(x509.IPAddress(ip))
        except (ValueError, TypeError):
            altnames.append(x509.DNSName(name))

    return x509.SubjectAlternativeName(altnames)


def is_in_keystore(alias, keystore_file, password, storetype=None):
    """
    Uses keytool to check if there is a certificate named alias in the keystore_file.

    Args:
        alias (str): Alias name of certificate to look for in the keystore.
        keystore_file (str): Path to the keystore file.
        password (str): Password to keystore.
        storetype (str, optional): If the -storetype flag needs passed to keytool in order
            to open the keystore file, set it to this.

    Returns
        bool
    """
    command = [
        KEYTOOL,
        '-list',
        '-alias', alias,
        '-storepass', password,
        '-keystore', keystore_file
    ]
    if storetype is not None:
        command += ['-storetype', storetype]

    return run_command(command)
