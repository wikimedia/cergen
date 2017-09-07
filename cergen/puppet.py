import requests
import shutil
import socket

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from cergen.command import run_command
from cergen.signer import AbstractSigner


class PuppetCA(AbstractSigner):
    """
    A PuppetCA signs and generates a new Certificate using the Puppet CA HTTP API and CLI.
    After submitting the CSR to the Puppet CA API, the CSR will be signed Puppet by
    shelling out to a custom ruby script that imports and extends
    Puppet internals to support wildcard certificates and other x509 extensions that
    Puppet CA does not on its own.

    NOTE: This has only been tested with Puppet 3.8.5 and the v1 HTTP API.

    Args:
        hostname (str): HTTP hostname for Puppet API.  Defaults to 'puppet'.

        port (int): HTTP port for Puppet API.  Defaults to 8140.

        sign_command (list of str): command line arguments to pass to subprocess.check_output.
            The common_name of the certificate to sign will be appended to this list.
            Defaults to 'puppet-sign-cert' script.

        crt_file (str): path to the Puppet CA cert file. Every puppet agent should have this
            installed locally.  Defaults to '/var/lib/puppet/ssl/certs/ca.pem'.

        agent_crt_file (str): path to the signed Puppet agent certificate.
            This is used to authenticate with the Puppet CA HTTP API.
            Defaults to /var/lib/puppet/ssl/certs/<fqdn>.pem

        agent_private_key_file (str): path to the Puppet agent private key file.
            This is used to authenticate with the Puppet CA HTTP API.
            Defaults to /var/lib/puppet/ssl/private_keys/<fqdn>.pem

        environment (str): Puppet environment to use in API calls.  Defaults to 'production'.
    """
    def __init__(
        self,
        hostname='puppet',
        port=8140,
        sign_command=None,
        crt_file='/var/lib/puppet/ssl/certs/ca.pem',
        agent_crt_file=None,
        agent_private_key_file=None,
        environment='production'
    ):
        self._name = '{}:{}'.format(hostname, port)
        super().__init__()

        if sign_command is None:
            sign_command = ['puppet-sign-cert']

        # Check that the sign_command is executable.
        if shutil.which(sign_command[0]) is None:
            raise RuntimeError(
                'Cannot use PuppetCA, {} either does not exist or is not executable'.format(
                    sign_command[0]
                )
            )

        self.hostname = hostname
        self.port = port
        self.sign_command = sign_command

        self.crt_file = crt_file

        if agent_crt_file is None:
            agent_crt_file = '/var/lib/puppet/ssl/certs/{}.pem'.format(socket.getfqdn())

        if agent_private_key_file is None:
            agent_private_key_file = '/var/lib/puppet/ssl/private_keys/{}.pem'.format(
                socket.getfqdn()
            )

        self.agent_crt_file = agent_crt_file
        self.agent_private_key_file = agent_private_key_file

        self.api_uri = 'https://{}:{}/{}'.format(
            self.hostname, self.port, environment
        )

        # Lazy load this, wait until self.cert() is called.
        self.x509_cert = None

    def send_csr(self, common_name, csr_bytes):
        """
        Send a CSR to the PuppetCA HTTP API.

        Raises:
            RuntimeError: if the HTTP send request failed.
        """
        url = '{}/certificate_request/{}'.format(self.api_uri, common_name)

        self.log.debug('Submitting CSR for %s to %s', common_name, url)
        # Using requests here because Python 3.4.2 (on Jessie) doesn't have
        # the ability to set an SSL.context in urllib.request, which means that
        # we can't specify the client cert and key, which Puppet API seems to need?
        # Otherwise, I'd more simply use urllib.request
        response = requests.put(
            url,
            data=csr_bytes,
            cert=(self.agent_crt_file, self.agent_private_key_file),
            verify=self.crt_file,
            headers={'content-type': 'text/plain'}
        )
        if response.ok:
            self.log.debug('CSR for %s to %s succeeded.', common_name, url)
        else:
            raise RuntimeError(
                'CSR for %s to %s failed with HTTP status code %s: %s',
                common_name, url, response.status_code, response.text
            )

    def get_cert(self, common_name):
        """
        Gets the certificate named common_name from the Puppet CA API, and
        returns it as an cryptography.x509.Certificate.

        common_name (str): common name of certificate to get from Puppet CA API.

        Returns:
            cryptography.x509.Certificate
        """
        url = '{}/certificate/{}'.format(self.api_uri, common_name)
        self.log.debug('Getting signed certificate for %s from %s', common_name, url)
        response = requests.get(
            url,
            cert=(self.agent_crt_file, self.agent_private_key_file),
            verify=self.crt_file
        )
        if response.ok:
            return x509.load_pem_x509_certificate(
                bytes(response.text, 'utf-8'), backend=default_backend()
            )
        else:
            raise RuntimeError(
                'Could not get signed certificate for {} from {}, '
                'failed with HTTP status code {}: {}'.format(
                    common_name, url, response.status_code, response.text
                )
            )

    # --- Implement AbstractSigner methods

    def sign(self, csr, expiry=None):
        """
        Sends the CSR to the Puppet CA HTTP API, then shells out to sign_command
        to ask Puppet to sign the certifiate.  We have to shell out so we can override
        some puppet restrictions on certificates, like SAN wildcards and BasicConstraints.

        Args:
            csr (cryptographyx509.CertificateSigningRequest): CSR to sign.

            expiry (datetime): expiration time. Unfortunetly, Puppet CA does not respect
                custom expiration dates in the CSR. It overrides them to 5 years.

        Raises:
            RuntimeError if signing the CSR with the sign_command fails.

        Returns:
            cryptography.x509.Certificate: signed certificate
        """

        common_name = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

        if expiry:
            self.log.warn(
                'Puppet CA will not respect the custom expiration dates in CSR for  %s. '
                'It will always choose an expiration of 5 years from now.', common_name
            )

        # Check Puppet doesn't already have a certificate with this common name.
        try:
            if self.get_cert(common_name):
                self.log.warn(
                    'CSR for %s to %s has already been submitted and signed. '
                    'Not submitting again.', common_name, self.name
                )
                return
        except RuntimeError:
            pass

        csr_bytes = csr.public_bytes(serialization.Encoding.PEM)
        self.send_csr(common_name, csr_bytes)

        # copy sign_command list and append common name
        command = list(self.sign_command)
        command.append(common_name)

        self.log.debug('Signing CSR for %s', common_name)
        if not run_command(command):
            raise RuntimeError('Sign of CSR for %s failed', common_name)

        # Great, puppet signed the certificate!  Get it!
        return self.get_cert(common_name)

    @property
    def name(self):
        return self._name

    @property
    def parent(self):
        """
        PuppetCA does not have a parent, this always returns None.

        Returns:
            None
        """
        return None

    @property
    def cert(self):
        if not self.x509_cert:
            with open(self.cert_file, 'rb') as f:
                self.x509_cert = x509.load_pem_x509_certificate(
                    f.read(), backend=default_backend()
                )

        return self.x509_cert

    # Override this so we can just return the local Puppet CA crt_file path.
    @property
    def cert_file(self):
        return self.crt_file
