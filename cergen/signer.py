import abc
import logging
import importlib
import networkx
import os
import re
import tempfile

from cryptography.hazmat.primitives import serialization
from OpenSSL import crypto


class AbstractSigner(abc.ABC):
    """
    A Signer is anything that can sign python cryptography.x509.Certificates.

    This class is meant to be subclass and implemented. Any implementing Signer
    class must implement the name(), cert(), parent() and sign()
    methods.  name, cert, and parent are all read only @properties, and as such they
    must be marked as @property in the implementing class.

    - ``name``:     Returns the string name of the Signer.

    - ``cert``:     Return the cryptography.x509.Certificate object associated with this Signer.

    - ``parent``:   Return the parent Signer (authority) of this Signer.

    - ``sign``:     Given a cryptography.x509.CertificateSigningRequest, this should return a new
        created and signed cryptography.x509.Certificate object.

    In this way, implementing Signer (authority) classes can be modular.  A Signer can be
    implemented by using local certificate .pem files, or it can be implemented by calling out to
    an HTTP API somewhere.
    """

    def __init__(self):
        """
        Creates a class instance specific logger as self.log using the implemented
        name property method.  Your implementing class should probably call
        super().__init__() from its __init__ method to get this.
        """

        # Use a logger that is named module.ClassName, but has an extra
        # entry in the logging record that is ClassName(instance_name).
        self.log = logging.LoggerAdapter(
            logging.getLogger('{}.{}'.format(self.__module__, self.__class__.__name__)),
            {'instance_name': '{}({})'.format(self.__class__.__name__, self.name)}
        )

    @property
    @abc.abstractmethod
    def name(self):
        """
        Returns
            str: name of this Signer.
        """

    @property
    @abc.abstractmethod
    def cert(self):
        """
        Returns:
            cryptography.x509.Certificate: representing this Signer's certificate
        """

    @property
    @abc.abstractmethod
    def parent(self):
        """
        Parent Signer (authority) of this Signer, or None (or self) if
        this is root self signed.

        Returns:
            AbstractSigner: subclass of AbstractSigner
        """

    @abc.abstractmethod
    def sign(self, csr, expiry):
        """
        Signs a CSR to create a new x509.Certificate.

        Args:
            csr     (cryptography.x509.CertificateSigningRequest): to sign
            expiry  (datetime): expiration date.

        Returns:
            cryptography.x509.Certificate:  newly signed Certificate
        """

    @property
    def cert_file(self):
        """
        For some operations (e.g. openssl CLI) the Signer's certificate needs to exist in a.
        file. Instead of making users of Signer write the x509 cert returned by cert()
        to a file themselves, they can call this method to get a temporary local path
        that will have the Signer's cert bytes in it in pem format.  If your Signer already
        has this a file somewhere locally, you may override this method to just return
        that path, rather than letting this method generate a temp file.

        Returns:
            str: path to .pem certificate file of this Signer
        """
        # This temp file name will be cached after the first call to this method
        # as self.cert_file.crt_file_path.  If this is not set, or the file
        # does not exist, a new temp file will be created, the certificates's
        # bytes will be written to it in PEM format.
        if not hasattr(self.cert_file, 'crt_file_path') or \
                not os.path.exists(self.cert_file.crt_file_path):
            with tempfile.NamedTemporaryFile(delete=False) as f:
                f.write(self.cert.public_bytes(serialization.Encoding.PEM))
                self.cert_file.crt_file_path = f.name

        return self.cert_file.crt_file_path

    @property
    def root(self):
        """
        Returns:
            AbstractSigner: the root Signer (authority) in the chain,
                a subclass of AbstractSigner.
        """
        return next(a for a in self.chain() if a.is_root)

    @property
    def is_root(self):
        """
        Returns True if this Signer is a root authority.  This is true if
        self.parent == self, or if self.parent is None.

        Returns:
            bool: True if this Signer is a root authority, False otherwise.
        """
        return self.parent is None or self == self.parent

    def chain(self, include_self=True):
        """
        A generator that yields each Signer in the authority chain
        of this Signer, all the way up to the root.

        Args:
            include_self (bool, optional): If False, this Signer will not be
                included in the returned chain.  Defaults to True.

        Returns:
            generator: of an Signer chain.
        """
        if include_self:
            yield self

        curr = self
        while not curr.is_root:
            yield curr.parent
            curr = curr.parent

    def chain_names(self, include_self=True):
        """
        Returns a list of names in the authority chain, from the current to the root.

        Args:
            include_self (bool, optional): If False, this Signer name will not be
                included in the returned chain.  Defaults to True.

        Returns:
            list of str: Signer names in this chain
        """
        return [a.name for a in self.chain(include_self)]

    def verify(self, x509_cert):
        """
        Verifies that the x509.Certificate was signed with by this Signer and its parents.
        Override this if your Signer has a way to verify certificates without iterating
        through the authority chain here.  E.g. if your Signer has an HTTP API for verifying.

        Args:
            x509_cert (cryptography.x509.Certificate): Certificate to verify

        Returns:
            bool: True, or raises a CertificateVerificationError

        Raises:
            CertificateVerificationError: if this Signer fails to verify the x509_cert
        """

        # The cryptography library doesn't have a good way to verify certificates, so
        # we convert the x509.Certificates into pyopenssl crypto x509 certificates and use
        # the pyopenssl library instead.
        store = crypto.X509Store()

        # Add the cert to verify to the store.
        store.add_cert(from_cryptography(x509_cert))

        # Add any authority certs in the chain to the store, without
        # double adding the x509_cert (in the case where this is a self signed cert)
        for authority in [a for a in self.chain() if a.cert != x509_cert]:
            store.add_cert(from_cryptography(authority.cert))

        # Create a new store context with the above store,
        # finally using the root authority to verify the chain of certs in the store.
        store_ctx = crypto.X509StoreContext(
            store, from_cryptography(self.root.cert)
        )

        # If store_ctx.verify_certificate() raises a X509StoreContextError,
        # then the certificate did not verify against its authority chain.
        # Otherwise, it did!
        try:
            store_ctx.verify_certificate()
        except crypto.X509StoreContextError as e:
            # Re-raise the error with more information.
            raise CertificateVerificationError(
                'Verification of certificate with common name \'{}\' with chain {} '
                # X509StoreContextError.certificate is a pyopenssl crypto X509 object.
                'failed.'.format(e.certificate.get_subject().commonName, self.chain_names()),
                self,
                x509_cert
            ) from e

        return True

    def __repr__(self):
        chain = [
            '{}({})'.format(a.__class__.__name__, a.name)
            for a in self.chain(include_self=False)
        ]

        if chain:
            return '{}({}, authorities=[{}])'.format(
                self.__class__.__name__,
                self.name,
                ', '.join(chain)
            )
        else:
            return '{}({})'.format(
                self.__class__.__name__,
                self.name
            )


def from_cryptography(x509_cert):
    """
    Converts from an python cryptography module x509 Certificate object
    to a pyopenssl module crypto x509 certificate object.
    pyopenssl >=17.0.0 has a from_cryptography() function, but older versions don't.

    Args:
        x509_cert (cryptography.x509.Certificate)
    Returns:
        OpenSSL.crypto.x509
    """
    # If using a newer version of pyopenssl, we can just
    # call its from_cryptography method.
    if hasattr(crypto.X509, 'from_cryptography'):
        return crypto.X509.from_cryptography(x509_cert)
    # Else we need to get the PEM bytes and pass them to
    # pyopensslload_certificate.
    else:
        return crypto.load_certificate(
            crypto.FILETYPE_PEM,
            x509_cert.public_bytes(serialization.Encoding.PEM)
        )


class CertificateVerificationError(Exception):
    def __init__(self, message, signer, x509_cert):
        super().__init__(message)
        self.signer = signer
        self.certificate = x509_cert


def instantiate(class_name=None, cls=None, **kwargs):
    """
    Factory method for instantiating AbstractSigner implementation classes from
    kwargs.  class_name is expected to be a fully qualified class name of a subclass
    of AbstractSigner that is importable in PYTHONPATH.

    Args:
        class_name (str): a fully qualified class name string of a subclass
            of AbstractSigner that is importable in PYTHONPATH.

        ``**kwargs``: These are passed to the class' constructor.

    Returns:
        AbstractSigner: instance of AbstractSigner

    Raises:
        RuntimeError

    Example: ::

        $ tree /path/to/cergen_extentions
        /path/to/cergen_extentions/
        --- ext
            |-- myca.py

        $ head -n 5 /path/to/cergen_extentions/ext/myca.py
        from cergen import AbstractSigner
        class MyAuthority(AbstractSigner):
            def __init__(name):
                self.name = name
                super().__init__()

        $ export PYTHONPATH=/path/to/cergen_extentions
        ...
        >>> instantiate(type='ext.myca.MyAuthority', **{name: 'my_authority_instance'})

    """

    if '.' not in class_name:
        raise RuntimeError(
            'Cannot import AbstractSigner subclass from {}, it is not in'
            'a fully qualified \'module.ClassName\' format.'.format(class_name)
        )
    module_name, symbol_name = class_name.rsplit('.', 1)
    module = importlib.import_module(module_name)
    SignerClass = getattr(module, symbol_name)

    if not issubclass(SignerClass, AbstractSigner):
        raise RuntimeError(
            'Cannot instantiate {}, it is not a subclass of {}'.format(
                SignerClass, AbstractSigner
            )
        )
    return SignerClass(**kwargs)


class SignerGraph(object):
    """
    A directed graph of certificates and their dependencies, as given by iterating through
    certificate manifest and examining each 'authority' entry.  This class helps us to
    instantiate Signer classes in proper order, so that parent authorities
    are always generated before child certificates.

    Note that since local Certificates implement AbstractSigner, they are 'Signers',
    in that they can always at least sign themselves.  Everything in this graph
    implements AbstractSigner.
    """
    def __init__(self, manifest):
        """
        Creates the SignerGraph by first iterating through a manifest and building
        a directed graph based on manifest entry 'authority' names.  Once the graph has,
        been created it can be iterated in an an order such that parent entries are
        instantiated before child entries.

        Args:
            manifest (dict): Manifest entries as read in using manifest.load_manifests().
                These will each be passed to instantiate().
        """
        self.graph = networkx.DiGraph()

        # Iterate through the flat config and add nodes and edges
        # to represent dependencies.
        for name, entry in manifest.items():
            # If this entry doesn't specify a ca, then
            # it doesn't have any dependencies.  Add it as a node; other
            # nodes will depend on it.
            if 'authority' not in entry:
                self.graph.add_node(name)
            # Else, add an edge from this name -> the CA name.
            else:
                self.graph.add_edge(name, entry['authority'])

        # Now that we have a directed graph (forest) of Signer names,
        # iterate through it and instantiate each
        # Signer from manifest as kwargs in dependency order.
        # We'll set each node's attribute data to an instantiated Signer instance.
        for name in self:
            entry = manifest[name]

            # If authority is set, at this point we know that the Signer has already been
            # instantiated (because we are iterating the graph in proper order),
            # and can set authority to the instantiated Signer.
            if 'authority' in entry:
                entry['authority'] = self.get(entry['authority'])

            # Instantiate the entry and set the graph node's attributes to it.
            self.graph.node[name] = instantiate(**entry)

    def get(self, name):
        """
        Given a name, gets the entry instance out of the graph.

        Returns:
            AbstractSigner: instance
        """
        return self.graph.node[name]

    def select(self, name_patterns=None, subordinates=False):
        """
        Searches for names that match any of a list of patterns,
        and returns a list of matched signers.  If name_patterns is
        not provided, this will just return all Signers in the graph.

        Args:
            name_patterns (list of str regexes, optional): list of patterns to match against.
                Defaults to None, which means all Signers in the graph will be returned.

            subordinates (bool, optional): If True, all subordinates of found matches will
                also be returned.  Defaults to False.

        Returns:
            list: of matched Signer instances in order of high to low in the chain(s),
                i.e., parents will be earlier than children in this list.
        """
        if name_patterns is None:
            return [self.get(n) for n in self]

        matched_names = []
        for name in self:
            for pattern in name_patterns:
                if name not in matched_names and re.fullmatch(pattern, name):
                    matched_names.append(name)
                    # Append all subordinates of this signer.
                    if subordinates:
                        for a in self.children(name):
                            if a.name not in matched_names:
                                matched_names.append(a.name)

        return [self.get(name) for name in matched_names]

    def _walk(self, start_node, down=True):
        """
        Recursively walks the graph starting at the node named start_node.
        The default is to walk 'down' the graph, from parents to subordinates.
        If down=False, instead this will walk up the the chain to each parent.

        This is useful if you want to iterate over just a specific chain in the
        graph, but not all nodes.  (A DiGraph is a forest, and can contain multiple
        root nodes, and thus multiple chains.)

        Args:
            start_node (str): Name of authority from which to start walking.
            down (bool, optional): Direction to walk.  Defaults to True.

        Returns:
            list of AbstractSigner: Signers in the chain.
        """
        # Use predecessors() for walking 'down', because the DiGraph points TOWARDS
        # dependencies, i.e. that is from children to parents.
        if down:
            connected_nodes = self.graph.predecessors(start_node)
        # If down=False, there's only one other way to go: up!
        # Use successors() for walking 'up' to leaf certificates.
        else:
            connected_nodes = self.graph.successors(start_node)

        all_nodes = connected_nodes
        for node in connected_nodes:
            all_nodes += self._walk(node, down=down)

        return all_nodes

    def children(self, name):
        """
        Returns all subordinate instances of the given instance name.

        Args:
            name (str): Signer name.
        Returns:
            list of AbstractSigner: children Signers of name.
        """
        return [self.get(n) for n in self._walk(name, down=True)]

    def parents(self, name):
        """
        Returns all parent instances that are parents of the given instance name.

        Args:
            name (str): Signer name.
        Returns:
            list of AbstractSigner: parent Signers of name.
        """
        return [self.get(n) for n in self._walk(name, down=False)]

    def __iter__(self):
        """
        Iterates over the graph node names in an order suitable for Certificate generation,
        so that all parents can be instantiated/generated before children.
        """
        # reverse=True, because the graph points towards dependencies, so from
        # children to parents.  We want to iterate from parents to children.
        return (n for n in networkx.topological_sort(self.graph, reverse=True))
