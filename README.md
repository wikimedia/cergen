# cergen

Generates asymmetric keys and x509 certificate files declared in a YAML manifest.

x509 certificates can be self signed, signed by other local certificates also declared in the
manifest, or signed by external certificate authorities also declared in the manifest and
implemented as subclasses of AbstractSigner.

## Usage

```
Reads in certificate and external authority configration manifests and generates
keys and x509 certificate files in various formats.

Usage: cergen [options] <manifest_path>

    <manifest_path> is the path to the certificate and authority manifest config file(s).
                    If this is a directory, then all files that match --manifest-glob
                    (default '*.certs.yaml') will be loaded as manifests.

Options:
    -h --help                       Show this help message and exit.

    -c --certificates=<certs>       Comma separated list of certificate names or regexes to select.
                                    Without --generate, this will just print out certificates statuses
                                    for these certificates.  With --generate, it will attempt to
                                    generate any missing certificate files for these certificates.
                                    By default all certificates will be selected.

    -s --subordinates               If given, not only will the certificates that match the
                                    --certificates option be selected, but also any of their
                                    subordinate certificates in the CA chain.

    -g --generate                   Generate selected certificates and files.

    -F --force                      If not provied --force, any existing files will not be
                                    overwritten.  If want to overwrite files, provide --force.

    -m --manifest-glob=<glob>       If <manifest_path> is a directory, this glob will be used to loaded
                                    files from that directory. [default: *.certs.yaml]

    -b --base-path=<path>           Default directory in which generated files will be stored.
                                    [default: ./certificates/certs]

    -B --base-private-path=<path>   Default directory in which generated private key files
                                    will be stored.
                                    [default: ./certificates/private]

    -v --verbose                    Turn on verbose debug logging.
```

cergen's CLI works with a YAML manifest.  The manifest declares various certificate and key
parameters that are then used to instantiate Certificates and external authorities.  The
Certificates and Keys can then be generated and stored in local files in various formats.


## cergen manifest .yaml

The manifest YAML attempts to match the kwargs that can be used to instantiate
Certificate and authority classes.  This allows new subclasses to be created and
instantiated with manifest configuration without having to write code to
handle the config -> code instantiation.

A manifest is a dictionary of names to entry kwargs.  The default entry that will be
instantiated is a Certificate.  A Certificate represents a locally stored Certificate.
Other entry types can be instantiated by setting the special `class_name` config.
This should be set to a fully qualified class name that can be loaded from the Python path.
The `class_name` must refer to a class that implements AbstractSigner and its abstract methods.  
The remaining entry kwargs will be passed to the class's constructor.

```
# Common name of this certificate.
root_ca:
  is_authority: true
  # 'authority' is not given, so this will be a self signed certificate.
  subject:
    country_name: US
    state_or_province_name: CA
  key:
    algorithm: rsa
    password: qwerty

# Common name of the certificate
hostname1.example.org:
  # Directory where OpenSSL files will live
  path: certificates/hostname1.example.org
  # Name of the certificate authority to use for this certificate.
  # This must match another entry name in the manifest.
  authority: root_ca
  # is_authority is not given, so x509 BasicConstraints will specify ca: false.
  # x509 subject. Must match symbols in the Python cryptography.x509.oid.NameOID module.
  subject:
    country_name: US
    state_or_province_name: VA
  # DNS subject alternate names to put in the SAN (optional)
  alt_names: [*.example.org, yeehaw.com]
  # Key class configuration
  key:
    # Private key password.
    password: qwerty
    # Asymmetric key algorithm.  Must be one of key.supported_algorithms.
    algorithm: rsa

  hostname2.example.org
    ...
````

## External Authorities
It is also possible to declare non local certificate authorities in the manifest.  In this case
you must specify the class to instantiate by settings class_name: fully.qualified.ClassName.
This class must be a subclass of AbstractSigner.  Every class that implements
AbstractSigner is able to sign and verify other certificates. (Note that Certificate also
implements AbstractSigner, as a local Certifiate can always at least sign itself.)

cergen ships with one external authority: PuppetCA.  This uses the Puppet CA HTTP API
to submit CSRs, and then shells out to a ruby script to get Puppet to sign a CSR.  PuppetCA
can only be used if you are running cergen on your puppet CA host.  To declare a PuppetCA
in your manifest, you may set `class_name: puppet` and any other PuppetCA constructor kwargs.


Example:

```
puppet_ca:
  class_name: puppet
  hostname: puppetmaster.example.org

puppet_signed_cert:
  authority: puppet_ca
  ...
```

### Plugin Authorities
You may implement your own external authority by creating your own subclass of AbstractSigner.
To declare a custom plugin authority in your manifest, make sure it is importable on PYTHONPATH,
and set class_name to the fully qualified module.ClassName, e.g.

```
my_custom_ca:
  class_name: my.module.CustomCA
  constructor_arg1: value1
  ...
```

## Note on 'Signers' and 'Authorities'
Generally, anything that can sign a certificate is an 'authority' for that certificate.
However, when people usually refer to certificate authorities, they are thinking
of a certificate that has been given a special status and is meant
to sign many other subordinate certificates.  In order to avoid confusion, cergen
uses the name 'Signer' to refer to anything that can sign a certificate.  All
Certificates are Signers, in that they can always at least sign themselves.  Certificates
that can sign other certificates are considered to be 'authorities'.  cergen
originally used the term 'Authority' rather than 'Signer', but this was found
conflate the usual conceptual hierarchy of certificates and authorities.



