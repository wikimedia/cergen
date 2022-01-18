#!/usr/bin/env python3

"""
Reads in Certificate and external certificate authority configration manifests and generates
keys and x509 certificate files in various formats.

Usage: cergen [options]     <manifest_path>

    <manifest_path> is the path to the certificate and authority manifest config file(s).
                    If this is a directory, then all files that match --manifest-glob
                    (default '*.certs.yaml') will be loaded as manifests.

Options:
    -h --help                       Show this help message and exit.

    -c --certificates=<certs>       Comma separated list of certificate names or regexes to select.
                                    Without --generate, this will just print out certificates
                                    statuses for these certificates.  With --generate, it will
                                    attempt to generate any missing certificate files for
                                    these certificates.  If not given, all certificate entries in
                                    the manifests will be selected.

    -s --subordinates               If given, not only will the certificates that match the
                                    --certificates option be selected, but also any of their
                                    subordinate certificates in the CA chain.

    -g --generate                   Generate selected certificates and files.

    -F --force                      If not provided any existing files will not be
                                    overwritten.  If want to overwrite files, provide --force.

    -m --manifest-glob=<glob>       If <manifest_path> is a directory, this glob will be used to
                                    loaded files from that directory. [default: *.certs.yaml]

    -b --base-path=<path>           Default directory in which generated files will be stored.
                                    [default: ./certificates]

    -B --base-private-path=<path>   Default directory in which generated private key files
                                    will be stored. Defaults to value of --base-path.


    -v --verbose                    Enable verbose debug logging.
"""

from docopt import docopt
import logging

from cergen.certificate import Certificate
from cergen.signer import SignerGraph
from cergen.manifest import load_manifests

import os
import sys


def main(argv=sys.argv[1:]):
    # parse arguments with docopt
    args = docopt(__doc__, argv)

    log_level = None
    if args['--verbose']:
        log_level = logging.DEBUG
    setup_logging(log_level)

    log = logging.getLogger('cergen')

    manifest = load_manifests(
        args['<manifest_path>'],
        args['--manifest-glob'],
        args['--base-path'],
        args['--base-private-path']
    )

    # Create a directed graph of Authorities and Certificates from the manifest.
    graph = SignerGraph(manifest)

    certificate_patterns = args['--certificates']
    if certificate_patterns is not None:
        certificate_patterns = certificate_patterns.split(',')

    # Select all matching Certificate instances in the graph.
    certificates = [c for c in graph.select(
        certificate_patterns, subordinates=args['--subordinates']
    ) if isinstance(c, Certificate)]

    certificate_names = [c.name for c in certificates]

    if args['--generate']:
        log.info('Generating certificates {} with force={}'.format(
            certificate_names, args['--force'])
        )
        for certificate in certificates:
            certificate.generate(force=args['--force'])

    print("\nStatus of certificates {}".format(certificate_names))
    print(certificates_status_string(list(certificates)))


def certificates_status_string(certificates):
    s = '\n'
    for cert in certificates:
        s += '{}\n\n'.format(cert.status_string())
    return s


def setup_logging(level=None):
    """
    Configures basic logging defaults.
    If level is not given, but the environment variable LOG_LEVEL
    is set, it will be used as the level.  Otherwise INFO is the default level.

    Args:
        level (str): log level
    """
    if level is None:
        level = getattr(
            logging, os.environ.get('LOG_LEVEL', 'INFO')
        )

    logging.basicConfig(
        level=level,
        format='%(asctime)s %(levelname)-8s %(instance_name)-40s %(message)s',
    )

    logging.getLogger('cergen.yamlreader').setLevel(logging.INFO)

    # Since we use instance_name in the format of the basic logger,
    # All log records also need to have an instance_name entry.
    # Add a logging filter to the root logger's handlers to
    # make sure that instance_name is set if a child logger hasn't set it.
    def inject_instance_name(record):
        if not hasattr(record, 'instance_name'):
            record.instance_name = record.name
        return True

    root_logger = logging.getLogger()
    for handler in root_logger.handlers:
        handler.addFilter(inject_instance_name)


if __name__ == '__main__':
    main(sys.argv[1:])
