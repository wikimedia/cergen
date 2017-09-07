import os
import logging
import pprint

from cergen.yamlreader import yaml_load

# Used by set_manifest_entry_defaults to pick a default Signer
default_signer_class_name = 'cergen.certificate.Certificate'


internal_signer_aliases = {
    'puppet': 'cergen.puppet.PuppetCA',
    'certificate': 'cergen.certificate.Certificate'
}


def load_manifests(path, glob='*.certs.yaml', base_path=None, base_private_path=None):
    """
    Given a directory, this will load all files matching glob
    as YAML and then recursively merge them into a single manifest dict
    using the yamlreader library and set some nice defaults.

    Args:
        path (str): Path to load, can be a file or a directory.

        glob (str): If path is a directory, all files matching this will be loaded.

        base_path (str): If a Certificate config doesn't specify a path, this will be used.

        base_private_path (str): If a Certificate config doesn't specify a private_path,
            this will be used.

    Returns:
        dict: of all read in and defaulted manifest configs.
    """
    log = logging.getLogger(__name__)

    path = os.path.abspath(path)

    # If this is a directory, it probably containing multiple manifest files.
    # Load any file that matches path glob.
    if os.path.isdir(path):
        path = os.path.join(path, glob)

    log.debug('Loading certificate and Signer manifest from %s', path)
    manifest = yaml_load(path)

    # Use base_path as the default base directory for local Certificates that don't
    # explicitly specify 'path'.
    # Use base_private_path as the default base directory for certificate or key
    # configs that don't specify 'private_path'.
    # Default base_private_path to base_path if it is given.
    if base_path is not None and base_private_path is None:
        base_private_path = base_path

    # Set unspecified defaults for each certificate config
    for name, entry in manifest.items():
        manifest[name] = set_manifest_entry_defaults(
            entry,
            name,
            base_path,
            base_private_path
        )

    log.debug('Read manifest:\n%s', pprint.pformat(manifest))
    return manifest


def set_manifest_entry_defaults(
    entry,
    name,
    base_path=None,
    base_private_path=None
):
    """
    After reading in manifests, each entry should include
    some defaults in case they aren't set in the manifests themselves.

    Currently, this only sets defaults for cergen.certificate.Certificate entries.

    Args:
        entry (dict): manifest entry
        name (str): name of this entry
        base_path (str): Certificate path will default to base_path/name
        base_private_path (str): Certificate private_path will default to base_private_path/name

    Returns:
        dict
    """

    entry.setdefault('class_name', default_signer_class_name)

    # If we have a class name alias defined in internal_signer_aliases, use it!
    if entry['class_name'] in internal_signer_aliases:
        entry['class_name'] = internal_signer_aliases[entry['class_name']]

    if entry['class_name'] == default_signer_class_name:
        entry.setdefault('name', name)

        if base_path:
            entry.setdefault('path', os.path.join(base_path, name))

        if base_private_path:
            entry.setdefault('private_path', os.path.join(base_private_path, name))

    return entry
