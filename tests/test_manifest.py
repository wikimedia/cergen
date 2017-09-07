import pytest
import os

import cergen

from fixtures import *

# Use this entry from test.certs.yaml manifest for testing
common_name = 'hostname1.example.org'


def test_set_manifest_entry_defaults(manifest_entry, tmpdir):
    entry = cergen.manifest.set_manifest_entry_defaults(
        manifest_entry,
        common_name,
        base_path=str(tmpdir),
        base_private_path=str(tmpdir)
    )

    assert entry['name'] == common_name, \
        'entry name should be set'
    assert entry['class_name'] == cergen.manifest.default_signer_class_name, \
        'entry class should be set to default'
    assert entry['path'] == os.path.join(str(tmpdir), common_name), \
        'entry path should be set to default'
    assert entry['private_path'] == os.path.join(str(tmpdir), common_name), \
        'entry private_path should be set to default'

    # set some specific values to make sure defaults do not override them
    manifest_entry['path'] = 'mypath/certs'
    manifest_entry['private_path'] = 'mypath/private'

    entry = cergen.manifest.set_manifest_entry_defaults(
        manifest_entry,
        common_name,
        # These are only defaults, since path and private_path are set,
        # they should not be used.
        base_path=str(tmpdir),
        base_private_path=str(tmpdir)
    )

    assert entry['path'] == 'mypath/certs', \
        'entry path should be set to provided value'
    assert entry['private_path'] == 'mypath/private', \
        'entry private_path should be set to provided value'

    # Test that internal class aliases work
    manifest_entry['class_name'] = 'puppet'
    entry = cergen.manifest.set_manifest_entry_defaults(
        manifest_entry,
        common_name,
        base_path=str(tmpdir),
        base_private_path=str(tmpdir)
    )
    assert entry['class_name'] == cergen.manifest.internal_signer_aliases['puppet'], \
        'entry class_name should be looked up from internal_signer_aliases'


def test_load_manifests(manifest_path, tmpdir):
    m = cergen.manifest.load_manifests(
        manifest_path, base_path=str(tmpdir), base_private_path=str(tmpdir)
    )
    entry = m[common_name]

    assert entry['name'] == common_name, \
        'entry name should be set'
    assert entry['class_name'] == cergen.manifest.default_signer_class_name, \
        'entry class should be set to default'
    assert entry['path'] == os.path.join(str(tmpdir), common_name), \
        'entry path should be set to default'
    assert entry['private_path'] == os.path.join(str(tmpdir), common_name), \
        'entry private_path should be set to default'




