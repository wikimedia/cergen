import pytest

import networkx

from cergen.signer import AbstractSigner, SignerGraph

from fixtures import *

# Test using these cert names from the tests.certs.yaml manifest
root_common_name = 'root_ca'
intermediate_common_name = 'intermediate_ca'
common_name = 'hostname1.example.org'


def test_init(signer_graph):
    """
    Test that the SignerGraph is instantiated.
    """
    assert isinstance(signer_graph.graph, networkx.DiGraph)


def test_get(signer_graph):
    """
    Test that get() gets an signer out of the graph by name
    """
    a = signer_graph.get(common_name)
    assert isinstance(a, AbstractSigner)
    assert a.name == common_name


def test_iter(signer_graph, manifest_dict):
    """
    Test that iterating over the signer graph includes the root CA as the
    first element, and that every name in the graph is also in the manifest
    """
    graph_list = list(signer_graph)

    assert graph_list[0] == root_common_name, \
        '{} should be first element in graph iter'.format(root_common_name)

    manifest_entry_names = manifest_dict.keys()
    for name in graph_list:
        assert name in manifest_entry_names, \
            '{} should match an entry in the manifest'.format(name)


def test_children(signer_graph):
    """
    Test that children() returns all children of root_ca
    """
    children = signer_graph.children(root_common_name)
    children_names = [c.name for c in children]

    children_should_be = [intermediate_common_name, common_name]
    assert len(children_names) == len(children_should_be), \
        'Should be 3 children of {}'.format(root_common_name)

    for name in children_should_be:
        assert name in children_names, \
            '{} should be in list of {}\'s children'.format(name, root_common_name)


def test_parents(signer_graph):
    """
    Test that parents return all parents of leaf node
    """
    parents = signer_graph.parents(common_name)
    parent_names = [c.name for c in parents]

    parents_should_be = [intermediate_common_name, root_common_name]
    assert len(parent_names) == len(parents_should_be), \
        'Should be 2 parents of {}'.format(common_name)

    for name in parents_should_be:
        assert name in parent_names, \
            '{} should be in list of {}\'s parents'.format(name, common_name)


def test_select_all(signer_graph, manifest_dict):
    """
    Test that all nodes in the graph are returned when no patterns are given.
    """
    results = signer_graph.select()

    manifest_entry_names = manifest_dict.keys()
    for name in [a.name for a in results]:
        assert name in manifest_entry_names, \
            '{} should match an entry in the manifest'.format(name)


def test_select_by_name(signer_graph):
    """
    Test that only one signer is selected
    """
    patterns = [common_name]
    results = signer_graph.select(patterns)
    assert len(results) == 1, \
        'Only 1 result for {} should be found'.format(common_name)
    assert results[0].name == common_name, \
        'The found result should be {}'.format(patterns)


def test_select_by_names(signer_graph):
    """
    Test that seleted authorities are returned in top down order
    """
    patterns = [common_name, intermediate_common_name]
    results = signer_graph.select(patterns)
    assert len(results) == 2, \
        'Only 2 results for {} should be found'.format(patterns)
    assert results[0].name == intermediate_common_name, \
        'The first result should be {}'.format(intermediate_common_name)
    assert results[1].name == common_name, \
        'The second result should be {}'.format(common_name)


def test_select_by_patterns(signer_graph):
    """
    Test that seleted authorities are returned in top down order with regex patterns
    """
    patterns = ['root.*', '.*\.example\.org']
    results = signer_graph.select(patterns)
    assert len(results) == 2, \
        'Only 2 results for {} should be found'.format(patterns)
    assert results[0].name == root_common_name, \
        'The first result should be {}'.format(root_common_name)
    assert results[1].name == common_name, \
        'The second result should be {}'.format(common_name)


def test_select_with_subordinates(signer_graph):
    """
    Test that seleted authorities are returned in top down order with subordinates
    """
    patterns = [intermediate_common_name]
    results = signer_graph.select(patterns, subordinates=True)
    assert len(results) == 2, \
        'Only 2 results for {} with subordinates should be found'.format(patterns)
    assert results[0].name == intermediate_common_name, \
        'The first result should be {}'.format(intermediate_common_name)
    assert results[1].name == common_name, \
        'The second result should be {}'.format(common_name)

