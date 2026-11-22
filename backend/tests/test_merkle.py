"""Merkle 块的单元测试。"""

from __future__ import annotations

from app import merkle


def test_empty_root():
    assert merkle.root_of([]) == merkle.EMPTY_ROOT


def test_single_leaf_is_the_root():
    leaf = merkle.leaf(b"abc")
    assert merkle.root_of([leaf]) == leaf


def test_two_leaves():
    a, b = merkle.leaf(b"a"), merkle.leaf(b"b")
    assert merkle.root_of([a, b]) == merkle.node(a, b)


def test_odd_level_duplicates_last():
    a, b, c = merkle.leaf(b"a"), merkle.leaf(b"b"), merkle.leaf(b"c")
    left = merkle.node(a, b)
    right = merkle.node(c, c)
    assert merkle.root_of([a, b, c]) == merkle.node(left, right)


def test_order_matters():
    a, b = merkle.leaf(b"a"), merkle.leaf(b"b")
    assert merkle.root_of([a, b]) != merkle.root_of([b, a])


def test_leaf_and_node_are_domain_separated():
    chunk = b"same bytes"
    assert merkle.leaf(chunk) != merkle.node(chunk, chunk)
