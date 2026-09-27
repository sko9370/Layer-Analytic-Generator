from lag.models import Citation
from lag.text import citation_labels, link_citations, plain_text, strip_citations, table_cell

CITES = {"A B 2020": Citation("A B 2020", "https://a.example"), "NoUrl": Citation("NoUrl", None)}


def test_citation_labels_unique_in_order():
    text = "x(Citation: A B 2020)(Citation: NoUrl) y (Citation: A B 2020)"
    assert citation_labels(text) == ["A B 2020", "NoUrl"]


def test_link_citations_exact_match_and_spacing():
    out = link_citations("Used AES.(Citation: A B 2020) Also (Citation: NoUrl)", CITES)
    assert out == "Used AES. ([A B 2020](https://a.example)) Also (NoUrl)"


def test_link_citations_does_not_substring_match():
    out = link_citations("x (Citation: A B)", CITES)
    assert out == "x (A B)"


def test_plain_text():
    text = "[APT1](https://attack.mitre.org/groups/G0006) ran <code>cmd.exe</code>.(Citation: NoUrl)"
    assert plain_text(text) == "APT1 ran cmd.exe."
    assert strip_citations("a (Citation: X) b") == "a b"


def test_table_cell():
    assert table_cell("a|b\nc") == "a\\|b<br>c"
