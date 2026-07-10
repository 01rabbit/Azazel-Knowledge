from __future__ import annotations

import pytest

from azazel_grimoire.normalize.ioc import (
    NormalizationError,
    normalize,
    pack_ipv4_range,
    pack_ipv6_range,
)
from ipaddress import ip_network


def test_defang_rearm_domain():
    assert normalize("domain", "hxxp[.]example[.]com") == "http.example.com"


def test_defang_rearm_url():
    assert normalize("url", "hxxps[:]//example[.]com/path") == "https://example.com/path"


def test_defang_rearm_email_at():
    assert normalize("email", "user[at]example.com") == "user@example.com"


def test_defang_rearm_paren_dot():
    assert normalize("domain", "example(.)com") == "example.com"


def test_domain_lowercase_and_trailing_dot():
    assert normalize("domain", "EXAMPLE.COM.") == "example.com"


def test_domain_idn_to_alabel():
    assert normalize("domain", "bücher.example") == "xn--bcher-kva.example"


def test_domain_accepts_already_punycode():
    assert normalize("domain", "xn--bcher-kva.example") == "xn--bcher-kva.example"


def test_domain_invalid_raises():
    with pytest.raises(NormalizationError):
        normalize("domain", "not a domain!!")


def test_url_scheme_and_host_lowercased():
    assert normalize("url", "HTTP://EXAMPLE.COM/Path?Query=1") == "http://example.com/Path?Query=1"


def test_url_default_port_removed():
    assert normalize("url", "http://example.com:80/x") == "http://example.com/x"
    assert normalize("url", "https://example.com:443/x") == "https://example.com/x"


def test_url_non_default_port_kept():
    assert normalize("url", "http://example.com:8080/x") == "http://example.com:8080/x"


def test_url_host_idn_alabel():
    assert normalize("url", "http://bücher.example/path") == "http://xn--bcher-kva.example/path"


def test_url_percent_encoding_uppercased():
    assert normalize("url", "http://example.com/a%2fb%3D") == "http://example.com/a%2Fb%3D"


def test_url_ip_host_preserved():
    assert normalize("url", "http://192.168.1.1:80/x") == "http://192.168.1.1/x"


def test_url_missing_scheme_raises():
    with pytest.raises(NormalizationError):
        normalize("url", "example.com/path")


def test_ip_v4_canonical():
    assert normalize("ip", "1.1.1.1") == "1.1.1.1"


def test_ip_v6_canonical_compressed():
    assert normalize("ip", "2001:0db8:0000:0000:0000:0000:0000:0001") == "2001:db8::1"


def test_ip_invalid_rejected():
    with pytest.raises(NormalizationError):
        normalize("ip", "999.999.999.999")


def test_ip_invalid_leading_zero_rejected():
    with pytest.raises(NormalizationError):
        normalize("ip", "010.1.1.1")


def test_hash_md5_valid():
    assert normalize("md5", "A" * 32) == "a" * 32


def test_hash_sha1_valid():
    assert normalize("sha1", "B" * 40) == "b" * 40


def test_hash_sha256_valid():
    assert normalize("sha256", "C" * 64) == "c" * 64


def test_hash_wrong_length_rejected():
    with pytest.raises(NormalizationError):
        normalize("md5", "a" * 31)


def test_hash_non_hex_rejected():
    with pytest.raises(NormalizationError):
        normalize("sha1", "z" * 40)


def test_email_local_case_preserved_domain_lowered():
    assert normalize("email", "User.Name@EXAMPLE.COM") == "User.Name@example.com"


def test_email_missing_at_rejected():
    with pytest.raises(NormalizationError):
        normalize("email", "not-an-email")


def test_ja3_valid_lowercased():
    assert normalize("ja3", "A" * 32) == "a" * 32


def test_ja3_wrong_length_rejected():
    with pytest.raises(NormalizationError):
        normalize("ja3", "a" * 31)


def test_ja4_case_preserved():
    value = "t13d1516h2_8daaf6152771_02713d6af8f2"
    assert normalize("ja4", value) == value


def test_ja4_invalid_charset_rejected():
    with pytest.raises(NormalizationError):
        normalize("ja4", "bad ja4 value!")


def test_asn_normalized_with_prefix():
    assert normalize("asn", "12345") == "AS12345"
    assert normalize("asn", "as12345") == "AS12345"
    assert normalize("asn", "AS012345") == "AS12345"


def test_asn_invalid_rejected():
    with pytest.raises(NormalizationError):
        normalize("asn", "ASxyz")


def test_cidr_canonical():
    assert normalize("cidr", "10.1.2.3/24") == "10.1.2.0/24"


def test_cidr_invalid_rejected():
    with pytest.raises(NormalizationError):
        normalize("cidr", "not-a-cidr")


def test_pack_ipv4_range():
    network = ip_network("10.1.2.0/24")
    start, end = pack_ipv4_range(network)
    assert start == bytes([10, 1, 2, 0])
    assert end == bytes([10, 1, 2, 255])
    assert len(start) == 4 and len(end) == 4


def test_pack_ipv6_range():
    network = ip_network("2001:db8::/126")
    start, end = pack_ipv6_range(network)
    assert len(start) == 16 and len(end) == 16
    assert start < end


def test_pack_ipv4_range_rejects_ipv6():
    with pytest.raises(NormalizationError):
        pack_ipv4_range(ip_network("2001:db8::/126"))


def test_unknown_type_rejected():
    with pytest.raises(NormalizationError):
        normalize("bogus_type", "value")
