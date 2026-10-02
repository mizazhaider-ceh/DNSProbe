"""Tests for dnsprobe.py. The resolver is fully mocked so no network is needed."""
import sys
import os
import types
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import dns.resolver  # noqa: E402
import dnsprobe  # noqa: E402


class FakeRdata:
    def __init__(self, text):
        self._text = text

    def __str__(self):
        return self._text


class FakeMX:
    def __init__(self, preference, exchange):
        self.preference = preference
        self.exchange = exchange


class FakeTXT:
    def __init__(self, chunks):
        self.strings = chunks


class FakeSOA:
    def __init__(self):
        self.mname = "ns1.example.com."
        self.rname = "hostmaster.example.com."
        self.serial = 2026020501
        self.refresh = 7200
        self.retry = 3600
        self.expire = 1209600
        self.minimum = 3600


class FakeCAA:
    def __init__(self):
        self.flags = 0
        self.tag = "issue"
        self.value = "letsencrypt.org"


RECORDS = {
    "A": [FakeRdata("93.184.216.34")],
    "AAAA": [],
    "MX": [FakeMX(10, "mail.example.com.")],
    "TXT": [FakeTXT([b"v=spf1 -all"])],
    "NS": [FakeRdata("ns1.example.com."), FakeRdata("ns2.example.com.")],
    "CNAME": [],
    "SOA": [FakeSOA()],
    "CAA": [FakeCAA()],
}


class FakeResolver:
    def __init__(self, *args, **kwargs):
        self.lifetime = None

    def resolve(self, name, rdtype, *args, **kwargs):
        rdtype = str(rdtype).upper()
        if name == "example.com" and rdtype in RECORDS and RECORDS[rdtype]:
            return RECORDS[rdtype]
        if name == "dead.invalid":
            raise dns.resolver.NXDOMAIN()
        if rdtype == "PTR":
            raise dns.resolver.NoAnswer()
        raise dns.resolver.NoAnswer()


@pytest.fixture(autouse=True)
def patch_resolver(monkeypatch):
    monkeypatch.setattr(dns.resolver, "Resolver", FakeResolver)


def test_domain_normalization():
    auditor = dnsprobe.DNSAuditor("  Example.COM. ")
    assert auditor.domain == "example.com"


def test_check_record_a():
    auditor = dnsprobe.DNSAuditor("example.com")
    assert auditor.check_record("A") == ["93.184.216.34"]


def test_check_record_mx_formatted():
    auditor = dnsprobe.DNSAuditor("example.com")
    assert auditor.check_record("MX") == ["10 mail.example.com."]


def test_check_record_txt_joined():
    auditor = dnsprobe.DNSAuditor("example.com")
    assert auditor.check_record("TXT") == ["v=spf1 -all"]


def test_check_record_soa_formatted():
    auditor = dnsprobe.DNSAuditor("example.com")
    soa = auditor.check_record("SOA")
    assert len(soa) == 1
    assert "serial=2026020501" in soa[0]
    assert "mname=ns1.example.com." in soa[0]


def test_check_record_caa_formatted():
    auditor = dnsprobe.DNSAuditor("example.com")
    caa = auditor.check_record("CAA")
    assert caa == ['0 issue "letsencrypt.org"']


def test_check_record_missing_returns_empty():
    auditor = dnsprobe.DNSAuditor("example.com")
    assert auditor.check_record("AAAA") == []
    assert auditor.check_record("CNAME") == []


def test_dead_domain_status():
    auditor = dnsprobe.DNSAuditor("dead.invalid")
    auditor.perform_audit()
    assert auditor.results["status"] == "dead or misconfigured"


def test_alive_domain_status():
    auditor = dnsprobe.DNSAuditor("example.com")
    auditor.perform_audit()
    assert auditor.results["status"] == "alive"
    assert auditor.results["domain"] == "example.com"
    assert set(RECORDS.keys()) <= {k.upper() for k in auditor.results.keys()}


def test_json_output(capsys):
    rc = dnsprobe.main(["example.com", "--json"])
    assert rc == 0
    out = capsys.readouterr().out
    import json as jsonlib

    data = jsonlib.loads(out)
    assert data["domain"] == "example.com"
    assert data["status"] == "alive"
    assert data["a"] == ["93.184.216.34"]


def test_ptr_flag_runs():
    auditor = dnsprobe.DNSAuditor("example.com", do_ptr=True)
    auditor.perform_audit()
    assert "ptr" in auditor.results
