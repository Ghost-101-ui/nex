from nex.gate import Gate, GateError, in_scope
from nex.registry import TOOLS


def test_ip_and_domain_scope():
    assert in_scope("10.10.10.5", ["10.10.10.0/24"])
    assert not in_scope("10.10.11.5", ["10.10.10.0/24"])
    assert in_scope("api.lab.test", ["lab.test"])
    assert not in_scope("notlab.test", ["lab.test"])


def test_gate_rejects_out_of_scope(monkeypatch):
    monkeypatch.setenv("NEX_LAB_ACK", "I_AM_AUTHORIZED")
    try:
        Gate().authorize(TOOLS["nmap_scan"], {"target": "8.8.8.8", "scan_type": "quick"}, {"scope": ["10.0.0.0/8"], "phase": "recon"})
    except GateError:
        return
    assert False, "expected scope rejection"
