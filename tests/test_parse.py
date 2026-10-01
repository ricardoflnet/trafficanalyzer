import pytest

scapy = pytest.importorskip("scapy.all")
from scapy.all import ARP, ICMP, IP, TCP, UDP, Ether, IPv6, IPv6ExtHdrHopByHop, Raw  # noqa: E402
from scapy.layers.inet6 import ICMPv6EchoRequest  # noqa: E402

from app.capture import parse_packet  # noqa: E402


def test_ipv4_tcp():
    pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP() / Raw(b"x" * 10)
    _, src, dst, proto, length = parse_packet(pkt)
    assert (src, dst, proto) == ("10.0.0.1", "10.0.0.2", "TCP")
    assert length == len(pkt)


def test_ipv4_udp_and_icmp():
    assert parse_packet(IP(src="1.1.1.1", dst="2.2.2.2") / UDP())[3] == "UDP"
    assert parse_packet(IP(src="1.1.1.1", dst="2.2.2.2") / ICMP())[3] == "ICMP"


def test_ipv6_with_extension_header():
    pkt = Ether() / IPv6(src="fe80::1", dst="fe80::2") / IPv6ExtHdrHopByHop() / TCP()
    _, src, dst, proto, _ = parse_packet(pkt)
    assert (src, dst, proto) == ("fe80::1", "fe80::2", "TCP")


def test_icmpv6():
    assert parse_packet(IPv6() / ICMPv6EchoRequest())[3] == "ICMPv6"


def test_arp_and_unknown():
    assert parse_packet(Ether() / ARP(psrc="192.168.0.1", pdst="192.168.0.2"))[1:4] == (
        "192.168.0.1", "192.168.0.2", "ARP")
    assert parse_packet(Ether(type=0x88CC) / Raw(b"lldp"))[1:4] == (None, None, "OTHER")
