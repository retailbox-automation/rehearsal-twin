from rt.twin.lifecycle import has_public_ip


def test_vpc_only_twin_reports_vpc_address_as_main_ip():
    # Shape seen live on 2026-11-03 for a VPC-only instance: main_ip is the VPC address.
    inst = {"main_ip": "10.77.0.6", "internal_ip": "10.77.0.6", "v6_main_ip": ""}
    assert has_public_ip(inst) is False


def test_unset_addresses_are_not_public():
    assert has_public_ip({"main_ip": "0.0.0.0", "v6_main_ip": "::"}) is False
    assert has_public_ip({}) is False


def test_global_ipv4_or_ipv6_is_public():
    assert has_public_ip({"main_ip": "45.77.102.50", "v6_main_ip": ""}) is True
    assert has_public_ip({"main_ip": "10.77.0.6", "v6_main_ip": "2001:19f0:5:1::1"}) is True


def test_garbage_is_not_treated_as_public():
    assert has_public_ip({"main_ip": "not-an-ip", "v6_main_ip": None}) is False
