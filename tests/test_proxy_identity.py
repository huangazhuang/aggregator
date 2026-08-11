from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from scripts.proxy_identity import (
    IdentityCollisionError,
    IdentityError,
    IdentitySettings,
    asn_id,
    assert_unique_public_id_bindings,
    candidate_id,
    canonical_proxy_fingerprint,
    canonical_public_ip,
    canonical_asn,
    compute_public_ids,
    endpoint_id,
    exit_id,
    load_identity_test_vector,
    server_id,
    validate_public_id,
    validate_proxy_fingerprint,
    verify_identity_preflight,
    verify_identity_test_vector,
)


FIXTURE = Path(__file__).resolve().parent / "fixtures" / "gmgn_identity_v1.json"


class ProxyIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.vector = load_identity_test_vector(FIXTURE)
        self.proxy = copy.deepcopy(self.vector["proxy"])
        self.key = self.vector["_test_key"]
        self.key_version = str(self.vector["identity_key_version"])
        self.epoch = str(self.vector["identity_epoch"])

    def candidate(self, proxy: dict | None = None, **overrides: object) -> str:
        return candidate_id(
            proxy or self.proxy,
            key=overrides.get("key", self.key),
            identity_key_version=str(
                overrides.get("identity_key_version", self.key_version)
            ),
            identity_epoch=str(overrides.get("identity_epoch", self.epoch)),
        )

    def test_fixed_cross_platform_vector(self) -> None:
        self.assertEqual(verify_identity_test_vector(FIXTURE), self.vector["expected"])

    def test_rename_provenance_and_key_order_do_not_change_identity(self) -> None:
        renamed = copy.deepcopy(self.proxy)
        renamed["name"] = "Renamed by source"
        renamed["provenance"] = [{"source_id": "another-source"}]
        renamed["delay_ms"] = 42
        reordered = {key: renamed[key] for key in reversed(list(renamed))}

        self.assertEqual(
            canonical_proxy_fingerprint(self.proxy),
            canonical_proxy_fingerprint(reordered),
        )
        self.assertEqual(self.candidate(), self.candidate(reordered))

    def test_every_connection_field_change_changes_identity(self) -> None:
        mutations = {
            "protocol": lambda item: item.__setitem__("type", "trojan"),
            "server": lambda item: item.__setitem__("server", "other.example"),
            "port": lambda item: item.__setitem__("port", 8443),
            "credential": lambda item: item.__setitem__(
                "uuid", "00000000-0000-4000-8000-000000000002"
            ),
            "transport": lambda item: item.__setitem__("network", "grpc"),
            "tls": lambda item: item.__setitem__("tls", False),
            "reality": lambda item: item.__setitem__(
                "reality-opts", {"public-key": "fixture-public-key", "short-id": "01"}
            ),
            "nested-list-order": lambda item: item.__setitem__("alpn", ["h2", "http/1.1"]),
            "scalar-type": lambda item: item.__setitem__("udp", 1),
        }
        baseline = canonical_proxy_fingerprint(self.proxy)
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                changed = copy.deepcopy(self.proxy)
                mutate(changed)
                self.assertNotEqual(baseline, canonical_proxy_fingerprint(changed))

        with self.assertRaises(IdentityError):
            canonical_proxy_fingerprint({**self.proxy, 1: "invalid-key"})

    def test_identity_domains_and_versions_are_separated(self) -> None:
        ids = compute_public_ids(
            self.proxy,
            key=self.key,
            identity_key_version=self.key_version,
            identity_epoch=self.epoch,
            public_ip=self.vector["public_ipv4"],
        )
        self.assertEqual(len(set(ids.values())), 4)
        self.assertTrue(ids["candidate_id"].startswith("c1_"))
        self.assertTrue(ids["server_id"].startswith("srv1_"))
        self.assertTrue(ids["endpoint_id"].startswith("ep1_"))
        self.assertTrue(ids["exit_id"].startswith("exit1_"))
        self.assertNotEqual(self.candidate(), self.candidate(identity_key_version="test-key-v2"))
        self.assertNotEqual(self.candidate(), self.candidate(identity_epoch="identity-v2"))
        self.assertNotEqual(self.candidate(), self.candidate(key=b"different-test-key"))

    def test_server_and_endpoint_canonicalization(self) -> None:
        self.assertEqual(
            server_id(
                "ExAmPle.COM.",
                key=self.key,
                identity_key_version=self.key_version,
                identity_epoch=self.epoch,
            ),
            server_id(
                "example.com",
                key=self.key,
                identity_key_version=self.key_version,
                identity_epoch=self.epoch,
            ),
        )
        self.assertEqual(
            endpoint_id(
                "ExAmPle.COM.",
                "443",
                key=self.key,
                identity_key_version=self.key_version,
                identity_epoch=self.epoch,
            ),
            endpoint_id(
                "example.com",
                443,
                key=self.key,
                identity_key_version=self.key_version,
                identity_epoch=self.epoch,
            ),
        )

    def test_ipv4_ipv6_canonicalization_and_non_global_rejection(self) -> None:
        self.assertEqual(canonical_public_ip(" 8.8.8.8 "), "8.8.8.8")
        self.assertEqual(
            canonical_public_ip("2001:4860:4860:0:0:0:0:8888"),
            "2001:4860:4860::8888",
        )
        self.assertEqual(
            exit_id(
                "2001:4860:4860:0:0:0:0:8888",
                key=self.key,
                identity_key_version=self.key_version,
                identity_epoch=self.epoch,
            ),
            self.vector["expected"]["exit_id_ipv6"],
        )
        for address in (
            "127.0.0.1",
            "10.0.0.1",
            "169.254.1.1",
            "224.0.0.1",
            "0.0.0.0",
            "::1",
            "fe80::1",
            "fc00::1",
            "not-an-ip",
        ):
            with self.subTest(address=address), self.assertRaises(IdentityError):
                canonical_public_ip(address)

    def test_asn_identity_is_canonical_domain_separated_and_strict(self) -> None:
        self.assertEqual(canonical_asn(13335), "AS13335")
        self.assertEqual(canonical_asn("AS13335"), "AS13335")
        self.assertEqual(canonical_asn("13335"), "AS13335")
        identifier = asn_id(
            "AS13335",
            key=self.key,
            identity_key_version=self.key_version,
            identity_epoch=self.epoch,
        )
        self.assertTrue(identifier.startswith("asn1_"))
        self.assertEqual(validate_public_id(identifier, "asn"), identifier)
        self.assertNotEqual(
            identifier,
            exit_id(
                self.vector["public_ipv4"],
                key=self.key,
                identity_key_version=self.key_version,
                identity_epoch=self.epoch,
            ),
        )
        for value in (0, -1, True, "AS0", " AS13335", "AS1.5", "not-an-asn"):
            with self.subTest(asn=value), self.assertRaises(IdentityError):
                canonical_asn(value)

    def test_missing_key_version_or_epoch_fails_closed(self) -> None:
        for environment in (
            {},
            {"GMGN_IDENTITY_HMAC_KEY": "key"},
            {
                "GMGN_IDENTITY_HMAC_KEY": "key",
                "GMGN_IDENTITY_KEY_VERSION": "v1",
            },
        ):
            with self.subTest(environment=environment), self.assertRaises(IdentityError):
                IdentitySettings.from_environment(environment)
        with self.assertRaises(IdentityError):
            self.candidate(identity_key_version="")
        with self.assertRaises(IdentityError):
            self.candidate(identity_epoch="")

        for args in (
            (b"", "v1", "identity-v1"),
            (b"key", " v1", "identity-v1"),
            (b"key", "v1", "identity-v1 "),
        ):
            with self.subTest(args=args), self.assertRaises(IdentityError):
                IdentitySettings(*args)

    def test_public_identity_inputs_are_strict_and_not_silently_normalized(self) -> None:
        fingerprint = canonical_proxy_fingerprint(self.proxy)
        self.assertEqual(validate_proxy_fingerprint(fingerprint), fingerprint)
        for value in (fingerprint.upper(), f" {fingerprint}", 123):
            with self.subTest(fingerprint=value), self.assertRaises(IdentityError):
                validate_proxy_fingerprint(value)
        public_id = self.candidate()
        for value in (f" {public_id}", public_id.upper(), 123):
            with self.subTest(public_id=value), self.assertRaises(IdentityError):
                validate_public_id(value, "candidate")
        with self.assertRaises(IdentityError):
            server_id(
                123,
                key=self.key,
                identity_key_version=self.key_version,
                identity_epoch=self.epoch,
            )

    def test_preflight_mismatch_and_public_id_collision_fail_closed(self) -> None:
        expected = dict(self.vector["expected"])
        expected.pop("exit_id_ipv6")
        expected["candidate_id"] = "c1_000000000000000000000000"
        with self.assertRaisesRegex(IdentityError, "preflight mismatch"):
            verify_identity_preflight(
                self.proxy,
                expected,
                key=self.key,
                identity_key_version=self.key_version,
                identity_epoch=self.epoch,
                public_ip=self.vector["public_ipv4"],
            )

        public_id = self.vector["expected"]["candidate_id"]
        with self.assertRaises(IdentityCollisionError):
            assert_unique_public_id_bindings(
                [(public_id, "private-a"), (public_id, "private-b")]
            )
        assert_unique_public_id_bindings(
            [(public_id, "private-a"), (public_id, "private-a")]
        )

    def test_public_outputs_do_not_leak_secret_fingerprint_or_exit_ip(self) -> None:
        public_ids = compute_public_ids(
            self.proxy,
            key=self.key,
            identity_key_version=self.key_version,
            identity_epoch=self.epoch,
            public_ip=self.vector["public_ipv4"],
        )
        serialized = json.dumps(public_ids, sort_keys=True)
        self.assertNotIn(self.key.hex(), serialized)
        self.assertNotIn(canonical_proxy_fingerprint(self.proxy), serialized)
        self.assertNotIn(str(self.vector["public_ipv4"]), serialized)
        for kind, value in (
            ("candidate", public_ids["candidate_id"]),
            ("server", public_ids["server_id"]),
            ("endpoint", public_ids["endpoint_id"]),
            ("exit", public_ids["exit_id"]),
        ):
            self.assertEqual(validate_public_id(value, kind), value)


if __name__ == "__main__":
    unittest.main()
