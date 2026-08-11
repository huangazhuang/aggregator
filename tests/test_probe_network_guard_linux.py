import copy
import json
import os
import tempfile
import unittest
from pathlib import Path

from scripts.probe_network_guard import (
    NETWORK_GUARD_POLICY_VERSION,
    RESOLVER_POLICY_VERSION,
    validate_guard_evidence,
)
from scripts.probe_network_guard_linux import (
    BACKEND,
    BACKEND_VERSION,
    CommandResult,
    LinuxGuardError,
    LinuxGuardLease,
    build_guard_plan,
    discover_runner_networks,
    effective_cap_net_admin,
    effective_cap_sys_admin,
    exercise_netns_mutation,
    load_guard_lease,
    normalize_pinned_targets,
    preflight_linux_backend,
    provision_guard,
    validate_linux_guard_evidence,
)


TEST_LEASE_ID = "0123456789abcdef0123456789abcdef"


def candidate_id(index: int) -> str:
    return f"c1_{index:024x}"


def pinned_targets(*, ipv6: bool = False) -> dict:
    values = {
        candidate_id(1): {
            "server": "one.example.test",
            "port": 443,
            "addresses": ["8.8.8.8"],
            "resolver_policy_version": RESOLVER_POLICY_VERSION,
        },
        candidate_id(2): {
            "server": "two.example.test",
            "port": 8443,
            "addresses": ["1.1.1.1"],
            "resolver_policy_version": RESOLVER_POLICY_VERSION,
        },
    }
    if ipv6:
        values[candidate_id(3)] = {
            "server": "six.example.test",
            "port": 443,
            "addresses": ["2606:4700:4700::1111"],
            "resolver_policy_version": RESOLVER_POLICY_VERSION,
        }
    return values


def auxiliary_targets() -> dict:
    return {
        "gmgn-control": {
            "server": "gmgn.ai",
            "port": 443,
            "addresses": ["9.9.9.9"],
            "resolver_policy_version": RESOLVER_POLICY_VERSION,
        },
        "egress-check": {
            "server": "egress.example.test",
            "port": 443,
            "addresses": ["208.67.222.222"],
            "resolver_policy_version": RESOLVER_POLICY_VERSION,
            "protocols": ["tcp"],
        },
    }


def capabilities(*, ipv6: bool = True) -> dict:
    return {
        "linux": True,
        "root": True,
        "cap_net_admin": True,
        "cap_sys_admin": True,
        "ip_netns": True,
        "iptables": True,
        "ip6tables": True,
        "ipv4_forwarding": True,
        "ipv6_forwarding": ipv6,
    }


class FakeRunner:
    def __init__(self, *, fail_contains: str | None = None) -> None:
        self.commands: list[tuple[str, ...]] = []
        self.fail_contains = fail_contains

    def __call__(self, command, *, check=True, capture_output=True):
        value = tuple(command)
        self.commands.append(value)
        if self.fail_contains and self.fail_contains in " ".join(value):
            return CommandResult(returncode=7, stderr="injected")
        if value == ("ip", "-j", "route", "show", "table", "all"):
            return CommandResult(
                stdout=json.dumps(
                    [
                        {"dst": "default", "gateway": "172.17.0.1"},
                        {"dst": "172.17.0.0/16", "dev": "eth0"},
                        {"dst": "198.18.20.0/24", "dev": "ci0"},
                    ]
                )
            )
        if value == ("ip", "-j", "-6", "route", "show", "table", "all"):
            return CommandResult(
                stdout=json.dumps(
                    [
                        {"dst": "default", "gateway": "fe80::1"},
                        {"dst": "fd12:3456::/64", "dev": "eth0"},
                    ]
                )
            )
        if "-S" in value:
            return CommandResult(stdout="-A GMGN_TEST -j DROP\n")
        return CommandResult()


class CapabilityTests(unittest.TestCase):
    def test_netns_requires_both_net_admin_and_sys_admin_capabilities(self):
        self.assertTrue(effective_cap_net_admin("CapEff:\t0000000000001000\n"))
        self.assertFalse(effective_cap_net_admin("CapEff:\t0000000000000800\n"))
        self.assertFalse(effective_cap_net_admin("not-a-status-file"))
        self.assertTrue(effective_cap_sys_admin("CapEff:\t0000000000200000\n"))
        self.assertFalse(effective_cap_sys_admin("CapEff:\t0000000000001000\n"))

    def test_preflight_fails_closed_before_any_namespace_mutation(self):
        runner = FakeRunner()
        with self.assertRaisesRegex(LinuxGuardError, "Linux network namespaces"):
            preflight_linux_backend(
                runner=runner,
                system=lambda: "Windows",
                geteuid=lambda: 0,
                which=lambda name: f"/usr/sbin/{name}",
                read_text=lambda path: "1",
            )
        self.assertEqual(runner.commands, [])

        with self.assertRaisesRegex(LinuxGuardError, "CAP_NET_ADMIN"):
            preflight_linux_backend(
                runner=runner,
                system=lambda: "Linux",
                geteuid=lambda: 0,
                which=lambda name: f"/usr/sbin/{name}",
                read_text=lambda path: "CapEff:\t0\n" if path.endswith("status") else "1",
            )
        self.assertEqual(runner.commands, [])

        with self.assertRaisesRegex(LinuxGuardError, "CAP_SYS_ADMIN"):
            preflight_linux_backend(
                runner=runner,
                system=lambda: "Linux",
                geteuid=lambda: 0,
                which=lambda name: f"/usr/sbin/{name}",
                read_text=lambda path: (
                    "CapEff:\t0000000000001000\n" if path.endswith("status") else "1"
                ),
            )
        self.assertEqual(runner.commands, [])

    def test_preflight_checks_tools_netns_tables_and_forwarding(self):
        runner = FakeRunner()

        def read_text(path: str) -> str:
            if path.endswith("/status"):
                return "CapEff:\t0000000000201000\n"
            return "1\n"

        result = preflight_linux_backend(
            runner=runner,
            system=lambda: "Linux",
            geteuid=lambda: 0,
            which=lambda name: f"/usr/sbin/{name}",
            read_text=read_text,
        )
        self.assertTrue(result["ipv4_forwarding"])
        self.assertTrue(result["ipv6_forwarding"])
        self.assertIn(("ip", "netns", "list"), runner.commands)
        self.assertIn(("iptables", "-w", "5", "-t", "nat", "-L"), runner.commands)
        self.assertIn(("ip6tables", "-w", "5", "-L"), runner.commands)

    def test_capability_smoke_really_adds_and_deletes_a_unique_namespace(self):
        runner = FakeRunner()
        evidence = exercise_netns_mutation(
            "gmgnv2-cap-0123456789ab", runner=runner
        )
        self.assertTrue(evidence["netns_mutation_smoke"])
        self.assertEqual(
            runner.commands,
            [
                ("ip", "netns", "add", "gmgnv2-cap-0123456789ab"),
                ("ip", "netns", "delete", "gmgnv2-cap-0123456789ab"),
            ],
        )
        with self.assertRaisesRegex(LinuxGuardError, "unsafe"):
            exercise_netns_mutation("not-owned", runner=runner)

        failing = FakeRunner(fail_contains="netns delete")
        with self.assertRaisesRegex(LinuxGuardError, "command failed"):
            exercise_netns_mutation(
                "gmgnv2-cap-abcdef012345", runner=failing
            )


class PinningAndPlanTests(unittest.TestCase):
    def test_private_metadata_and_noncanonical_addresses_are_rejected(self):
        for address in (
            "127.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "169.254.169.254",
            "224.0.0.1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
        ):
            with self.subTest(address=address):
                value = pinned_targets()
                value[candidate_id(1)]["addresses"] = [address]
                with self.assertRaisesRegex(LinuxGuardError, "forbidden non-public"):
                    normalize_pinned_targets(value)

        value = pinned_targets()
        value[candidate_id(1)]["addresses"] = ["8.8.8.8", "8.8.8.8"]
        with self.assertRaisesRegex(LinuxGuardError, "duplicated or non-canonical"):
            normalize_pinned_targets(value)

    def test_plan_has_double_enforcement_controller_isolation_nat_and_cleanup(self):
        plan = build_guard_plan(
            pinned_targets(ipv6=True),
            shard_index=2,
            controller_port=19092,
            local_ports=[17892],
            auxiliary_targets=auxiliary_targets(),
            runner_networks={
                "ipv4": ["172.17.0.0/16"],
                "ipv6": ["fd12:3456::/64"],
            },
            lease_id=TEST_LEASE_ID,
        )
        commands = [" ".join(command) for command in plan["setup_commands"]]
        combined = "\n".join(commands)
        namespace = plan["names"]["namespace"]
        self.assertIn(f"ip netns add {namespace}", combined)
        self.assertIn("type veth peer name", combined)
        self.assertIn("iptables -w 5 -t nat -A POSTROUTING", combined)
        self.assertIn("ip6tables -w 5 -t nat -A POSTROUTING", combined)
        self.assertIn("169.254.169.254/32", combined)
        self.assertIn("100.100.100.200/32", combined)
        self.assertIn("168.63.129.16/32", combined)
        self.assertIn("fd00:ec2::254/128", combined)
        self.assertIn("172.17.0.0/16", combined)
        self.assertIn("fd12:3456::/64", combined)
        self.assertIn("8.8.8.8/32 -p tcp --dport 443", combined)
        self.assertIn("8.8.8.8/32 -p udp --dport 443", combined)
        self.assertIn("2606:4700:4700::1111/128", combined)
        self.assertIn("9.9.9.9/32 -p tcp --dport 443", combined)
        self.assertNotIn("9.9.9.9/32 -p udp --dport 443", combined)
        self.assertIn("-o lo -d 127.0.0.1/32 -p tcp --dport 19092", combined)
        self.assertIn("-o lo -d 127.0.0.1/32 -p tcp --dport 17892", combined)
        self.assertIn("-I OUTPUT", combined)
        self.assertIn("-I FORWARD", combined)
        self.assertTrue(any(command.endswith(" -j DROP") for command in commands))

        cleanup = [tuple(command) for command in plan["cleanup_commands"]]
        self.assertIn(("ip", "netns", "delete", namespace), cleanup)
        self.assertFalse(
            any("netns list" in " ".join(command) for command in plan["cleanup_commands"])
        )
        self.assertFalse(any("*" in item for command in cleanup for item in command))

    def test_auxiliary_targets_have_separate_binding_from_shard_candidates(self):
        base = build_guard_plan(
            pinned_targets(),
            shard_index=0,
            controller_port=19090,
            runner_networks={"ipv4": [], "ipv6": []},
            lease_id=TEST_LEASE_ID,
        )
        extended = build_guard_plan(
            pinned_targets(),
            shard_index=0,
            controller_port=19090,
            auxiliary_targets=auxiliary_targets(),
            runner_networks={"ipv4": [], "ipv6": []},
            lease_id=TEST_LEASE_ID,
        )
        self.assertEqual(
            extended["candidate_ids_sha256"], base["candidate_ids_sha256"]
        )
        self.assertEqual(extended["fixed_targets_sha256"], base["fixed_targets_sha256"])
        self.assertNotEqual(
            extended["auxiliary_targets_sha256"], base["auxiliary_targets_sha256"]
        )
        self.assertNotEqual(
            extended["all_fixed_targets_sha256"], base["all_fixed_targets_sha256"]
        )

        unsafe = auxiliary_targets()
        unsafe["gmgn-control"]["addresses"] = ["169.254.169.254"]
        with self.assertRaisesRegex(LinuxGuardError, "forbidden non-public"):
            build_guard_plan(
                pinned_targets(),
                shard_index=0,
                controller_port=19090,
                auxiliary_targets=unsafe,
                runner_networks={"ipv4": [], "ipv6": []},
                lease_id=TEST_LEASE_ID,
            )

    def test_runner_routes_are_bound_into_the_deny_policy(self):
        networks = discover_runner_networks(FakeRunner())
        self.assertEqual(networks["ipv4"], ("172.17.0.0/16", "198.18.20.0/24"))
        self.assertEqual(networks["ipv6"], ("fd12:3456::/64",))

        value = pinned_targets()
        value[candidate_id(1)]["addresses"] = ["8.8.8.8"]
        with self.assertRaisesRegex(LinuxGuardError, "overlaps"):
            build_guard_plan(
                value,
                shard_index=0,
                controller_port=19090,
                runner_networks={"ipv4": ["8.8.8.0/24"], "ipv6": []},
                lease_id=TEST_LEASE_ID,
            )


class ProvisionAndLeaseTests(unittest.TestCase):
    def temporary_directory(self):
        root = os.environ.get("AGGREGATOR_TEST_TMPDIR")
        if root:
            Path(root).mkdir(parents=True, exist_ok=True)
        return tempfile.TemporaryDirectory(dir=root or None)

    def test_provision_emits_strict_c2_compatible_evidence_and_launch_prefix(self):
        runner = FakeRunner()
        values = pinned_targets()
        with self.temporary_directory() as directory:
            state_path = Path(directory) / "guard-state.json"
            lease = provision_guard(
                values,
                shard_index=0,
                controller_port=19090,
                local_ports=[17890],
                auxiliary_targets=auxiliary_targets(),
                state_path=state_path,
                runner=runner,
                capabilities=capabilities(),
                runner_networks={"ipv4": ["172.17.0.0/16"], "ipv6": []},
                lease_id=TEST_LEASE_ID,
            )
            validate_guard_evidence(lease.c2_evidence, candidate_ids=values.keys())
            detailed = validate_linux_guard_evidence(
                lease.evidence, candidate_ids=values.keys()
            )
            self.assertEqual(detailed["backend"], BACKEND)
            self.assertEqual(detailed["backend_version"], BACKEND_VERSION)
            self.assertEqual(detailed["policy_version"], NETWORK_GUARD_POLICY_VERSION)
            self.assertTrue(detailed["self_test"]["deny_rules"])
            self.assertTrue(detailed["self_test"]["allow_rules"])
            self.assertEqual(
                detailed["candidate_ids_sha256"],
                detailed["guard_evidence"]["candidate_ids_sha256"],
            )
            self.assertNotEqual(
                detailed["auxiliary_targets_sha256"],
                build_guard_plan(
                    values,
                    shard_index=0,
                    controller_port=19090,
                    runner_networks={"ipv4": [], "ipv6": []},
                    lease_id=TEST_LEASE_ID,
                )["auxiliary_targets_sha256"],
            )
            wrapped = lease.wrap_command(["python3", "-m", "scripts.fake_probe"])
            self.assertEqual(wrapped[:4], ["ip", "netns", "exec", lease.state["names"]["namespace"]])
            self.assertEqual(wrapped[4:], ["python3", "-m", "scripts.fake_probe"])

            reloaded = load_guard_lease(state_path, runner=runner)
            self.assertEqual(reloaded.c2_evidence, lease.c2_evidence)
            reloaded.cleanup()
            cleaned = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(cleaned["phase"], "cleaned")
            self.assertIn(
                ("ip", "netns", "delete", lease.state["names"]["namespace"]),
                runner.commands,
            )

    def test_ipv6_target_fails_before_setup_when_forwarding_is_unavailable(self):
        runner = FakeRunner()
        with self.assertRaisesRegex(LinuxGuardError, "IPv6 forwarding"):
            provision_guard(
                pinned_targets(ipv6=True),
                shard_index=0,
                controller_port=19090,
                runner=runner,
                capabilities=capabilities(ipv6=False),
                runner_networks={"ipv4": [], "ipv6": []},
                lease_id=TEST_LEASE_ID,
            )
        self.assertFalse(any(command[:3] == ("ip", "netns", "add") for command in runner.commands))

    def test_setup_or_self_test_failure_cleans_only_the_owned_lease(self):
        runner = FakeRunner(fail_contains="169.254.169.254/32")
        with self.assertRaisesRegex(LinuxGuardError, "exit code 7"):
            provision_guard(
                pinned_targets(),
                shard_index=1,
                controller_port=19091,
                runner=runner,
                capabilities=capabilities(),
                runner_networks={"ipv4": [], "ipv6": []},
                lease_id=TEST_LEASE_ID,
            )
        namespace = build_guard_plan(
            pinned_targets(),
            shard_index=1,
            controller_port=19091,
            runner_networks={"ipv4": [], "ipv6": []},
            lease_id=TEST_LEASE_ID,
        )["names"]["namespace"]
        self.assertIn(("ip", "netns", "delete", namespace), runner.commands)
        self.assertFalse(any(command[:3] == ("ip", "netns", "list") for command in runner.commands))
        self.assertFalse(any("rm" in command or "del" in command for command in runner.commands))

    def test_tampered_cleanup_plan_is_rejected_without_executing_it(self):
        plan = build_guard_plan(
            pinned_targets(),
            shard_index=3,
            controller_port=19093,
            runner_networks={"ipv4": [], "ipv6": []},
            lease_id=TEST_LEASE_ID,
        )
        plan["phase"] = "active"
        plan["cleanup_commands"] = [["ip", "netns", "delete", "somebody-else"]]
        runner = FakeRunner()
        lease = LinuxGuardLease(plan, None, runner)
        with self.assertRaisesRegex(LinuxGuardError, "exceeds its owned lease"):
            lease.cleanup()
        self.assertEqual(runner.commands, [])

    def test_detailed_evidence_rejects_failed_self_test_and_candidate_drift(self):
        values = pinned_targets()
        lease = provision_guard(
            values,
            shard_index=0,
            controller_port=19090,
            runner=FakeRunner(),
            capabilities=capabilities(),
            runner_networks={"ipv4": [], "ipv6": []},
            lease_id=TEST_LEASE_ID,
        )
        failed = copy.deepcopy(lease.evidence)
        failed["self_test"]["deny_rules"] = False
        with self.assertRaisesRegex(LinuxGuardError, "self-test"):
            validate_linux_guard_evidence(failed, candidate_ids=values.keys())
        with self.assertRaises(Exception):
            validate_linux_guard_evidence(
                lease.evidence, candidate_ids=[candidate_id(99)]
            )
        lease.cleanup()


if __name__ == "__main__":
    unittest.main()
