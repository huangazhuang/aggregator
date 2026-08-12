from __future__ import annotations

import socket
import traceback
import unittest
from unittest import mock

from scripts import candidate_sources
from scripts.candidate_sources import (
    CandidateDnsResolutionSession,
    EndpointResolutionCandidateError,
    EndpointResolutionInfrastructureError,
    EndpointSafetyError,
    validate_proxy_endpoint,
)


def proxy(server: str, password: str) -> dict:
    return {
        "name": "JP candidate",
        "type": "ss",
        "server": server,
        "port": 443,
        "cipher": "aes-128-gcm",
        "password": password,
    }


def public_answer(_host: str, port: int, *, type: int) -> list[tuple]:
    return [(socket.AF_INET, type, socket.IPPROTO_TCP, "", ("8.8.8.8", port))]


class CandidateDefaultResolverRetryTests(unittest.TestCase):
    def test_validate_uses_the_default_resolver_retry_policy(self) -> None:
        calls = 0

        def getaddrinfo(host: str, port: int, *, type: int) -> list[tuple]:
            nonlocal calls
            calls += 1
            self.assertEqual((host, port, type), ("wired.example", 443, socket.SOCK_STREAM))
            if calls <= 2:
                raise socket.gaierror(socket.EAI_AGAIN, "temporary resolver failure")
            return public_answer(host, port, type=type)

        with mock.patch.object(
            candidate_sources.socket,
            "getaddrinfo",
            side_effect=getaddrinfo,
        ), mock.patch.object(candidate_sources.time, "sleep") as sleep:
            result = validate_proxy_endpoint(proxy("wired.example", "safe-credential"))

        self.assertEqual(result["resolved_address_count"], 1)
        self.assertEqual(calls, 3)
        self.assertEqual([item.args[0] for item in sleep.call_args_list], [0.25, 1.0])

    def test_recovers_after_two_transient_resolution_failures(self) -> None:
        calls = 0
        sleeps: list[float] = []

        def getaddrinfo(host: str, port: int, *, type: int) -> list[tuple]:
            nonlocal calls
            calls += 1
            self.assertEqual((host, port, type), ("recover.example", 443, socket.SOCK_STREAM))
            if calls <= 2:
                raise socket.gaierror(socket.EAI_AGAIN, "temporary resolver failure")
            return public_answer(host, port, type=type)

        addresses = candidate_sources._default_resolver(
            "recover.example",
            443,
            getaddrinfo=getaddrinfo,
            sleeper=sleeps.append,
        )

        self.assertEqual(addresses, ["8.8.8.8"])
        self.assertEqual(calls, 3)
        self.assertEqual(sleeps, [0.25, 1.0])

    def test_four_transient_failures_are_exhausted_and_sanitized(self) -> None:
        hostname = "credential-host-token.example"
        credential = "PROXY-CREDENTIAL-SECRET"
        calls = 0
        sleeps: list[float] = []

        def getaddrinfo(_host: str, _port: int, *, type: int) -> list[tuple]:
            nonlocal calls
            calls += 1
            self.assertEqual(type, socket.SOCK_STREAM)
            raise socket.gaierror(
                socket.EAI_AGAIN,
                f"temporary resolver failure for {hostname} {credential}",
            )

        def resolver(host: str, port: int) -> list[str]:
            return candidate_sources._default_resolver(
                host,
                port,
                getaddrinfo=getaddrinfo,
                sleeper=sleeps.append,
            )

        with self.assertRaises(EndpointResolutionInfrastructureError) as raised:
            validate_proxy_endpoint(proxy(hostname, credential), resolver=resolver)

        rendered = "".join(traceback.format_exception(raised.exception))
        self.assertEqual(calls, 4)
        self.assertEqual(sleeps, [0.25, 1.0, 2.0])
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
        self.assertNotIn(hostname, rendered)
        self.assertNotIn(credential, rendered)
        self.assertEqual(
            str(raised.exception),
            "proxy endpoint DNS infrastructure failed",
        )


class CandidateDnsResolutionSessionTests(unittest.TestCase):
    CANARIES = {"example.com", "one.one.one.one", "dns.google"}

    def resolver_for(
        self,
        failed_hosts: set[str],
        *,
        failed_canaries: set[str] | None = None,
        calls: dict[str, int] | None = None,
    ):
        failed_canaries = failed_canaries or set()

        def resolver(host: str, _port: int) -> list[str]:
            if calls is not None:
                calls[host] = calls.get(host, 0) + 1
            if host in failed_hosts or host in failed_canaries:
                raise socket.gaierror(socket.EAI_AGAIN, "private resolver text")
            return ["8.8.8.8"]

        return resolver

    def test_isolated_persistent_target_is_candidate_failure_with_two_of_three_canaries(self) -> None:
        sleeps: list[float] = []
        calls: dict[str, int] = {}
        session = CandidateDnsResolutionSession(
            expected_domain_hostnames=100,
            resolver=self.resolver_for(
                {"isolated.example"},
                failed_canaries={"dns.google"},
                calls=calls,
            ),
            sleeper=sleeps.append,
        )

        with self.assertRaises(EndpointResolutionCandidateError):
            session.resolve("isolated.example", 443)
        session.finalize()

        self.assertEqual(sleeps, [5.0])
        self.assertEqual(calls["isolated.example"], 2)
        self.assertEqual(sum(calls.get(host, 0) for host in self.CANARIES), 6)

    def test_two_failed_canaries_make_the_target_an_infrastructure_failure(self) -> None:
        session = CandidateDnsResolutionSession(
            expected_domain_hostnames=100,
            resolver=self.resolver_for(
                {"isolated.example"},
                failed_canaries={"dns.google", "example.com"},
            ),
            sleeper=lambda _delay: None,
        )
        with self.assertRaises(EndpointResolutionInfrastructureError):
            session.resolve("isolated.example", 443)

    def test_same_hostname_different_ports_resolves_once(self) -> None:
        calls: dict[str, int] = {}
        session = CandidateDnsResolutionSession(
            expected_domain_hostnames=1,
            resolver=self.resolver_for(set(), calls=calls),
            sleeper=lambda _delay: None,
        )
        self.assertEqual(session.resolve("shared.example", 443), ["8.8.8.8"])
        self.assertEqual(session.resolve("shared.example", 8443), ["8.8.8.8"])
        self.assertEqual(calls, {"shared.example": 1})

    def test_target_recovery_after_canary_check_is_retained(self) -> None:
        calls: dict[str, int] = {}

        def resolver(host: str, _port: int) -> list[str]:
            calls[host] = calls.get(host, 0) + 1
            if host == "recover-later.example" and calls[host] == 1:
                raise socket.gaierror(socket.EAI_FAIL, "sensitive target detail")
            return ["8.8.8.8"]

        session = CandidateDnsResolutionSession(
            expected_domain_hostnames=100,
            resolver=resolver,
            sleeper=lambda _delay: None,
        )
        self.assertEqual(session.resolve("recover-later.example", 443), ["8.8.8.8"])
        session.finalize()
        self.assertEqual(calls["recover-later.example"], 2)
        self.assertEqual(sum(calls.get(host, 0) for host in self.CANARIES), 3)

    def test_definitive_and_private_answers_do_not_run_canaries(self) -> None:
        calls: dict[str, int] = {}

        def definitive(host: str, _port: int) -> list[str]:
            calls[host] = calls.get(host, 0) + 1
            raise socket.gaierror(socket.EAI_NONAME, "secret hostname detail")

        session = CandidateDnsResolutionSession(
            expected_domain_hostnames=1,
            resolver=definitive,
            sleeper=lambda _delay: None,
        )
        with self.assertRaises(socket.gaierror):
            session.resolve("missing.example", 443)
        self.assertEqual(calls, {"missing.example": 1})

        private_calls: dict[str, int] = {}

        def private_answer(host: str, _port: int) -> list[str]:
            private_calls[host] = private_calls.get(host, 0) + 1
            return ["10.0.0.1"]

        private_session = CandidateDnsResolutionSession(
            expected_domain_hostnames=1,
            resolver=private_answer,
            sleeper=lambda _delay: None,
        )
        with self.assertRaises(EndpointSafetyError):
            validate_proxy_endpoint(
                proxy("private-answer.example", "private-secret"),
                resolver=private_session.resolve,
            )
        self.assertEqual(private_calls, {"private-answer.example": 1})

    def test_failure_ratio_boundaries_are_exact(self) -> None:
        for expected, allowed, rejected in ((100, 2, 3), (150, 3, 4), (1000, 20, 21)):
            with self.subTest(expected=expected):
                failed = {f"bad-{index}.example" for index in range(rejected)}
                session = CandidateDnsResolutionSession(
                    expected_domain_hostnames=expected,
                    resolver=self.resolver_for(failed),
                    sleeper=lambda _delay: None,
                )
                for index in range(allowed):
                    with self.assertRaises(EndpointResolutionCandidateError):
                        session.resolve(f"bad-{index}.example", 443)
                with self.assertRaises(EndpointResolutionInfrastructureError):
                    session.resolve(f"bad-{allowed}.example", 443)

    def test_definitive_dns_failure_is_not_retried_or_slept(self) -> None:
        hostname = "private-hostname-token.example"
        credential = "PRIVATE-PROXY-CREDENTIAL"
        calls = 0
        sleeps: list[float] = []

        def getaddrinfo(_host: str, _port: int, *, type: int) -> list[tuple]:
            nonlocal calls
            calls += 1
            self.assertEqual(type, socket.SOCK_STREAM)
            raise socket.gaierror(
                socket.EAI_NONAME,
                f"not found: {hostname} {credential}",
            )

        def resolver(host: str, port: int) -> list[str]:
            return candidate_sources._default_resolver(
                host,
                port,
                getaddrinfo=getaddrinfo,
                sleeper=sleeps.append,
            )

        with self.assertRaises(EndpointSafetyError) as raised:
            validate_proxy_endpoint(proxy(hostname, credential), resolver=resolver)

        rendered = "".join(traceback.format_exception(raised.exception))
        self.assertEqual(calls, 1)
        self.assertEqual(sleeps, [])
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
        self.assertNotIn(hostname, rendered)
        self.assertNotIn(credential, rendered)
        self.assertEqual(str(raised.exception), "proxy endpoint DNS resolution failed")

    def test_non_dns_exception_is_not_retried_or_exposed(self) -> None:
        hostname = "exception-host-token.example"
        credential = "EXCEPTION-CREDENTIAL-SECRET"
        calls = 0
        sleeps: list[float] = []

        def getaddrinfo(_host: str, _port: int, *, type: int) -> list[tuple]:
            nonlocal calls
            calls += 1
            self.assertEqual(type, socket.SOCK_STREAM)
            raise OSError(f"resolver failed for {hostname} {credential}")

        def resolver(host: str, port: int) -> list[str]:
            return candidate_sources._default_resolver(
                host,
                port,
                getaddrinfo=getaddrinfo,
                sleeper=sleeps.append,
            )

        with self.assertRaises(EndpointResolutionInfrastructureError) as raised:
            validate_proxy_endpoint(proxy(hostname, credential), resolver=resolver)

        rendered = "".join(traceback.format_exception(raised.exception))
        self.assertEqual(calls, 1)
        self.assertEqual(sleeps, [])
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
        self.assertNotIn(hostname, rendered)
        self.assertNotIn(credential, rendered)
        self.assertEqual(
            str(raised.exception),
            "proxy endpoint DNS infrastructure failed",
        )

    def test_eai_fail_uses_the_same_bounded_retry_and_is_not_exposed(self) -> None:
        hostname = "failed-host-token.example"
        credential = "FAILED-CREDENTIAL-SECRET"
        calls = 0
        sleeps: list[float] = []

        def getaddrinfo(_host: str, _port: int, *, type: int) -> list[tuple]:
            nonlocal calls
            calls += 1
            self.assertEqual(type, socket.SOCK_STREAM)
            raise socket.gaierror(
                socket.EAI_FAIL,
                f"resolver refused {hostname} {credential}",
            )

        def resolver(host: str, port: int) -> list[str]:
            return candidate_sources._default_resolver(
                host,
                port,
                getaddrinfo=getaddrinfo,
                sleeper=sleeps.append,
            )

        with self.assertRaises(EndpointResolutionInfrastructureError) as raised:
            validate_proxy_endpoint(proxy(hostname, credential), resolver=resolver)

        rendered = "".join(traceback.format_exception(raised.exception))
        self.assertEqual(calls, 4)
        self.assertEqual(sleeps, [0.25, 1.0, 2.0])
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
        self.assertNotIn(hostname, rendered)
        self.assertNotIn(credential, rendered)
        self.assertEqual(
            str(raised.exception),
            "proxy endpoint DNS infrastructure failed",
        )


if __name__ == "__main__":
    unittest.main()
