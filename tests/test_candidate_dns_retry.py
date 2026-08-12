from __future__ import annotations

import socket
import traceback
import unittest
from unittest import mock

from scripts import candidate_sources
from scripts.candidate_sources import (
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

    def test_eai_fail_is_not_retried_or_exposed(self) -> None:
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


if __name__ == "__main__":
    unittest.main()
