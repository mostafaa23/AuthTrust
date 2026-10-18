import asyncio
import unittest

from wily.api_discovery import DiscoveryReport
from wily.bola_tester import (
    BolaTester,
    Identity,
    ReplaySample,
    _PublicOnlyResolver,
    _redact_url,
    _sample_contains_auth_material,
    _url_in_scope,
    compare,
)


class BolaComparisonTests(unittest.TestCase):
    def sample(self, status, body):
        return ReplaySample(
            status=status,
            length=len(body.encode()),
            content_type="application/json",
            body_snippet=body,
            elapsed_ms=1.0,
        )

    def test_same_owner_specific_data_can_reach_high(self):
        body = '{"id":"order_123456789","tenant_id":"tenant_alpha_123","email":"alice@example.test","state":"active"}'
        verdict, similarity, notes = compare(
            self.sample(200, body), self.sample(200, body), grounded=True
        )
        self.assertEqual(verdict, "HIGH")
        self.assertEqual(similarity, 1.0)
        self.assertTrue(any("identity-specific JSON value overlap 100%" in n for n in notes))

    def test_same_json_shape_different_tenant_data_is_not_high(self):
        owner = '{"id":"order_alpha_12345","tenant_id":"tenant_alpha_123","email":"alice@example.test","state":"active"}'
        other = '{"id":"order_bravo_67890","tenant_id":"tenant_bravo_678","email":"bob@example.test","state":"active"}'
        verdict, similarity, notes = compare(
            self.sample(200, owner), self.sample(200, other), grounded=True
        )
        self.assertNotEqual(verdict, "HIGH")
        self.assertEqual(similarity, 1.0)
        self.assertTrue(any("identity-specific JSON value overlap" in n for n in notes))

    def test_403_is_not_a_bola_finding(self):
        verdict, _, _ = compare(self.sample(200, '{"id":"abc123456789"}'), self.sample(403, '{"error":"forbidden"}'), grounded=True)
        self.assertEqual(verdict, "NONE")

    def test_unowned_endpoint_is_never_high(self):
        body = '{"id":"order_123456789","tenant_id":"tenant_alpha_123"}'
        verdict, _, _ = compare(self.sample(200, body), self.sample(200, body), grounded=False)
        self.assertEqual(verdict, "MEDIUM")


class BolaCandidateTests(unittest.TestCase):
    def setUp(self):
        self.identities = [
            Identity("alice", {"Authorization": "Bearer alice-secret"}),
            Identity("bob", {"Authorization": "Bearer bob-secret"}),
        ]

    def test_query_parameter_candidate_requires_observed_concrete_request(self):
        report = DiscoveryReport(target="https://example.com")
        report.add_endpoint(
            "https://example.com/api/orders",
            source="user_spec",
            methods={"GET"},
            details={"bola_candidate": True, "id_like_query_params": ["tenant_id"]},
        )
        self.assertEqual(BolaTester(self.identities).candidates(report), [])

    def test_captured_query_candidate_is_replayable(self):
        report = DiscoveryReport(target="https://example.com")
        report.add_endpoint(
            "https://example.com/api/orders",
            source="traffic_monitoring",
            methods={"GET"},
            details={
                "bola_candidate": True,
                "owner_identity": "alice",
                "id_like_query_params": ["tenant_id"],
            },
            replay_sample={
                "method": "GET",
                "url": "https://example.com/api/orders?tenant_id=alpha-12345",
                "body": None,
                "content_type": None,
            },
        )
        candidates = BolaTester(self.identities).candidates(report)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0][1], "GET")
        self.assertEqual(len(report.endpoints[next(iter(report.endpoints))].replay_samples), 1)
        # Concrete request details are for runtime use and must not leak into JSON.
        self.assertNotIn("alpha-12345", str(report.to_json()))

    def test_external_host_is_not_a_bola_candidate(self):
        report = DiscoveryReport(target="https://example.com")
        report.add_endpoint(
            "https://evil.example.net/api/orders/123",
            source="user_spec",
            methods={"GET"},
            details={"bola_candidate": True, "path_param_positions": [2]},
        )
        self.assertEqual(BolaTester(self.identities).candidates(report), [])

    def test_post_candidate_requires_opt_in_and_observed_body(self):
        report = DiscoveryReport(target="https://example.com")
        report.add_endpoint(
            "https://example.com/api/orders",
            source="traffic_monitoring",
            methods={"POST"},
            details={
                "bola_candidate": True,
                "id_like_body_params": ["tenant_id"],
            },
            replay_sample={
                "method": "POST",
                "url": "https://example.com/api/orders",
                "body": '{"tenant_id":"tenant_alpha_123"}',
                "content_type": "application/json",
            },
        )
        self.assertEqual(BolaTester(self.identities).candidates(report), [])
        self.assertEqual(len(BolaTester(self.identities, allow_destructive=True).candidates(report)), 1)


class SafetyTests(unittest.TestCase):
    def test_scope_allows_target_and_subdomains_only(self):
        self.assertTrue(_url_in_scope("https://api.example.com/v1", "https://example.com"))
        self.assertTrue(_url_in_scope("https://example.com/v1", "https://www.example.com"))
        self.assertFalse(_url_in_scope("https://example.net/v1", "https://example.com"))
        self.assertFalse(_url_in_scope("https://example.com.attacker.net/v1", "https://example.com"))
        self.assertFalse(_url_in_scope("http://example.com/v1", "https://example.com"))
        self.assertFalse(_url_in_scope("https://user:pass@example.com/v1", "https://example.com"))
        self.assertTrue(_url_in_scope("https://203.0.113.7/v1", "https://203.0.113.7"))
        self.assertFalse(_url_in_scope("https://evil.203.0.113.7/v1", "https://203.0.113.7"))

    def test_secret_query_values_are_redacted(self):
        redacted = _redact_url("https://example.com/api?tenant_id=tenant123&access_token=topsecret")
        self.assertIn("tenant123", redacted)
        self.assertNotIn("topsecret", redacted)
        self.assertIn("REDACTED", redacted)
        private_key_redacted = _redact_url("https://example.com/api?private_key=topsecret")
        self.assertNotIn("topsecret", private_key_redacted)

    def test_captured_query_or_body_credentials_are_not_replayed(self):
        self.assertTrue(_sample_contains_auth_material({
            "url": "https://example.com/api?tenant_id=123&access_token=alice-token",
            "body": None,
        }))
        self.assertTrue(_sample_contains_auth_material({
            "url": "https://example.com/api",
            "body": '{"tenant_id":"123","refresh_token":"alice-token"}',
        }))
        self.assertFalse(_sample_contains_auth_material({
            "url": "https://example.com/api?tenant_id=tenant123",
            "body": '{"tenant_id":"tenant123"}',
        }))

    def test_resolver_rejects_loopback(self):
        async def run():
            with self.assertRaises(OSError):
                await _PublicOnlyResolver().resolve("127.0.0.1", 443)
        asyncio.run(run())


class _FakeContent:
    async def read(self, _limit):
        return b'{"ok":true}'


class _FakeResponse:
    status = 200
    headers = {"Content-Type": "application/json", "Content-Length": "11"}
    content = _FakeContent()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False


class _FakeSession:
    def __init__(self):
        self.kwargs = None

    def request(self, *args, **kwargs):
        self.kwargs = {"args": args, **kwargs}
        return _FakeResponse()


class ReplayRequestTests(unittest.IsolatedAsyncioTestCase):

    async def test_body_is_replayed_with_content_type_and_redirects_disabled(self):
        tester = BolaTester([
            Identity("alice", {"Authorization": "Bearer alice"}),
            Identity("bob", {"Authorization": "Bearer bob"}),
        ], rate_limit=0)
        fake = _FakeSession()
        tester._session = fake
        tester._scope_target = "https://example.com"
        sample = {
            "method": "POST",
            "url": "https://example.com/api/orders",
            "body": '{"tenant_id":"tenant_alpha_123"}',
            "content_type": "application/json",
        }
        result = await tester._replay(sample["url"], "POST", tester.identities[1], sample)
        self.assertEqual(result.status, 200)
        self.assertEqual(fake.kwargs["data"], sample["body"])
        self.assertEqual(fake.kwargs["headers"]["Content-Type"], "application/json")
        self.assertFalse(fake.kwargs["allow_redirects"])

    def test_curl_output_redacts_auth_headers(self):
        identity = Identity("alice", {
            "Authorization": "Bearer super-secret-token",
            "Cookie": "session=super-secret-cookie",
            "X-Tenant-ID": "tenant-123",
        })
        command = BolaTester._curl(
            "https://example.com/api?tenant_id=tenant-123&access_token=super-secret-query",
            "GET", identity,
        )
        self.assertNotIn("super-secret-token", command)
        self.assertNotIn("super-secret-cookie", command)
        self.assertNotIn("super-secret-query", command)
        self.assertIn("tenant-123", command)
        post_command = BolaTester._curl(
            "https://example.com/api/orders", "POST", identity,
            {"body": '{"tenant_id":"tenant-123","password":"body-secret"}'},
        )
        self.assertIn("tenant-123", post_command)
        self.assertNotIn("body-secret", post_command)


if __name__ == "__main__":
    unittest.main()
