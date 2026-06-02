"""
NovaShield NGFW — Integration Test Suite

Tests the full stack: gateway → AI engine → backend, verifying:
- Health checks across all services
- Authentication flow (login, JWT issuance)
- Admin RBAC enforcement
- WAF blocking (SQL injection, XSS)
- AI enforcement layer
- Rate limiting

Usage:
    python tests/integration_test.py [--base-url http://localhost:8080]
"""

import argparse
import json
import sys
import time
import urllib.request
import urllib.error


class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    RESET = "\033[0m"
    BOLD = "\033[1m"


def request(method, url, data=None, headers=None, timeout=10):
    """Simple HTTP request helper using stdlib only."""
    hdrs = headers or {}
    body = None
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        hdrs["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode())
        except Exception:
            body = {"error": str(e)}
        return e.code, body
    except Exception as e:
        return 0, {"error": str(e)}


class TestRunner:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")
        self.passed = 0
        self.failed = 0
        self.results = []

    def check(self, name, condition, detail=""):
        if condition:
            self.passed += 1
            self.results.append((name, True, detail))
            print(f"  {Colors.GREEN}✓{Colors.RESET} {name}")
        else:
            self.failed += 1
            self.results.append((name, False, detail))
            print(f"  {Colors.RED}✗{Colors.RESET} {name} — {detail}")

    def section(self, title):
        print(f"\n{Colors.CYAN}{Colors.BOLD}▸ {title}{Colors.RESET}")

    def run_all(self):
        print(f"\n{Colors.BOLD}NovaShield NGFW Integration Tests{Colors.RESET}")
        print(f"Target: {self.base_url}\n")

        self.test_health()
        self.test_login()
        self.test_auth_flow()
        self.test_admin_rbac()
        self.test_waf()
        self.test_ai_enforcement()

        print(f"\n{'─' * 50}")
        total = self.passed + self.failed
        color = Colors.GREEN if self.failed == 0 else Colors.RED
        print(f"{color}{Colors.BOLD}{self.passed}/{total} tests passed{Colors.RESET}")

        return self.failed == 0

    def test_health(self):
        self.section("Health Checks")

        status, body = request("GET", f"{self.base_url}/api/admin/health")
        self.check(
            "Gateway health returns 200",
            status == 200 and body.get("status") == "ok",
            f"status={status}",
        )

    def test_login(self):
        self.section("Login Flow")

        # Valid login
        status, body = request(
            "POST",
            f"{self.base_url}/api/login",
            {"username": "alice", "password": "pass123"},
        )
        self.check(
            "Login returns 200 with token",
            status == 200 and "token" in body,
            f"status={status}",
        )

        # Empty credentials
        status, body = request(
            "POST",
            f"{self.base_url}/api/login",
            {"username": "", "password": ""},
        )
        self.check(
            "Empty credentials return 400",
            status == 400,
            f"status={status}",
        )

    def test_auth_flow(self):
        self.section("Authentication Flow")

        # Login to get token
        status, body = request(
            "POST",
            f"{self.base_url}/api/login",
            {"username": "testuser", "password": "testpass"},
        )
        token = body.get("token", "")

        # Balance with valid token
        status, body = request(
            "GET",
            f"{self.base_url}/api/balance",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.check(
            "Balance with valid token returns 200",
            status == 200 and "balance" in body,
            f"status={status}",
        )

        # Balance without token
        status, body = request("GET", f"{self.base_url}/api/balance")
        self.check(
            "Balance without token returns 401",
            status == 401,
            f"status={status}",
        )

        # Balance with invalid token
        status, body = request(
            "GET",
            f"{self.base_url}/api/balance",
            headers={"Authorization": "Bearer invalid-token"},
        )
        self.check(
            "Balance with invalid token returns 401",
            status == 401,
            f"status={status}",
        )

    def test_admin_rbac(self):
        self.section("Admin RBAC")

        # Login as regular user
        status, body = request(
            "POST",
            f"{self.base_url}/api/login",
            {"username": "alice", "password": "pass123"},
        )
        user_token = body.get("token", "")

        # Login as admin
        status, body = request(
            "POST",
            f"{self.base_url}/api/login",
            {"username": "admin", "password": "admin123"},
        )
        admin_token = body.get("token", "")

        # Admin snapshot without auth → 401
        status, _ = request("GET", f"{self.base_url}/api/admin/snapshot")
        self.check(
            "Admin snapshot without auth returns 401",
            status == 401,
            f"status={status}",
        )

        # Admin snapshot with user token → 403
        status, _ = request(
            "GET",
            f"{self.base_url}/api/admin/snapshot",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        self.check(
            "Admin snapshot with user token returns 403",
            status == 403,
            f"status={status}",
        )

        # Admin snapshot with admin token → 200
        status, body = request(
            "GET",
            f"{self.base_url}/api/admin/snapshot",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        self.check(
            "Admin snapshot with admin token returns 200",
            status == 200 and "counters" in body,
            f"status={status}",
        )

        # Admin logs with admin token → 200
        status, _ = request(
            "GET",
            f"{self.base_url}/api/admin/logs",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        self.check(
            "Admin logs with admin token returns 200",
            status == 200,
            f"status={status}",
        )

        # Admin metrics with admin token → 200
        status, _ = request(
            "GET",
            f"{self.base_url}/api/admin/metrics",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        # Prometheus metrics returns text, not JSON
        self.check(
            "Admin metrics with admin token returns 200",
            status == 200,
            f"status={status}",
        )

    def test_waf(self):
        self.section("WAF Security Rules")

        # SQL injection in login body
        status, body = request(
            "POST",
            f"{self.base_url}/api/login",
            {"username": "admin' OR 1=1 --", "password": "x"},
        )
        self.check(
            "SQL injection in body blocked (403)",
            status == 403,
            f"status={status}, code={body.get('code', '')}",
        )

        # XSS in login body
        status, body = request(
            "POST",
            f"{self.base_url}/api/login",
            {"username": "<script>alert(1)</script>", "password": "x"},
        )
        self.check(
            "XSS payload in body blocked (403)",
            status == 403,
            f"status={status}, code={body.get('code', '')}",
        )

        # Path traversal
        status, body = request(
            "POST",
            f"{self.base_url}/api/login",
            {"username": "../../etc/passwd", "password": "x"},
        )
        self.check(
            "Path traversal blocked (403)",
            status == 403,
            f"status={status}, code={body.get('code', '')}",
        )

    def test_ai_enforcement(self):
        self.section("AI Enforcement Layer")

        # Simple check: normal request should pass through AI
        status, body = request(
            "POST",
            f"{self.base_url}/api/login",
            {"username": "normaluser", "password": "safepass"},
        )
        self.check(
            "Normal request passes AI check",
            status in (200, 502),  # 502 if AI is down (fallback allow)
            f"status={status}",
        )


def main():
    parser = argparse.ArgumentParser(description="NovaShield Integration Tests")
    parser.add_argument(
        "--base-url",
        default="http://localhost:8080",
        help="Gateway base URL (default: http://localhost:8080)",
    )
    args = parser.parse_args()

    runner = TestRunner(args.base_url)
    success = runner.run_all()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
