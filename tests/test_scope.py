"""Tier A - scope-enforcement safety tests (offline, no Docker, no API).

Run from the repo root:  python -m unittest tests.test_scope -v
"""
import unittest
from unittest import mock

from agent import tools
from agent import net


class TestExtractHosts(unittest.TestCase):
    def test_scheme_url(self):
        self.assertIn("host.docker.internal",
                      tools.extract_hosts("curl http://host.docker.internal:3000/api"))

    def test_scheme_less_not_parsed(self):
        # a scheme-less bare domain yields no host token (the net-tool guard
        # in run_command is what blocks it, not extract_hosts)
        self.assertEqual(tools.extract_hosts("curl example.com"), set())

    def test_decimal_ip_normalized(self):
        self.assertIn("127.0.0.1", tools.extract_hosts("curl http://2130706433/"))

    def test_hex_ip_normalized(self):
        self.assertIn("127.0.0.1", tools.extract_hosts("curl http://0x7f000001/"))

    def test_ipv6_bracketed(self):
        self.assertIn("::1", tools.extract_hosts("curl http://[::1]:8080/"))

    def test_user_at_host(self):
        self.assertIn("evil.com", tools.extract_hosts("ssh root@evil.com"))

    def test_nc_host_port(self):
        self.assertIn("evil.com", tools.extract_hosts("nc evil.com 4444"))

    def test_dotted_ipv4(self):
        self.assertIn("10.0.0.5", tools.extract_hosts("ping 10.0.0.5"))

    def test_creds_and_port_stripped(self):
        self.assertEqual(tools.extract_hosts("curl http://u:p@target.local:8443/x"),
                         {"target.local"})


class TestHostAllowed(unittest.TestCase):
    def test_exact(self):
        self.assertTrue(tools.host_allowed("a.com", ["a.com"]))

    def test_wildcard_sub(self):
        self.assertTrue(tools.host_allowed("x.a.com", ["*.a.com"]))

    def test_wildcard_apex(self):
        self.assertTrue(tools.host_allowed("a.com", ["*.a.com"]))

    def test_deny(self):
        self.assertFalse(tools.host_allowed("evil.com", ["a.com"]))

    def test_empty_allowlist(self):
        self.assertFalse(tools.host_allowed("a.com", []))


ENG = {"allowed_hosts": ["host.docker.internal"]}


class TestRunCommandScope(unittest.TestCase):
    """The block vectors return before any docker exec, so these need no Docker."""

    def _assert_blocked(self, cmd, eng=ENG):
        r = tools.run_command(cmd, eng)
        self.assertTrue(r.startswith("ALLOWLIST BLOCKED"),
                        f"expected a block, got: {r[:140]!r}")

    def test_scheme_less_curl(self):
        self._assert_blocked("curl example.com")

    def test_out_of_scope_url(self):
        self._assert_blocked("curl http://evil.com/")

    def test_decimal_ip(self):
        self._assert_blocked("curl http://2130706433/")

    def test_hex_ip(self):
        self._assert_blocked("wget http://0x7f000001/x")

    def test_ipv6(self):
        self._assert_blocked("curl http://[::1]:8080/")

    def test_shell_variable(self):
        self._assert_blocked("H=evil.com; curl http://$H/")

    def test_command_substitution(self):
        self._assert_blocked("curl http://$(cat /tmp/h)/")

    def test_nc_out_of_scope(self):
        self._assert_blocked("nc evil.com 4444")

    def test_ssh_out_of_scope(self):
        self._assert_blocked("ssh root@evil.com")

    def test_net_tool_empty_allowlist(self):
        self._assert_blocked("curl http://host.docker.internal:3000/",
                             {"allowed_hosts": []})

    @mock.patch("agent.tools.subprocess.run")
    def test_in_scope_allowed(self, mrun):
        mrun.return_value = mock.Mock(returncode=0, stdout="ok", stderr="")
        r = tools.run_command("curl http://host.docker.internal:3000/api", ENG)
        self.assertNotIn("BLOCKED", r)
        self.assertIn("(exit=0)", r)

    @mock.patch("agent.tools.subprocess.run")
    def test_non_network_command_allowed(self, mrun):
        mrun.return_value = mock.Mock(returncode=0, stdout="files", stderr="")
        r = tools.run_command("ls -la /workspace && semgrep --version", ENG)
        self.assertNotIn("BLOCKED", r)


class TestFirewallTamper(unittest.TestCase):
    """The agent must not be able to reconfigure the egress firewall / network
    stack from the command layer. Blocked before any docker exec, so no Docker."""

    def _assert_fw_blocked(self, cmd):
        r = tools.run_command(cmd, ENG)
        self.assertTrue(r.startswith("BLOCKED:") and "network stack" in r,
                        f"expected a firewall-tamper block, got: {r[:140]!r}")

    def test_iptables_flush(self):
        self._assert_fw_blocked("iptables -F OUTPUT")

    def test_iptables_accept_policy(self):
        self._assert_fw_blocked("iptables -P OUTPUT ACCEPT")

    def test_ip6tables(self):
        self._assert_fw_blocked("ip6tables -P OUTPUT ACCEPT")

    def test_nft_flush(self):
        self._assert_fw_blocked("nft flush ruleset")

    def test_absolute_path_nft(self):
        self._assert_fw_blocked("/usr/sbin/nft flush ruleset")

    def test_ip_route_change(self):
        self._assert_fw_blocked("ip route add default via 10.0.0.1")

    def test_ip_link(self):
        self._assert_fw_blocked("ip link set eth0 down")

    def test_chained_tamper(self):
        self._assert_fw_blocked("echo hi && iptables -F")

    @mock.patch("agent.tools.subprocess.run")
    def test_readonly_ip_query_allowed(self, mrun):
        # `ip addr` / `ip a` (read-only) must NOT be blocked; only mutating subcommands are.
        mrun.return_value = mock.Mock(returncode=0, stdout="1: lo", stderr="")
        r = tools.run_command("ip addr show", ENG)
        self.assertNotIn("BLOCKED", r)


class TestNet(unittest.TestCase):
    def test_ruleset_drop_policy(self):
        rs = net.build_nft_ruleset(["93.184.216.34"])
        self.assertIn("policy drop", rs)
        self.assertIn("ip daddr 93.184.216.34 accept", rs)

    def test_ruleset_ipv6(self):
        rs = net.build_nft_ruleset(["::1"])
        self.assertIn("ip6 daddr ::1 accept", rs)

    def test_iptables_fallback(self):
        s = net.build_iptables_script(["10.0.0.1"])
        self.assertIn("iptables -P OUTPUT DROP", s)
        self.assertIn("iptables -A OUTPUT -d 10.0.0.1 -j ACCEPT", s)

    def test_resolve_literal_ip(self):
        r = net.resolve_hosts(["10.0.0.1"])
        self.assertIn("10.0.0.1", r["ips"])

    def test_resolve_wildcard_separated(self):
        r = net.resolve_hosts(["*.example.com"])
        self.assertEqual(r["ips"], [])
        self.assertIn("*.example.com", r["wildcards"])

    def test_resolve_localhost(self):
        r = net.resolve_hosts(["localhost"])
        self.assertTrue(any(ip.startswith("127.") or ip == "::1" for ip in r["ips"]))

    def test_sibling_nft_command_has_netadmin_and_shared_netns(self):
        c = net.sibling_nft_command("evalbox-x", "pentest-tools:latest")
        self.assertIn("--cap-add=NET_ADMIN", c)
        self.assertIn("--network=container:evalbox-x", c)
        self.assertIn("--rm", c)
        self.assertEqual(c[-3:], ["nft", "-f", "-"])

    def test_sibling_iptables_command(self):
        c = net.sibling_iptables_command("evalbox-x", "img", "iptables -F", docker="podman")
        self.assertEqual(c[0], "podman")
        self.assertIn("--cap-add=NET_ADMIN", c)
        self.assertIn("--network=container:evalbox-x", c)
        self.assertEqual(c[-3:], ["sh", "-lc", "iptables -F"])

    def test_apply_requires_image(self):
        # The firewall is applied from a sibling container, so an image is mandatory;
        # without it we must fail loudly rather than silently skip containment.
        with self.assertRaises(ValueError):
            net.apply_egress_firewall("evalbox-x", ["10.0.0.1"])


class TestProvisionNoNetAdmin(unittest.TestCase):
    """The trial container must be created WITHOUT NET_ADMIN (the sibling holds it),
    so the agent inside cannot flush its own egress firewall."""

    def test_default_provision_omits_net_admin(self):
        from eval import runner
        with mock.patch("eval.runner.subprocess.run") as mrun:
            mrun.return_value = mock.Mock(returncode=0, stdout="", stderr="")
            runner._default_provision("evalbox-x", ".", "img", "docker", 60)
        # _default_provision runs `docker rm -f` then `docker run -d ...`; grab the create call
        create = next(ca.args[0] for ca in mrun.call_args_list if "run" in ca.args[0])
        self.assertNotIn("--cap-add=NET_ADMIN", create)


if __name__ == "__main__":
    unittest.main()
