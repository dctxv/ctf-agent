"""Network-level egress enforcement for evaluation trial containers.

tools.py enforces scope at the command layer (best-effort, defense in depth).
The authoritative boundary is here: a default-drop egress firewall that permits
outbound traffic ONLY to the resolved in-scope hosts (plus loopback, established
flows, and DNS). It is applied by the evaluation runner to ephemeral trial
containers; it is deliberately NOT applied to the operator's long-lived
agent-box, whose scope stays enforced at the command layer.

Resistance to agent modification. The trial container itself runs WITHOUT
NET_ADMIN, so the agent inside it cannot flush or relax its own egress rules.
The rules are installed by an ephemeral SIBLING container that joins the trial
container's network namespace (`--network=container:<trial>`), holds NET_ADMIN
just long enough to write the ruleset, and then exits. nftables/iptables state
is per-netns, so the rules persist after the sibling is gone while the trial
container, lacking the capability, cannot alter them. (The earlier design gave
the trial container NET_ADMIN directly, which left the agent able to tear down
the firewall; this sibling model closes that gap.)

Wildcard allowlist entries ('*.example.com') cannot be pre-resolved to a fixed
IP set and are reported separately for future proxy-based handling; a trial
whose scope is purely wildcard cannot be IP-firewalled by this module alone.
"""
import ipaddress
import socket
import subprocess


def resolve_hosts(allowed_hosts):
    """Resolve allowlist entries to IPs on the host. Literal IPs pass through;
    hostnames are resolved (A/AAAA); wildcards and failures are reported apart.
    (The runner resolves inside the container instead - see _resolve_in_container
    - so Docker-internal names map correctly; this host-side form is for tests
    and planning.)"""
    ips, wildcards, unresolved = set(), [], []
    for h in allowed_hosts or []:
        h = (h or "").strip().lower()
        if not h:
            continue
        if h.startswith("*."):
            wildcards.append(h)
            continue
        try:
            ipaddress.ip_address(h)
            ips.add(h)
            continue
        except ValueError:
            pass
        try:
            for _fam, _t, _p, _c, sa in socket.getaddrinfo(h, None):
                ips.add(sa[0])
        except socket.gaierror:
            unresolved.append(h)
    return {"ips": sorted(ips), "wildcards": wildcards, "unresolved": unresolved}


def build_nft_ruleset(ips, *, allow_dns=True):
    """nftables script: default-drop egress, allow loopback, established/related,
    optional DNS, and each allowlisted IP."""
    lines = [
        "flush ruleset",
        "table inet egress {",
        "  chain output {",
        "    type filter hook output priority 0; policy drop;",
        '    oifname "lo" accept',
        "    ct state established,related accept",
    ]
    if allow_dns:
        lines += ["    udp dport 53 accept", "    tcp dport 53 accept"]
    for ip in ips:
        fam = "ip6" if ":" in ip else "ip"
        lines.append(f"    {fam} daddr {ip} accept")
    lines += ["  }", "}"]
    return "\n".join(lines) + "\n"


def build_iptables_script(ips, *, allow_dns=True):
    """Fallback for images without nftables: equivalent iptables/ip6tables rules
    as a single bash-joined command string."""
    c = ["iptables -F OUTPUT", "iptables -P OUTPUT DROP",
         "iptables -A OUTPUT -o lo -j ACCEPT",
         "iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT"]
    c6 = ["ip6tables -F OUTPUT", "ip6tables -P OUTPUT DROP",
          "ip6tables -A OUTPUT -o lo -j ACCEPT",
          "ip6tables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT"]
    if allow_dns:
        for proto in ("udp", "tcp"):
            c.append(f"iptables -A OUTPUT -p {proto} --dport 53 -j ACCEPT")
            c6.append(f"ip6tables -A OUTPUT -p {proto} --dport 53 -j ACCEPT")
    for ip in ips:
        if ":" in ip:
            c6.append(f"ip6tables -A OUTPUT -d {ip} -j ACCEPT")
        else:
            c.append(f"iptables -A OUTPUT -d {ip} -j ACCEPT")
    return " ; ".join(c + c6)


def sibling_nft_command(container, image, *, docker="docker"):
    """Command that applies the nftables ruleset (fed on stdin) from an ephemeral
    sibling that shares `container`'s network namespace and holds NET_ADMIN, then
    exits. `container` itself has no NET_ADMIN, so the agent cannot alter the rules."""
    return [docker, "run", "--rm", "-i", "--cap-add=NET_ADMIN",
            f"--network=container:{container}", image, "nft", "-f", "-"]


def sibling_iptables_command(container, image, script, *, docker="docker"):
    """iptables fallback, same sibling model as sibling_nft_command."""
    return [docker, "run", "--rm", "--cap-add=NET_ADMIN",
            f"--network=container:{container}", image, "sh", "-lc", script]


def _resolve_in_container(container, allowed_hosts, docker="docker"):
    """Resolve names from INSIDE the container so Docker-internal names (e.g.
    host.docker.internal) map to the right gateway IP."""
    ips, wildcards, unresolved = set(), [], []
    for h in allowed_hosts or []:
        h = (h or "").strip().lower()
        if not h:
            continue
        if h.startswith("*."):
            wildcards.append(h)
            continue
        try:
            ipaddress.ip_address(h)
            ips.add(h)
            continue
        except ValueError:
            pass
        r = subprocess.run([docker, "exec", container, "getent", "ahosts", h],
                           capture_output=True, text=True, timeout=20)
        found = False
        for line in (r.stdout or "").splitlines():
            parts = line.split()
            if not parts:
                continue
            try:
                ipaddress.ip_address(parts[0])
                ips.add(parts[0])
                found = True
            except ValueError:
                pass
        if not found:
            unresolved.append(h)
    return {"ips": sorted(ips), "wildcards": wildcards, "unresolved": unresolved}


def apply_egress_firewall(container, allowed_hosts, *, docker="docker", image=None):
    """Install the default-drop egress firewall on `container`'s network namespace
    from an ephemeral NET_ADMIN sibling (see module docstring). `container` runs
    WITHOUT NET_ADMIN; `image` is the firewall-capable image (nftables/iptables
    installed) the sibling runs - normally the same toolbox image as the trial.
    Tries nftables, falls back to iptables. Returns (resolved_dict, backend_name)."""
    if not image:
        raise ValueError(
            "apply_egress_firewall requires `image`: the firewall is applied from a "
            "sibling container so the trial container needs no NET_ADMIN of its own.")
    resolved = _resolve_in_container(container, allowed_hosts, docker=docker)
    ruleset = build_nft_ruleset(resolved["ips"])
    p = subprocess.run(sibling_nft_command(container, image, docker=docker),
                       input=ruleset, capture_output=True, text=True, timeout=60)
    if p.returncode == 0:
        return resolved, "nft"
    script = build_iptables_script(resolved["ips"])
    p2 = subprocess.run(sibling_iptables_command(container, image, script, docker=docker),
                        capture_output=True, text=True, timeout=60)
    if p2.returncode == 0:
        return resolved, "iptables"
    raise RuntimeError(
        f"egress firewall apply failed: nft={(p.stderr or '').strip()[:150]} | "
        f"iptables={(p2.stderr or '').strip()[:150]}")
