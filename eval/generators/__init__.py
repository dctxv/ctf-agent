"""Challenge generators: randomized, isolated, auto-verifiable instances.

Each generator exposes generate(out_dir, seed) -> {"engagement": <dict>, "key": "FLAG{...}"}.
It writes the challenge artifact(s) into out_dir (the trial workspace, which is
mounted into the agent container) and returns the engagement plus the answer.

The key (the answer) is NEVER written into out_dir. The runner records it
host-side, out of the agent's reach, and the verifier checks the agent's evidence
against it by exact match. Because the flag is randomized per instance, these are
generalization probes: the model cannot have memorized the answer. All generated
challenges are file-only (no network in scope).

Categories: crypto (xor_flag), reverse (layered_encoding), forensics (buried_flag).
"""
import hashlib
import random
import string


def make_flag(rng, n=16):
    body = "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(n))
    return "FLAG{" + body + "}"


def seed_int(seed):
    """Stable (process-independent) int seed from any string."""
    return int(hashlib.sha256(str(seed).encode()).hexdigest()[:8], 16)


def base_engagement(name, targets, goal, *, max_steps=15, max_cost=0.3):
    return {
        "engagement_name": name,
        "targets": targets,
        "allowed_hosts": [],            # file-only: nothing is in network scope
        "goal": goal,
        "evidence": {"type": "file_exists", "path": "evidence/flag.txt"},
        "max_steps": max_steps,
        "max_cost_usd": max_cost,
        "cmd_timeout_s": 120,
    }


def get_generator(name):
    from eval.generators import (crypto, crypto_hard, forensics, intercode, nyu,
                                  reverse, reverse_hard)
    gens = {"xor_flag": crypto, "layered_encoding": reverse, "buried_flag": forensics,
            "xor_multibyte": crypto_hard, "chained_decode": reverse_hard,
            "intercode": intercode, "nyu": nyu}
    if name not in gens:
        raise ValueError(f"unknown generator: {name}")
    return gens[name]
