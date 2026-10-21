import argparse
import json

from dotenv import load_dotenv

from agent.agent import AgentSession
from agent.privacy import from_engagement


def human_input(question):
    print(f"\n>>> AGENT NEEDS YOU: {question}")
    return input("Your answer: ")


if __name__ == "__main__":
    load_dotenv()
    ap = argparse.ArgumentParser()
    ap.add_argument("engagement", help="path to an engagement JSON file")
    ap.add_argument("--privacy", action="store_true",
                    help="anonymize target identifiers (hosts/IPs/emails) before the model API")
    a = ap.parse_args()
    engagement = json.load(open(a.engagement))
    priv = from_engagement(engagement) if a.privacy else None
    session = AgentSession(engagement, human_input, auto_learn=True, privacy=priv)
    try:
        session.run()
    except KeyboardInterrupt:
        session._emit("session_end", {"summary": "interrupted by human"})
        session._save_artifacts()
    print(f"\nSession cost: ${session.cost_usd:.4f} | steps: {session.steps}")
