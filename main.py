import json, sys
from dotenv import load_dotenv
from agent.agent import AgentSession

def human_input(question):
    print(f"\n>>> AGENT NEEDS YOU: {question}")
    return input("Your answer: ")

if __name__ == "__main__":
    load_dotenv()
    engagement = json.load(open(sys.argv[1]))
    session = AgentSession(engagement, human_input, auto_learn=True)
    try:
        session.run()
    except KeyboardInterrupt:
        session._emit("session_end", {"summary": "interrupted by human"})
        session._save_artifacts()
    print(f"\nSession cost: ${session.cost_usd:.4f} | steps: {session.steps}")
