import sys
from main import analyze_action, ActionRequest

def check(content, action_type="run_command", source="cli"):
    req = ActionRequest(action_type=action_type, content=content, source=source)
    return analyze_action(req)

def print_result(result):
    print("\n🛡️  AgentShield — Runtime Check")
    print("-" * 44)
    print(f"Action Type : {result['action_type']}")
    print(f"Payload     : {result['content']}")
    print(f"Source      : {result['source']}")
    print(f"Risk Score  : {result['risk_score']}/100")
    print(f"Threat Type : {result['threat_type']}")
    print(f"VERDICT     : {result['verdict']}")
    print("Reasons:")
    for r in result['reasons']:
        print(f"   - {r}")
    print("-" * 44 + "\n")

def interactive_mode():
    print("AgentShield CLI — interactive mode. Type an action, or 'exit' to quit.\n")
    while True:
        try:
            content = input("agent> ")
        except (EOFError, KeyboardInterrupt):
            break
        if content.strip().lower() in ("exit", "quit"):
            break
        if not content.strip():
            continue
        result = check(content)
        print_result(result)

def main():
    if len(sys.argv) > 1:
        content = sys.argv[1]
        action_type = sys.argv[2] if len(sys.argv) > 2 else "run_command"
        source = sys.argv[3] if len(sys.argv) > 3 else "cli"
        print_result(check(content, action_type, source))
    elif not sys.stdin.isatty():
        for line in sys.stdin:
            line = line.strip()
            if line:
                print_result(check(line))
    else:
        interactive_mode()

if __name__ == "__main__":
    main()