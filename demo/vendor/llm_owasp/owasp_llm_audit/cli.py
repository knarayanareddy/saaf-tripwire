"""CLI entry point — run with: python -m owasp_llm_audit <target>"""

import argparse
import sys

from owasp_llm_audit.auditor import run_audit


def main():
    parser = argparse.ArgumentParser(
        prog="owasp-llm-audit",
        description="Audit an AI agent against the OWASP LLM Top 10 (2025)",
    )
    parser.add_argument(
        "target",
        help="Path to agent codebase (directory), config file, or '-' for stdin text",
    )
    parser.add_argument(
        "-o", "--output",
        help="Write report to this file (default: print to stdout)",
    )
    parser.add_argument(
        "-m", "--model",
        default="claude-sonnet-4-20250514",
        help="Claude model to use (default: claude-sonnet-4-20250514)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Generate a sample report without calling the API",
    )

    args = parser.parse_args()

    # Handle stdin input
    target = args.target
    if target == "-":
        target = sys.stdin.read()

    report = run_audit(target, model=args.model, output_path=args.output, dry_run=args.dry_run)

    if not args.output:
        print(report)


if __name__ == "__main__":
    main()
