import sys
import re
from signature import Signature

# Regular expression pattern for matching signature rules
REGEX = re.compile(r""" ^
    (\d{,99999}:\s)?          #! sID Range badaio 
    ([A-Z]{,4}\s)             # PROTO
    (!?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:)|any:)  # IP
    (!?[0-9]{,6}\s|(any)\s|!?\[[0-9]{,6}-[0-9]{,6}\]\s)  # PORT
    (<>\s|->\s)               # DIR
    (!?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:)|any:)  # IP
    (!?[0-9]{,6}\s|(any)\s|!?\[[0-9]{,6}-[0-9]{,6}]\s)  # PORT
    (\*)                      # PAYLOAD
    $ """, re.VERBOSE)

# Default path for the rule file
DEFAULT_RULEPATH = 'eval.rules'


def load_rules(rule_path="test.rules"):
    """
    Load signature rules from a file.

    Args:
        rule_path (str): Path to the rule file.

    Returns:
        list: List of Signature objects.
    """
    try:
        with open(rule_path) as file:
            rules = file.readlines()
    except FileNotFoundError:
        sys.exit(f"Error: Rule file '{rule_path}' not found.")
    else:
        return [Signature(rule.strip()) for rule in rules if rule.strip() and not rule.startswith('#')]


#
# try:
#     RULES = load_rules(RULEPATH)
#     print('[*] parsed rules')
# except ValueError as err:
#     exit(f"[@] {err}")


def main():
    """
    Main function for loading and parsing signature rules.
    """
    # Determine the rule file path
    try:
        rule_path = sys.argv[1]
    except IndexError:
        rule_path = DEFAULT_RULEPATH

    print(f"[*] Loading rules from '{rule_path}'")

    # Load and parse rules
    try:
        rules = load_rules(rule_path)
    except ValueError as err:
        sys.exit(f"Error: {err}")

    print(f"[*] Successfully loaded {len(rules)} rules.")
    print("[*] Rules:")
    for rule in rules:
        print(rule)


if __name__ == "__main__":
    main()
