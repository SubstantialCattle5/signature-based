import re


class Signature:
    """
    Represents a network traffic signature or rule.
    """
    COMMON_LOCATION_KEYS = ["uri_raw", "http_header_content_type", "http_header", "http_client_body"]

    def __init__(self, action, protocol, source_ip, destination_ip, source_port, destination_port, options):
        self.action = action
        self.protocol = protocol
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.source_port = source_port
        self.destination_port = destination_port
        self.options = options

    @staticmethod
    def parse_options(options_str):
        # Initialize option dictionary
        options = {}

        # Split options string by semicolons outside of quotes
        options_list = re.split(r';(?=(?:[^"]*"[^"]*")*[^"]*$)', options_str)

        # Parse each option
        for item in options_list:
            if not item.strip():
                continue
            key_value = item.split(":", 1)
            key = key_value[0].strip()
            value = key_value[1].strip("'") if len(key_value) > 1 else None
            if key not in Signature.COMMON_LOCATION_KEYS:
                options[key] = value
            else :
                options["location"] = key

        return options

    @staticmethod
    def parse_rule(rule_str: str):
        # Split the rule string into parts
        parts = rule_str.split(" ")

        # Extract action and protocol
        action = parts[0]
        protocol = parts[1]

        # Extract source and destination IPs and ports
        source_ip, source_port = parts[2:4]
        direction = parts[4]
        destination_ip, destination_port = parts[5:7]

        # Extract options
        options_start, options_end = rule_str.index("(") + 1, rule_str.rindex(")")
        options_str = rule_str[options_start:options_end]
        # Initialize option dictionary
        options = Signature.parse_options(options_str)

        return Signature(action, protocol, source_ip, destination_ip, source_port, destination_port, options)

    def __eq__(self, other):
        """
        Compare two Signature objects for equality.

        Args:
            other: Another Signature object.

        Returns:
            bool: True if the objects are equal, False otherwise.
        """
        if not isinstance(other, Signature):
            return False

        # check if any is present in either source or destination ip
        if 'any' in [self.source_ip, self.destination_ip, other.source_ip, other.destination_ip]:
            ip_equal = True
        else:
            ip_equal = self.source_ip == other.source_ip and self.destination_ip == other.destination_ip

        # Check if 'any' is present in either source or destination port
        if 'any' in [self.source_port, self.destination_port, other.source_port, other.destination_port]:
            port_equal = True
        else:
            port_equal = self.source_port == other.source_port and self.destination_port == other.destination_port

        return ip_equal and port_equal

    def __str__(self):
        return f"Signature(action='{self.action}', protocol='{self.protocol}', source_ip='{self.source_ip}', " \
               f"destination_ip='{self.destination_ip}', source_port='{self.source_port}', " \
               f"destination_port='{self.destination_port}', options={self.options})"

    def __repr__(self):
        return f"Signature(action='{self.action}', protocol='{self.protocol}', source_ip='{self.source_ip}', " \
               f"destination_ip='{self.destination_ip}', source_port='{self.source_port}', " \
               f"destination_port='{self.destination_port}', options={self.options})"


if __name__ == "__main__":
    # Example usage
    # # Define two signature rules
    # signature_rule1 = 'alert http any any -> any any (msg:"SQL Injection Attempt in HTTP Request Body"; content:"'"; http_client_body; pcre:"'(?:[?&;]|$)/U"; sid:1000002;)'
    # signature_rule2 = 'alert http any any -> any any (msg:"XSS Attempt in HTTP Request Body"; http_client_body; pcre:"/(<|%3C)(script|%73%63%72%69%70%74)/i"; sid:1000002;)'
    # signature_rule3 = 'alert http any any -> any any (msg:"XSS Attempt in HTML Content-Type"; content:"text/html"; http_header_content_type; http_header; pcre:"/(<|%3C)(script|%73%63%72%69%70%74)/i"; sid:1000004;)'
    #
    # # Parse the signature rules
    # signature1 = Signature.parse_rule(signature_rule1)
    # signature2 = Signature.parse_rule(signature_rule2)
    # signature3 = Signature.parse_rule(signature_rule3)
    #
    # # Print the signatures
    # print("Signature 1:", signature1)
    # print("Signature 2:", signature2)
    # print("Signature 3:", signature3)
    #
    # # Check if signatures are equal
    # if signature1 == signature2 and signature1 == signature3:
    #     print("Signatures are equal.")
    # else:
    #     print("Signatures are not equal.")

    # Read signature rules from file
    with open("test.rules", "r") as file:
        signature_rules = file.readlines()

    # Parse each signature rule and print the Signature object
    for rule in signature_rules:
        print(f"Rule ==> {rule}")
        signature = Signature.parse_rule(rule.strip())
        print(f"Signature ==> {signature} \n")

