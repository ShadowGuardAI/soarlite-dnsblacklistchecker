#!/usr/bin/env python3

import argparse
import asyncio
import dns.resolver
import logging
import sys
import concurrent.futures  # For parallel execution
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

# List of DNSBL servers (feel free to expand this list)
DNSBL_SERVERS = [
    "bl.spamcop.net",
    "dnsbl.sorbs.net",
    "zen.spamhaus.org",
    "spam.abuse.ch",
    "cbl.abuseat.org",
    "b.barracudacentral.org",
]


async def check_dnsbl(target, dnsbl_server, resolver):
    """
    Asynchronously checks a target (domain or IP) against a single DNSBL server.

    Args:
        target (str): The target domain or IP address to check.
        dnsbl_server (str): The DNSBL server to query.
        resolver (dns.resolver.Resolver):  A pre-configured DNS resolver object.

    Returns:
        tuple: A tuple containing the DNSBL server and a boolean indicating if the target is listed.
               Returns (dnsbl_server, None) on DNS resolution failure.
    """
    try:
        # Construct the query string
        query = target + "." + dnsbl_server
        # Perform the DNS query
        answers = await resolver.resolve(query, "A")  # Await the result

        if answers:
            logging.debug(f"Target {target} listed on {dnsbl_server}")
            return dnsbl_server, True
        else:
            logging.debug(f"Target {target} not listed on {dnsbl_server}")
            return dnsbl_server, False
    except dns.resolver.NXDOMAIN:
        logging.debug(f"Target {target} not listed on {dnsbl_server} (NXDOMAIN)")
        return dnsbl_server, False  # Not listed
    except dns.resolver.NoAnswer:
        logging.debug(f"Target {target} not listed on {dnsbl_server} (NoAnswer)")
        return dnsbl_server, False  # Not listed
    except dns.exception.Timeout:
        logging.warning(f"Timeout querying {dnsbl_server} for {target}")
        return dnsbl_server, None  # Timeout
    except dns.resolver.YxDomain:
        logging.warning(f"YXDOMAIN error querying {dnsbl_server} for {target}")
        return dnsbl_server, None
    except Exception as e:
        logging.error(
            f"Error querying {dnsbl_server} for {target}: {e}", exc_info=True
        )
        return dnsbl_server, None  # Error


async def check_target_parallel(target, dnsbl_servers):
    """
    Checks a target against multiple DNSBL servers in parallel using asyncio.

    Args:
        target (str): The target domain or IP address to check.
        dnsbl_servers (list): A list of DNSBL server addresses.

    Returns:
        dict: A dictionary where keys are DNSBL servers and values are booleans
              indicating if the target is listed (True), not listed (False), or
              the query resulted in an error (None).
    """
    results = {}
    resolver = dns.resolver.Resolver()  # Create a resolver instance
    resolver.timeout = 5  # Set timeout to 5 seconds

    # Use asyncio.gather to run the checks concurrently
    tasks = [check_dnsbl(target, server, resolver) for server in dnsbl_servers]
    completed = await asyncio.gather(*tasks)

    for server, listed in completed:
        results[server] = listed

    return results


def is_valid_domain(domain):
    """
    Validates if a given string is a valid domain name.

    Args:
        domain (str): The string to validate.

    Returns:
        bool: True if the string is a valid domain, False otherwise.
    """
    try:
        # A very basic check; can be improved with more robust regex
        if "." not in domain:
            return False
        domain.encode("idna")  # Check for IDNA compatibility
        return True
    except UnicodeError:
        return False


def is_valid_ip(ip):
    """
    Validates if a given string is a valid IPv4 address.

    Args:
        ip (str): The string to validate.

    Returns:
        bool: True if the string is a valid IPv4 address, False otherwise.
    """
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        for part in parts:
            if not part.isdigit():
                return False
            num = int(part)
            if num < 0 or num > 255:
                return False
        return True
    except ValueError:
        return False


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(
        description="Check a domain or IP address against multiple DNS blacklists."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-d", "--domain", help="The domain name to check (e.g., example.com)"
    )
    group.add_argument("-i", "--ip", help="The IP address to check (e.g., 127.0.0.1)")
    parser.add_argument(
        "-l",
        "--list",
        nargs="+",
        default=DNSBL_SERVERS,
        help=f"A list of DNSBL servers to check against. Defaults to: {DNSBL_SERVERS}",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging (DEBUG level)."
    )

    return parser


def main():
    """
    The main function of the script.  Parses arguments, validates inputs, performs DNSBL checks,
    and prints the results.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose logging enabled.")

    target = None
    if args.domain:
        if not is_valid_domain(args.domain):
            logging.error("Invalid domain name provided.")
            sys.exit(1)
        target = args.domain
    elif args.ip:
        if not is_valid_ip(args.ip):
            logging.error("Invalid IP address provided.")
            sys.exit(1)
        # Reverse the IP address for DNSBL queries
        parts = args.ip.split(".")
        target = ".".join(reversed(parts))
    
    dnsbl_servers = args.list

    try:
        # Run the checks asynchronously
        results = asyncio.run(check_target_parallel(target, dnsbl_servers))

        print(f"DNSBL check results for: {target}")
        for server, listed in results.items():
            if listed is True:
                print(f"  {server}: LISTED")
            elif listed is False:
                print(f"  {server}: NOT LISTED")
            else:
                print(f"  {server}: UNKNOWN (Error or Timeout)")

    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()


# Usage Examples:
#
# 1. Check a domain against the default DNSBL servers:
#    python dnsbl_checker.py -d example.com
#
# 2. Check an IP address against the default DNSBL servers:
#    python dnsbl_checker.py -i 127.0.0.1
#
# 3. Check a domain against a specific list of DNSBL servers:
#    python dnsbl_checker.py -d example.com -l bl.spamcop.net zen.spamhaus.org
#
# 4. Check an IP address with verbose logging:
#    python dnsbl_checker.py -i 127.0.0.1 -v
#
# 5. Check a domain with a custom list of DNSBLs and verbose logging
#    python dnsbl_checker.py -d example.com -l bl.spamcop.net dnsbl.sorbs.net -v