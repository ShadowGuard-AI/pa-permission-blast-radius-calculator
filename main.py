import argparse
import logging
import os
import json
from rich.console import Console
from rich.table import Column, Table

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Default configuration file path
DEFAULT_CONFIG_FILE = "config.json"


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(
        description="Calculates the potential impact of a compromised identity by mapping its permissions to accessible resources and their criticality."
    )

    parser.add_argument(
        "--user",
        type=str,
        required=True,
        help="The username or identity to assess permissions for."
    )

    parser.add_argument(
        "--config",
        type=str,
        default=DEFAULT_CONFIG_FILE,
        help="Path to the configuration file (default: config.json)."
    )

    parser.add_argument(
        "--output",
        type=str,
        help="Path to the output file to store results (optional)."
    )

    return parser.parse_args()


def load_configuration(config_file):
    """
    Loads configuration data from a JSON file.

    Args:
        config_file (str): The path to the configuration file.

    Returns:
        dict: The configuration data as a dictionary.

    Raises:
        FileNotFoundError: If the configuration file does not exist.
        json.JSONDecodeError: If the configuration file is not valid JSON.
    """
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
        logging.info(f"Configuration loaded from {config_file}")
        return config
    except FileNotFoundError:
        logging.error(f"Configuration file not found: {config_file}")
        raise
    except json.JSONDecodeError:
        logging.error(f"Invalid JSON in configuration file: {config_file}")
        raise


def _counts_as_access(value):
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        text = value.strip().lower()
        if not text:
            return False
        # Any string outside this short deny list counts as access, including odd values like a zero written as text or a note someone left in the config. I would rather overstate the blast radius than argue about shades of grant in a hand written file.
        if text in ("deny", "denied", "none", "no", "false"):
            return False
        return True
    return bool(value)


def simulate_access(user, resource, permissions_data, group_membership=None):
    """
    Simulates access to a resource based on the user and permissions data.

    Args:
        user (str): The user to simulate access for.
        resource (str): The resource to check access to.
        permissions_data (dict): A dictionary containing user/group permissions.
        group_membership (dict): Mapping of user names to lists of group names,
            read from the config file under the group_membership key.

    Returns:
        bool: True if the user has access to the resource, False otherwise.
    """

    try:
        if user in permissions_data and resource in permissions_data[user]:
            value = permissions_data[user][resource]
            if _counts_as_access(value):
                logging.info(f"User {user} has explicit access to {resource} with permission value counted: {value}")
                return True

        # Reaching this line means a direct entry that did not count, including an explicit deny, does not end the check. Group access is still tried afterwards, so in my model a group grant overrides a user level deny rather than the deny winning.
        groups = simulate_group_membership(user, group_membership)

        for group in groups:
             if group in permissions_data:
                if resource in permissions_data[group]:
                    value = permissions_data[group][resource]
                    if _counts_as_access(value):
                        logging.info(f"User {user} has access to {resource} via group {group} with permission value counted: {value}")
                        return True
        logging.info(f"User {user} does not have access to {resource}.")
        return False
    # This wide handler is why a malformed permissions entry, say a list where I expect a mapping, reads as no access instead of as bad input. The failure and the honest no are indistinguishable in the final table.
    except Exception as e:
        logging.error(f"Error simulating access to {resource}: {e}")
        return False

def simulate_group_membership(user, group_membership=None):
    """Returns group membership for a user from the config data.
    Args:
        user (str): The user that we want to get group membership for
        group_membership (dict): Mapping from the config file under the
            group_membership key. A user with no entry is groupless.

    Returns:
        list: returns a list of the groups a user belongs to
    """
    if not isinstance(group_membership, dict):
        return []
    groups = group_membership.get(user, [])
    # Membership is one level deep only. A group nested inside another group in the config is never expanded, so access held through nested groups is missing from the result and the radius I report is smaller than the real one.
    if isinstance(groups, list):
        return groups
    return []

def assess_impact(user, resources, permissions_data, criticality_data, group_membership=None):
    """
    Assesses the impact of a compromised identity by mapping permissions to
    critical resources.

    Args:
        user (str): The username of the compromised identity.
        resources (list): A list of resources to assess.
        permissions_data (dict): A dictionary containing user/group permissions.
        criticality_data (dict): A dictionary containing criticality levels for resources.

    Returns:
        list: A ranked list of high-impact targets.
    """
    high_impact_targets = []
    for resource in resources:
        try:
            if simulate_access(user, resource, permissions_data, group_membership):
                criticality = criticality_data.get(resource, "low")  # Default to low
                high_impact_targets.append({"resource": resource, "criticality": criticality})
                logging.info(f"User {user} has access to {resource} (criticality: {criticality}).")

        except Exception as e:
            logging.error(f"Error processing resource {resource}: {e}")

    # Rank targets by criticality (high > medium > low)
    # The ranking knows nothing about the kind of access, only the resource criticality. Read access to a high resource sorts level with write access to it, and Python's stable sort leaves equal rows in the order the resources list named them.
    ranked_targets = sorted(high_impact_targets, key=lambda x: {"high": 3, "medium": 2, "low": 1}[x["criticality"]], reverse=True)

    return ranked_targets


def display_results(ranked_targets):
    """
    Displays the results in a user-friendly format using Rich.

    Args:
        ranked_targets (list): A list of ranked high-impact targets.
    """
    console = Console()
    table = Table(title="Potential Impact of Compromised Identity")

    table.add_column("Resource", style="cyan", no_wrap=True)
    table.add_column("Criticality", style="magenta")

    for target in ranked_targets:
        table.add_row(target["resource"], target["criticality"])

    console.print(table)


def save_results(ranked_targets, output_file):
    """
    Saves the results to a file in JSON format.

    Args:
        ranked_targets (list): A list of ranked high-impact targets.
        output_file (str): The path to the output file.
    """
    try:
        with open(output_file, 'w') as f:
            json.dump(ranked_targets, f, indent=4)
        logging.info(f"Results saved to {output_file}")
        return True
    except Exception as e:
        logging.error(f"Error saving results to {output_file}: {e}")
        return False


def main():
    """
    Main function to orchestrate the permission blast radius calculation.
    """
    args = setup_argparse()

    try:
        config = load_configuration(args.config)

        if args.output and os.path.realpath(args.output) == os.path.realpath(args.config):
            print("Error: Output file must not be the same as the config file.")
            exit(1)

        user = args.user
        resources = config.get("resources", [])
        permissions_data = config.get("permissions", {})
        criticality_data = config.get("criticality", {})
        group_membership = config.get("group_membership", {})

        # Input Validation
        if not isinstance(resources, list):
            raise ValueError("Resources must be a list in the configuration file.")
        if not isinstance(permissions_data, dict):
            raise ValueError("Permissions must be a dictionary in the configuration file.")
        if not isinstance(criticality_data, dict):
            raise ValueError("Criticality must be a dictionary in the configuration file.")
        if not isinstance(group_membership, dict):
            raise ValueError("group_membership must be a dictionary in the configuration file.")

        for resource_name, crit_value in criticality_data.items():
            if crit_value not in ("high", "medium", "low"):
                raise ValueError(f"Invalid criticality for resource {resource_name}: {crit_value}")

        if not resources:
            print("Nothing to assess: the resources list is empty.")
            exit(1)

        if user not in permissions_data and user not in group_membership:
            print(f"User not present: {user} has no entry in the configuration.")
            exit(1)

        ranked_targets = assess_impact(user, resources, permissions_data, criticality_data, group_membership)

        display_results(ranked_targets)

        if args.output:
            if not save_results(ranked_targets, args.output):
                print(f"Results not saved: {args.output}")
                exit(1)

    except FileNotFoundError:
        print("Error: Configuration file not found. Please check the path.")
        exit(1)
    except json.JSONDecodeError:
        print("Error: Invalid JSON in configuration file.")
        exit(1)
    except ValueError as e:
        print(f"Error: {e}")
        exit(1)
    except Exception as e:
        logging.exception("An unexpected error occurred:")
        print(f"An unexpected error occurred: {e}")
        exit(1)


if __name__ == "__main__":
    # Example Usage (Note: This example requires a config.json file)
    # Create config.json (example)
    # {
    #   "resources": ["/data/sensitive.txt", "/config/database.yml", "/logs/app.log"],
    #   "permissions": {
    #     "john.doe": {
    #       "/data/sensitive.txt": "read"
    #     },
    #     "administrators": {
    #       "/config/database.yml": "write"
    #     }
    #   },
    #   "criticality": {
    #     "/data/sensitive.txt": "high",
    #     "/config/database.yml": "medium"
    #   },
    #   "group_membership": {
    #     "jane.smith": ["administrators"]
    #   }
    # }

    # Run from command line:
    # python main.py --user john.doe --config config.json --output output.json

    main()