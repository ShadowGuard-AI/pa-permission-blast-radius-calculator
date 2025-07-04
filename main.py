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


def simulate_access(user, resource, permissions_data):
    """
    Simulates access to a resource based on the user and permissions data.

    Args:
        user (str): The user to simulate access for.
        resource (str): The resource to check access to.
        permissions_data (dict): A dictionary containing user/group permissions.

    Returns:
        bool: True if the user has access to the resource, False otherwise.
    """

    try:
        # Check user-specific permissions
        if user in permissions_data and resource in permissions_data[user]:
            if permissions_data[user][resource] == "read" or permissions_data[user][resource] == "write":
                logging.info(f"User {user} has explicit {permissions_data[user][resource]} access to {resource}.")
                return True

        # Simulate group membership and check group permissions (placeholder)
        # Replace with actual group membership logic
        groups = simulate_group_membership(user) # Use helper function

        for group in groups:
             if group in permissions_data:
                if resource in permissions_data[group]:
                    if permissions_data[group][resource] == "read" or permissions_data[group][resource] == "write":
                        logging.info(f"User {user} has {permissions_data[group][resource]} access to {resource} via group {group}.")
                        return True
        logging.info(f"User {user} does not have access to {resource}.")
        return False
    except Exception as e:
        logging.error(f"Error simulating access to {resource}: {e}")
        return False

def simulate_group_membership(user):
    """Simulates Group Membership
    Args:
        user (str): The user that we want to get group membership for

    Returns:
        list: returns a list of the groups a user belongs to
    """
    #This is an extremely simplified example.  In a real implementation, this would
    #interact with an actual user/group directory (LDAP, Active Directory, etc.)
    #or a local database of group memberships.
    if user == "john.doe":
        return ["developers", "testers"]
    elif user == "jane.smith":
        return ["administrators"]
    else:
        return []

def assess_impact(user, resources, permissions_data, criticality_data):
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
            if simulate_access(user, resource, permissions_data):
                criticality = criticality_data.get(resource, "low")  # Default to low
                high_impact_targets.append({"resource": resource, "criticality": criticality})
                logging.info(f"User {user} has access to {resource} (criticality: {criticality}).")

        except Exception as e:
            logging.error(f"Error processing resource {resource}: {e}")

    # Rank targets by criticality (high > medium > low)
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
    except Exception as e:
        logging.error(f"Error saving results to {output_file}: {e}")


def main():
    """
    Main function to orchestrate the permission blast radius calculation.
    """
    args = setup_argparse()

    try:
        config = load_configuration(args.config)

        user = args.user
        resources = config.get("resources", [])
        permissions_data = config.get("permissions", {})
        criticality_data = config.get("criticality", {})

        # Input Validation
        if not isinstance(resources, list):
            raise ValueError("Resources must be a list in the configuration file.")
        if not isinstance(permissions_data, dict):
            raise ValueError("Permissions must be a dictionary in the configuration file.")
        if not isinstance(criticality_data, dict):
            raise ValueError("Criticality must be a dictionary in the configuration file.")

        ranked_targets = assess_impact(user, resources, permissions_data, criticality_data)

        display_results(ranked_targets)

        if args.output:
            save_results(ranked_targets, args.output)

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
    #   }
    # }

    # Run from command line:
    # python main.py --user john.doe --config config.json --output output.json

    main()