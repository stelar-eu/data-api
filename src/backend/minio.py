
import subprocess
import logging

logger = logging.getLogger(__name__)

def minio_add_policy(policy_name: str, policy_file: str):
    """Add a new policy to the Minio server.

    Args:
        policy_name: The name of the policy.
        policy_file: The path to the policy file.
    """
    try:

        subprocess.run(
            [
                "mc",
                "admin",
                "policy",
                "create",
                "myminio",
                policy_name,
                policy_file,
            ],
            check=True,
        )
        logger.info(f"Policy '{policy_name}' created successfully(v2).")
    except subprocess.CalledProcessError as e:
        print(f"Error adding policy: {e}")
        raise e
    

def minio_remove_policy(policy_name: str):
    """Remove a policy from the Minio server.

    Args:
        policy_name: The name of the policy.
    """
    try:

        subprocess.run(
            [
                "mc",
                "admin",
                "policy",
                "rm",
                "myminio",
                policy_name,
            ]
        )
        logger.info(f"Policy '{policy_name}' removed successfully(v2).")
    except subprocess.CalledProcessError as e:
        print(f"Error removing policy: {e}")
        raise e
    

def minio_fetch_policies():
    """Fetch all policies from the Minio server.

    Returns:
        A list of policies.
    """
    command = "mc admin policy ls myminio"

    result = subprocess.run(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True
    )

    # Check if the command was successful
    if result.returncode != 0:
        print(f"Error running command: {result.stderr}")
        return set()

    # Split the output into lines or words (depending on the expected output format)
    output_lines = result.stdout.splitlines()
    logger.info(f"Policy list fetched successfully(v2).")

    return output_lines