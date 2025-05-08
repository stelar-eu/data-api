
import subprocess
import threading
import urllib3
import logging
import json
from minio import MinioAdmin
from minio import Minio
from minio.credentials.providers import StaticProvider

logger = logging.getLogger(__name__)

class MinioClientSingleton:
    """
    Lazy‐initialized singleton that holds one Minio + MinioAdmin pair
    sharing a single urllib3.PoolManager.
    """
    _lock = threading.Lock()
    _initialized = False
    client = None          # type: Minio
    admin = None          # type: MinioAdmin

    @classmethod
    def initialize(
        cls,
        endpoint: str,
        access_key: str,
        secret_key: str,
        secure: bool = True,
        num_pools: int = 5,
        maxsize: int = 20,
        block: bool = True,
        retries: int = 3,
        read_timeout: float = 10.0,
        connect_timeout: float = None,
    ):
        """
        Must be called once (e.g. at app startup) before using get_client()/get_admin().
        """
        with cls._lock:
            if cls._initialized:
                return

            # build the shared PoolManager
            timeout = urllib3.Timeout(
                connect=connect_timeout if connect_timeout is not None else urllib3.Timeout.DEFAULT_TIMEOUT,
                read=read_timeout
            )
            pool = urllib3.PoolManager(
                num_pools=num_pools,
                maxsize=maxsize,
                block=block,
                retries=urllib3.Retry(total=retries),
                timeout=timeout,
            )

            # object‐storage client
            cls.client = Minio(
                endpoint,
                access_key=access_key,
                secret_key=secret_key,
                secure=secure,
                http_client=pool,
            )

            # admin client (reusing same pool & credentials provider)
            cls.admin = MinioAdmin(
                endpoint,
                credentials=cls.client._provider,
                secure=secure,
                http_client=pool,
            )

            cls._initialized = True

    @classmethod
    def get_client(cls) -> Minio:
        """Returns the initialized Minio client (or raises if you forgot to initialize)."""
        if not cls._initialized:
            raise RuntimeError("MinioClientSingleton not initialized; call .initialize(...) first.")
        return cls.client

    @classmethod
    def get_admin(cls) -> MinioAdmin:
        """Returns the initialized MinioAdmin client."""
        if not cls._initialized:
            raise RuntimeError("MinioClientSingleton not initialized; call .initialize(...) first.")
        return cls.admin

# def init_minio_admin_client():
#     """Initialize the Minio Admin client.

#     Returns:
#         MinioAdmin: The initialized Minio Admin client.
#     """
#     # Use the StaticProvider to create a credentials object
#     provider = StaticProvider(
#         access_key="root",
#         secret_key="stelartuc",
#     )
    
#     try:
#         # Initialize the Minio Admin client
#         minio_admin_client = MinioAdmin(
#             endpoint="minio.minikube",
#             credentials=provider,
#             secure=False,
#         )
#         return minio_admin_client
#     except Exception as e:
#         logger.error(f"Error initializing Minio Admin client: {e}")
#         raise e

def minio_add_policy(policy_name: str, policy_file: str):
    """Add a new policy to the Minio server.

    Args:
        policy_name: The name of the policy.
        policy_file: The path to the policy file.
    """
    try:

        # subprocess.run(
        #     [
        #         "mc",
        #         "admin",
        #         "policy",
        #         "create",
        #         "myminio",
        #         policy_name,
        #         policy_file,
        #     ],
        #     check=True,
        # )

        # Use the Minio Admin client to create the policy
        MINIO_ADMIN.policy_add(policy_name=policy_name, policy_file=policy_file)
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

        # subprocess.run(
        #     [
        #         "mc",
        #         "admin",
        #         "policy",
        #         "rm",
        #         "myminio",
        #         policy_name,
        #     ]
        # )
        MINIO_ADMIN.policy_remove(policy_name=policy_name)
        logger.info(f"Policy '{policy_name}' removed successfully(v2).")
    except subprocess.CalledProcessError as e:
        print(f"Error removing policy: {e}")
        raise e
    

def minio_fetch_policies():
    """Fetch all policies from the Minio server.

    Returns:
        A list of policies.
    """
    # command = "mc admin policy ls myminio"

    # result = subprocess.run(
    #     command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True
    # )

    # # Check if the command was successful
    # if result.returncode != 0:
    #     print(f"Error running command: {result.stderr}")
    #     return set()

    # # Split the output into lines or words (depending on the expected output format)
    # output_lines = result.stdout.splitlines()
    # logger.info(f"Policy list fetched successfully(v2).")

    minio_policy_list = MINIO_ADMIN.policy_list()
    minio_policy_list = json.loads(minio_policy_list)
    output_lines = minio_policy_list
    logger.info(minio_policy_list)
    logger.info(f"Policy list fetched successfully(v2).")

    return output_lines

MinioClientSingleton.initialize(
    endpoint="minio.minikube",
    access_key="root",
    secret_key="stelartuc",
    secure=False,
    num_pools=5,
    maxsize=20,
    block=True,
    retries=3,
    read_timeout=10.0,
    connect_timeout=None,
)

MINIO_ADMIN = MinioClientSingleton.get_admin()
MINIO_CLIENT = MinioClientSingleton.get_client()