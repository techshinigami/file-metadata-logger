from os import path, stat  # Importing modules for file path handling and file statistics
from json import dump  # Importing module for writing JSON data
from time import ctime  # Importing module to convert time to a readable format
from subprocess import check_output  # Importing module to execute shell commands

from hash_functions import md5_file, sha256_file  # Importing custom hash functions for MD5 and SHA256


def get_file_metadata(file_path: str) -> dict:
    """
    Retrieves metadata of the specified file, including permissions, birth time,
    access time, and modification time.

    Args:
        file_path (str): Path to the file.

    Returns:
        dict: A dictionary containing file metadata.
    """
    file_stats = stat(file_path)  # Get file statistics
    file_permissions_absolute = oct(file_stats.st_mode)[-3:]  # Extract file permissions in octal format
    file_permissions = absolute_to_symbolic(file_permissions_absolute)  # Convert to symbolic format
    file_birth_time = ctime(get_birth_time(file_path))  # Get file birth time in readable format
    file_access_time = ctime(file_stats.st_atime)  # Get file access time in readable format
    file_mod_time = ctime(file_stats.st_mtime)  # Get file modification time in readable format

    return {
        "file_permissions": file_permissions,
        "file_permissions_absolute": file_permissions_absolute,
        "file_birth_time": file_birth_time,
        "file_access_time": file_access_time,
        "file_mod_time": file_mod_time
    }


def get_birth_time(file_path: str) -> float:
    """
    Retrieves the birth time of a file. If unavailable, returns the creation time.

    Args:
        file_path (str): Path to the file.

    Returns:
        float: The birth time of the file as a timestamp.
    """
    stat_output = check_output(["stat", "--format=%W", file_path])  # Execute shell command to get birth time
    birth_time = float(stat_output.strip())  # Convert output to float
    if birth_time != 0:  # If birth time is valid, return it
        return birth_time
    else:
        return stat(file_path).st_ctime  # Otherwise, return creation time


def absolute_to_symbolic(absolute_permissions: str) -> str:
    """
    Converts file permissions from octal (absolute) format to symbolic format.

    Args:
        absolute_permissions (str): File permissions in octal format.

    Returns:
        str: File permissions in symbolic format (e.g., "rwxr-xr--").
    """
    permissions = int(absolute_permissions, 8)  # Convert octal string to integer
    symbolic_permissions = ''

    for i in range(3):  # Loop over three permission groups (owner, group, others)
        perm = (permissions >> (3 * (2 - i))) & 7  # Extract permission bits for the group

        symbolic_permissions += (
            ('r' if perm & 4 else '-') +  # Check read permission
            ('w' if perm & 2 else '-') +  # Check write permission
            ('x' if perm & 1 else '-')    # Check execute permission
        )

    return symbolic_permissions


def calculate_hashes(file_path: str) -> tuple:
    """
    Calculates MD5 and SHA256 hashes for the specified file.

    Args:
        file_path (str): Path to the file.

    Returns:
        tuple: A tuple containing MD5 and SHA256 hashes as strings.
    """
    md5_hash = md5_file(file_path)  # Calculate MD5 hash using the custom function
    sha256_hash = sha256_file(file_path)  # Calculate SHA256 hash using the custom function

    return md5_hash, sha256_hash


def generate_json_log(file_paths: list) -> None:
    """
    Generates a JSON log file containing metadata and hash values for a list of files.

    Args:
        file_paths (list): List of file paths to process.

    Returns:
        None
    """
    logs = []  # Initialize an empty list to store log entries

    for file in file_paths:  # Iterate over each file in the list
        file_name = path.basename(file)  # Get the file name from the path
        md5, sha256 = calculate_hashes(file)  # Calculate MD5 and SHA256 hashes
        metadata = get_file_metadata(file)  # Retrieve file metadata

        # Create a log entry as a dictionary
        log = {
            "file_name": file_name,
            "md5_hash": md5,
            "sha256_hash": sha256,
            "file_permissions": metadata["file_permissions"],
            "file_permissions_absolute": metadata["file_permissions_absolute"],
            "file_birth_time": metadata["file_birth_time"],
            "file_access_time": metadata["file_access_time"],
            "file_mod_time": metadata["file_mod_time"]
        }

        logs.append(log)  # Add the log entry to the list

    with open("log.json", "w") as log_file:  # Open a JSON file for writing
        dump(logs, log_file, indent=4)  # Write the log entries to the file in JSON format


if __name__ == "__main__":
    file_path_list = ["foo", "bar"]  # List of files to process (example: replace "foo" with actual file paths)
    generate_json_log(file_path_list)  # Generate the JSON log
