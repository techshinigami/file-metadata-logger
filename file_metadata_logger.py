from os import path, stat, walk, makedirs  # Importing modules for file path handling and file statistics
from json import dump, load  # Importing module for writing JSON data
from time import ctime, sleep  # Importing module to convert time to a readable format
from datetime import datetime
from subprocess import check_output  # Importing module to execute shell commands

from hash_functions import md5_file, sha256_file  # Importing custom hash functions for MD5 and SHA256


def get_file_metadata(file_path: str) -> dict:
    file_stats = stat(file_path)  # Get file statistics
    file_permissions_absolute = oct(file_stats.st_mode)[-3:]  # Extract file permissions in octal format
    file_permissions = absolute_to_symbolic(file_permissions_absolute)  # Convert to symbolic format
    file_birth_time = ctime(get_birth_time(file_path))  # Get file birth time in readable format
    # file_birth_time = ctime(file_stats.st_birthtime) # Get file birth time in windows
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
    stat_output = check_output(["stat", "--format=%W", file_path])  # Execute shell command to get birth time
    birth_time = float(stat_output.strip())  # Convert output to float
    if birth_time != 0:  # If birth time is valid, return it
        return birth_time
    else:
        return stat(file_path).st_ctime  # Otherwise, return creation time


def absolute_to_symbolic(absolute_permissions: str) -> str:
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
    md5_hash = md5_file(file_path)  # Calculate MD5 hash using the custom function
    sha256_hash = sha256_file(file_path)  # Calculate SHA256 hash using the custom function

    return md5_hash, sha256_hash

def generate_json_log(file_paths: list) -> None:
    # Ensure the logs directory exists
    makedirs("logs", exist_ok=True)
    
    # Get the current date and time in YYYY-MM-DD_HH-MM-SS format
    current_timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_file_name = f"log_{current_timestamp}.ndjson"
    with open(f"logs/{log_file_name}", "w") as log_file:  # Open the JSON file for writing
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

            # Write each log entry as a JSON object on a new line
            dump(log, log_file)
            log_file.write("\n")


def get_all_files(directories: list) -> list:
    file_paths = []
    for directory in directories:
        for root, _, files in walk(directory):
            for file in files:
                file_paths.append(path.join(root, file))
    return file_paths


def main():
    # Load configuration
    with open("config.json", "r") as config_file:
        config = load(config_file)

    directories = config.get("directories", [])
    scan_interval = config.get("scan_interval", 600)

    if not directories:
        print("No directories specified in the configuration.")
        return

    while True:
        print(f"Scanning directories: {directories}")
        file_paths = get_all_files(directories)
        generate_json_log(file_paths)
        print(f"Scan complete. Waiting for {scan_interval} seconds.")
        sleep(scan_interval)


if __name__ == "__main__":
    main()
