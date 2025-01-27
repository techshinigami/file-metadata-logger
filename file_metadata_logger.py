from os import path, stat, walk, makedirs  # Importing modules for file path handling and file statistics
from json import dump, load  # Importing module for writing JSON data
from time import ctime, sleep  # Importing module to convert time to a readable format
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


def is_malware(md5_hash: str, sha256_hash: str) -> bool:
    # Initialize sets to store MD5 and SHA-256 hashes
    md5_hashes = set()
    sha256_hashes = set()

    # Read and process MD5 hashes from the file
    with open("full_md5.txt", "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                md5_hashes.add(line)

    # Read and process SHA-256 hashes from the file
    with open("full_sha256.txt", "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                sha256_hashes.add(line)
    
    # Check if either hash is in the respective set
    return md5_hash in md5_hashes or sha256_hash in sha256_hashes


def generate_json_log(file_paths: list, log_directory) -> None:
    # Ensure the logs directory exists
    makedirs(log_directory, exist_ok=True)
    
    log_file_name = "log.ndjson"
    log_file_path = path.join(log_directory, log_file_name)
    with open(log_file_path, "w") as log_file:  # Open the JSON file for writing
        for file in file_paths:  # Iterate over each file in the list
            file_name = path.basename(file)  # Get the file name from the path
            file_path = path.abspath(file) # Get the absolute path of the file
            md5, sha256 = calculate_hashes(file)  # Calculate MD5 and SHA256 hashes
            is_malware_result = is_malware(md5, sha256)
            metadata = get_file_metadata(file)  # Retrieve file metadata

            # Create a log entry as a dictionary
            log = {
                "file_name": file_name,
                "file_path": file_path,
                "md5_hash": md5,
                "sha256_hash": sha256,
                "is_malware": is_malware_result,
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
    log_directory = config.get("log_directory", "logs")

    if not directories:
        print("No directories specified in the configuration.")
        return

    while True:
        print(f"Scanning directories: {directories}")
        file_paths = get_all_files(directories)
        generate_json_log(file_paths, log_directory)
        print(f"Scan complete. Waiting for {scan_interval} seconds.")
        sleep(scan_interval)


if __name__ == "__main__":
    main()
