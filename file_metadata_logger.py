from os import path, stat
from json import dump
from time import ctime
from subprocess import check_output

from hash_functions import md5_file, sha256_file

def get_file_metadata(file_path: str) -> dict:
    file_stats = stat(file_path)
    file_permissions_absolute = oct(file_stats.st_mode)[-3:]
    file_permissions = absolute_to_symbolic(file_permissions_absolute)
    file_birth_time = ctime(get_birth_time(file_path))
    file_access_time = ctime(file_stats.st_atime)
    file_mod_time = ctime(file_stats.st_mtime)
    
    return {
        "file_permissions": file_permissions,
        "file_permissions_absolute": file_permissions_absolute,
        "file_birth_time": file_birth_time,
        "file_access_time": file_access_time,
        "file_mod_time": file_mod_time
    }

def get_birth_time(file_path: str) -> float:
    stat_output = check_output(["stat", "--format=%W", file_path])
    birth_time = float(stat_output.strip())
    if birth_time != 0:
        return birth_time
    else:
        return stat(file_path).st_ctime


def absolute_to_symbolic(absolute_permissions: str) -> str:
    permissions = int(absolute_permissions, 8)
    symbolic_permissions = ''
    
    for i in range(3):
        perm = (permissions >> (3 * (2 - i))) & 7
        
        symbolic_permissions += (
            ('r' if perm & 4 else '-') +
            ('w' if perm & 2 else '-') +
            ('x' if perm & 1 else '-')
        )
    
    return symbolic_permissions

def calculate_hashes(file_path: str) -> tuple:
    md5_hash = md5_file(file_path)
    sha256_hash = sha256_file(file_path)
    
    return md5_hash, sha256_hash

def generate_json_log(file_paths: list) -> None:
    logs = []

    for file in file_paths:
        file_name = path.basename(file)
        md5, sha256 = calculate_hashes(file)
        metadata = get_file_metadata(file)

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

        logs.append(log)
    
    with open("log.json", "w") as log_file:
        dump(logs, log_file, indent=4)

if __name__ == "__main__":
    file_list = ["foo"]
    generate_json_log(file_list)
