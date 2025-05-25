# 🔍 File Scanner

A Python script that scans files in given directories, logs their metadata, computes hashes, and detects known malware based on hash lists. Output is logged in NDJSON format.

⚠️ Linux only — uses Unix-specific tools like `stat`.

## 🛠 Features

- MD5 & SHA-256 hashing
- Metadata logging (timestamps, permissions)
- Hash-based malware detection
- NDJSON log format

## ⚙️ Configuration

The script uses a `config.json` file to define:

- Directories to scan
- Time between scans
- Output log directory

You can customize it as needed.
