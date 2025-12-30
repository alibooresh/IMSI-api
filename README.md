# Sherlock IMSI Script Manager

A Flask-based backend service for managing, executing, and monitoring external IMSI catcher scripts.

This application allows a frontend client to:
- Load available scripts from configuration
- Execute scripts securely using sudo
- Monitor script execution status
- Stop running scripts
- Read and paginate data from script-generated SQLite databases

---

## Features

- Script execution with sudo
- Process lifecycle management
- Persistent execution history
- Real-time status checks
- SQLite data reader with filtering and pagination
- Safe process termination

---

## Script Configuration

Scripts are defined in `scripts.json`:

```json
{
  "imsi": {
    "id": 1,
    "file": "imsi.py",
    "path": "/usr/src/imsi1",
    "args": "--sniff",
    "dbName": "imsi.sqlite"
  }
}
