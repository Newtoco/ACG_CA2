import os, glob, shutil, sys
from datetime import datetime
from pathlib import Path

# Add parent directory to path for imports
script_dir = Path(__file__).parent
project_root = script_dir.parent
os.chdir(project_root)

AUDIT_DB = os.path.join("instance", "audit.db")
BACKUP_DIR = os.path.join("backups")
KEEP = 10

os.makedirs(BACKUP_DIR, exist_ok=True)

ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
dst = os.path.join(BACKUP_DIR, f"audit_{ts}.db")

shutil.copy2(AUDIT_DB, dst)

# rotate
backups = sorted(glob.glob(os.path.join(BACKUP_DIR, "audit_*.db")))
for old in backups[:-KEEP]:
    os.remove(old)

print("Backup created:", dst)
