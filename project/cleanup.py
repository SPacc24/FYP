"""
FYP Project - Cleanup Script

Removes generated files to clean up the project workspace.

What gets deleted:
1. storage/logs/ - All generated operation and test logs
2. __pycache__/ - Python bytecode directories (all subdirectories)
3. *.pyc - Compiled Python files

Use Cases:
- Development cleanup between test runs
- Preparing for version control (Git)
- Removing temporary generated files
- Resetting logs before fresh test run

After running this script:
- Re-run tests or the application normally
- Log files will be regenerated as needed

WARNING: Logs will be permanently deleted. Back up any important logs first if needed.
"""

import os
import shutil
from pathlib import Path


def delete_file(filepath):
    """Delete a file if it exists. Safe operation (no error if file doesn't exist)"""
    try:
        if os.path.exists(filepath):
            os.remove(filepath)
            print(f"  Deleted: {filepath}")
            return True
        return False
    except Exception as e:
        print(f"  Error deleting {filepath}: {e}")
        return False


def clear_directory(directory):
    """Clear all files in a directory without deleting the directory itself."""
    try:
        if os.path.exists(directory):
            files_deleted = 0
            for filename in os.listdir(directory):
                file_path = os.path.join(directory, filename)
                try:
                    if os.path.isfile(file_path) or os.path.islink(file_path):
                        os.unlink(file_path)
                        files_deleted += 1
                        print(f"  Deleted: {filename}")
                    elif os.path.isdir(file_path):
                        shutil.rmtree(file_path)
                        files_deleted += 1
                        print(f"  Deleted directory: {filename}")
                except Exception as e:
                    print(f"  Failed to delete {file_path}: {e}")
            
            if files_deleted > 0:
                print(f"  → Cleared {files_deleted} item(s)")
            else:
                print(f"  → Directory already empty")
        else:
            print(f"  → Directory not found (skipped)")
    except Exception as e:
        print(f"  Error clearing directory {directory}: {e}")


def delete_pycache_directories(root_dir):
    """Recursively find and delete all __pycache__ directories."""
    deleted_count = 0
    try:
        for root, dirs, files in os.walk(root_dir):
            if "__pycache__" in dirs:
                pycache_path = os.path.join(root, "__pycache__")
                try:
                    shutil.rmtree(pycache_path)
                    print(f"  Deleted: {pycache_path}")
                    deleted_count += 1
                except Exception as e:
                    print(f"  Failed to delete {pycache_path}: {e}")
        
        if deleted_count > 0:
            print(f"  → Removed {deleted_count} __pycache__ director(ies)")
        else:
            print(f"  → No __pycache__ directories found")
    except Exception as e:
        print(f"  Error walking directory tree: {e}")


def delete_pyc_files(root_dir):
    """Recursively find and delete all .pyc files."""
    deleted_count = 0
    try:
        for root, dirs, files in os.walk(root_dir):
            for file in files:
                if file.endswith(".pyc"):
                    file_path = os.path.join(root, file)
                    try:
                        os.unlink(file_path)
                        print(f"  Deleted: {file_path}")
                        deleted_count += 1
                    except Exception as e:
                        print(f"  Failed to delete {file_path}: {e}")
        
        if deleted_count > 0:
            print(f"  → Removed {deleted_count} .pyc file(s)")
        else:
            print(f"  → No .pyc files found")
    except Exception as e:
        print(f"  Error walking directory tree: {e}")


def main():
    """Main cleanup function."""
    print("=" * 60)
    print("FYP PROJECT - CLEANUP SCRIPT")
    print("=" * 60)
    print("\nThis will delete generated files and caches.\n")
    
    # Get the project root directory (this script's location)
    base_dir = Path(__file__).parent
    
    # Clear logs
    print("1. Clearing operation logs (storage/logs/)...")
    clear_directory(base_dir / "storage" / "logs")
    
    # Remove __pycache__ directories
    print("\n2. Removing __pycache__ directories...")
    delete_pycache_directories(base_dir)
    
    # Remove .pyc files
    print("\n3. Removing .pyc compiled files...")
    delete_pyc_files(base_dir)
    
    print("\n" + "=" * 60)
    print("CLEANUP COMPLETE")
    print("=" * 60)
    print("\nYou can now safely commit to version control.")
    print("Logs and caches will be regenerated when needed.\n")


if __name__ == "__main__":
    main()
