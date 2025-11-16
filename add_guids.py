#!/usr/bin/env python3
"""
Script to add UUID7 GUIDs to all tests in YAML files.
This should be run by the CI/CD pipeline before merging to main.
"""

import glob
import re
import sys
from uuid import uuid7


def generate_guids_for_yaml(path: str, get_guid: callable, existing_guids: set) -> bool:
    """
    Add GUIDs to a YAML file using regex-based approach.

    Args:
        path: Path to the YAML file
        get_guid: Function that returns a new GUID string
        existing_guids: Set of GUIDs that already exist across all files

    Returns:
        True if file was modified, False otherwise
    """
    with open(path, "r") as file:
        og_text = file.read()

    # First, extract all existing GUIDs from this file to add to our tracking set
    existing_guid_matches = re.findall(
        r"(?i)^[ \t]*guid:[ \t]*([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})[ \t]*$",
        og_text,
        flags=re.MULTILINE,
    )
    for guid in existing_guid_matches:
        existing_guids.add(guid.lower())

    # Add the "guid:" element after the "- name:" element if it isn't already there
    text = re.sub(
        r"(?i)(^([ \t]*-[ \t]*)name:.*$(?!\s*guid))",
        lambda m: f"{m.group(1)}\n{m.group(2).replace('-', ' ')}guid:",
        og_text,
        flags=re.MULTILINE,
    )

    # Fill the "guid:" element in if it doesn't contain a guid (UUID7 format)
    # UUID7 uses version 7, so we look for UUIDs with version 7 in the correct position
    def replace_guid(m):
        new_guid = get_guid()
        # Ensure uniqueness - keep generating until we get a unique one
        while new_guid.lower() in existing_guids:
            print(f"  ⚠️  Duplicate GUID detected: {new_guid}, generating new one...")
            new_guid = get_guid()
        existing_guids.add(new_guid.lower())
        return f"{m.group(1)} {new_guid}"

    text = re.sub(
        r"(?i)^([ \t]*guid:)(?!([ \t]*[a-f0-9]{8}-[a-f0-9]{4}-7[a-f0-9]{3}-[89aAbB][a-f0-9]{3}-[a-f0-9]{12})).*$",
        replace_guid,
        text,
        flags=re.MULTILINE,
    )

    if text != og_text:
        with open(path, "wb") as file:
            # using wb mode instead of w. If not, the end of line characters are auto-converted to OS specific ones.
            file.write(text.encode())
        return True
    return False


def check_for_duplicate_guids(yaml_dir: str = "yaml") -> tuple[bool, dict]:
    """
    Check all YAML files for duplicate GUIDs.

    Args:
        yaml_dir: Directory containing YAML files

    Returns:
        Tuple of (has_duplicates, guid_locations_map)
    """
    yaml_files = glob.glob(f"{yaml_dir}/**/*.yaml", recursive=True)
    guid_locations = {}  # guid -> list of (file, line_number)

    for yaml_file in yaml_files:
        with open(yaml_file, "r") as f:
            for line_num, line in enumerate(f, 1):
                match = re.match(
                    r"(?i)^[ \t]*guid:[ \t]*([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})[ \t]*$",
                    line,
                )
                if match:
                    guid = match.group(1).lower()
                    if guid not in guid_locations:
                        guid_locations[guid] = []
                    guid_locations[guid].append((yaml_file, line_num))

    # Find duplicates
    duplicates = {guid: locs for guid, locs in guid_locations.items() if len(locs) > 1}

    return len(duplicates) > 0, duplicates


def add_guids_to_yaml_files(yaml_dir: str = "yaml") -> tuple[int, int]:
    """
    Add GUIDs to all tests in YAML files that don't already have them.

    Args:
        yaml_dir: Directory containing YAML files

    Returns:
        Tuple of (total_files, files_updated)
    """
    yaml_files = glob.glob(f"{yaml_dir}/**/*.yaml", recursive=True)
    total_files = len(yaml_files)
    files_updated = 0

    # Track all GUIDs across all files to ensure uniqueness
    existing_guids = set()

    for yaml_file in yaml_files:
        print(f"Processing {yaml_file}...")

        if generate_guids_for_yaml(yaml_file, lambda: str(uuid7()), existing_guids):
            files_updated += 1
            print(f"  ✓ Updated {yaml_file}")

    return total_files, files_updated


def main():
    """Main entry point"""
    print("=" * 60)
    print("Adding GUIDs to YAML test files...")
    print("=" * 60)

    total_files, files_updated = add_guids_to_yaml_files()

    print("=" * 60)
    print(f"Total files processed: {total_files}")
    print(f"Files updated with GUIDs: {files_updated}")
    print("=" * 60)

    # Check for duplicates after processing
    print("\nChecking for duplicate GUIDs...")
    has_duplicates, duplicates = check_for_duplicate_guids()

    if has_duplicates:
        print("\n❌ ERROR: Duplicate GUIDs found!")
        for guid, locations in duplicates.items():
            print(f"\n  GUID {guid} appears in:")
            for file_path, line_num in locations:
                print(f"    - {file_path}:{line_num}")
        sys.exit(2)  # Exit with error code 2 for duplicates
    else:
        print("✓ No duplicate GUIDs found.")

    if files_updated > 0:
        print("\n⚠️  YAML files have been modified with new GUIDs.")
        print("Please commit these changes.")
        sys.exit(1)  # Exit with error to indicate files were modified
    else:
        print("\n✓ All tests already have GUIDs.")
        sys.exit(0)


if __name__ == "__main__":
    main()
