# Name: Adam Mohamed | Student ID: 101336503
"""Audit an XML device inventory against a YAML compliance policy."""

import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import yaml


class InputFileError(Exception):
    """Represent an error while reading or interpreting an input file."""


class Device:
    """Hold the inventory information and policy checks for one device."""

    def __init__(self, element):
        """Read a device's attributes and children from an XML element."""
        self.id = element.get("id")
        self.role = element.get("role", "")
        self.os = element.get("os", "")
        self.owner = (element.findtext("owner") or "").strip()
        self.statuses = [interface.get("status", "") for interface in element.findall("interface")]

    def interface_counts(self):
        """Count interfaces with up, down, or other statuses."""
        counts = {"up": 0, "down": 0, "other": 0}
        for status in self.statuses:
            counts[status if status in ("up", "down") else "other"] += 1
        return counts

    def violations(self, policy):
        """Return all violations of the checks enabled in the policy."""
        problems = []
        if "min_os" in policy:
            minimums = policy["min_os"]
            if self.role not in minimums:
                problems.append({"device": self.id, "type": "unknown_role", "role": self.role})
            elif version_parts(self.os) < version_parts(str(minimums[self.role])):
                problems.append({
                    "device": self.id,
                    "type": "os_outdated",
                    "found": self.os,
                    "required": str(minimums[self.role]),
                })
        if policy.get("require_owner") is True and not self.owner:
            problems.append({"device": self.id, "type": "missing_owner"})
        if "max_down_interfaces" in policy:
            down = self.interface_counts()["down"]
            if down > policy["max_down_interfaces"]:
                problems.append({"device": self.id, "type": "too_many_down", "down": down})
        return problems


def version_parts(version):
    """Make a version numerically comparable, ignoring trailing zero parts."""
    try:
        parts = tuple(int(part) for part in version.split("."))
    except ValueError as error:
        raise ValueError(f"invalid OS version {version!r}") from error
    # Numeric tuples already compare missing parts as smaller; pad both via
    # a custom object instead of comparing 9.1 and 9.1.0 as unequal.
    return Version(parts)


class Version:
    """Provide numeric dotted-version ordering with trailing zeros ignored."""

    def __init__(self, parts):
        """Store version segments without insignificant trailing zeros."""
        trimmed = list(parts)
        while len(trimmed) > 1 and trimmed[-1] == 0:
            trimmed.pop()
        self.parts = tuple(trimmed)

    def __lt__(self, other):
        """Compare versions after padding their segments with zeros."""
        width = max(len(self.parts), len(other.parts))
        left = self.parts + (0,) * (width - len(self.parts))
        right = other.parts + (0,) * (width - len(other.parts))
        return left < right


def read_inventory(filename):
    """Load XML and return the site, devices, and count of skipped devices."""
    try:
        root = ET.parse(filename).getroot()
    except (OSError, ET.ParseError) as error:
        raise InputFileError(f"{filename}: {error}") from error
    devices = []
    skipped = 0
    for element in root.findall("device"):
        if element.get("id") is None:
            skipped += 1
        else:
            devices.append(Device(element))
    return root.get("site"), devices, skipped


def read_policy(filename):
    """Load YAML safely and require a mapping, allowing an empty policy."""
    try:
        with Path(filename).open("r", encoding="utf-8") as file:
            policy = yaml.safe_load(file)
    except (OSError, yaml.YAMLError) as error:
        raise InputFileError(f"{filename}: {error}") from error
    if policy is None:
        return {}
    if not isinstance(policy, dict):
        raise InputFileError(f"{filename}: policy must be a YAML mapping")
    return policy


def make_report(site, devices, skipped, policy):
    """Calculate inventory counts, violations, and compliant device IDs."""
    report = {
        "site": site,
        "total_devices": len(devices),
        "skipped_devices": skipped,
        "roles": {},
        "interfaces": {"up": 0, "down": 0, "other": 0},
        "violations": [],
        "compliant": [],
    }
    for device in devices:
        report["roles"][device.role] = report["roles"].get(device.role, 0) + 1
        for status, count in device.interface_counts().items():
            report["interfaces"][status] += count
        problems = device.violations(policy)
        report["violations"].extend(problems)
        if not problems:
            report["compliant"].append(device.id)
    report["compliant"].sort()
    return report


def main(arguments):
    """Validate arguments, perform the audit, and write audit.json."""
    if len(arguments) != 2:
        print("usage: python pa2.py DEVICES.xml POLICY.yaml")
        return 2
    inventory_path, policy_path = arguments
    try:
        site, devices, skipped = read_inventory(inventory_path)
        policy = read_policy(policy_path)
        report = make_report(site, devices, skipped, policy)
        with Path("audit.json").open("w", encoding="utf-8") as file:
            json.dump(report, file, indent=2)
            file.write("\n")
    except (InputFileError, OSError, ValueError, TypeError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    print(f"Audited {report['total_devices']} devices; {len(report['violations'])} violations; "
          f"{len(report['compliant'])} compliant.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
