"""Basic automated tests for the PA2 fleet auditor."""

import tempfile
import unittest
from pathlib import Path

from pa2 import InputFileError, make_report, read_inventory, read_policy, version_parts


class AuditorTests(unittest.TestCase):
    """Check the provided sample and version requirements."""

    def test_sample_report(self):
        """The official sample produces the required counts and violations."""
        site, devices, skipped = read_inventory(Path(__file__).with_name('PA2_sample.xml'))
        policy = read_policy(Path(__file__).with_name('PA2_policy.yaml'))
        report = make_report(site, devices, skipped, policy)
        self.assertEqual((report['site'], report['total_devices'], report['skipped_devices']), ('ott-dc1', 5, 1))
        self.assertEqual(report['interfaces'], {'up': 6, 'down': 4, 'other': 1})
        self.assertEqual(len(report['violations']), 4)
        self.assertEqual(report['compliant'], ['fw-dmz-01', 'sw-core-01'])

    def test_numeric_versions(self):
        """Compare dotted versions by number rather than text."""
        self.assertFalse(version_parts('15.10') < version_parts('15.2'))
        self.assertFalse(version_parts('9.1.0') < version_parts('9.1'))
        self.assertTrue(version_parts('17.3') < version_parts('17.3.1'))


    def test_empty_inventory_and_policy(self):
        """An empty inventory and empty YAML policy are accepted."""
        with tempfile.TemporaryDirectory() as directory:
            inventory = Path(directory) / 'empty.xml'
            policy_file = Path(directory) / 'empty.yaml'
            inventory.write_text('<inventory/>', encoding='utf-8')
            policy_file.write_text('', encoding='utf-8')
            site, devices, skipped = read_inventory(inventory)
            report = make_report(site, devices, skipped, read_policy(policy_file))
            self.assertIsNone(report['site'])
            self.assertEqual(report['total_devices'], 0)
            self.assertEqual(report['violations'], [])

    def test_skipped_device_and_unknown_interface_status(self):
        """Skip missing identifiers and group unrecognized statuses under other."""
        with tempfile.TemporaryDirectory() as directory:
            inventory = Path(directory) / 'devices.xml'
            inventory.write_text('<inventory><device role="switch"/><device id="a" role="switch"><interface status="admin-down"/></device></inventory>', encoding='utf-8')
            site, devices, skipped = read_inventory(inventory)
            report = make_report(site, devices, skipped, {})
            self.assertEqual(skipped, 1)
            self.assertEqual(report['interfaces']['other'], 1)
            self.assertEqual(report['compliant'], ['a'])

    def test_non_mapping_policy_raises_custom_error(self):
        """Reject YAML lists rather than treating them as policies."""
        with tempfile.TemporaryDirectory() as directory:
            policy_file = Path(directory) / 'policy.yaml'
            policy_file.write_text('- not\n- a mapping\n', encoding='utf-8')
            with self.assertRaises(InputFileError):
                read_policy(policy_file)


if __name__ == '__main__':
    unittest.main()
