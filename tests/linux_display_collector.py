#!/usr/bin/env python3
"""Offline tests for the read-only Linux display inventory collector."""
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("collect_linux_display", ROOT / "tools" / "collect_linux_display.py")
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


def make_edid(*, invalid_checksum=False, extension_count=0):
    data = bytearray(128 * (extension_count + 1))
    data[:8] = b"\x00\xff\xff\xff\xff\xff\xff\x00"
    manufacturer = (1 << 10) | (2 << 5) | 3  # ABC
    data[8:10] = manufacturer.to_bytes(2, "big")
    data[10:12] = (0x1234).to_bytes(2, "little")
    data[12:16] = b"SNUM"  # Must never enter the shareable report.
    data[20] = 0x90  # Digital EDID 1.4, six bits per primary color channel.
    data[18:20] = bytes((1, 4))
    data[24] = 0x02  # EDID 1.4 marks the first detailed timing as preferred.
    data[54:56] = (14850).to_bytes(2, "little")  # 148.5 MHz
    data[56:63] = bytes((0x80, 0x18, 0x71, 0x38, 0x2D, 0x40, 0x00))  # 1920x1080
    data[66:69] = bytes((88, 194, 0x10))  # 344x194 mm
    data[126] = extension_count
    for offset in range(0, len(data), 128):
        block = data[offset:offset + 128]
        block[127] = (-sum(block[:127])) & 0xFF
        data[offset:offset + 128] = block
    if invalid_checksum:
        data[20] ^= 1
    return bytes(data)


def make_vbt(*, malformed=False, preceding_mipi_v3=False, duplicate_child=False,
             trailing_malformed=False, checksum_mismatch=False):
    child = bytearray(38)
    child[2:4] = (0x1004).to_bytes(2, "little")  # internal + DP
    child[16] = 9  # Tiger Lake DVO encoding interpreted by kern_vbt.hpp
    child[19] = 2
    child[23] = 0x20
    child[25] = 0x40
    child[33] = 0
    second_child = bytearray(38)
    second_child[2:4] = (0x1004).to_bytes(2, "little")
    second_child[16] = 3  # HDMI DVO code shares Tiger Lake's DDI 3 slot with DVO 9.
    children = child + (second_child if duplicate_child else b"")
    general = bytes(4) + bytes((38,)) + children
    block = bytes((2,)) + len(general).to_bytes(2, "little") + general
    mipi = bytes((53, 0, 0, 3)) + (5).to_bytes(4, "little") if preceding_mipi_v3 else b""
    tail = bytes((58, 2, 0, 1)) if trailing_malformed else b""
    blocks = mipi + block + tail
    bdb = bytearray(b"BIOS_DATA_BLOCK " + (216).to_bytes(2, "little") +
                    (22).to_bytes(2, "little") + (22 + len(blocks)).to_bytes(2, "little") + blocks)
    data = bytearray(48 + len(bdb))
    data[:4] = b"$VBT"
    data[22:24] = (48).to_bytes(2, "little")
    data[24:26] = len(data).to_bytes(2, "little")
    data[28:32] = (48).to_bytes(4, "little")
    data[48:] = bdb
    data[26] = (-sum(data)) & 0xFF
    if malformed:
        data[22:24] = (0xFFFF).to_bytes(2, "little")
        data[26] = (-sum(data)) & 0xFF
    if checksum_mismatch:
        data[26] ^= 1
    return bytes(data)


class Fixture:
    def __init__(self, parent):
        self.base = Path(parent)
        self.sys = self.base / "sys"
        self.proc = self.base / "proc"
        self.etc = self.base / "etc"
        self.debug = self.sys / "kernel" / "debug"
        for directory in (self.sys / "bus" / "pci" / "devices", self.sys / "bus" / "pci" / "drivers" / "i915",
                          self.sys / "bus" / "pci" / "drivers" / "nvidia", self.sys / "class" / "drm",
                          self.sys / "class" / "dmi" / "id", self.sys / "module" / "i915",
                          self.sys / "firmware" / "efi", self.proc / "sys" / "kernel", self.etc):
            directory.mkdir(parents=True, exist_ok=True)
        (self.sys / "class" / "dmi" / "id" / "sys_vendor").write_text("Fixture Vendor\n")
        (self.sys / "class" / "dmi" / "id" / "product_name").write_text("Fixture Model\n")
        (self.proc / "cpuinfo").write_text("processor : 0\nvendor_id : GenuineIntel\ncpu family : 6\nmodel : 140\nstepping : 1\nmodel name : Fixture Test CPU\n\n")
        (self.proc / "cmdline").write_text("BOOT_IMAGE=/private/marker i915.enable_psr=0 xe.force_probe=9a49 other=value\n")
        (self.proc / "modules").write_text("i915 123 0 - Live 0x0\ndrm 456 2 i915, Live 0x0\nnvidia 789 1 - Live 0x0\n")
        (self.proc / "sys" / "kernel" / "osrelease").write_text("6.12.1-test\n")
        (self.etc / "os-release").write_text('NAME="Test Linux"\nID=test\nVERSION_ID="1"\n')
        self.intel = self._pci("0000:00:02.0", 0x8086, 0x9A49, "i915")
        self.nvidia = self._pci("0000:01:00.0", 0x10DE, 0x1F99, "nvidia")
        self._card("card0", self.nvidia)
        self._card("card1", self.intel)
        self.connector("card1-eDP-1", status="connected", enabled="enabled", modes="1920x1080\n1366x768\n",
                       edid=make_edid())
        self.connector("card1-DP-1", status="disconnected", enabled="disabled", modes="")
        self.connector("card0-HDMI-A-1", status="connected", enabled="enabled", modes="1920x1080\n")

    def _pci(self, bdf, vendor, device, driver):
        path = self.sys / "bus" / "pci" / "devices" / bdf
        path.mkdir(parents=True, exist_ok=True)
        values = {"vendor": vendor, "device": device, "revision": 1,
                  "subsystem_vendor": 0x1234, "subsystem_device": 0xABCD, "class": 0x030000}
        for key, value in values.items():
            (path / key).write_text(f"0x{value:06x}\n" if key == "class" else f"0x{value:04x}\n")
        config = bytearray(256)
        config[6:8] = (0x10).to_bytes(2, "little")
        config[0x34] = 0x40
        config[0x40:0x42] = bytes((0x10, 0))
        (path / "config").write_bytes(config)
        (path / "driver").symlink_to(self.sys / "bus" / "pci" / "drivers" / driver)
        return path

    def _card(self, name, pci):
        path = self.sys / "class" / "drm" / name
        path.mkdir(parents=True, exist_ok=True)
        (path / "device").symlink_to(pci)

    def connector(self, name, *, status, enabled, modes, edid=None):
        path = self.sys / "class" / "drm" / name
        path.mkdir(parents=True, exist_ok=True)
        (path / "status").write_text(status + "\n")
        (path / "enabled").write_text(enabled + "\n")
        (path / "modes").write_text(modes)
        if edid is not None:
            (path / "edid").write_bytes(edid)
        return path

    def collect(self, import_evidence_dir=None):
        return collector.collect_inventory(sys_root=self.sys, proc_root=self.proc, etc_root=self.etc,
                                           debug_root=self.debug, read_kernel_logs=False,
                                           import_evidence_dir=import_evidence_dir)

    def staged_import(self, directory, *, target_bdf="0000:00:02.0", identity_contents="i915 dev=0000:00:02.0 unique=fixture-private"):
        directory = Path(directory)
        directory.mkdir(mode=0o700)
        vbt_path = directory / "vbt.bin"
        vbt_path.write_bytes(make_vbt())
        vbt_path.chmod(0o600)
        manifest = {
            "schema_version": 1,
            "target_pci_bdf": target_bdf,
            "collection_method": "approved read-only debugfs copy",
            "source_identity": {
                "path": "/sys/kernel/debug/dri/7/name",
                "contents": identity_contents,
            },
            "files": {
                "i915_vbt": {
                    "filename": "vbt.bin",
                    "source": "/sys/kernel/debug/dri/7/i915_vbt",
                },
            },
        }
        manifest_path = directory / "manifest.json"
        manifest_path.write_text(json.dumps(manifest))
        manifest_path.chmod(0o600)
        return directory


class LinuxDisplayCollectorTests(unittest.TestCase):
    def test_multiple_gpus_and_nondefault_intel_card_mapping(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(temp)
            report, _ = fixture.collect()
            devices = {item["kind"]: item for item in report["display_controllers"]}
            self.assertEqual(set(devices), {"Intel", "NVIDIA"})
            intel = devices["Intel"]
            self.assertEqual(intel["bdf"], "0000:00:02.0")
            self.assertEqual(intel["device_id"]["value"], 0x9A49)
            self.assertEqual(intel["kernel_driver"]["value"], "i915")
            self.assertEqual(intel["drm_cards"]["value"], ["card1"])
            self.assertEqual(intel["source_catalog_match"]["value"]["gt_backend"], "TGLGT2")
            self.assertEqual(intel["compatibility"]["value"], "CONDITIONAL")
            self.assertEqual(intel["pci_capabilities"]["value"]["items"], [{"id": 0x10, "offset": 0x40}])
            self.assertEqual([item["name"]["value"] for item in report["connectors"]],
                             ["card1-DP-1", "card1-eDP-1"])

    def test_missing_edid_is_unknown_without_fabrication(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(temp)
            (fixture.sys / "class" / "drm" / "card1-eDP-1" / "edid").unlink()
            report, raw = fixture.collect()
            edp = next(item for item in report["connectors"] if item["type"]["value"] == "eDP")
            self.assertFalse(edp["edid"]["present"]["value"])
            self.assertIsNone(edp["edid"]["valid"]["value"])
            self.assertNotIn("intel-edid-01.bin", raw)

    def test_edid_validation_and_preferred_timing(self):
        valid = collector.parse_edid(make_edid())
        self.assertTrue(valid["valid"])
        self.assertEqual(valid["manufacturer_code"], "ABC")
        self.assertEqual(valid["product_id"], 0x1234)
        self.assertEqual(valid["advertised_color_depth_bpc"], 6)
        self.assertEqual(valid["preferred_timing"]["width"], 1920)
        self.assertEqual(valid["preferred_timing"]["height"], 1080)
        self.assertEqual(valid["physical_dimensions_mm"], {"width": 344, "height": 194})
        self.assertEqual(collector.parse_edid(make_edid()[:80])["error"], "truncated_base_block")
        self.assertEqual(collector.parse_edid(make_edid(extension_count=1)[:128])["error"], "truncated_extensions")
        self.assertEqual(collector.parse_edid(make_edid(invalid_checksum=True))["error"], "checksum_failure")

    def test_debugfs_unavailable_blocks_vbt_without_stopping_inventory(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(temp)
            report, _ = fixture.collect()
            self.assertEqual(report["debugfs"]["availability"]["status"], "BLOCKED")
            self.assertEqual(report["connectors"][1]["type"]["value"], "eDP")
            self.assertIsNone(report["topology"]["physical_ddi"]["value"])

    def test_valid_vbt_extracts_metadata_and_internal_child(self):
        parsed = collector.parse_vbt(make_vbt(), family="TigerLake")
        self.assertTrue(parsed["valid"], parsed["error"])
        self.assertEqual(parsed["declared_length"], len(make_vbt()))
        self.assertEqual(parsed["bdb_version"], 216)
        self.assertEqual(parsed["child_descriptor_stride"], 38)
        self.assertEqual(parsed["children"][0]["physical_ddi_slot_from_project_parser"], 3)
        self.assertTrue(parsed["children"][0]["firmware_internal_flag"])

    def test_vbt_parser_matches_project_mipi_sequence_v3_block_sizing(self):
        parsed = collector.parse_vbt(make_vbt(preceding_mipi_v3=True), family="TigerLake")
        self.assertTrue(parsed["valid"], parsed["error"])
        self.assertEqual(parsed["bdb_version"], 216)
        self.assertEqual(parsed["children"][0]["dvo_port"], 9)
        self.assertEqual(parsed["children"][0]["physical_ddi_slot_from_project_parser"], 3)

    def test_vbt_ddi_slot_decoding_uses_observed_source_family(self):
        tiger_lake = collector.parse_vbt(make_vbt(), family="TigerLake")
        alder_lake_n = collector.parse_vbt(make_vbt(), family="AlderLakeN")
        unknown = collector.parse_vbt(make_vbt())
        self.assertEqual(tiger_lake["children"][0]["physical_ddi_slot_from_project_parser"], 3)
        self.assertIsNone(alder_lake_n["children"][0]["physical_ddi_slot_from_project_parser"])
        self.assertIsNone(unknown["children"][0]["physical_ddi_slot_from_project_parser"])

    def test_vbt_parser_rejects_conflicting_mapped_child_records(self):
        parsed = collector.parse_vbt(make_vbt(duplicate_child=True), family="TigerLake")
        self.assertFalse(parsed["valid"])
        self.assertEqual(parsed["error"], "conflicting_child_records")

    def test_checksum_diagnostic_extracts_candidates_without_passing_strict_gate(self):
        damaged = make_vbt(checksum_mismatch=True)
        strict = collector.parse_vbt(damaged, family="TigerLake")
        self.assertFalse(strict["valid"])
        self.assertEqual(strict["error"], "vbt_checksum_failure")
        self.assertEqual(strict["children"], [])

        diagnostic = collector.parse_vbt(damaged, family="TigerLake", diagnostic_only=True)
        self.assertFalse(diagnostic["valid"])
        self.assertFalse(diagnostic["strict_validation_passed"])
        self.assertEqual(diagnostic["checksum_status"], "MISMATCH")
        self.assertEqual(diagnostic["error"], "vbt_checksum_failure")
        self.assertTrue(diagnostic["header_valid"])
        self.assertTrue(diagnostic["bdb_bounds_valid"])
        self.assertTrue(diagnostic["bdb_block_stream_valid"])
        self.assertTrue(diagnostic["structure_valid"])
        self.assertTrue(diagnostic["general_definitions_valid"])
        self.assertTrue(diagnostic["child_descriptors_valid"])
        self.assertEqual(diagnostic["children"][0]["aux_channel"], 0x40)
        self.assertEqual(diagnostic["runtime_acceptance"], "NOT_EVALUATED_BY_COLLECTOR")

    def test_malformed_unrelated_bdb_tail_does_not_hide_bounded_child_table(self):
        parsed = collector.parse_vbt(make_vbt(trailing_malformed=True),
                                     family="TigerLake", diagnostic_only=True)
        self.assertTrue(parsed["header_checksum_valid"])
        self.assertTrue(parsed["bdb_bounds_valid"])
        self.assertFalse(parsed["bdb_block_stream_valid"])
        self.assertEqual(parsed["bdb_block_stream_error"]["block_id"], 58)
        self.assertEqual(parsed["bdb_block_stream_error"]["overrun_bytes"], 1)
        self.assertTrue(parsed["general_definitions_valid"])
        self.assertTrue(parsed["child_descriptors_valid"])
        self.assertFalse(parsed["structure_valid"])
        self.assertFalse(parsed["strict_validation_passed"])
        self.assertFalse(parsed["valid"])
        self.assertEqual(parsed["error"], "bdb_block_out_of_bounds")
        self.assertEqual(len(parsed["children"]), 1)

    def test_staged_vbt_import_requires_matching_private_provenance_and_reuses_parser(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(temp)
            import_dir = fixture.staged_import(Path(temp) / "import")
            report, raw = fixture.collect(import_evidence_dir=import_dir)
            intel_debug = next(item for item in report["debugfs"]["devices"]
                               if item["bdf"] == "0000:00:02.0")
            self.assertEqual(intel_debug["node"]["value"], "7")
            self.assertEqual(intel_debug["name"]["value"],
                             "i915 dev=0000:00:02.0 unique=fixture-private")
            vbt = intel_debug["files"]["i915_vbt"]
            self.assertTrue(vbt["parsed"]["valid"])
            self.assertEqual(vbt["parsed"]["children"][0]["aux_channel"], 0x40)
            self.assertEqual(raw[vbt["raw_file"]], make_vbt())
            self.assertIn("collection_method", intel_debug["import_provenance"])
            shareable_data = collector.shareable_inventory(report)
            self.assertEqual(shareable_data["vbt"]["acquisition"]["status"], "CONFIRMED")
            self.assertEqual(shareable_data["vbt"]["validated_files"][0]["children"][0]["capabilities"], 0)
            shareable = json.dumps(shareable_data)
            self.assertNotIn("0000:00:02.0", shareable)
            self.assertNotIn("fixture-private", shareable)
            self.assertNotIn(make_vbt().hex(), shareable)
            with mock.patch.object(collector, "run_optional_decoders"):
                session = collector.write_reports(report, raw, Path(temp) / "reports")
            imported_raw = session / "raw" / vbt["raw_file"]
            self.assertEqual(imported_raw.read_bytes(), make_vbt())
            self.assertEqual(imported_raw.stat().st_mode & 0o777, 0o600)
            self.assertEqual(session.stat().st_mode & 0o777, 0o700)
            saved_shareable = (session / "shareable.json").read_text()
            self.assertNotIn("0000:00:02.0", saved_shareable)
            self.assertNotIn("fixture-private", saved_shareable)
            self.assertNotIn("/sys/kernel/debug/dri/7", saved_shareable)

    def test_imported_checksum_failure_is_diagnostic_only_and_stays_unadmitted(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(temp)
            import_dir = fixture.staged_import(Path(temp) / "import")
            (import_dir / "vbt.bin").write_bytes(make_vbt(checksum_mismatch=True))
            report, _ = fixture.collect(import_evidence_dir=import_dir)
            intel_debug = next(item for item in report["debugfs"]["devices"]
                               if item["bdf"] == "0000:00:02.0")
            vbt = intel_debug["files"]["i915_vbt"]
            self.assertFalse(vbt["parsed"]["valid"])
            self.assertTrue(vbt["parsed"]["diagnostic_only"])
            self.assertTrue(vbt["parsed"]["child_descriptors_valid"])
            self.assertEqual(len(vbt["parsed"]["firmware_route_candidates"]), 1)
            self.assertEqual(vbt["project_runtime_acceptance"]["value"], "BLOCKED_BY_CHECKSUM")
            self.assertEqual(vbt["project_runtime_acceptance"]["status"], "BLOCKED")
            shareable = collector.shareable_inventory(report)
            shareable_vbt = shareable["vbt"]["validated_files"][0]
            self.assertFalse(shareable_vbt["valid"]["value"])
            self.assertEqual(shareable_vbt["project_runtime_acceptance"]["value"],
                             "BLOCKED_BY_CHECKSUM")
            self.assertEqual(shareable_vbt["firmware_route_candidates"][0]["status"], "UNKNOWN")
            self.assertNotIn(make_vbt(checksum_mismatch=True).hex(), json.dumps(shareable))

    def test_debugfs_raw_names_do_not_collide_across_intel_devices(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(temp)
            second = fixture._pci("0000:00:04.0", 0x8086, 0x9A49, "i915")
            node_first = fixture.debug / "dri" / "2"
            node_second = fixture.debug / "dri" / "9"
            node_first.mkdir(parents=True)
            node_second.mkdir(parents=True)
            (node_first / "name").write_text("i915 dev=0000:00:02.0\n")
            (node_first / "i915_vbt").write_bytes(make_vbt())
            (node_second / "name").write_text("i915 dev=0000:00:04.0\n")
            (node_second / "i915_vbt").write_bytes(make_vbt(preceding_mipi_v3=True))
            report, raw = fixture.collect()
            files = [item["files"]["i915_vbt"]["raw_file"] for item in report["debugfs"]["devices"]]
            self.assertEqual(len(files), 2)
            self.assertEqual(len(set(files)), 2)
            self.assertTrue(all(filename in raw for filename in files))
            self.assertIsNotNone(second)

    def test_debugfs_mapping_requires_explicit_unique_dev_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(temp)
            node = fixture.debug / "dri" / "4"
            node.mkdir(parents=True)
            (node / "name").write_text("i915 alias=0000:00:02.0\n")
            (node / "i915_vbt").write_bytes(make_vbt())

            report, raw = fixture.collect()
            intel_debug = next(item for item in report["debugfs"]["devices"]
                               if item["bdf"] == "0000:00:02.0")
            self.assertIsNone(intel_debug["node"]["value"])
            self.assertNotIn("i915_vbt", intel_debug["files"])
            self.assertFalse(any(name.endswith("i915_vbt.bin") for name in raw))

    def test_staged_import_rejects_mismatched_or_ambiguous_device_provenance(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(temp)
            mismatch = fixture.staged_import(Path(temp) / "mismatch", target_bdf="0000:00:04.0")
            with self.assertRaises(collector.EvidenceImportError):
                fixture.collect(import_evidence_dir=mismatch)
            ambiguous = fixture.staged_import(
                Path(temp) / "ambiguous",
                identity_contents="i915 dev=0000:00:02.0 alias=0000:00:04.0",
            )
            with self.assertRaises(collector.EvidenceImportError):
                fixture.collect(import_evidence_dir=ambiguous)

    def test_staged_import_rejects_symlinks_and_oversized_files(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(temp)
            import_dir = Path(temp) / "symlink-import"
            import_dir.mkdir(mode=0o700)
            target = Path(temp) / "outside.bin"
            target.write_bytes(make_vbt())
            target.chmod(0o600)
            (import_dir / "vbt.bin").symlink_to(target)
            manifest = {
                "schema_version": 1,
                "target_pci_bdf": "0000:00:02.0",
                "collection_method": "approved read-only debugfs copy",
                "source_identity": {"path": "/sys/kernel/debug/dri/7/name",
                                    "contents": "i915 dev=0000:00:02.0"},
                "files": {"i915_vbt": {"filename": "vbt.bin",
                                          "source": "/sys/kernel/debug/dri/7/i915_vbt"}},
            }
            manifest_path = import_dir / "manifest.json"
            manifest_path.write_text(json.dumps(manifest))
            manifest_path.chmod(0o600)
            with self.assertRaises(collector.EvidenceImportError):
                fixture.collect(import_evidence_dir=import_dir)

            oversized = fixture.staged_import(Path(temp) / "oversized")
            (oversized / "vbt.bin").write_bytes(b"x" * (65_537))
            (oversized / "vbt.bin").chmod(0o600)
            with self.assertRaises(collector.EvidenceImportError):
                fixture.collect(import_evidence_dir=oversized)

    def test_staged_import_rejects_a_symlinked_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(temp)
            actual = fixture.staged_import(Path(temp) / "actual-import")
            linked = Path(temp) / "linked-import"
            linked.symlink_to(actual, target_is_directory=True)
            with self.assertRaises(collector.EvidenceImportError):
                fixture.collect(import_evidence_dir=linked)

    def test_vbt_shareable_checksum_status_reflects_checksum_not_other_parser_errors(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(temp)
            node = fixture.debug / "dri" / "7"
            node.mkdir(parents=True)
            (node / "name").write_text("i915 dev=0000:00:02.0\n")
            unsupported = bytearray(make_vbt())
            unsupported[48 + 16:48 + 18] = (257).to_bytes(2, "little")
            unsupported[26] = 0
            unsupported[26] = (-sum(unsupported)) & 0xFF
            (node / "i915_vbt").write_bytes(unsupported)

            report, _ = fixture.collect()
            summary = collector.shareable_inventory(report)
            checksum = summary["vbt"]["validated_files"][0]["header_checksum_valid"]
            self.assertTrue(checksum["value"])
            self.assertEqual(checksum["status"], "CONFIRMED")

    def test_malformed_vbt_metadata_is_rejected(self):
        parsed = collector.parse_vbt(make_vbt(malformed=True), family="TigerLake")
        self.assertFalse(parsed["valid"])
        self.assertEqual(parsed["error"], "invalid_vbt_bounds")
        self.assertEqual(collector.parse_vbt(b"$VBT")["error"], "truncated_vbt_header")

    def test_missing_optional_utilities_are_reported_without_execution(self):
        with mock.patch.object(collector.shutil, "which", return_value=None):
            result, output = collector._run_known_decoder("edid-decode", ["ignored"])
            logs = collector._collect_kernel_logs({})
        self.assertEqual(result["availability"], "MISSING")
        self.assertIsNone(output)
        self.assertEqual(logs["available"]["availability"], "MISSING")

    def test_permission_error_is_blocked(self):
        path = Path("/synthetic/card1-eDP-1")
        with mock.patch.object(collector, "_read_bytes", return_value=(None, "DENIED", "PermissionError")):
            result = collector._read_edid(path, Path("/synthetic"), {}, 0)
        self.assertEqual(result["present"]["status"], "BLOCKED")
        self.assertEqual(result["present"]["error"], "PermissionError")
        self.assertIsNone(result["valid"]["value"])

    def test_short_pci_config_does_not_claim_an_empty_capability_list(self):
        config = bytearray(64)
        config[6:8] = (0x10).to_bytes(2, "little")
        config[0x34] = 0x40
        parsed = collector._pci_capabilities(bytes(config))
        self.assertFalse(parsed["complete"])
        self.assertEqual(parsed["error"], "truncated_or_malformed_capability_list")

    def test_ambiguous_multiple_edp_connectors_do_not_guess_port(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(temp)
            fixture.connector("card1-eDP-2", status="connected", enabled="enabled", modes="1920x1080\n")
            report, _ = fixture.collect()
            self.assertEqual(report["topology"]["edp_connector_count"]["value"], 2)
            self.assertEqual(report["topology"]["physical_ddi"]["status"], "UNKNOWN")
            self.assertIn("Multiple eDP-type connectors", report["topology"]["physical_ddi"]["ambiguity"])

    def test_safe_reports_exclude_identifiers_and_raw_private_data(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(temp)
            vbt_node = fixture.debug / "dri" / "7"
            vbt_node.mkdir(parents=True)
            (vbt_node / "name").write_text("i915 dev=0000:00:02.0 unique=local-private-token\n")
            (vbt_node / "i915_vbt").write_bytes(make_vbt())
            report, raw = fixture.collect()
            raw["private-kernel.log"] = b"i915 private-log-marker serial-marker\n"
            output_root = Path(temp) / "private-output"
            with mock.patch.object(collector, "run_optional_decoders"):
                session = collector.write_reports(report, raw, output_root)
            shareable = (session / "shareable.json").read_text()
            shareable_md = (session / "shareable.md").read_text()
            combined = shareable + shareable_md
            for forbidden in ("0000:00:02.0", "0000:01:00.0", "SNUM", "serial-marker",
                              "private-log-marker", "private/marker", "local-private-token", "$VBT"):
                self.assertNotIn(forbidden, combined)
            safe_data = json.loads(shareable)
            self.assertTrue(safe_data["vbt"]["validated_files"][0]["valid"]["value"])
            self.assertEqual(safe_data["connectors"][1]["type"]["source"],
                             "Linux DRM connector interface; connector number omitted")
            self.assertIn("source", safe_data["connectors"][1]["preferred_timing"])
            self.assertIn("1920", combined)
            self.assertEqual((session.stat().st_mode & 0o777), 0o700)
            self.assertEqual(((session / "raw").stat().st_mode & 0o777), 0o700)
            self.assertEqual(((session / "raw" / "intel-edid-01.bin").stat().st_mode & 0o777), 0o600)
            vbt_raw = next((session / "raw").glob("*i915_vbt.bin"))
            self.assertEqual((vbt_raw.stat().st_mode & 0o777), 0o600)
            self.assertEqual(vbt_raw.read_bytes(), make_vbt())
            self.assertEqual(((session / "shareable.json").stat().st_mode & 0o777), 0o600)
            self.assertEqual((session / "raw" / "intel-edid-01.bin").read_bytes(), make_edid())
            json.loads(shareable)

    def test_command_line_allowlist_omits_private_and_unrelated_arguments(self):
        item = collector._sanitize_cmdline("root=UUID=secret i915.enable_psr=0 video=eDP-1:1920x1080 secret=marker",
                                           "/proc/cmdline")
        self.assertEqual(item["value"], ["i915.enable_psr=0", "video=eDP-1:1920x1080"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
