#!/usr/bin/env python3
"""Collect a privacy-conscious, read-only Linux Intel display inventory.

The collector reads sysfs/procfs and already-mounted debugfs files. An optional
offline import accepts bounded, user-staged private copies of existing i915
debugfs diagnostics; it never requests privileges. It never mounts filesystems,
writes hardware state, or runs a shell. Raw EDID, VBT, OpRegion, decoder output,
and relevant kernel messages stay in a private 0700/0600 session directory.
Shareable output is built from an explicit allowlist and excludes direct PCI
addresses, EDID identity fields, raw data, host names, usernames, serial
numbers, UUIDs, and arbitrary log lines.
"""
from __future__ import annotations

import argparse
import datetime as _datetime
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
_HEX = re.compile(r"^[0-9a-fA-F]+$")
_BDF = re.compile(r"^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$")
_DRM_CARD = re.compile(r"^card([0-9]+)$")
_CONNECTOR = re.compile(r"^card([0-9]+)-([A-Za-z0-9_.-]+)$")
_SAFE_OPTION_VALUE = re.compile(r"^[A-Za-z0-9,.:+_-]{1,80}$")
_RELEVANT_LOG = re.compile(
    r"\b(i915|xe|drm|edp|eDP|vbt|opregion|aux|psr|backlight|link train|displayport)\b",
    re.IGNORECASE,
)
_IMPORT_BDB_FILES = {
    "i915_vbt": 65_536,
    "i915_opregion": 1_048_576,
    "i915_display_info": 1_048_576,
    "i915_edp_psr_status": 262_144,
}
_IMPORT_MANIFEST_LIMIT = 65_536
_GPU_OPTION_KEYS = {
    "i915.enable_guc", "i915.enable_psr", "i915.enable_fbc", "i915.force_probe",
    "i915.modeset", "xe.force_probe", "xe.enable_psr", "xe.enable_fbc",
    "xe.modeset", "drm.debug", "video", "nomodeset",
}


def evidence(value: Any, source: str, method: str, *, status: str = "CONFIRMED",
             availability: str = "AVAILABLE", confidence: str = "high",
             interpretation: str = "Directly observed.", ambiguity: str = "None identified.",
             error: str | None = None) -> dict[str, Any]:
    """Keep each observation with its provenance and limits."""
    result = {
        "value": value, "source": source, "method": method, "status": status,
        "availability": availability, "confidence": confidence,
        "interpretation": interpretation, "ambiguity": ambiguity,
    }
    if error:
        result["error"] = error
    return result


def _source(path: Path, root: Path, virtual_prefix: str) -> str:
    try:
        relative = path.relative_to(root)
    except ValueError:
        return virtual_prefix
    return f"{virtual_prefix}/{relative.as_posix()}".replace("//", "/")


def _read_bytes(path: Path) -> tuple[bytes | None, str, str | None]:
    try:
        return path.read_bytes(), "AVAILABLE", None
    except PermissionError:
        return None, "DENIED", "PermissionError"
    except FileNotFoundError:
        return None, "MISSING", "FileNotFoundError"
    except IsADirectoryError:
        return None, "ERROR", "IsADirectoryError"
    except OSError as exc:
        return None, "ERROR", type(exc).__name__


def _read_prefix_bytes(path: Path, size: int) -> tuple[bytes | None, str, str | None]:
    try:
        with path.open("rb") as stream:
            return stream.read(size), "AVAILABLE", None
    except PermissionError:
        return None, "DENIED", "PermissionError"
    except FileNotFoundError:
        return None, "MISSING", "FileNotFoundError"
    except OSError as exc:
        return None, "ERROR", type(exc).__name__


def _read_text(path: Path) -> tuple[str | None, str, str | None]:
    data, availability, error = _read_bytes(path)
    if data is None:
        return None, availability, error
    try:
        return data.decode("utf-8", errors="replace").strip(), availability, None
    except Exception as exc:  # pragma: no cover - bytes.decode with replace is total
        return None, "ERROR", type(exc).__name__


def _obs_text(path: Path, root: Path, prefix: str, method: str = "read-only text read") -> dict[str, Any]:
    value, availability, error = _read_text(path)
    if availability == "AVAILABLE":
        return evidence(value, _source(path, root, prefix), method)
    status = "BLOCKED" if availability == "DENIED" else "UNKNOWN"
    return evidence(None, _source(path, root, prefix), method, status=status,
                    availability=availability, confidence="none",
                    interpretation="No value was collected.", ambiguity="Source unavailable.", error=error)


def _obs_int(path: Path, root: Path, prefix: str, *, base: int = 16) -> dict[str, Any]:
    item = _obs_text(path, root, prefix)
    raw = item["value"]
    if raw is None:
        return item
    try:
        value = int(raw, base)
    except ValueError:
        item.update(value=None, status="CONTRADICTED", confidence="none",
                    interpretation="The interface returned a malformed numeric value.",
                    ambiguity="The attribute could not be interpreted.")
        return item
    item["value"] = value
    return item


def _obs_bool(value: bool | None, source: str, method: str, *, unavailable: str | None = None) -> dict[str, Any]:
    if value is None:
        return evidence(None, source, method, status="UNKNOWN", availability="MISSING",
                        confidence="none", interpretation="No value was collected.",
                        ambiguity=unavailable or "Interface does not expose this fact.")
    return evidence(value, source, method)


def _safe_link_name(path: Path) -> tuple[str | None, str | None]:
    try:
        return path.resolve(strict=True).name, None
    except PermissionError:
        return None, "PermissionError"
    except (FileNotFoundError, OSError) as exc:
        return None, type(exc).__name__


def parse_edid(data: bytes) -> dict[str, Any]:
    """Decode only basic, non-text EDID fields; never expose serial/text blocks."""
    result: dict[str, Any] = {
        "present": True, "valid": False, "edid_version": None, "extension_count": None,
        "manufacturer_code": None, "product_id": None, "preferred_timing": None,
        "first_detailed_timing": None,
        "physical_dimensions_mm": None, "advertised_color_depth_bpc": None,
        "checksum_valid": False, "valid_blocks": 0,
        "error": None,
    }
    if len(data) < 128:
        result["error"] = "truncated_base_block"
        return result
    if data[:8] != b"\x00\xff\xff\xff\xff\xff\xff\x00":
        result["error"] = "invalid_header"
        return result
    result["edid_version"] = f"{data[18]}.{data[19]}"
    result["extension_count"] = data[126]
    depth_code = (data[20] >> 4) & 0x7
    if (data[20] & 0x80) and data[18] == 1 and data[19] >= 4:
        result["advertised_color_depth_bpc"] = {1: 6, 2: 8, 3: 10, 4: 12, 5: 14, 6: 16}.get(depth_code)
    manufacturer = (data[8] << 8) | data[9]
    letters = "".join(chr(64 + ((manufacturer >> shift) & 0x1F))
                      for shift in (10, 5, 0))
    result["manufacturer_code"] = letters if all("A" <= c <= "Z" for c in letters) else None
    result["product_id"] = int.from_bytes(data[10:12], "little")
    expected = 128 * (1 + data[126])
    if len(data) < expected:
        result["error"] = "truncated_extensions"
        return result
    blocks = [data[offset:offset + 128] for offset in range(0, expected, 128)]
    result["valid_blocks"] = sum(sum(block) % 256 == 0 for block in blocks)
    result["checksum_valid"] = result["valid_blocks"] == len(blocks)
    if not result["checksum_valid"]:
        result["error"] = "checksum_failure"
        return result
    result["valid"] = True
    dtd = data[54:72]
    pixel_clock_10khz = int.from_bytes(dtd[0:2], "little")
    if pixel_clock_10khz:
        h_active = dtd[2] | ((dtd[4] & 0xF0) << 4)
        h_blank = dtd[3] | ((dtd[4] & 0x0F) << 8)
        v_active = dtd[5] | ((dtd[7] & 0xF0) << 4)
        v_blank = dtd[6] | ((dtd[7] & 0x0F) << 8)
        h_size = dtd[12] | ((dtd[14] & 0xF0) << 4)
        v_size = dtd[13] | ((dtd[14] & 0x0F) << 8)
        h_total, v_total = h_active + h_blank, v_active + v_blank
        refresh = (pixel_clock_10khz * 10000 / (h_total * v_total)) if h_total and v_total else None
        timing = {
            "width": h_active, "height": v_active,
            "refresh_hz": round(refresh, 2) if refresh is not None else None,
            "pixel_clock_khz": pixel_clock_10khz * 10,
        }
        result["first_detailed_timing"] = timing
        preferred = data[18] == 1 and (data[19] < 4 or bool(data[24] & 0x02))
        if preferred:
            result["preferred_timing"] = timing
        if h_size and v_size:
            result["physical_dimensions_mm"] = {"width": h_size, "height": v_size}
    return result


def _project_vbt_ddi(family: str | None, dvo: int) -> int | None:
    if family != "TigerLake":
        return None
    dp = (10, 7, 8, 9, 11, 13, 15, 17, 19)
    hdmi = (0, 1, 2, 3, 12, 14, 16, 18, 20)
    for port, (dp_code, hdmi_code) in enumerate(zip(dp, hdmi)):
        if dvo in (dp_code, hdmi_code):
            return None if port == 2 else port
    return None


def parse_vbt(data: bytes, *, family: str | None = None) -> dict[str, Any]:
    """Validate bounded VBT/BDB metadata and extract General Definitions children."""
    result: dict[str, Any] = {
        "valid": False, "signature": None, "declared_length": None,
        "header_length": None, "header_checksum_valid": None,
        "bdb_offset": None, "bdb_header_length": None, "bdb_length": None,
        "bdb_version": None, "general_definitions_present": False,
        "child_descriptor_stride": None, "children": [], "unmapped_children": 0,
        "error": None,
    }

    def fail(message: str) -> dict[str, Any]:
        result["error"] = message
        return result

    if len(data) < 48:
        return fail("truncated_vbt_header")
    result["signature"] = data[:4].decode("ascii", errors="replace")
    if data[:4] != b"$VBT":
        return fail("invalid_vbt_signature")
    header = int.from_bytes(data[22:24], "little")
    declared = int.from_bytes(data[24:26], "little")
    bdb = int.from_bytes(data[28:32], "little")
    result.update(header_length=header, declared_length=declared, bdb_offset=bdb)
    if header < 48 or declared < header or declared > len(data) or bdb < header or bdb > declared:
        return fail("invalid_vbt_bounds")
    result["header_checksum_valid"] = sum(data[:declared]) % 256 == 0
    if not result["header_checksum_valid"]:
        return fail("vbt_checksum_failure")
    if declared - bdb < 22:
        return fail("truncated_bdb_header")
    bdata = data[bdb:declared]
    if bdata[:16] != b"BIOS_DATA_BLOCK ":
        return fail("invalid_bdb_signature")
    bdb_version = int.from_bytes(bdata[16:18], "little")
    bdb_header = int.from_bytes(bdata[18:20], "little")
    bdb_length = int.from_bytes(bdata[20:22], "little")
    result.update(bdb_version=bdb_version, bdb_header_length=bdb_header, bdb_length=bdb_length)
    if bdb_header < 22 or bdb_length < bdb_header or bdb_length > len(bdata):
        return fail("invalid_bdb_bounds")
    if not 216 <= bdb_version <= 256:
        return fail("unsupported_bdb_version")
    offset, general = bdb_header, None
    while offset < bdb_length:
        if bdb_length - offset < 3:
            return fail("truncated_bdb_block_header")
        block_id = bdata[offset]
        block_length = int.from_bytes(bdata[offset + 1:offset + 3], "little")
        if block_id == 53:
            if bdb_length - offset < 4:
                return fail("truncated_bdb_block_header")
            if bdata[offset + 3] >= 3:
                if bdb_length - offset < 8:
                    return fail("truncated_bdb_block_header")
                block_length = int.from_bytes(bdata[offset + 4:offset + 8], "little")
        if block_length > bdb_length - offset - 3:
            return fail("bdb_block_out_of_bounds")
        if block_id == 2:
            general = bdata[offset + 3:offset + 3 + block_length]
            break
        offset += 3 + block_length
    if general is None:
        return fail("general_definitions_missing")
    result["general_definitions_present"] = True
    if len(general) < 5:
        return fail("general_definitions_truncated")
    stride = general[4]
    result["child_descriptor_stride"] = stride
    if stride < 38 or stride > 64 or (len(general) - 5) % stride:
        return fail("invalid_child_descriptor_layout")
    mapped_slots: set[int] = set()
    for offset in range(5, len(general), stride):
        child = general[offset:offset + stride]
        port_type = int.from_bytes(child[2:4], "little")
        if not port_type:
            continue
        dvo, ddc, aux = child[16], child[19], child[25]
        physical_slot = _project_vbt_ddi(family, dvo)
        if physical_slot is None:
            result["unmapped_children"] += 1
        elif physical_slot in mapped_slots:
            return fail("conflicting_child_records")
        else:
            mapped_slots.add(physical_slot)
        result["children"].append({
            "port_type": port_type, "dvo_port": dvo, "ddc_pin": ddc,
            "aux_channel": aux, "physical_ddi_slot_from_project_parser": physical_slot,
            "firmware_internal_flag": bool(port_type & 0x1000),
            "firmware_dp_flag": bool(port_type & 0x4),
            "descriptor_flags": child[23], "capabilities": child[33],
        })
    result["valid"] = True
    return result


def _parse_cpuinfo(text: str) -> dict[str, str]:
    allowed = {"vendor_id", "cpu family", "model", "stepping", "model name"}
    first = text.split("\n\n", 1)[0]
    values: dict[str, str] = {}
    for line in first.splitlines():
        if ":" not in line:
            continue
        key, value = (part.strip() for part in line.split(":", 1))
        if key in allowed:
            values[key] = value
    return values


def _sanitize_cmdline(text: str, source: str) -> dict[str, Any]:
    kept: list[str] = []
    for token in text.split():
        key, sep, value = token.partition("=")
        if key not in _GPU_OPTION_KEYS:
            continue
        if not sep:
            kept.append(key)
        elif _SAFE_OPTION_VALUE.fullmatch(value):
            kept.append(f"{key}={value}")
        else:
            kept.append(f"{key}=<redacted>")
    return evidence(kept, source, "allowlisted GPU kernel command-line parameter scan",
                    interpretation="Only explicitly allowlisted graphics options are retained.",
                    ambiguity="Other command-line parameters were intentionally omitted.")


def _read_os_release(path: Path, root: Path, prefix: str) -> dict[str, Any]:
    text, availability, error = _read_text(path)
    if text is None:
        return evidence(None, _source(path, root, prefix), "read-only os-release parse",
                        status="BLOCKED" if availability == "DENIED" else "UNKNOWN",
                        availability=availability, confidence="none",
                        interpretation="No distribution metadata was collected.",
                        ambiguity="Source unavailable.", error=error)
    values: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key not in {"ID", "NAME", "PRETTY_NAME", "VERSION_ID"}:
            continue
        values[key] = value.strip().strip('"').strip("'")
    return evidence(values, _source(path, root, prefix), "allowlisted os-release parse")


def _pci_capabilities(config: bytes) -> dict[str, Any]:
    """Read standard PCI capability IDs from an already-readable sysfs config file."""
    if len(config) < 0x40:
        return {"items": [], "complete": False, "error": "truncated_standard_header"}
    if not (int.from_bytes(config[6:8], "little") & 0x10):
        return {"items": [], "complete": True, "error": None}
    pointer = config[0x34] & 0xFC
    seen: set[int] = set()
    capabilities: list[dict[str, int]] = []
    while pointer:
        if pointer in seen or not 0x40 <= pointer <= 0xFC or pointer + 2 > len(config):
            return {"items": capabilities, "complete": False, "error": "truncated_or_malformed_capability_list"}
        seen.add(pointer)
        capabilities.append({"id": config[pointer], "offset": pointer})
        pointer = config[pointer + 1] & 0xFC
    return {"items": capabilities, "complete": True, "error": None}


def _scan_pci(pci_root: Path, sys_root: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    devices: list[dict[str, Any]] = []
    status = evidence("AVAILABLE", "/sys/bus/pci/devices", "enumerate sysfs PCI device directories")
    try:
        candidates = sorted(pci_root.iterdir(), key=lambda item: item.name)
    except PermissionError:
        return [], evidence(None, "/sys/bus/pci/devices", "enumerate sysfs PCI device directories",
                            status="BLOCKED", availability="DENIED", confidence="none",
                            interpretation="PCI devices could not be enumerated.",
                            ambiguity="Read access is unavailable.", error="PermissionError")
    except OSError as exc:
        return [], evidence(None, "/sys/bus/pci/devices", "enumerate sysfs PCI device directories",
                            status="UNKNOWN", availability="ERROR", confidence="none",
                            interpretation="PCI devices could not be enumerated.",
                            ambiguity="The PCI sysfs directory could not be read.", error=type(exc).__name__)
    for device_path in candidates:
        if not _BDF.fullmatch(device_path.name):
            continue
        class_ev = _obs_int(device_path / "class", sys_root, "/sys")
        vendor_ev = _obs_int(device_path / "vendor", sys_root, "/sys")
        if class_ev["value"] is None or vendor_ev["value"] is None:
            continue
        pci_class = class_ev["value"]
        if ((pci_class >> 16) & 0xFF) != 0x03:
            continue
        device_ev = _obs_int(device_path / "device", sys_root, "/sys")
        revision_ev = _obs_int(device_path / "revision", sys_root, "/sys")
        subvendor = _obs_int(device_path / "subsystem_vendor", sys_root, "/sys")
        subdevice = _obs_int(device_path / "subsystem_device", sys_root, "/sys")
        driver, link_error = _safe_link_name(device_path / "driver")
        if driver is None:
            driver_ev = evidence(None, _source(device_path / "driver", sys_root, "/sys"),
                                 "resolve PCI driver symlink", status="UNKNOWN",
                                 availability="DENIED" if link_error == "PermissionError" else "MISSING",
                                 confidence="none", interpretation="No bound driver was observed.",
                                 ambiguity="The driver link is absent or inaccessible.", error=link_error)
        else:
            driver_ev = evidence(driver, _source(device_path / "driver", sys_root, "/sys"),
                                 "resolve PCI driver symlink")
        config, availability, config_error = _read_prefix_bytes(device_path / "config", 256)
        cap_data = _pci_capabilities(config) if config is not None else None
        cap_complete = bool(cap_data and cap_data["complete"])
        cap_ev = evidence(cap_data,
                          _source(device_path / "config", sys_root, "/sys"),
                          "read-only parse of standard PCI capability list (first 256 bytes)",
                          status="CONFIRMED" if cap_complete else
                          ("BLOCKED" if availability == "DENIED" or config is not None else "UNKNOWN"),
                          availability=("AVAILABLE" if cap_complete else "PARTIAL" if config is not None else availability),
                          confidence="high" if cap_complete else "none",
                          interpretation="Capability IDs and offsets only; no configuration writes were issued.",
                          ambiguity="A short sysfs config read may prevent following the capability pointer.",
                          error=(cap_data["error"] if cap_data else config_error))
        device_bdf = device_path.name.lower()
        drm_cards: list[str] = []
        drm_root = sys_root / "class" / "drm"
        try:
            for entry in drm_root.iterdir():
                match = _DRM_CARD.fullmatch(entry.name)
                if not match:
                    continue
                resolved, _ = _safe_link_name(entry / "device")
                try:
                    resolved_path = (entry / "device").resolve(strict=True)
                except OSError:
                    continue
                if resolved == device_bdf or resolved_path.name.lower() == device_bdf:
                    drm_cards.append(entry.name)
        except OSError:
            pass
        devices.append({
            "bdf": device_bdf,
            "kind": "Intel" if vendor_ev["value"] == 0x8086 else
                    ("NVIDIA" if vendor_ev["value"] == 0x10DE else "other display controller"),
            "vendor_id": vendor_ev,
            "device_id": device_ev,
            "revision_id": revision_ev,
            "subsystem_vendor_id": subvendor,
            "subsystem_device_id": subdevice,
            "pci_class": class_ev,
            "kernel_driver": driver_ev,
            "pci_capabilities": cap_ev,
            "drm_cards": evidence(sorted(drm_cards), "/sys/class/drm", "associate card device symlinks with PCI BDF",
                                   status="CONFIRMED" if drm_cards else "UNKNOWN",
                                   confidence="high" if drm_cards else "none",
                                   interpretation="DRM cards are associated by their sysfs device target.",
                                   ambiguity="An empty mapping means no card association was visible."),
        })
    return devices, status


def _read_edid(connector_path: Path, sys_root: Path, raw: dict[str, bytes], index: int) -> dict[str, Any]:
    path = connector_path / "edid"
    data, availability, error = _read_bytes(path)
    src = _source(path, sys_root, "/sys")
    if data is None:
        return {
            "present": evidence(False if availability == "MISSING" else None, src, "read EDID sysfs attribute",
                                 status="UNKNOWN" if availability != "DENIED" else "BLOCKED",
                                 availability=availability, confidence="none",
                                 interpretation="No EDID bytes were collected.", ambiguity="Source unavailable.", error=error),
            "valid": evidence(None, src, "validate EDID blocks", status="UNKNOWN",
                              availability=availability, confidence="none",
                              interpretation="No bytes were available to validate.", ambiguity="Source unavailable."),
            "facts": None,
        }
    raw_name = f"intel-edid-{index:02d}.bin"
    raw[raw_name] = data
    parsed = parse_edid(data)
    facts: dict[str, Any] = {}
    for key in ("edid_version", "extension_count", "manufacturer_code", "product_id",
                "preferred_timing", "first_detailed_timing", "physical_dimensions_mm", "advertised_color_depth_bpc",
                "checksum_valid", "valid_blocks", "error"):
        value = parsed[key]
        status = ("CONFIRMED" if key == "error" or (parsed["valid"] and value is not None) else
                  "CONTRADICTED" if not parsed["valid"] and key == "checksum_valid" else "UNKNOWN")
        facts[key] = evidence(value, src, "read-only EDID base/extension parser",
                              status=status,
                              confidence="high" if status == "CONFIRMED" else "none",
                              interpretation="Decoded from EDID bytes; descriptor text and serial fields are omitted.",
                              ambiguity="EDID data does not prove an operational macOS display backend.")
    return {
        "present": evidence(True, src, "read EDID sysfs attribute"),
        "valid": evidence(parsed["valid"], src, "validate EDID header, declared blocks, and checksums",
                          status="CONFIRMED" if parsed["valid"] else "CONTRADICTED",
                          confidence="high" if parsed["valid"] else "none",
                          interpretation="Valid means the header, complete declared blocks, and block checksums pass.",
                          ambiguity=parsed["error"] or "No EDID validity ambiguity identified."),
        "facts": facts,
        "raw_file": raw_name,
    }


def _connector_type(name_tail: str) -> str:
    match = re.match(r"^([A-Za-z]+)", name_tail)
    return match.group(1) if match else "unknown"


def _scan_connectors(sys_root: Path, intel_devices: list[dict[str, Any]], raw: dict[str, bytes]) -> list[dict[str, Any]]:
    drm_root = sys_root / "class" / "drm"
    intel_bdfs = {item["bdf"] for item in intel_devices}
    cards: dict[str, str | None] = {}
    try:
        entries = sorted(drm_root.iterdir(), key=lambda item: item.name)
    except OSError:
        return []
    for entry in entries:
        if not _DRM_CARD.fullmatch(entry.name):
            continue
        try:
            target = (entry / "device").resolve(strict=True).name.lower()
        except OSError:
            target = None
        cards[entry.name] = target
    result: list[dict[str, Any]] = []
    for entry in entries:
        match = _CONNECTOR.fullmatch(entry.name)
        if not match:
            continue
        card = f"card{match.group(1)}"
        bdf = cards.get(card)
        if bdf not in intel_bdfs:
            continue
        tail = match.group(2)
        ctype = _connector_type(tail)
        type_src = _source(entry, sys_root, "/sys")
        internal_types = {"edp", "lvds", "dsi"}
        external_types = {"dp", "hdmi", "vga", "dvi", "dvid", "dvia", "dvii", "composite", "s-video"}
        normalized_type = ctype.lower()
        internal_value = True if normalized_type in internal_types else (
            False if normalized_type in external_types else None)
        internal_ev = evidence(internal_value, type_src, "classify from kernel DRM connector type",
                               status="INFERRED" if internal_value is not None else "UNKNOWN",
                               confidence="medium" if internal_value is not None else "none",
                               interpretation="eDP/LVDS/DSI are classified as internal; known DP/HDMI/VGA/DVI types as external." if internal_value is not None else "Connector type does not establish internal or external classification.",
                               ambiguity="Connector type/name does not prove physical DDI/AUX wiring or macOS usability.")
        status_ev = _obs_text(entry / "status", sys_root, "/sys")
        enabled_ev = _obs_text(entry / "enabled", sys_root, "/sys")
        modes_text, modes_availability, modes_error = _read_text(entry / "modes")
        modes = modes_text.splitlines() if modes_text else []
        modes_ev = evidence(modes, _source(entry / "modes", sys_root, "/sys"), "read advertised DRM modes",
                            status="CONFIRMED" if modes_text is not None else
                            ("BLOCKED" if modes_availability == "DENIED" else "UNKNOWN"),
                            availability=modes_availability,
                            confidence="high" if modes_text is not None else "none",
                            interpretation="These are modes advertised by the connector, not necessarily the active mode.",
                            ambiguity="Current scanout mode is reported only if a separate mode attribute exists.", error=modes_error)
        current_ev = _obs_text(entry / "mode", sys_root, "/sys", "read optional connector current mode attribute")
        if current_ev["value"] is None and current_ev["availability"] == "MISSING":
            current_ev.update(status="UNKNOWN", availability="MISSING", confidence="none",
                              interpretation="The sysfs connector does not expose a current mode attribute.",
                              ambiguity="Advertised modes do not establish the active resolution.")
        edid = _read_edid(entry, sys_root, raw, len(result))
        color_depth = evidence(None, _source(entry, sys_root, "/sys"),
                               "inspect available connector attributes for current color depth",
                               status="UNKNOWN", availability="MISSING", confidence="none",
                               interpretation="No reliable current color-depth attribute was exposed by the collector.",
                               ambiguity="Advertised EDID color formats are not treated as active scanout depth.")
        result.append({
            "name": evidence(entry.name, type_src, "enumerate DRM connector directory"),
            "type": evidence(ctype, type_src, "parse connector type prefix from kernel DRM name"),
            "internal": internal_ev,
            "status": status_ev,
            "enabled": enabled_ev,
            "advertised_modes": modes_ev,
            "current_mode": current_ev,
            "color_depth": color_depth,
            "associated_drm_card": evidence(card, type_src, "map connector card prefix to PCI device symlink"),
            "associated_pci_bdf": evidence(bdf, type_src, "map connector card prefix to PCI device symlink"),
            "edid": edid,
        })
    return result


def _scan_backlights(sys_root: Path, intel_devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
    root = sys_root / "class" / "backlight"
    try:
        entries = sorted(root.iterdir(), key=lambda item: item.name)
    except OSError:
        return []
    bdfs = {item["bdf"] for item in intel_devices}
    result = []
    for entry in entries:
        try:
            target = (entry / "device").resolve(strict=True)
            target_text = target.as_posix().lower()
            owner = next((bdf for bdf in bdfs if bdf in target_text), None)
        except OSError:
            owner = None
        result.append({
            "name": evidence(entry.name, _source(entry, sys_root, "/sys"), "enumerate backlight class interface"),
            "associated_intel_bdf": evidence(owner, _source(entry / "device", sys_root, "/sys"),
                                              "match resolved backlight device path to Intel PCI device",
                                              status="CONFIRMED" if owner else "UNKNOWN",
                                              confidence="high" if owner else "none",
                                              interpretation="Association requires the resolved device path to contain an enumerated Intel BDF.",
                                              ambiguity="An unassociated backlight is not attributed to Intel."),
            "maximum_brightness_steps": _obs_int(entry / "max_brightness", sys_root, "/sys", base=10),
        })
    return result


def _topology_unknown(source: str, method: str, explanation: str) -> dict[str, Any]:
    return evidence(None, source, method, status="UNKNOWN", availability="MISSING", confidence="none",
                    interpretation=explanation,
                    ambiguity="No exact physical mapping is inferred from connector naming or Tiger Lake generation.")


def _topology_inventory(connectors: list[dict[str, Any]]) -> dict[str, Any]:
    edp = [item for item in connectors if item["type"]["value"].lower() == "edp"]
    result = {
        "edp_connector_count": evidence(len(edp), "/sys/class/drm", "count Intel-associated eDP-type connector entries",
                                         status="CONFIRMED" if edp else "UNKNOWN",
                                         confidence="high" if edp else "none",
                                         interpretation="Connector type count is direct Linux DRM enumeration.",
                                         ambiguity="It does not identify physical DDI or prove a macOS backend."),
        "physical_ddi": _topology_unknown("/sys/class/drm plus matched Intel debugfs display diagnostics",
                                           "require an explicit connector-to-physical-DDI observation",
                                           "No stable sysfs association from DRM connector to physical DDI was established."),
        "aux_channel": _topology_unknown("matched Intel display diagnostics", "require explicit AUX channel evidence",
                                          "No exact live AUX channel association is established by generic sysfs fields."),
        "lane_count": _topology_unknown("matched Intel display diagnostics", "inspect read-only driver diagnostics",
                                         "No structured negotiated lane count was safely extracted."),
        "link_rate": _topology_unknown("matched Intel display diagnostics", "inspect read-only driver diagnostics",
                                        "No structured negotiated link rate was safely extracted."),
        "pipe_transcoder": _topology_unknown("matched Intel display diagnostics", "inspect read-only driver diagnostics",
                                              "No structured eDP pipe/transcoder association was safely extracted."),
        "panel_power_vdd": _topology_unknown("matched Intel display diagnostics", "inspect read-only driver diagnostics",
                                              "No structured panel power/VDD state was safely extracted."),
        "psr": _topology_unknown("matched Intel display diagnostics", "inspect read-only driver diagnostics",
                                 "No structured PSR capability or runtime state was safely extracted."),
    }
    if len(edp) > 1:
        for key in ("physical_ddi", "aux_channel", "lane_count", "link_rate", "pipe_transcoder"):
            result[key]["ambiguity"] += " Multiple eDP-type connectors make connector-to-port association ambiguous."
    return result


def _debugfs_name_matches_bdf(name: str, bdf: str) -> bool:
    """Require the DRI name's explicit dev field to identify exactly one PCI address."""
    normalized_bdf = bdf.lower()
    identities = {match.lower() for match in re.findall(
        r"\b[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]\b", name)}
    declared = re.findall(r"\bdev=([0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7])\b",
                          name, flags=re.IGNORECASE)
    return identities == {normalized_bdf} and len(declared) == 1 and declared[0].lower() == normalized_bdf


def _scan_debugfs(debug_root: Path, intel_devices: list[dict[str, Any]], raw: dict[str, bytes]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "availability": evidence(None, "/sys/kernel/debug", "inspect already-mounted debugfs only",
                                  status="BLOCKED", availability="UNKNOWN", confidence="none",
                                  interpretation="No automatic mount is attempted.", ambiguity="Availability has not been established."),
        "devices": [],
    }
    try:
        dri_root = debug_root / "dri"
        nodes = sorted(dri_root.iterdir(), key=lambda item: item.name)
    except PermissionError:
        result["availability"] = evidence(None, "/sys/kernel/debug/dri", "list already-mounted debugfs DRI directory",
                                           status="BLOCKED", availability="DENIED", confidence="none",
                                           interpretation="Debugfs data could not be inspected without elevation.",
                                           ambiguity="No privileged retry or mount was attempted.", error="PermissionError")
        return result
    except FileNotFoundError:
        result["availability"] = evidence(False, "/sys/kernel/debug/dri", "inspect already-mounted debugfs DRI directory",
                                           status="BLOCKED", availability="MISSING", confidence="none",
                                           interpretation="No DRI debugfs directory is exposed.",
                                           ambiguity="VBT acquisition through debugfs is blocked.", error="FileNotFoundError")
        return result
    except OSError as exc:
        result["availability"] = evidence(None, "/sys/kernel/debug/dri", "inspect already-mounted debugfs DRI directory",
                                           status="BLOCKED", availability="ERROR", confidence="none",
                                           interpretation="Debugfs could not be inspected.",
                                           ambiguity="VBT acquisition through debugfs is blocked.", error=type(exc).__name__)
        return result
    result["availability"] = evidence(True, "/sys/kernel/debug/dri", "list already-mounted debugfs DRI directory",
                                      interpretation="The existing interface is readable; no mount was attempted.")
    for device in intel_devices:
        matching: list[tuple[Path, str]] = []
        for node in nodes:
            name, _, _ = _read_text(node / "name")
            if name and _debugfs_name_matches_bdf(name, device["bdf"]):
                matching.append((node, name))
        if len(matching) != 1:
            result["devices"].append({
                "bdf": device["bdf"],
                "node": evidence(None, "/sys/kernel/debug/dri", "match debugfs DRI node name to PCI BDF",
                                 status="UNKNOWN", availability="MISSING", confidence="none",
                                 interpretation="No unique DRI debugfs node was linked to this Intel PCI device.",
                                 ambiguity="Could not safely choose a node by card number or enumeration order."),
                "files": {},
            })
            continue
        node, name = matching[0]
        item: dict[str, Any] = {"bdf": device["bdf"],
                                "node": evidence(node.name, "/sys/kernel/debug/dri/*/name",
                                                 "match DRI debugfs name contents to PCI BDF"),
                                "name": evidence(name, f"/sys/kernel/debug/dri/{node.name}/name", "read DRI debugfs name"),
                                "files": {}}
        for filename in ("i915_vbt", "i915_opregion", "i915_display_info", "i915_edp_psr_status"):
            path = node / filename
            data, availability, error = _read_bytes(path)
            if data is None:
                item["files"][filename] = evidence(None, f"/sys/kernel/debug/dri/{node.name}/{filename}",
                                                   "read existing debugfs diagnostic file",
                                                   status="BLOCKED" if availability == "DENIED" else "UNKNOWN",
                                                   availability=availability, confidence="none",
                                                   interpretation="No data was collected.",
                                                   ambiguity="The file may be unavailable for this driver or kernel.", error=error)
                continue
            raw_index = len([name for name in raw if name.startswith("intel-debug-")])
            raw_name = f"intel-debug-{raw_index:02d}-{filename}.bin"
            raw[raw_name] = data
            filespec: dict[str, Any] = {"bytes": len(data), "raw_file": raw_name}
            if filename == "i915_vbt":
                family = (device.get("source_catalog_match", {}).get("value", {}) or {}).get("family")
                parsed = parse_vbt(data, family=family)
                filespec["parsed"] = parsed
                filespec["validation"] = evidence(parsed["valid"], f"/sys/kernel/debug/dri/{node.name}/{filename}",
                                                   "validate VBT signature, bounds, checksum, BDB and child records",
                                                   status="CONFIRMED" if parsed["valid"] else "CONTRADICTED",
                                                   confidence="high" if parsed["valid"] else "none",
                                                   interpretation="Independent bounded parser; raw VBT remains private.",
                                                   ambiguity=parsed["error"] or "Validated fields still describe firmware declarations, not live link state.")
            elif filename in {"i915_display_info", "i915_edp_psr_status"}:
                text = data.decode("utf-8", errors="replace")
                excerpts = [{"line": n, "text": line.strip()[:500]}
                            for n, line in enumerate(text.splitlines(), 1) if _RELEVANT_LOG.search(line)][:120]
                filespec["relevant_lines"] = evidence(excerpts, f"/sys/kernel/debug/dri/{node.name}/{filename}",
                                                      "allowlisted line selection from read-only driver diagnostic",
                                                      status="CONFIRMED" if excerpts else "UNKNOWN",
                                                      confidence="high" if excerpts else "none",
                                                      interpretation="Selected lines are preserved privately for manual topology review.",
                                                      ambiguity="Kernel-version-specific text has not been interpreted as proof of undocumented wiring.")
            else:
                filespec["availability"] = evidence(True, f"/sys/kernel/debug/dri/{node.name}/{filename}",
                                                      "read existing debugfs diagnostic file")
            item["files"][filename] = filespec
        result["devices"].append(item)
    return result


class EvidenceImportError(ValueError):
    """Raised when a staged diagnostic import is unsafe or ambiguously mapped."""


def _open_private_import_directory(path: Path) -> int:
    """Open and pin the final user-owned private import directory without following symlinks."""
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise EvidenceImportError("staged evidence directory is unavailable") from exc
    if not stat.S_ISDIR(before.st_mode) or before.st_uid != os.getuid() or before.st_mode & 0o077:
        raise EvidenceImportError("staged evidence directory must be user-owned and private")
    flags = (os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) |
             getattr(os, "O_DIRECTORY", 0))
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise EvidenceImportError("staged evidence directory could not be opened safely") from exc
    opened = os.fstat(descriptor)
    if (not stat.S_ISDIR(opened.st_mode) or opened.st_uid != os.getuid() or opened.st_mode & 0o077 or
            (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)):
        os.close(descriptor)
        raise EvidenceImportError("staged evidence directory identity changed during validation")
    return descriptor


def _read_import_regular_file(path: Path, limit: int, *, directory_fd: int | None = None) -> bytes:
    """Read a private regular file without following symlinks or accepting races."""
    try:
        before = (os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
                  if directory_fd is not None else os.lstat(path))
    except OSError as exc:
        raise EvidenceImportError("staged evidence path is unavailable") from exc
    if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_mode & 0o077:
        raise EvidenceImportError("staged evidence must be a user-owned private regular file")
    if before.st_size < 1 or before.st_size > limit:
        raise EvidenceImportError("staged evidence file size is outside the allowed bound")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = (os.open(path.name, flags, dir_fd=directory_fd)
                      if directory_fd is not None else os.open(path, flags))
    except OSError as exc:
        raise EvidenceImportError("staged evidence file could not be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != os.getuid() or opened.st_mode & 0o077 or
                (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)):
            raise EvidenceImportError("staged evidence file identity changed during validation")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(limit + 1)
        after = os.fstat(descriptor)
        if (len(data) != before.st_size or len(data) > limit or
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) !=
                (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)):
            raise EvidenceImportError("staged evidence file changed while being read")
        return data
    finally:
        os.close(descriptor)


def _json_object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceImportError("import manifest contains duplicate keys")
        result[key] = value
    return result


def _import_staged_evidence(report: dict[str, Any], raw: dict[str, bytes], import_dir: Path) -> None:
    """Merge previously staged, private i915 debugfs reads into one inventory."""
    directory_fd = _open_private_import_directory(import_dir)
    try:
        _import_staged_evidence_from_fd(report, raw, import_dir, directory_fd)
    finally:
        os.close(directory_fd)


def _import_staged_evidence_from_fd(report: dict[str, Any], raw: dict[str, bytes], import_dir: Path,
                                    directory_fd: int) -> None:
    """Validate a staged import using its pinned private directory descriptor."""
    manifest_path = import_dir / "manifest.json"
    manifest_bytes = _read_import_regular_file(manifest_path, _IMPORT_MANIFEST_LIMIT,
                                               directory_fd=directory_fd)
    try:
        manifest = json.loads(manifest_bytes, object_pairs_hook=_json_object_without_duplicates)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
        raise EvidenceImportError("import manifest is not bounded valid JSON") from exc
    required_keys = {"schema_version", "target_pci_bdf", "collection_method", "source_identity", "files"}
    schema_version = manifest.get("schema_version") if isinstance(manifest, dict) else None
    if (not isinstance(manifest, dict) or set(manifest) != required_keys or
            isinstance(schema_version, bool) or schema_version != 1):
        raise EvidenceImportError("import manifest schema is invalid")

    target_bdf = manifest.get("target_pci_bdf")
    if not isinstance(target_bdf, str) or not _BDF.fullmatch(target_bdf):
        raise EvidenceImportError("import target PCI address is invalid")
    target_bdf = target_bdf.lower()
    matched_devices = [item for item in report["display_controllers"]
                       if item.get("kind") == "Intel" and str(item.get("bdf", "")).lower() == target_bdf]
    if len(matched_devices) != 1:
        raise EvidenceImportError("import target does not uniquely match an observed Intel controller")

    method = manifest.get("collection_method")
    if (not isinstance(method, str) or not method or len(method) > 256 or
            not all(char.isprintable() for char in method)):
        raise EvidenceImportError("import collection method is invalid")

    identity = manifest.get("source_identity")
    if not isinstance(identity, dict) or set(identity) != {"path", "contents"}:
        raise EvidenceImportError("import source identity is invalid")
    identity_path = identity.get("path")
    identity_contents = identity.get("contents")
    identity_match = re.fullmatch(r"/sys/kernel/debug/dri/([0-9]+)/name", identity_path or "") \
        if isinstance(identity_path, str) else None
    if (not identity_match or not isinstance(identity_contents, str) or len(identity_contents) > 4096 or
            not identity_contents or not all(char.isprintable() for char in identity_contents)):
        raise EvidenceImportError("import source identity is invalid")
    node_id = identity_match.group(1)
    if not _debugfs_name_matches_bdf(identity_contents, target_bdf):
        raise EvidenceImportError("debugfs name contents do not uniquely identify the requested Intel controller")

    files = manifest.get("files")
    if not isinstance(files, dict) or not files or not set(files).issubset(_IMPORT_BDB_FILES):
        raise EvidenceImportError("import file list is invalid")
    imported_files: dict[str, tuple[bytes, str, str]] = {}
    filenames: set[str] = set()
    for diagnostic, info in files.items():
        if not isinstance(info, dict) or set(info) != {"filename", "source"}:
            raise EvidenceImportError("import file record is invalid")
        filename, source = info["filename"], info["source"]
        if (not isinstance(filename, str) or filename in {".", ".."} or
                not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", filename) or filename in filenames):
            raise EvidenceImportError("import filename is invalid")
        source_match = re.fullmatch(
            rf"/sys/kernel/debug/dri/{re.escape(node_id)}/{re.escape(diagnostic)}", source or "") \
            if isinstance(source, str) else None
        if not source_match:
            raise EvidenceImportError("import source path does not match the identified debugfs node")
        content = _read_import_regular_file(import_dir / filename, _IMPORT_BDB_FILES[diagnostic],
                                            directory_fd=directory_fd)
        filenames.add(filename)
        imported_files[diagnostic] = (content, source, filename)

    debugfs = report["debugfs"]
    debug_devices = debugfs.setdefault("devices", [])
    existing = [item for item in debug_devices if str(item.get("bdf", "")).lower() == target_bdf]
    if len(existing) > 1:
        raise EvidenceImportError("observed debugfs mapping is ambiguous for the import target")
    device = existing[0] if existing else {
        "bdf": target_bdf,
        "files": {},
    }
    current_node = device.get("node", {}).get("value")
    current_name = device.get("name", {}).get("value")
    if current_node is not None and str(current_node) != node_id:
        raise EvidenceImportError("staged node conflicts with the directly observed debugfs mapping")
    if current_name is not None and current_name != identity_contents:
        raise EvidenceImportError("staged name contents conflict with the directly observed debugfs identity")
    device["node"] = evidence(node_id, identity_path, "match staged debugfs name provenance to Intel PCI address")
    device["name"] = evidence(identity_contents, identity_path, "record staged debugfs name provenance")
    device_files = device.setdefault("files", {})
    for diagnostic in imported_files:
        current = device_files.get(diagnostic, {})
        if isinstance(current, dict) and current.get("raw_file"):
            raise EvidenceImportError("import duplicates directly collected data for the same diagnostic")

    provenance = {
        "manifest_path": str(manifest_path),
        "target_pci_bdf": evidence(target_bdf, "manifest.json", "match explicit import target to one Intel PCI controller"),
        "source_identity_path": evidence(identity_path, "manifest.json", "validate staged debugfs node identity path"),
        "source_identity_contents": evidence(identity_contents, identity_path,
                                              "validate the DRI name content includes only the target PCI address"),
        "collection_method": evidence(method, "manifest.json", "record the declared read-only staging method"),
        "files": {},
    }
    for diagnostic, (content, source, filename) in imported_files.items():
        index = sum(1 for key in raw if key.startswith("intel-import-"))
        raw_name = f"intel-import-{index:02d}-{diagnostic}.bin"
        raw[raw_name] = content
        entry: dict[str, Any] = {
            "bytes": len(content), "raw_file": raw_name,
            "import": evidence(filename, source, "read bounded user-staged regular file through the offline import interface",
                               interpretation="No privileges were requested by the collector; raw bytes remain private.",
                               ambiguity="The manifest records the declared source and method; staging itself is not independently authenticated."),
        }
        if diagnostic == "i915_vbt":
            family = (matched_devices[0].get("source_catalog_match", {}).get("value", {}) or {}).get("family")
            parsed = parse_vbt(content, family=family)
            entry["parsed"] = parsed
            entry["validation"] = evidence(
                parsed["valid"], source, "validate VBT signature, bounds, checksum, BDB and child records",
                status="CONFIRMED" if parsed["valid"] else "CONTRADICTED",
                confidence="high" if parsed["valid"] else "none",
                interpretation="Independent bounded parser; raw VBT remains private.",
                ambiguity=parsed["error"] or "Validated firmware declarations do not establish live link state.",
            )
        elif diagnostic in {"i915_display_info", "i915_edp_psr_status"}:
            text = content.decode("utf-8", errors="replace")
            excerpts = [{"line": number, "text": line.strip()[:500]}
                        for number, line in enumerate(text.splitlines(), 1)
                        if _RELEVANT_LOG.search(line)][:120]
            entry["relevant_lines"] = evidence(
                excerpts, source, "allowlisted line selection from staged read-only driver diagnostic",
                status="CONFIRMED" if excerpts else "UNKNOWN", confidence="high" if excerpts else "none",
                interpretation="Selected lines are preserved privately for manual topology review.",
                ambiguity="Kernel-version-specific text is not treated as proof of undocumented wiring.",
            )
        else:
            entry["availability"] = evidence(True, source, "import staged read-only diagnostic bytes")
        device_files[diagnostic] = entry
        provenance["files"][diagnostic] = {
            "filename": evidence(filename, str(import_dir), "read private staged file"),
            "source": evidence(source, "manifest.json", "record the declared debugfs diagnostic path"),
            "bytes": evidence(len(content), source, "bounded offline file read"),
        }
    device["import_provenance"] = provenance
    if not existing:
        debug_devices.append(device)


def _collect_kernel_logs(raw: dict[str, bytes]) -> dict[str, Any]:
    executable = shutil.which("dmesg")
    if not executable:
        return {"available": evidence(False, "dmesg utility", "resolve known read-only diagnostic utility",
                                       status="UNKNOWN", availability="MISSING", confidence="none",
                                       interpretation="Kernel log collection was skipped.",
                                       ambiguity="The utility is not installed or not on PATH."), "matches": []}
    try:
        result = subprocess.run([executable, "--color=never", "--time-format=iso"],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, timeout=15, check=False, shell=False)
    except PermissionError:
        return {"available": evidence(None, "dmesg utility", "run fixed read-only dmesg invocation",
                                       status="BLOCKED", availability="DENIED", confidence="none",
                                       interpretation="Kernel messages could not be read.",
                                       ambiguity="No elevated retry was attempted.", error="PermissionError"), "matches": []}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"available": evidence(None, "dmesg utility", "run fixed read-only dmesg invocation",
                                       status="UNKNOWN", availability="ERROR", confidence="none",
                                       interpretation="Kernel messages could not be collected.",
                                       ambiguity="The utility failed or timed out.", error=type(exc).__name__), "matches": []}
    if result.returncode:
        return {"available": evidence(None, "dmesg utility", "run fixed read-only dmesg invocation",
                                       status="BLOCKED" if "operation not permitted" in result.stderr.lower() else "UNKNOWN",
                                       availability="DENIED" if "operation not permitted" in result.stderr.lower() else "ERROR",
                                       confidence="none", interpretation="Kernel messages could not be read.",
                                       ambiguity="No permission change was attempted.", error="dmesg_exit_nonzero"), "matches": []}
    lines = [(n, line) for n, line in enumerate(result.stdout.splitlines(), 1) if _RELEVANT_LOG.search(line)]
    selected = "\n".join(line for _, line in lines).encode("utf-8", errors="replace")
    if selected:
        raw["relevant-kernel-messages.log"] = selected
    matches = [{"line": n, "text": line[:500]} for n, line in lines[:200]]
    return {"available": evidence(True, "dmesg utility", "fixed read-only invocation; select graphics-related lines"),
            "matches": evidence(matches, "dmesg output", "select lines matching graphics/display allowlist",
                                 status="CONFIRMED" if matches else "UNKNOWN",
                                 confidence="high" if matches else "none",
                                 interpretation="Selected log text is private and not copied to the shareable report.",
                                 ambiguity="Text alone does not establish runtime driver success.")}


def _system_inventory(sys_root: Path, proc_root: Path, etc_root: Path) -> dict[str, Any]:
    dmi_root = sys_root / "class" / "dmi" / "id"
    cpu_text, cpu_availability, cpu_error = _read_text(proc_root / "cpuinfo")
    if cpu_text is None:
        cpu = evidence(None, "/proc/cpuinfo", "read first CPU stanza with an explicit field allowlist",
                       status="BLOCKED" if cpu_availability == "DENIED" else "UNKNOWN",
                       availability=cpu_availability, confidence="none",
                       interpretation="CPU identification was unavailable.", ambiguity="Source unavailable.", error=cpu_error)
    else:
        cpu = evidence(_parse_cpuinfo(cpu_text), "/proc/cpuinfo", "read first CPU stanza with an explicit field allowlist",
                       interpretation="Only CPU vendor/family/model/stepping/name fields are retained.",
                       ambiguity="This is the host-visible CPU identification, not a GPU qualification.")
    cmdline, cmd_availability, cmd_error = _read_text(proc_root / "cmdline")
    cmd = (_sanitize_cmdline(cmdline, "/proc/cmdline") if cmdline is not None else
           evidence(None, "/proc/cmdline", "read kernel command line then retain allowlisted graphics options",
                    status="BLOCKED" if cmd_availability == "DENIED" else "UNKNOWN",
                    availability=cmd_availability, confidence="none", interpretation="No command-line options collected.",
                    ambiguity="Source unavailable.", error=cmd_error))
    kernel_path = proc_root / "sys" / "kernel" / "osrelease"
    kernel_text, kernel_availability, kernel_error = _read_text(kernel_path)
    kernel = (evidence(kernel_text, "/proc/sys/kernel/osrelease", "read running kernel release")
              if kernel_text is not None else
              evidence(os.uname().release, "uname(2)", "fallback running-kernel release",
                       status="INFERRED", availability=kernel_availability,
                       confidence="medium", interpretation="/proc kernel release was unavailable; uname supplied the value.",
                       ambiguity="No ambiguity identified.", error=kernel_error))
    return {
        "system_vendor": _obs_text(dmi_root / "sys_vendor", sys_root, "/sys"),
        "system_model": _obs_text(dmi_root / "product_name", sys_root, "/sys"),
        "cpu": cpu,
        "kernel": kernel,
        "distribution": _read_os_release(etc_root / "os-release", etc_root, "/etc"),
        "boot_mode": evidence("UEFI" if (sys_root / "firmware" / "efi").exists() else "legacy_or_unknown",
                               "/sys/firmware/efi", "test whether UEFI runtime interface exists",
                               status="CONFIRMED" if (sys_root / "firmware" / "efi").exists() else "INFERRED",
                               confidence="high" if (sys_root / "firmware" / "efi").exists() else "medium",
                               interpretation="An accessible EFI runtime directory indicates UEFI boot.",
                               ambiguity="Absence may reflect disabled/unavailable EFI sysfs rather than legacy firmware."),
        "gpu_kernel_options": cmd,
    }


def _module_inventory(proc_root: Path, sys_root: Path) -> dict[str, Any]:
    path = proc_root / "modules"
    text, availability, error = _read_text(path)
    if text is None:
        return {"active": evidence(None, "/proc/modules", "read module names and allowlist graphics modules",
                                    status="BLOCKED" if availability == "DENIED" else "UNKNOWN",
                                    availability=availability, confidence="none",
                                    interpretation="Active module list is unavailable.", ambiguity="Source unavailable.", error=error),
                "versions": {}}
    allowed = {"i915", "xe", "drm", "drm_kms_helper", "drm_display_helper", "intel_gtt", "i2c_algo_bit"}
    names = [line.split()[0] for line in text.splitlines() if line.split() and line.split()[0] in allowed]
    versions = {}
    for name in names:
        version_path = sys_root / "module" / name / "version"
        versions[name] = _obs_text(version_path, sys_root, "/sys")
    return {"active": evidence(sorted(set(names)), "/proc/modules", "read only allowlisted active graphics modules"),
            "versions": versions}


def collect_inventory(*, sys_root: Path = Path("/sys"), proc_root: Path = Path("/proc"),
                      etc_root: Path = Path("/etc"), debug_root: Path = Path("/sys/kernel/debug"),
                      read_kernel_logs: bool = True,
                      import_evidence_dir: Path | None = None) -> tuple[dict[str, Any], dict[str, bytes]]:
    """Collect observations from supplied roots (defaulting to the running host)."""
    raw: dict[str, bytes] = {}
    system = _system_inventory(sys_root, proc_root, etc_root)
    modules = _module_inventory(proc_root, sys_root)
    pci_devices, pci_scan = _scan_pci(sys_root / "bus" / "pci" / "devices", sys_root)
    intel_devices = [device for device in pci_devices if device["kind"] == "Intel"]
    for device in intel_devices:
        device_id = device["device_id"]["value"]
        try:
            source_path = Path(__file__).resolve().parents[1] / "WhateverXe" / "kern_xelp_devices.hpp"
            source = source_path.read_text(encoding="utf-8")
            match = (re.search(rf"\{{0x{device_id:04X},\s*Family::(\w+),\s*Display::(\w+),\s*GT::(\w+)", source)
                     if device_id is not None else None)
            recognized = bool(match)
            backend = match.group(3) if match else None
            is_tgl_backend = bool(match and match.group(1) == "TigerLake" and
                                  match.group(2) == "XeD" and backend in {"TGLGT2", "TGLG4"})
            classification = "CONDITIONAL" if is_tgl_backend else "UNSUPPORTED"
            device["source_catalog_match"] = evidence(
                {"recognized": recognized, "family": match.group(1) if match else None,
                 "display": match.group(2) if match else None, "gt_backend": backend},
                "WhateverXe/kern_xelp_devices.hpp", "match observed physical device ID to repository device table",
                status="CONFIRMED" if recognized else "CONTRADICTED", confidence="high",
                interpretation="Catalog match confirms device-family recognition only; runtime admission additionally requires the exact donor and physical identity guards.",
                ambiguity="CONDITIONAL means source-catalogued, not proven operational on macOS; board wiring and panel support remain separate.")
            device["compatibility"] = evidence(
                classification, "kern_xelp_devices.hpp and kern_xelp_platform.hpp",
                "classify catalog entry and runtime admission constraints",
                status="INFERRED" if recognized else "CONFIRMED", confidence="high",
                interpretation=("CONDITIONAL: a known backend exists, subject to exact donor, revision and runtime guards." if classification == "CONDITIONAL"
                                else "UNSUPPORTED: no implemented Tiger Lake backend is selected for this PCI device."),
                ambiguity="This classification says nothing about the observed Linux panel mapping or successful macOS eDP operation.")
        except OSError as exc:
            device["source_catalog_match"] = evidence(None, "WhateverXe/kern_xelp_devices.hpp",
                                                      "match observed device ID to the repository Tiger Lake device table",
                                                      status="UNKNOWN", availability="ERROR", confidence="none",
                                                      interpretation="Source comparison was unavailable.", ambiguity="Source file could not be read.",
                                                      error=type(exc).__name__)
    connectors = _scan_connectors(sys_root, intel_devices, raw)
    debugfs = _scan_debugfs(debug_root, intel_devices, raw)
    backlights = _scan_backlights(sys_root, intel_devices)
    topology = _topology_inventory(connectors)
    logs = (_collect_kernel_logs(raw) if read_kernel_logs else {
        "available": evidence(False, "dmesg utility", "kernel log collection disabled for offline fixture",
                               status="UNKNOWN", availability="SKIPPED", confidence="none",
                               interpretation="No system command was executed.", ambiguity="Offline fixture mode.") ,
        "matches": [],
    })
    report = {
        "schema_version": SCHEMA_VERSION,
        "collected_at_utc": _datetime.datetime.now(_datetime.timezone.utc).isoformat(timespec="seconds"),
        "collector": "collect_linux_display.py",
        "collection_safety": evidence("read-only", "collector policy", "read-only sysfs/procfs/already-mounted debugfs and fixed utility invocations",
                                        interpretation="No mount, hardware write, modeset, reset, module action, or privileged retry is performed.",
                                        ambiguity="Some diagnostic interfaces may be unavailable to this user."),
        "system": system,
        "modules": modules,
        "pci_scan": pci_scan,
        "display_controllers": pci_devices,
        "intel_controller_count": evidence(len(intel_devices), "/sys/bus/pci/devices", "filter PCI display-class devices by Intel vendor ID"),
        "connectors": connectors,
        "backlights": backlights,
        "topology": topology,
        "debugfs": debugfs,
        "kernel_messages": logs,
    }
    if import_evidence_dir is not None:
        _import_staged_evidence(report, raw, import_evidence_dir)
    return report, raw


def _run_known_decoder(name: str, args: list[str]) -> tuple[dict[str, Any], bytes | None]:
    executable = shutil.which(name)
    if not executable:
        return evidence(False, name, "resolve optional fixed decoder utility",
                        status="UNKNOWN", availability="MISSING", confidence="none",
                        interpretation="Decoder was not run.", ambiguity="Utility is not installed or not on PATH."), None
    try:
        result = subprocess.run([executable, *args], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=20, check=False, shell=False)
    except PermissionError:
        return evidence(None, name, "run fixed decoder command without a shell", status="BLOCKED",
                        availability="DENIED", confidence="none", interpretation="Decoder could not run.",
                        ambiguity="No elevated retry was attempted.", error="PermissionError"), None
    except (OSError, subprocess.TimeoutExpired) as exc:
        return evidence(None, name, "run fixed decoder command without a shell", status="UNKNOWN",
                        availability="ERROR", confidence="none", interpretation="Decoder could not run.",
                        ambiguity="Utility failed or timed out.", error=type(exc).__name__), None
    output = result.stdout or b""
    return evidence({"exit_code": result.returncode}, name, "run fixed decoder command without a shell",
                    status="CONFIRMED" if result.returncode == 0 else "UNKNOWN",
                    confidence="high" if result.returncode == 0 else "none",
                    interpretation="Decoder output is private and retained separately.",
                    ambiguity="A decoder's output does not imply an operational macOS backend."), output


def run_optional_decoders(report: dict[str, Any], raw: dict[str, bytes], raw_dir: Path) -> None:
    """Run known, fixed, read-only decoders against private copies when present."""
    for device in report["debugfs"].get("devices", []):
        for filename, utility, args_builder in (
            ("i915_vbt", "intel_vbt_decode", lambda path: [f"--file={path}"]),
        ):
            file_info = device.get("files", {}).get(filename)
            if not file_info or "raw_file" not in file_info:
                continue
            path = raw_dir / file_info["raw_file"]
            result, output = _run_known_decoder(utility, args_builder(str(path)))
            file_info["decoder"] = result
            if output:
                name = f"{file_info['raw_file']}.decode.txt"
                raw[name] = output
                file_info["decoder"]["private_output_file"] = name
    for connector in report["connectors"]:
        edid = connector.get("edid", {})
        if edid.get("present", {}).get("value") is not True:
            continue
        name = edid.get("raw_file")
        if name not in raw:
            continue
        path = raw_dir / name
        result, output = _run_known_decoder("edid-decode", [str(path)])
        edid["edid_decode"] = result
        if output:
            out_name = f"{name}.decode.txt"
            raw[out_name] = output
            edid["edid_decode"]["private_output_file"] = out_name


def shareable_inventory(report: dict[str, Any]) -> dict[str, Any]:
    """Construct the non-identifying shareable report from a strict field allowlist."""
    def public_evidence(item: dict[str, Any], source: str) -> dict[str, Any]:
        result = {key: item.get(key) for key in ("value", "status", "availability", "confidence",
                                                   "interpretation", "ambiguity")}
        result["source"] = source
        result["method"] = item.get("method", "read-only collector observation")
        return result

    connectors = []
    for item in report["connectors"]:
        facts = item["edid"].get("facts") or {}
        connectors.append({
            "type": public_evidence(item["type"], "Linux DRM connector interface; connector number omitted"),
            "internal_classification": public_evidence(item["internal"], "Linux DRM connector type"),
            "status": public_evidence(item["status"], "Linux DRM connector interface"),
            "enabled": public_evidence(item["enabled"], "Linux DRM connector interface"),
            "advertised_modes": public_evidence(item["advertised_modes"], "Linux DRM connector modes interface"),
            "current_mode": public_evidence(item["current_mode"], "Linux DRM connector mode interface"),
            "current_color_depth": public_evidence(item["color_depth"], "Linux DRM connector attributes"),
            "edid_present": public_evidence(item["edid"]["present"], "Linux DRM connector EDID interface"),
            "edid_valid": public_evidence(item["edid"]["valid"], "locally validated EDID bytes; binary omitted"),
            "edid_version": public_evidence(facts["edid_version"], "locally parsed EDID; identity fields omitted") if facts.get("edid_version") else None,
            "preferred_timing": public_evidence(facts["preferred_timing"], "locally parsed preferred EDID timing") if facts.get("preferred_timing") else None,
            "physical_dimensions_mm": public_evidence(facts["physical_dimensions_mm"], "locally parsed EDID timing") if facts.get("physical_dimensions_mm") else None,
            "edid_advertised_color_depth_bpc": public_evidence(facts["advertised_color_depth_bpc"], "locally parsed EDID; advertised value, not current scanout") if facts.get("advertised_color_depth_bpc") else None,
        })
    vbt_files = []
    for device in report["debugfs"].get("devices", []):
        vbt = device.get("files", {}).get("i915_vbt", {})
        if "parsed" in vbt:
            parsed = vbt["parsed"]
            vbt_files.append({
                "valid": public_evidence(vbt["validation"], "matched Intel read-only VBT interface; node omitted"),
                "bdb_version": evidence(parsed["bdb_version"], "matched Intel read-only VBT interface",
                                         "parse bounded BDB header", status="CONFIRMED" if parsed["valid"] else "UNKNOWN",
                                         confidence="high" if parsed["valid"] else "none",
                                         interpretation="Firmware metadata version only.", ambiguity="Does not establish runtime display state."),
                "declared_length": evidence(parsed["declared_length"], "matched Intel read-only VBT interface",
                                            "parse bounded VBT header", status="CONFIRMED" if parsed["valid"] else "UNKNOWN",
                                            confidence="high" if parsed["valid"] else "none",
                                            interpretation="VBT header declared length.", ambiguity="Does not establish runtime display state."),
                "header_checksum_valid": evidence(parsed["header_checksum_valid"], "matched Intel read-only VBT interface",
                                                  "validate VBT checksum over declared bytes",
                                                  status="CONFIRMED" if parsed["header_checksum_valid"] is True else
                                                  "CONTRADICTED" if parsed["header_checksum_valid"] is False else "UNKNOWN",
                                                  confidence="high" if isinstance(parsed["header_checksum_valid"], bool) else "none",
                                                  interpretation="Checksum validity for the VBT header-declared extent.",
                                                  ambiguity="A valid checksum does not establish supported topology."),
                "bdb_length": evidence(parsed["bdb_length"], "matched Intel read-only VBT interface",
                                       "parse bounded BDB header", status="CONFIRMED" if parsed["valid"] else "UNKNOWN",
                                       confidence="high" if parsed["valid"] else "none",
                                       interpretation="BDB header declared length.", ambiguity="Does not establish runtime display state."),
                "child_descriptor_stride": evidence(parsed["child_descriptor_stride"], "matched Intel read-only VBT interface",
                                                      "parse General Definitions block", status="CONFIRMED" if parsed["valid"] else "UNKNOWN",
                                                      confidence="high" if parsed["valid"] else "none",
                                                      interpretation="Descriptor byte stride.", ambiguity="Does not establish live connector wiring."),
                "children": [{
                    "port_type": child.get("port_type"),
                    "dvo_port": child.get("dvo_port"), "ddc_pin": child.get("ddc_pin"),
                    "aux_channel": child.get("aux_channel"),
                    "physical_ddi_slot_from_project_parser": child.get("physical_ddi_slot_from_project_parser"),
                    "firmware_internal_flag": child.get("firmware_internal_flag"),
                    "firmware_dp_flag": child.get("firmware_dp_flag"),
                    "descriptor_flags": child.get("descriptor_flags"),
                    "capabilities": child.get("capabilities"),
                    "source": "matched Intel read-only VBT interface; raw firmware omitted",
                    "method": "decode General Definitions child descriptor",
                    "status": "CONFIRMED" if parsed["valid"] else "UNKNOWN",
                    "availability": "AVAILABLE", "confidence": "high" if parsed["valid"] else "none",
                    "interpretation": "These are firmware declarations, not live link state.",
                    "ambiguity": "Firmware DVO/AUX fields do not alone prove connector-to-port association.",
                } for child in parsed["children"]],
            })
    drivers = []
    for device in report["display_controllers"]:
        driver = device["kernel_driver"]["value"]
        if driver:
            drivers.append({"name": public_evidence(device["kernel_driver"], "Linux PCI driver binding"),
                             "controller_kind": device["kind"]})
    observed_vbts = [device.get("files", {}).get("i915_vbt", {})
                     for device in report["debugfs"].get("devices", [])]
    acquired_vbt = any(vbt.get("raw_file") for vbt in observed_vbts)
    acquisition_status = "CONFIRMED" if acquired_vbt else report["debugfs"]["availability"]["status"]
    acquisition_availability = "AVAILABLE" if acquired_vbt else report["debugfs"]["availability"]["availability"]
    if not acquired_vbt:
        unavailable_vbts = [vbt for vbt in observed_vbts if vbt]
        if unavailable_vbts:
            acquisition_status = unavailable_vbts[0].get("status", "UNKNOWN")
            acquisition_availability = unavailable_vbts[0].get("availability", "MISSING")
    acquisition_source = (
        "matched Intel debugfs diagnostic staged for offline import; path omitted"
        if any(vbt.get("import") for vbt in observed_vbts) else
        "matched Intel driver debugfs interface; node omitted"
    )
    acquisition_evidence = evidence(acquisition_status, acquisition_source,
                                    "inspect matched Intel VBT or an offline staged read-only copy",
                                    status=acquisition_status, availability=acquisition_availability,
                                    confidence="none" if acquisition_status in {"BLOCKED", "UNKNOWN"} else "high",
                                    interpretation="VBT acquisition is reported independently from parser results.",
                                    ambiguity="A blocked or missing interface is not treated as absent firmware.")
    return {
        "schema_version": SCHEMA_VERSION,
        "collected_at_utc": report["collected_at_utc"],
        "scope": "Linux read-only display inventory; raw evidence and direct identifiers excluded",
        "kernel_version": public_evidence(report["system"]["kernel"], "running Linux kernel release interface"),
        "active_graphics_modules": public_evidence(report["modules"]["active"], "Linux loaded-module interface"),
        "display_drivers": drivers,
        "intel_controller_count": public_evidence(report["intel_controller_count"], "Linux PCI/DRM association; addresses omitted"),
        "connectors": connectors,
        "vbt": {
            "acquisition": public_evidence(acquisition_evidence, "matched Intel debugfs VBT interface; path omitted"),
            "validated_files": vbt_files,
        },
        "limitations": [
            "Linux connector naming does not establish physical DDI/AUX wiring.",
            "Linux display operation does not establish macOS display-backend support.",
            "Unavailable observations remain unknown or blocked.",
        ],
    }


def _safe_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")


def _format_evidence(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, ensure_ascii=True)
    return "unavailable" if value is None else str(value)


def render_private_markdown(report: dict[str, Any]) -> str:
    lines = ["# Private Linux Display Inventory", "", f"Collected: {report['collected_at_utc']}",
             "", "Raw evidence files are stored in the adjacent `raw/` directory with mode 0600.",
             "This report contains local hardware identifiers and must remain private.", ""]

    def section(title: str, items: list[tuple[str, Any]]) -> None:
        lines.extend([f"## {title}", ""])
        for label, item in items:
            if not isinstance(item, dict) or "value" not in item:
                continue
            lines.append(f"- **{label}:** `{_format_evidence(item['value'])}` — {item['status']} / {item['availability']}; "
                         f"source `{item['source']}`; {item['method']}. Confidence: {item['confidence']}. "
                         f"{item['interpretation']} Ambiguity: {item['ambiguity']}")
        lines.append("")

    section("System and kernel", [(key, report["system"].get(key)) for key in
                                   ("system_vendor", "system_model", "cpu", "kernel", "distribution", "boot_mode", "gpu_kernel_options")])
    section("Active graphics modules", [("modules", report["modules"]["active"])])
    lines.extend(["## PCI display controllers", ""])
    for device in report["display_controllers"]:
        lines.append(f"### {device['kind']} {device['bdf']}")
        lines.append("")
        section(f"PCI {device['bdf']} details", [(key, device[key]) for key in
                ("vendor_id", "device_id", "revision_id", "subsystem_vendor_id", "subsystem_device_id",
                 "pci_class", "kernel_driver", "pci_capabilities", "drm_cards", "source_catalog_match") if key in device])
    lines.extend(["## Intel DRM connectors", ""])
    if not report["connectors"]:
        lines.append("No Intel-associated DRM connectors were observed.\n")
    for connector in report["connectors"]:
        lines.extend([f"### {connector['name']['value']}", ""])
        section(connector["name"]["value"], [(key, connector[key]) for key in
                ("type", "internal", "status", "enabled", "advertised_modes", "current_mode",
                 "associated_drm_card", "associated_pci_bdf")])
        lines.extend(["EDID", ""])
        section("EDID details", [("present", connector["edid"]["present"]), ("valid", connector["edid"]["valid"])])
        if connector["edid"].get("facts"):
            section("EDID decoded fields", list(connector["edid"]["facts"].items()))
    lines.extend(["## Debugfs and firmware", ""])
    lines.append(f"Debugfs availability: {json.dumps(report['debugfs']['availability'], ensure_ascii=True)}\n")
    for device in report["debugfs"].get("devices", []):
        lines.extend([f"### Intel PCI device {device['bdf']}", "", f"DRI node: {json.dumps(device['node'], ensure_ascii=True)}", ""])
        if device.get("import_provenance"):
            lines.extend(["Staged import provenance:", "", json.dumps(device["import_provenance"], indent=2,
                                                                            ensure_ascii=True, sort_keys=True), ""])
        for filename, info in device.get("files", {}).items():
            lines.extend([f"#### `{filename}`", ""])
            lines.append(json.dumps(info, indent=2, ensure_ascii=True, sort_keys=True))
            lines.append("")
    lines.extend(["## Relevant kernel messages", "", json.dumps(report["kernel_messages"], indent=2, ensure_ascii=True, sort_keys=True), ""])
    return "\n".join(lines)


def render_shareable_markdown(summary: dict[str, Any]) -> str:
    def shown(item: dict[str, Any] | None) -> str:
        return "unknown" if item is None or item.get("value") is None else _format_evidence(item["value"])

    def provenance(item: dict[str, Any] | None, fallback: str) -> str:
        return f"{item['status']}; source: {item['source']}" if item else f"UNKNOWN; source: {fallback}"

    lines = ["# Shareable Linux Display Inventory", "",
             f"Collected: {summary['collected_at_utc']}", "",
             "Direct device identifiers, EDID identity fields, raw firmware, local paths, and log text are excluded.", "",
             f"- Kernel: `{shown(summary['kernel_version'])}` ({summary['kernel_version']['status']}; source: {summary['kernel_version']['source']})",
             f"- Active graphics modules: `{', '.join(summary['active_graphics_modules']['value'] or []) or 'unknown'}` ({summary['active_graphics_modules']['status']}; source: {summary['active_graphics_modules']['source']})",
             f"- Intel display controllers observed: `{shown(summary['intel_controller_count'])}` ({summary['intel_controller_count']['status']}; source: {summary['intel_controller_count']['source']})", "",
             "## Connectors", ""]
    if not summary["connectors"]:
        lines.append("No Intel-associated connector was observed.\n")
    for connector in summary["connectors"]:
        modes = connector["advertised_modes"]["value"] or []
        lines.extend([f"### {shown(connector['type'])} ({shown(connector['status'])})", "",
                      f"- Type: `{shown(connector['type'])}` ({connector['type']['status']}; source: {connector['type']['source']})",
                      f"- Internal classification: `{shown(connector['internal_classification'])}` ({connector['internal_classification']['status']}; source: {connector['internal_classification']['source']})",
                      f"- Enabled: `{shown(connector['enabled'])}` ({connector['enabled']['status']})",
                      f"- Advertised modes: `{', '.join(modes) or 'none observed'}` ({connector['advertised_modes']['status']}; source: {connector['advertised_modes']['source']})",
                      f"- Current mode: `{shown(connector['current_mode'])}` ({connector['current_mode']['status']}; source: {connector['current_mode']['source']})",
                      f"- EDID present/valid: `{shown(connector['edid_present'])}` ({connector['edid_present']['status']}; source: {connector['edid_present']['source']}) / `{shown(connector['edid_valid'])}` ({connector['edid_valid']['status']}; source: {connector['edid_valid']['source']})",
                      f"- Preferred timing: `{shown(connector['preferred_timing'])}` ({provenance(connector['preferred_timing'], 'EDID data if available')})",
                      f"- EDID-advertised depth: `{shown(connector['edid_advertised_color_depth_bpc'])}` bpc ({provenance(connector['edid_advertised_color_depth_bpc'], 'EDID data if available')})",
                      f"- Current color depth: `{shown(connector['current_color_depth'])}` ({connector['current_color_depth']['status']}; source: {connector['current_color_depth']['source']})", ""])
    acquisition = summary["vbt"]["acquisition"]
    lines.extend(["## VBT", "", f"- Acquisition status: `{shown(acquisition)}` ({acquisition['status']}; source: {acquisition['source']})"])
    for item in summary["vbt"]["validated_files"]:
        lines.append(f"- Valid: `{shown(item['valid'])}`; BDB version: `{shown(item['bdb_version'])}`; "
                     f"child descriptors: `{len(item['children'])}`; source: {item['valid']['source']}")
        for child in item["children"]:
            lines.append(f"  - DVO `{child['dvo_port']}`, DDC `{child['ddc_pin']}`, AUX `{child['aux_channel']}`, "
                         f"project parser DDI slot `{child['physical_ddi_slot_from_project_parser']}`, "
                         f"internal flag `{child['firmware_internal_flag']}`; {child['status']} from {child['source']}")
    lines.extend(["", "## Limits", ""])
    lines.extend(f"- {item}" for item in summary["limitations"])
    lines.append("")
    return "\n".join(lines)


def _write_private_file(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    os.chmod(path, 0o600)


def _default_state_root() -> Path:
    xdg = os.environ.get("XDG_STATE_HOME")
    if xdg and Path(xdg).is_absolute():
        return Path(xdg) / "whateverxe-mobile" / "p002"
    return Path.home() / ".local" / "state" / "whateverxe-mobile" / "p002"


def _new_session_dir(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(root, 0o700)
    stamp = _datetime.datetime.now(_datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    candidate = root / f"{stamp}-{os.getpid()}"
    suffix = 1
    while candidate.exists():
        candidate = root / f"{stamp}-{os.getpid()}-{suffix}"
        suffix += 1
    candidate.mkdir(mode=0o700)
    raw_dir = candidate / "raw"
    raw_dir.mkdir(mode=0o700)
    os.chmod(candidate, 0o700)
    os.chmod(raw_dir, 0o700)
    return candidate


def write_reports(report: dict[str, Any], raw: dict[str, bytes], output_root: Path) -> Path:
    session = _new_session_dir(output_root)
    raw_dir = session / "raw"
    for name, data in raw.items():
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
            continue
        _write_private_file(raw_dir / name, data)
    run_optional_decoders(report, raw, raw_dir)
    for name, data in raw.items():
        if name not in {path.name for path in raw_dir.iterdir()} and re.fullmatch(r"[A-Za-z0-9_.-]+", name):
            _write_private_file(raw_dir / name, data)
    shareable = shareable_inventory(report)
    _write_private_file(session / "private.json", _safe_json_bytes(report))
    _write_private_file(session / "private.md", render_private_markdown(report).encode("utf-8"))
    _write_private_file(session / "shareable.json", _safe_json_bytes(shareable))
    _write_private_file(session / "shareable.md", render_shareable_markdown(shareable).encode("utf-8"))
    return session


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, default=_default_state_root(),
                        help="private parent directory; default is XDG_STATE_HOME or ~/.local/state")
    parser.add_argument("--import-evidence-dir", type=Path,
                        help="import bounded private diagnostics staged by approved read-only operations; never requests privileges")
    args = parser.parse_args(argv)
    try:
        report, raw = collect_inventory(import_evidence_dir=args.import_evidence_dir)
        session = write_reports(report, raw, args.output_root)
    except EvidenceImportError as exc:
        print(f"collector rejected staged evidence ({exc})", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"collector could not safely write output ({type(exc).__name__})", file=sys.stderr)
        return 2
    print(f"Private inventory: {session / 'private.md'}")
    print(f"Shareable inventory: {session / 'shareable.md'}")
    print(f"Collected Intel display controllers: {report['intel_controller_count']['value']}")
    print(f"Debugfs status: {report['debugfs']['availability']['status']} ({report['debugfs']['availability']['availability']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
