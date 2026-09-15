"""Configuration inputs are data; these tests never invoke a backend."""
import copy
import json
import os
import tempfile
import unittest
from pathlib import Path

from azt_config import ConfigError, compare_configs, load_config, parse_config, propose_repair, verify_repair


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        # macOS /var and /tmp aliases are intentionally resolved by the test owner.
        self.root = Path(self.tmp.name).resolve()
        self.protected = str(self.root / "not-the-showcase-name")
        self.base = {"name": "regression", "services": {"worker": {
            "image": "python:3.12-alpine", "working_dir": "/workspace", "labels": {"purpose": "benign"},
            "volumes": [self.mount("./project", "/workspace", False)]}}}

    def mount(self, source, target, read_only=True):
        return {"type": "bind", "source": source, "target": target, "read_only": read_only}

    def write(self, name, data):
        path = self.root / name
        path.write_text(json.dumps(data, indent=2) + "\n")
        return path

    def pair(self, candidate=None):
        return (load_config(self.write("baseline.json", self.base)),
                load_config(self.write("candidate.json", candidate or self.base)))

    def exposed(self):
        data = copy.deepcopy(self.base)
        data["services"]["worker"]["volumes"].append(self.mount(self.protected, "/protected"))
        return data

    def test_unchanged_and_already_repaired(self):
        baseline, candidate = self.pair()
        self.assertEqual([], compare_configs(baseline, candidate, self.protected)["changes"])
        proposal = propose_repair(baseline, candidate, self.protected)
        self.assertEqual("no_change", proposal["status"])
        self.assertEqual(candidate.raw, verify_repair(candidate.path, proposal, baseline, self.protected))

    def test_added_exposure_minimal_repair_and_preserved_settings(self):
        data = self.exposed()
        data["services"]["worker"]["labels"]["keep"] = "candidate setting"
        data["services"]["worker"]["volumes"].append(self.mount("./cache", "/cache", False))
        baseline, candidate = self.pair(data)
        comparison = compare_configs(baseline, candidate, self.protected)
        self.assertFalse(comparison["access_exercised"])
        self.assertTrue(comparison["candidate_declares_protected_access"])
        proposal = propose_repair(baseline, candidate, self.protected)
        repaired = json.loads(verify_repair(candidate.path, proposal, baseline, self.protected))
        expected = copy.deepcopy(data)
        del expected["services"]["worker"]["volumes"][1]
        self.assertEqual(expected, repaired)
        self.assertEqual([1], proposal["affected_indices"])
        self.assertIn("-", proposal["diff"])
        self.assertNotIn('+      "image"', proposal["diff"])

    def test_modified_mount_restores_reviewed_source(self):
        data = copy.deepcopy(self.base)
        data["services"]["worker"]["volumes"][0]["source"] = self.protected
        baseline, candidate = self.pair(data)
        proposal = propose_repair(baseline, candidate, self.protected)
        self.assertEqual(self.base, json.loads(verify_repair(candidate.path, proposal, baseline, self.protected)))

    def test_parent_source_exposes_but_sibling_does_not(self):
        for source, exposed in [(str(self.root), True), (self.protected + "-sibling", False), (self.protected + "/child", False)]:
            data = self.exposed()
            data["services"]["worker"]["volumes"][-1]["source"] = source
            baseline, candidate = self.pair(data)
            self.assertEqual(exposed, compare_configs(baseline, candidate, self.protected)["candidate_declares_protected_access"])

    def test_harmless_changes_not_removed(self):
        data = copy.deepcopy(self.base)
        data["services"]["worker"]["image"] = "python:3.13-alpine"
        data["services"]["worker"]["volumes"].append(self.mount("./benign", "/data"))
        baseline, candidate = self.pair(data)
        proposal = propose_repair(baseline, candidate, self.protected)
        self.assertEqual(candidate.raw.decode(), proposal["repaired_content"])

    def test_stale_and_tampered_proposals_fail(self):
        baseline, candidate = self.pair(self.exposed())
        proposal = propose_repair(baseline, candidate, self.protected)
        altered = copy.deepcopy(proposal)
        altered["repaired_content"] = candidate.raw.decode()
        with self.assertRaises(ConfigError):
            verify_repair(candidate.path, altered, baseline, self.protected)
        altered = copy.deepcopy(proposal)
        altered["unexpected"] = True
        with self.assertRaises(ConfigError):
            verify_repair(candidate.path, altered, baseline, self.protected)
        candidate.path.write_bytes(candidate.raw + b" ")
        with self.assertRaisesRegex(ConfigError, "stale"):
            verify_repair(candidate.path, proposal, baseline, self.protected)

    def test_proposal_cannot_select_protected_resource(self):
        baseline, candidate = self.pair(self.exposed())
        malicious = propose_repair(baseline, candidate, self.protected + "-decoy")
        with self.assertRaises(ConfigError):
            verify_repair(candidate.path, malicious, baseline, self.protected)

    def test_generated_bytes_keep_logical_resolution_and_bounds(self):
        baseline, candidate = self.pair(self.exposed())
        proposal = propose_repair(baseline, candidate, self.protected)
        repaired = parse_config(proposal["repaired_content"].encode(), candidate.path)
        self.assertEqual(baseline.mounts[0]["source"], repaired.mounts[0]["source"])
        with self.assertRaises(ConfigError):
            parse_config(b" " * 65537, candidate.path)

    def test_unsafe_baseline_refused(self):
        self.base = self.exposed()
        baseline, candidate = self.pair()
        with self.assertRaisesRegex(ConfigError, "baseline"):
            propose_repair(baseline, candidate, self.protected)

    def test_malformed_unknown_and_ambiguous_declarations(self):
        variants = []
        for key, value in [("include", ["other.json"]), ("version", "3.9"), ("secrets", {})]:
            data = copy.deepcopy(self.base)
            data[key] = value
            variants.append(data)
        for key, value in [("environment", {"HOME": "/tmp"}), ("command", "echo hi"), ("extends", "other"), ("privileged", False)]:
            data = copy.deepcopy(self.base)
            data["services"]["worker"][key] = value
            variants.append(data)
        for source in ["../escape", "./../escape", "$HOME/secret", "~/secret", "/tmp//path", "./x/", "relative", "/tmp/./path"]:
            data = self.exposed()
            data["services"]["worker"]["volumes"][-1]["source"] = source
            variants.append(data)
        data = self.exposed()
        data["services"]["worker"]["volumes"][-1]["target"] = "/workspace/overlap"
        variants.append(data)
        data = self.exposed()
        data["services"]["worker"]["volumes"][-1] = "./secret:/protected:ro"
        variants.append(data)
        for data in variants:
            with self.subTest(data=data), self.assertRaises(ConfigError):
                load_config(self.write("bad.json", data))
        for raw in [b'{"services":{},"services":{}}', b'{', b'\xff', b'{"x":NaN}', b'[' * 65]:
            path = self.root / "bad.json"
            path.write_bytes(raw)
            with self.assertRaises(ConfigError):
                load_config(path)

    def test_symlink_hardlink_and_fifo_inputs_refused(self):
        path = self.write("regular.json", self.base)
        link = self.root / "link.json"
        link.symlink_to(path)
        with self.assertRaises(ConfigError):
            load_config(link)
        link.unlink()
        os.link(path, link)
        with self.assertRaises(ConfigError):
            load_config(path)
        fifo = self.root / "fifo.json"
        os.mkfifo(fifo)
        with self.assertRaises(ConfigError):
            load_config(fifo)

    def test_multiple_exposures_and_only_item_removed(self):
        self.base["services"]["worker"]["volumes"] = []
        data = self.exposed()
        data["services"]["worker"]["volumes"].append(self.mount(str(self.root), "/second"))
        baseline, candidate = self.pair(data)
        proposal = propose_repair(baseline, candidate, self.protected)
        self.assertEqual([], json.loads(proposal["repaired_content"])["services"]["worker"]["volumes"])

    def test_repair_is_repeatable_and_never_writes_candidate(self):
        baseline, candidate = self.pair(self.exposed())
        first = propose_repair(baseline, candidate, self.protected)
        self.assertEqual(first, propose_repair(baseline, candidate, self.protected))
        repaired = parse_config(verify_repair(candidate.path, first, baseline, self.protected), candidate.path)
        self.assertEqual("no_change", propose_repair(baseline, repaired, self.protected)["status"])
        self.assertEqual(candidate.raw, candidate.path.read_bytes())

    def test_mount_removal_positions_preserve_surrounding_values(self):
        self.base["services"]["worker"]["volumes"] = []
        for mask in range(16):
            data = copy.deepcopy(self.base)
            volumes = [self.mount(self.protected if mask & (1 << i) else "./safe" + str(i), "/resource" + str(i)) for i in range(4)]
            data["services"]["worker"]["volumes"] = volumes
            baseline, candidate = self.pair(data)
            proposal = propose_repair(baseline, candidate, self.protected)
            repaired = json.loads(proposal["repaired_content"])
            self.assertEqual([v for i, v in enumerate(volumes) if not mask & (1 << i)],
                             repaired["services"]["worker"]["volumes"])

    def test_different_config_directories_preserve_baseline_source_authority(self):
        baseline, _ = self.pair()
        alternate = self.root / "other"
        alternate.mkdir()
        data = copy.deepcopy(self.base)
        data["services"]["worker"]["volumes"][0]["source"] = self.protected
        path = alternate / "candidate.json"
        path.write_text(json.dumps(data))
        candidate = load_config(path)
        proposal = propose_repair(baseline, candidate, self.protected)
        repaired = parse_config(verify_repair(path, proposal, baseline, self.protected), path)
        self.assertEqual(baseline.mounts[0]["source"], repaired.mounts[0]["source"])

    def test_boolean_and_layer_conflicts_are_not_coerced(self):
        for value in [0, 1, "true", None]:
            data = self.exposed()
            data["services"]["worker"]["volumes"][-1]["read_only"] = value
            with self.assertRaises(ConfigError):
                load_config(self.write("bad.json", data))
        data = copy.deepcopy(self.base)
        data["services"]["other"] = copy.deepcopy(data["services"]["worker"])
        with self.assertRaises(ConfigError):
            load_config(self.write("bad.json", data))


if __name__ == "__main__":
    unittest.main()
