"""Regression checks for evidence boundaries and subprocess lifecycle handling."""

from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from analysis import compare, join_session
from run import LiveProcess, decode_config, pilot_passed, run_client, session_rows
from verify import normalize_ja4


def fixture():
    spec = {"attempt_id": "a", "mode": "accepted", "profile": "A"}
    client = {"attempt_id": "a", "profile": "A", "session": "s", "role": "client",
              "client_ip": "127.0.0.1", "client_port": 10001, "server_ip": "127.0.0.1", "server_port": 10002,
              "outer_random": "ab" * 32, "handshake_success": True, "version": 772, "alpn": "h2", "group": 29,
              "hrr": False, "resumed": False, "outer_count": 1, "inner_count": 1, "certificate_verified": True,
              "config_installed": True, "ech_grease_enabled": False, "accepted": True, "config_sha256": "cd" * 32}
    server = {**client, "role": "server", "attempt_id": "", "profile": ""}
    passive = {"client_endpoint": "b", "endpoint_b": {"ip": "127.0.0.1", "port": 10001},
               "endpoint_a": {"ip": "127.0.0.1", "port": 10002}, "complete_hello_pair": True,
               "limitations": [], "transport": [], "server": {"negotiated_version": 772},
               "client": {"outer_random": "ab" * 32, "outer_sni": "public.ech.test", "alpn": "h2",
                          "ja3": "ja3-example", "ja4": "ja4-example", "ech": {"presence": True, "findings": [],
                          "occurrences": [{"status": "complete", "variant": 0, "kdf_id": 1, "aead_id": 1,
                                           "config_id": 42, "enc_length": 32, "ciphertext_length": 128}]}}}
    return [spec], [{"attempt_id": "a", "returncode": 0}], [client], [server], [passive]


class JoinTests(unittest.TestCase):
    def test_accepted_requires_both_endpoints_and_complete_join(self):
        rows, anomalies = join_session("s", *fixture())
        self.assertTrue(rows[0]["eligible"])
        self.assertEqual(rows[0]["label"], "accepted_real")
        self.assertFalse(anomalies)

    def test_missing_or_duplicate_evidence_abstains(self):
        for index in (1, 2, 3, 4):
            for duplicate in (False, True):
                with self.subTest(index=index, duplicate=duplicate):
                    inputs = fixture()
                    inputs[index][:] = inputs[index] * 2 if duplicate else []
                    rows, _ = join_session("s", *inputs)
                    self.assertFalse(rows[0]["eligible"])
                    self.assertEqual(rows[0]["label"], "unknown")

    def test_failures_and_conflicting_endpoint_results_never_become_rejection(self):
        for field, value in (("handshake_success", False), ("accepted", False), ("inner_count", 0),
                             ("certificate_verified", False), ("config_installed", False), ("hrr", True),
                             ("config_sha256", "different")):
            with self.subTest(field=field):
                inputs = fixture()
                inputs[2][0][field] = value
                rows, _ = join_session("s", *inputs)
                self.assertEqual(rows[0]["label"], "unknown")
                self.assertFalse(rows[0]["eligible"])

    def test_tuple_reuse_is_separated_by_outer_random(self):
        inputs = fixture()
        second = deepcopy(inputs)
        second[0][0]["attempt_id"] = second[1][0]["attempt_id"] = second[2][0]["attempt_id"] = "b"
        second[2][0]["outer_random"] = second[3][0]["outer_random"] = "ef" * 32
        second[4][0]["client"]["outer_random"] = "ef" * 32
        combined = [left + right for left, right in zip(inputs, second)]
        rows, anomalies = join_session("s", *combined)
        self.assertTrue(all(row["eligible"] for row in rows))
        self.assertFalse(anomalies)

    def test_one_connection_cannot_label_two_attempts(self):
        inputs = fixture()
        inputs[0].append({**inputs[0][0], "attempt_id": "b"})
        inputs[1].append({**inputs[1][0], "attempt_id": "b"})
        inputs[2].append({**inputs[2][0], "attempt_id": "b"})
        rows, _ = join_session("s", *inputs)
        self.assertTrue(all(not row["eligible"] for row in rows))

    def test_duplicate_schedule_cannot_inflate_counts(self):
        inputs = fixture()
        inputs[0].append(deepcopy(inputs[0][0]))
        rows, _ = join_session("s", *inputs)
        self.assertTrue(all(not row["eligible"] for row in rows))

    def test_unmatched_rows_are_preserved(self):
        inputs = fixture()
        extra = deepcopy(inputs[4][0])
        extra["client"]["outer_random"] = "ef" * 32
        inputs[4].append(extra)
        _, anomalies = join_session("s", *inputs)
        self.assertEqual(anomalies[0]["records"], [extra])

    def test_grease_requires_effective_controls_and_no_acceptance(self):
        inputs = fixture()
        inputs[0][0]["mode"] = "grease"
        inputs[2][0].update(config_installed=False, ech_grease_enabled=True, accepted=False, inner_count=0)
        inputs[3][0].update(accepted=False, inner_count=0)
        rows, _ = join_session("s", *inputs)
        self.assertEqual(rows[0]["label"], "grease")
        self.assertFalse(pilot_passed(rows, []))

    def test_added_variation_does_not_imply_discrimination(self):
        base, _ = join_session("s", *fixture())
        rows = [base[0], {**base[0], "profile": "B"},
                {**base[0], "ciphertext_length": 160},
                {**base[0], "profile": "B", "ciphertext_length": 160}]
        metrics, _ = compare(rows)
        self.assertEqual(metrics[0]["distinct_groups"], 1)
        self.assertEqual(metrics[1]["distinct_groups"], 2)
        self.assertEqual(metrics[1]["shared_observation_fraction"], 1)


class RunnerTests(unittest.TestCase):
    def test_source_paths_follow_repository_layout(self):
        from run import REPO, ENGINE_SOURCE
        self.assertTrue((REPO / "Phase 1/code/db/seed_fingerprints.json").is_file())
        self.assertTrue((ENGINE_SOURCE / "CMakeLists.txt").is_file())

    def test_replay_accepts_explicit_engine_outside_lab_cache(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            source.mkdir()
            (source / "capture.pcap").write_bytes(b"fixture")
            engine = root / "engine"
            engine.write_text('#!/bin/sh\nwhile [ "$#" -gt 0 ]; do\n'
                              'if [ "$1" = "--json" ]; then shift; printf "{}\\n" > "$1"; fi\n'
                              'shift\ndone\n')
            engine.chmod(0o700)
            out = root / "out"
            result = subprocess.run([sys.executable, str(Path(__file__).with_name("run.py")),
                                     "replay", "--source", str(source), "--out", str(out),
                                     "--engine", str(engine)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((out / "0-source.jsonl").read_text(), '{}\n')

    def test_capture_loss_invalidates_otherwise_valid_join(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "s"
            path.mkdir()
            inputs = fixture()
            (path / "schedule.json").write_text(json.dumps(inputs[0]))
            for filename, rows in zip(("attempts.jsonl", "clients.jsonl", "server.jsonl", "engine.jsonl"), inputs[1:]):
                if filename == "server.jsonl":
                    rows = [{**row, "event": "connection"} for row in rows]
                (path / filename).write_text("".join(json.dumps(row) + "\n" for row in rows))
            (path / "capture-status.json").write_text(json.dumps({"returncode": 0, "dropped": 1}))
            rows, anomalies = session_rows(path)
            self.assertFalse(rows[0]["eligible"])
            self.assertEqual(rows[0]["label"], "unknown")
            self.assertEqual(anomalies[0]["source"], "capture")

    def test_timeout_kills_and_reaps_client(self):
        with tempfile.TemporaryDirectory() as temp:
            marker = Path(temp) / "pid"
            code = f"import os,time; open({str(marker)!r},'w').write(str(os.getpid())); time.sleep(30)"
            result = run_client([sys.executable, "-c", code], timeout=0.3)
            self.assertTrue(result["timeout"])
            pid = int(marker.read_text())
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)

    def test_readiness_failure_can_be_cleaned_up(self):
        with tempfile.TemporaryDirectory() as temp:
            child = LiveProcess([sys.executable, "-c", "import time; time.sleep(30)"], Path(temp) / "child.log")
            try:
                with self.assertRaises(RuntimeError):
                    child.ready(lambda line: False, timeout=0.1)
            finally:
                child.stop()
            self.assertIsNotNone(child.process.poll())
            self.assertFalse(child.thread.is_alive())

    def test_existing_output_rejected_before_any_work(self):
        with tempfile.TemporaryDirectory() as temp:
            marker = Path(temp) / "keep"
            marker.write_text("original")
            result = subprocess.run([sys.executable, str(Path(__file__).with_name("run.py")),
                                     "build", "--out", temp], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(marker.read_text(), "original")
            self.assertEqual(len(list(Path(temp).iterdir())), 1)

    def test_single_suite_config_decoder_enforces_framing(self):
        name = b"public.ech.test"
        body = b"\x2a\x00\x20\x00\x20" + bytes(32) + b"\x00\x04\x00\x01\x00\x01\x40" + bytes([len(name)]) + name + b"\x00\x00"
        data = b"\xfe\x0d" + len(body).to_bytes(2, "big") + body
        self.assertEqual(decode_config(data)["maximum_name_length"], 64)
        with self.assertRaises(ValueError):
            decode_config(data[:-1])

    def test_tshark_grease_signature_normalization(self):
        raw = ("t13d1517h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_"
               "0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,ca34,fe0d,ff01_"
               "caca,0904,0905,0906,0403,0804,0401,0503,0805,0501,0806,0601")
        self.assertEqual(normalize_ja4(raw), "t13d1517h2_8daaf6152771_cb7bf5808d99")


if __name__ == "__main__":
    unittest.main()
