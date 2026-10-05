import copy
import json
import os
from pathlib import Path
import platform
import tempfile
import unittest
from unittest.mock import patch

import deploy_spoof as spoof


def settings():
    return dict(version=spoof.VERSION, server_ip="127.0.0.2", client_ip="127.0.0.1",
                server_source="127.0.0.3", client_source="127.0.0.4", uplink="tcp", downlink="udp",
                server_port=19443, client_port=19444, overlay_port=19445, bridge_port=19446, socks_port=11004)


class SpoofTests(unittest.TestCase):
    def test_carrier_directions_and_strict_peer_filters(self):
        s = settings()
        server, client = spoof.carrier(s, "server"), spoof.carrier(s, "client")
        self.assertEqual(server["recv_transport"], client["send_transport"])
        self.assertEqual(server["send_transport"], client["recv_transport"])
        self.assertEqual(client["spoof_ip"], server["peer_spoof_ip"])
        self.assertEqual(server["spoof_ip"], client["peer_spoof_ip"])
        self.assertEqual(server["client_port"], client["recv_port"])
        self.assertEqual(server["listen_port"], client["remote_port"])

    def test_reject_invalid_and_unsupported_network_inputs(self):
        for key, value in [("client_source", "::1"), ("server_ip", "224.0.0.1"), ("client_ip", "0.0.0.0"),
                           ("uplink", "icmp"), ("server_port", 0), ("overlay_port", 19443), ("version", "latest")]:
            s = settings()
            s[key] = value
            with self.assertRaises(ValueError):
                spoof.validate(s)

    def test_merge_preserves_existing_routes_profiles_and_inputs(self):
        cfg = dict(routes=[dict(name="Primary", proxy="socks5h://127.0.0.1:11001")],
                   profiles={"All": ["Primary"], "TCP": ["Primary"]}, default_profile="TCP")
        route = dict(routes=[dict(name="Spoof", proxy="socks5h://127.0.0.1:11004")])
        original = copy.deepcopy(cfg)
        merged = spoof.merge_route(cfg, route)
        self.assertEqual(cfg, original)
        self.assertEqual(merged["profiles"]["TCP"], ["Primary"])
        self.assertEqual(merged["profiles"]["All"], ["Primary", "Spoof"])
        self.assertEqual(merged["profiles"]["Emergency"], ["Spoof"])
        self.assertEqual(merged["default_profile"], "TCP")
        with self.assertRaises(ValueError):
            spoof.merge_route(merged, route)

    def test_raw_service_has_only_required_capability(self):
        text = spoof.carrier_unit(Path("/opt/tunnelguard-spoof/client"))
        self.assertIn("CapabilityBoundingSet=CAP_NET_RAW\n", text)
        self.assertIn("ProtectKernelTunables=yes", text)
        self.assertNotIn("CAP_NET_ADMIN", text)
        self.assertNotIn("iptables", text)

    def test_corrupt_offline_binary_never_installed(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            offline = folder/"bad"
            offline.write_bytes(b"not-an-upstream-binary")
            with patch.object(platform, "system", return_value="Linux"), patch.object(platform, "machine", return_value="x86_64"):
                with self.assertRaisesRegex(ValueError, "SHA256"):
                    spoof.install_binary(folder, offline)
            self.assertFalse((folder/"spoof").exists())


if __name__ == "__main__":
    unittest.main()
