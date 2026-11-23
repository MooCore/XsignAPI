import json
import plistlib
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "ipa_tools.py"


class IpaToolsTests(unittest.TestCase):
    def make_ipa(self, path: Path, info=None, extra=None):
        base_info = {
            "CFBundleDisplayName": "Fixture App",
            "CFBundleName": "Fixture App",
            "CFBundleIdentifier": "com.example.fixture",
            "CFBundleShortVersionString": "1.0",
            "CFBundleVersion": "1",
            "CFBundleExecutable": "Fixture",
        }
        base_info.update(info or {})
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("Payload/Fixture.app/Info.plist", plistlib.dumps(base_info, fmt=plistlib.FMT_BINARY))
            archive.writestr("Payload/Fixture.app/Fixture", b"fake Mach-O placeholder")
            for name, content in (extra or {}).items():
                archive.writestr(name, content)

    def run_tool(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True)

    def test_extract_and_patch_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ipa = root / "fixture.ipa"
            extracted = root / "extracted"
            self.make_ipa(ipa)
            result = self.run_tool("extract", "--ipa", str(ipa), "--dest", str(extracted))
            self.assertEqual(result.returncode, 0, result.stderr)
            extract_info = json.loads(result.stdout)
            self.assertEqual(extract_info["metadata"]["bundleId"], "com.example.fixture")

            options = {
                "appName": "Xsign App",
                "bundleId": "com.example.xsign",
                "appVersion": "2.4.0",
                "buildNumber": "24",
                "minimumIOS": "16.0",
                "proMotion": True,
                "gameMode": True,
            }
            patched = self.run_tool("patch", "--app", extract_info["appPath"], "--options", json.dumps(options))
            self.assertEqual(patched.returncode, 0, patched.stderr)
            metadata = json.loads(patched.stdout)
            self.assertEqual(metadata["appName"], "Xsign App")
            self.assertEqual(metadata["bundleId"], "com.example.xsign")
            self.assertEqual(metadata["appVersion"], "2.4.0")
            self.assertEqual(metadata["buildNumber"], "24")

            with (Path(extract_info["appPath"]) / "Info.plist").open("rb") as handle:
                plist = plistlib.load(handle)
            self.assertTrue(plist["CADisableMinimumFrameDurationOnPhone"])
            self.assertTrue(plist["LSSupportsGameMode"])
            self.assertEqual(plist["MinimumOSVersion"], "16.0")

    def test_rejects_zip_slip(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ipa = root / "malicious.ipa"
            extracted = root / "extracted"
            with zipfile.ZipFile(ipa, "w") as archive:
                archive.writestr("Payload/Fixture.app/Info.plist", plistlib.dumps({"CFBundleIdentifier": "x"}))
                archive.writestr("Payload/../../outside.txt", "no")
            result = self.run_tool("extract", "--ipa", str(ipa), "--dest", str(extracted))
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / "outside.txt").exists())

    def test_rejects_archive_without_app_bundle(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ipa = root / "not-an-app.ipa"
            extracted = root / "extracted"
            with zipfile.ZipFile(ipa, "w") as archive:
                archive.writestr("Payload/readme.txt", "not an app")
            result = self.run_tool("extract", "--ipa", str(ipa), "--dest", str(extracted))
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
