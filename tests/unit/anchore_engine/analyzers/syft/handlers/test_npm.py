import pytest

from anchore_engine.analyzers.syft.handlers.npm import save_entry


class TestNpm:
    @pytest.mark.parametrize(
        "param",
        [
            pytest.param(
                {
                    "findings": {},
                    "engine_entry": {
                        "name": "test",
                    },
                    "pkg_key": "basic-test",
                    "expected": {"name": "test"},
                },
                id="basic-case",
            ),
            pytest.param(
                {
                    "findings": {},
                    "engine_entry": {
                        "name": "test",
                        "version": "1.0.0",
                    },
                    "pkg_key": None,
                    "expected": {
                        "name": "test",
                        "version": "1.0.0",
                    },
                },
                id="no-pkgkey-no-location-case",
            ),
            pytest.param(
                {
                    "findings": {},
                    "engine_entry": {"name": "test", "latest": "1.0.1"},
                    "pkg_key": None,
                    "expected": {"name": "test", "latest": "1.0.1"},
                },
                id="no-pkgkey-no-location-no-version-case",
            ),
            pytest.param(
                {
                    "findings": {},
                    "engine_entry": {"name": "test", "location": "/tmp/pkg-test"},
                    "pkg_key": None,
                    "expected": {"name": "test", "location": "/tmp/pkg-test"},
                },
                id="no-pkgkey-location-case",
            ),
        ],
    )
    def test_save_entry(self, param):
        findings = param["findings"]
        save_entry(findings, param["engine_entry"], param["pkg_key"])
        findings_key = param.get("pkg_key", None)
        if findings_key is None:
            engine_entry = param.get("engine_entry", {})
            if "location" in engine_entry:
                findings_key = engine_entry["location"]
            else:
                pkg_name = engine_entry.get("name", "test")
                pkg_version = engine_entry.get(
                    "version", engine_entry.get("latest", "")
                )
                findings_key = "/virtual/npmpkg/{}-{}".format(pkg_name, pkg_version)
        assert (
            findings.get("package_list", {})
            .get("pkgs.npms", {})
            .get("base", {})
            .get(findings_key, {})
            == param["expected"]
        )
