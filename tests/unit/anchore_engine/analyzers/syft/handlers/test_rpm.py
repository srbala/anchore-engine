import pytest

from anchore_engine.analyzers.syft.handlers.rpm import save_entry


class TestRpm:
    @pytest.mark.parametrize(
        "param",
        [
            pytest.param(
                {
                    "findings": {},
                    "engine_entry": {"name": "test"},
                    "pkg_key": "basic-test",
                    "expected": {"name": "test"},
                },
                id="basic-case",
            ),
            pytest.param(
                {
                    "findings": {},
                    "engine_entry": {"name": "test"},
                    "pkg_key": None,
                    "expected": {"name": "test"},
                },
                id="no-pkgkey-case",
            ),
        ],
    )
    def test_save_entry(self, param):
        findings = param["findings"]
        save_entry(findings, param["engine_entry"], param["pkg_key"])
        findings_key = param.get("pkg_key", None)
        if findings_key is None:
            findings_key = param.get("engine_entry", {}).get("name", "test")
        assert (
            findings.get("package_list", {})
            .get("pkgs.allinfo", {})
            .get("base", {})
            .get(findings_key, {})
            == param["expected"]
        )
