"""Package and executable smoke tests."""

import importlib.util
from pathlib import Path

from typer.testing import CliRunner

import azurator
from azurator.cli import app


def test_package_is_importable() -> None:
    assert azurator.__doc__
    assert azurator.__version__


def test_cli_reports_version() -> None:
    result = CliRunner().invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.stdout.strip() == f"azurator {azurator.__version__}"


def test_product_package_contains_no_test_fake_provider() -> None:
    assert importlib.util.find_spec("azurator.providers.fake") is None


def test_manual_binary_workflow_tracks_the_flat_package_layout() -> None:
    workflow = (Path(__file__).parents[1] / ".github" / "workflows" / "pyinstaller.yml").read_text(encoding="utf-8")

    assert "azurator/__main__.py" in workflow
    assert "--paths ." in workflow
    assert "src/azurator" not in workflow
