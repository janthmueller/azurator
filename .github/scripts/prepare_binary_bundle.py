"""Copy project and dependency notices into a PyInstaller bundle."""

from __future__ import annotations

import shutil
import sys
import sysconfig
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

_NOTICE_NAMES = ("license", "copying", "notice")


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: prepare_binary_bundle.py BUNDLE_DIRECTORY")
    repository = Path(__file__).resolve().parents[2]
    bundle = Path(sys.argv[1]).resolve()
    if not bundle.is_dir():
        raise SystemExit(f"bundle directory does not exist: {bundle}")

    for name in ("LICENSE", "README.md", "THIRD_PARTY_NOTICES.md"):
        _copy_file(repository / name, bundle / name)

    license_root = bundle / "licenses"
    for package_name in (*_runtime_dependency_names("azurator"), "pyinstaller"):
        _copy_distribution_notices(package_name, license_root)
    _copy_python_license(license_root)
    return 0


def _runtime_dependency_names(package_name: str) -> tuple[str, ...]:
    """Resolve the installed runtime dependency closure for this platform."""

    root_name = canonicalize_name(package_name)
    pending = [package_name]
    seen = {root_name}
    dependencies: list[str] = []
    while pending:
        package = distribution(pending.pop())
        for raw_requirement in package.requires or ():
            requirement = Requirement(raw_requirement)
            if requirement.marker is not None and not requirement.marker.evaluate({"extra": ""}):
                continue
            normalized = canonicalize_name(requirement.name)
            if normalized in seen:
                continue
            seen.add(normalized)
            dependencies.append(requirement.name)
            pending.append(requirement.name)
    return tuple(sorted(dependencies, key=canonicalize_name))


def _copy_distribution_notices(package_name: str, license_root: Path) -> None:
    try:
        package = distribution(package_name)
    except PackageNotFoundError:
        raise

    notice_files = tuple(
        item
        for item in package.files or ()
        if any(part.casefold().startswith(_NOTICE_NAMES) for part in item.parts)
        or item.name.casefold().startswith(_NOTICE_NAMES)
    )
    if not notice_files:
        raise RuntimeError(f"no license or notice file found for {package_name}")
    destination = license_root / f"{package.metadata['Name']}-{package.version}"
    destination.mkdir(parents=True, exist_ok=True)
    for index, relative in enumerate(notice_files, start=1):
        source = Path(package.locate_file(relative))
        if source.is_file():
            _copy_file(source, destination / f"{index:02d}-{source.name}")


def _copy_python_license(license_root: Path) -> None:
    executable = Path(sys.executable).resolve()
    candidates = (
        Path(sys.base_prefix) / "LICENSE.txt",
        Path(sys.base_prefix) / "LICENSE",
        Path(sysconfig.get_path("stdlib")) / "LICENSE.txt",
        Path(sysconfig.get_path("stdlib")) / "LICENSE",
        executable.parent / "LICENSE.txt",
        executable.parent.parent / "LICENSE.txt",
        executable.parent.parent
        / "share"
        / "doc"
        / f"python{sys.version_info.major}.{sys.version_info.minor}"
        / "LICENSE",
    )
    source = next((item for item in candidates if item.is_file()), None)
    if source is None:
        raise RuntimeError("could not locate the bundled Python runtime license")
    destination = license_root / f"Python-{sys.version_info.major}.{sys.version_info.minor}"
    destination.mkdir(parents=True, exist_ok=True)
    _copy_file(source, destination / source.name)


def _copy_file(source: Path, destination: Path) -> None:
    """Replace an existing notice even when its copied mode is read-only."""

    destination.unlink(missing_ok=True)
    shutil.copy2(source, destination)


if __name__ == "__main__":
    raise SystemExit(main())
