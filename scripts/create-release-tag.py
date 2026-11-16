#!/usr/bin/env python3
"""
create and push <package>-v<version> tags, where package is oonidata or oonipipeline

Usage: scripts/create-release-tag.py {oonidata,oonipipeline}

Checks that the version in <package>/src/<package>/__about__.py is newer than
the latest release before creating the new tag
"""

import json
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

PACKAGES = ("oonidata", "oonipipeline")
# Only oonidata is published to PyPI, oonipipeline releases are GitHub only
PYPI_PACKAGES = ("oonidata",)

CYAN = "\033[36m"
YELLOW = "\033[33m"
RED = "\033[31m"
RESET = "\033[0m"

REPO_ROOT = Path(__file__).resolve().parent.parent


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def git(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(REPO_ROOT), *args],
        check=check,
        capture_output=True,
        text=True,
    )


def version_tuple(v: str) -> tuple[int, ...]:
    """Leading numeric dotted version -> tuple for lexicographic compare,
    anything after it is ignored"""
    m = re.match(r"(\d+(?:\.\d+)*)", v.strip().strip("v"))
    if not m:
        raise ValueError(f"expected a dotted numeric version, got {v}")
    return tuple(int(p) for p in m.group(1).split("."))


def parse_about_version(about_py: Path) -> str:
    text = about_py.read_text(encoding="utf-8")
    m = re.search(r'^VERSION\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if not m:
        raise SystemExit(f"Error: could not parse version from {about_py}")
    return m.group(1)


def fetch_pypi_version(package: str) -> str:
    url = f"https://pypi.org/pypi/{package}/json"
    req = urllib.request.Request(url, headers={"User-Agent": "create-release-tag.py"})
    with urllib.request.urlopen(req, timeout=20) as response:
        data = json.load(response)
    return str(data["info"]["version"])


def max_tag_version(package: str) -> tuple[int, ...]:
    # Make sure we compare against releases pushed by others
    refspec = f"refs/tags/{package}-v*:refs/tags/{package}-v*"
    fetch = git("fetch", "origin", refspec, check=False)
    if fetch.returncode != 0:
        eprint(f"{RED}ERROR{RESET}: could not fetch tags from origin:")
        eprint(fetch.stderr.strip())
        sys.exit(1)
    tags_out = git("tag", "--list", f"{package}-v*").stdout
    best: tuple[int, ...] = (0,)
    for line in tags_out.splitlines():
        try:
            best = max(best, version_tuple(line.strip()[len(f"{package}-v") :]))
        except ValueError:
            continue
    return best


def tag_exists_remote(tag: str) -> bool:
    # ls-remote exits 0 with empty output when the ref is missing.
    out = git(
        "ls-remote",
        "--tags",
        "origin",
        f"refs/tags/{tag}",
    )
    return bool(out.stdout.strip())


def vstr(v_tuple: tuple[int, ...]) -> str:
    return ".".join(map(str, v_tuple))


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in PACKAGES:
        eprint(f"Usage: {sys.argv[0]} {{{','.join(PACKAGES)}}}")
        sys.exit(1)
    package = sys.argv[1]

    current_branch = git("rev-parse", "--abbrev-ref", "HEAD").stdout.strip()
    commit_sha = git("rev-parse", "--short", "HEAD").stdout.strip()

    about_py = REPO_ROOT / package / "src" / package / "__about__.py"
    if not about_py.is_file():
        eprint(f"Error: Missing {package} __about__.py file: {about_py}")
        sys.exit(1)

    try:
        local_version_str = parse_about_version(about_py)
        local_version = version_tuple(local_version_str)
    except ValueError as e:
        eprint(f"Error: {e}")
        sys.exit(1)

    tag_name = f"{package}-v{local_version_str}"

    # returns err if tag is unknown, which is what we want
    tag_exists = git("rev-parse", tag_name, check=False).returncode == 0
    if tag_exists:
        eprint(f"Error: tag {tag_name!r} already exists locally.")
        sys.exit(1)

    if tag_exists_remote(tag_name):
        eprint(f"Error: tag {tag_name!r} already exists on origin.")
        sys.exit(1)

    released_version = max_tag_version(package)
    released_source = "tags"
    if package in PYPI_PACKAGES:
        print("Checking last version from PyPI...")
        try:
            released_version = max(
                released_version, version_tuple(fetch_pypi_version(package))
            )
            released_source = "tags/PyPI"
        except Exception as e:
            eprint(f"Error: failed to fetch PyPI version: {e}")
            sys.exit(1)

    if local_version <= released_version:
        eprint(
            f"{RED}ERROR{RESET}: Local {package} version must be greater than the "
            f"latest release, bump {about_py.relative_to(REPO_ROOT)} before releasing.",
        )
        eprint(f"  Local:    {local_version_str}")
        eprint(f"  Released: {vstr(released_version)} ({released_source})")
        sys.exit(1)

    print("Version number OK!")

    print("Release tag preview:")
    print(f"  Tag scheme:     {package}-v<version>")
    print(f"  Tag:            {CYAN}{tag_name}{RESET}")
    if current_branch == "main":
        print(f"  Branch:         {current_branch}")
    else:
        print(f"  Branch:         {RED}{current_branch} (WARNING: not main){RESET}")
    print(f"  Commit:         {commit_sha}")
    print(
        f"  {package}: {local_version_str} "
        f"(released: {vstr(released_version)} from {released_source})"
    )
    print()
    if current_branch != "main":
        print(
            f"  {YELLOW}WARNING: current branch is '{current_branch}' (not main): "
            f"commit {commit_sha} is not in main{RESET}"
        )

    prompt = f"Create and push tag {CYAN} {tag_name} {RESET} to origin? [y/N] "
    try:
        answer = input(prompt).strip().lower()
    except KeyboardInterrupt as _:
        answer = "n"
        print("\n")
    if answer not in ("y", "yes"):
        print("Aborted.")
        return

    git("tag", "-a", tag_name, "-m", f"Release {tag_name}")
    git("push", "origin", tag_name)
    print(f"Done: pushed {CYAN}{tag_name}{RESET}")


if __name__ == "__main__":
    main()
