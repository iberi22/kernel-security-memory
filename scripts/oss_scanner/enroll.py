#!/usr/bin/env python3
"""Write an OSS-Scanner enrollment (DIR/projects/<name>/project.yaml) and validate it twice.

Validation 1 (KSM, stdlib): mirrors the rules in the upstream validator
(allowed keys, required keys, types, https URLs, email formats, Dockerfile
placement). Validation 2 (upstream): calls check_project() from the pinned
read-only clone's tools/validate.py against the generated directory.

Upstream note: tools/validate.py's CLI hardcodes its own projects/ tree and
takes no path argument, so we import its check_project() (same rules, same
messages) and call it on DIR/projects/<name>/ from a different cwd.
"""

import argparse
import importlib.util
import os
import re
import sys
from pathlib import Path

# A local, read-only clone of https://github.com/anthropics/oss-scanner (pin a commit).
# Its tools/validate.py is the authoritative enrolment validator.
OSS_SCANNER_CLONE_ENV = "OSS_SCANNER_CLONE"

NAME_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,62}")
EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
URL_RE = re.compile(r"https://[^\s#]+(#[A-Za-z0-9._/-]{1,100})?")
REPO_PATH_RE = re.compile(r"(?!/)(?!.*\.\.)[A-Za-z0-9._/-]+")
REQUIRED_KEYS = ("repo", "primary_contact")
OPTIONAL_KEYS = ("auto_ccs", "homepage", "pgp", "disabled",
                 "dockerfile", "threat_model")
ALLOWED_KEYS = REQUIRED_KEYS + OPTIONAL_KEYS


def _load_yaml(path):
    try:
        import yaml  # type: ignore
    except ImportError:
        raise RuntimeError("PyYAML is required for enrollment validation")
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def ksm_validate(project_dir):
    """Stdlib-structure mirror of the upstream rules. Returns [problems]."""
    project_dir = Path(project_dir)
    problems = []
    if not NAME_RE.fullmatch(project_dir.name):
        problems.append("the directory name must be a-z 0 9 . _ - "
                        "(starting with a letter or digit, at most 63)")
        return problems
    config_file = project_dir / "project.yaml"
    if not config_file.is_file():
        return [f"projects/{project_dir.name}/project.yaml is missing"]
    try:
        config = _load_yaml(config_file)
    except Exception as exc:  # noqa: BLE001
        return [f"project.yaml does not parse: {exc}"[:300]]
    if not isinstance(config, dict):
        return ["not a mapping"]
    for key in config:
        if key not in ALLOWED_KEYS:
            problems.append(
                f"unknown field {key!r} (allowed: {', '.join(ALLOWED_KEYS)})")
    for key in REQUIRED_KEYS:
        if not config.get(key):
            problems.append(f"missing {key}")
    for key in ("primary_contact", "homepage", "pgp"):
        if config.get(key) is not None and not isinstance(config[key], str):
            problems.append(f"{key} must be a string")
    if config.get("disabled") is not None and not isinstance(
            config["disabled"], bool):
        problems.append("disabled must be true or false")
    repo = config.get("repo")
    if repo is not None and not (isinstance(repo, str)
                                 and URL_RE.fullmatch(repo)):
        problems.append("repo must be ONE https:// URL of a git repository")
    homepage = config.get("homepage")
    if isinstance(homepage, str) and not URL_RE.fullmatch(
            homepage.split("#", 1)[0]):
        problems.append("homepage must be an https:// URL")
    addresses = []
    if isinstance(config.get("primary_contact"), str):
        addresses.append(config["primary_contact"])
    ccs = config.get("auto_ccs")
    if isinstance(ccs, list) and all(isinstance(a, str) for a in ccs):
        addresses += ccs
    elif ccs is not None:
        problems.append("auto_ccs must be a list of addresses")
    for address in addresses:
        if not EMAIL_RE.fullmatch(address):
            problems.append(f"bad email {address!r}")
    for key in ("dockerfile", "threat_model"):
        value = config.get(key)
        if value is not None and not (
                isinstance(value, str) and REPO_PATH_RE.fullmatch(value)):
            problems.append(
                f"{key} must be a relative path inside your repository")
    beside_dockerfile = (project_dir / "Dockerfile").exists()
    if not beside_dockerfile and config.get("dockerfile") is None:
        problems.append("a Dockerfile is required, in exactly one place: "
                        "beside project.yaml, or in your repository at the "
                        "path you give as dockerfile:")
    if beside_dockerfile and config.get("dockerfile") is not None:
        problems.append("Dockerfile is given both beside project.yaml and "
                        "as dockerfile: in your repository — one place only")
    return problems


def upstream_validate(project_dir, clone):
    """Run the real upstream check_project() on the generated directory.

    Runs with a different cwd to prove the check is path-based, not
    cwd-based. Returns (problems, summary)."""
    spec = importlib.util.spec_from_file_location(
        "oss_scanner_validate", str(Path(clone) / "tools" / "validate.py"))
    module = importlib.util.module_from_spec(spec)
    previous = os.getcwd()
    try:
        os.chdir("/tmp")
        spec.loader.exec_module(module)  # noqa: SIM102
        return module.check_project(Path(project_dir))
    finally:
        os.chdir(previous)


def _yaml_str(value):
    if re.fullmatch(r"[A-Za-z0-9._/#:+@-]+", value):
        return value
    return '"' + value.replace('"', '\\"') + '"'


def write_project_yaml(path, repo_url, contact, homepage,
                       dockerfile, threat_model):
    lines = ["# Enrollment generated by KSM scripts/oss_scanner/enroll.py.",
             f"repo: {_yaml_str(repo_url)}",
             f"primary_contact: {_yaml_str(contact)}"]
    if homepage:
        lines.append(f"homepage: {_yaml_str(homepage)}")
    lines.append("disabled: false")
    lines.append(f"dockerfile: {_yaml_str(dockerfile)}")
    lines.append(f"threat_model: {_yaml_str(threat_model)}")
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", required=True)
    parser.add_argument("--repo-url", required=True)
    parser.add_argument("--contact", required=True)
    parser.add_argument("--homepage", default=None)
    parser.add_argument("--in-repo-dockerfile",
                        default=".oss-scanner/Dockerfile")
    parser.add_argument("--in-repo-threat-model",
                        default=".oss-scanner/threat_model.md")
    parser.add_argument("--out", required=True)
    parser.add_argument("--force", action="store_true",
                        help="Replace an existing DIR/projects/<name>/project.yaml "
                             "(default: refuse to overwrite)")
    parser.add_argument("--oss-scanner-clone", default=os.environ.get(OSS_SCANNER_CLONE_ENV),
                        help="Path to a local anthropics/oss-scanner clone "
                             f"(default: ${OSS_SCANNER_CLONE_ENV})")
    args = parser.parse_args(argv)

    if not NAME_RE.fullmatch(args.name):
        print(f"bad --name {args.name!r}", file=sys.stderr)
        return 2
    if not URL_RE.fullmatch(args.repo_url):
        print(f"bad --repo-url {args.repo_url!r}", file=sys.stderr)
        return 2
    if not EMAIL_RE.fullmatch(args.contact):
        print(f"bad --contact {args.contact!r}", file=sys.stderr)
        return 2
    if args.homepage and not URL_RE.fullmatch(args.homepage):
        print(f"bad --homepage {args.homepage!r}", file=sys.stderr)
        return 2

    project_dir = Path(args.out) / "projects" / args.name
    existing = project_dir / "project.yaml"
    if existing.is_file() and not args.force:
        print(f"refusing to overwrite existing {existing} "
              f"(pass --force to replace)", file=sys.stderr)
        return 2
    project_dir.mkdir(parents=True, exist_ok=True)
    write_project_yaml(project_dir / "project.yaml", args.repo_url,
                       args.contact, args.homepage,
                       args.in_repo_dockerfile, args.in_repo_threat_model)
    print(f"enrollment written to {project_dir / 'project.yaml'}")

    ksm_problems = ksm_validate(project_dir)
    print(f"ksm-checks: {'PASS' if not ksm_problems else 'FAIL'}")
    for problem in ksm_problems:
        print(f"  ksm: {problem}")

    if not args.oss_scanner_clone:
        print(f"upstream-validator: ERROR (pass --oss-scanner-clone or set "
              f"${OSS_SCANNER_CLONE_ENV}; refusing to report PASS without it)")
        return 1
    try:
        upstream_problems, summary = upstream_validate(project_dir, args.oss_scanner_clone)
    except Exception as exc:  # noqa: BLE001
        print(f"upstream-validator: ERROR ({exc})")
        return 1
    print(f"upstream-validator: "
          f"{'PASS' if not upstream_problems else 'FAIL'}")
    for problem in upstream_problems:
        print(f"  upstream: {project_dir.name}: {problem}")
    if summary:
        print(f"  upstream: {summary}")
    return 0 if not ksm_problems and not upstream_problems else 1


if __name__ == "__main__":
    sys.exit(main())
