"""Tier-2 Deterministic Static AST/Import Reachability Analyzer for Python & Node.js.

Runs with zero external secrets and zero LLM tokens to separate actively imported/called
vulnerable packages from unused or transitive-only dependencies.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

from models import ReachabilityEvidence, ReachabilityStatus

SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
    ".next",
    "out",
    "coverage",
    ".pytest_cache",
    ".mypy_cache",
}

# Known PyPI distribution name -> Python top-level import package name mappings
PYPI_TO_IMPORT_MAP: dict[str, set[str]] = {
    "pyyaml": {"yaml"},
    "pillow": {"PIL"},
    "beautifulsoup4": {"bs4"},
    "scikit-learn": {"sklearn"},
    "python-jose": {"jose"},
    "python-multipart": {"multipart", "python_multipart"},
    "python-dotenv": {"dotenv"},
    "pyjwt": {"jwt"},
    "pycryptodome": {"Crypto"},
    "pycryptodomex": {"Cryptodome"},
    "pyopenssl": {"OpenSSL"},
    "python-dateutil": {"dateutil"},
    "opencv-python": {"cv2"},
    "protobuf": {"google"},
    "attrs": {"attr", "attrs"},
    "markupsafe": {"markupsafe"},
    "jinja2": {"jinja2"},
    "werkzeug": {"werkzeug"},
}

JS_EXTENSIONS = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}
JS_CONFIG_PREFIXES = (
    "vite.config.",
    "next.config.",
    "webpack.config.",
    "nuxt.config.",
    "svelte.config.",
    "astro.config.",
    "rollup.config.",
)


def _iter_source_files(root: Path, extensions: set[str]) -> list[Path]:
    files: list[Path] = []
    if not root.is_dir():
        return files
    for path in root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_file() and path.suffix.lower() in extensions:
            files.append(path)
    return sorted(files)


def _normalize_pypi_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def _candidate_python_modules(package_name: str) -> set[str]:
    norm = _normalize_pypi_name(package_name)
    candidates = {
        norm.replace("-", "_"),
        package_name.strip().lower().replace("-", "_"),
        package_name.strip(),
    }
    if norm in PYPI_TO_IMPORT_MAP:
        candidates.update(PYPI_TO_IMPORT_MAP[norm])
    return candidates


def _python_direct_declared_packages(root: Path) -> set[str]:
    declared: set[str] = set()
    req_pattern = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")

    for req_file in root.rglob("requirements*.txt"):
        if any(part in SKIP_DIRS for part in req_file.parts):
            continue
        try:
            for line in req_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                stripped = line.split("#", 1)[0].strip()
                if not stripped or stripped.startswith("-"):
                    continue
                m = req_pattern.match(stripped)
                if m:
                    declared.add(_normalize_pypi_name(m.group(1)))
        except Exception:
            continue

    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        text = pyproject.read_text(encoding="utf-8", errors="ignore")
        for m in re.finditer(r'["\']([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:[<>=!~;\[]|["\'])', text):
            declared.add(_normalize_pypi_name(m.group(1)))

    return declared


def _analyze_python_reachability(root: Path, package_name: str) -> ReachabilityEvidence:
    py_files = _iter_source_files(root, {".py"})
    if not py_files:
        return ReachabilityEvidence(
            status=ReachabilityStatus.UNVERIFIED_LOCKFILE_ONLY,
            is_potentially_reachable=True,
            confidence="LOW",
            explanation=(
                f"No Python source (.py) files found in target directory; "
                f"cannot rule out reachability for '{package_name}' from lockfile alone."
            ),
        )

    candidates = _candidate_python_modules(package_name)
    candidates_lower = {c.lower() for c in candidates}
    matched_files: list[str] = []
    matched_symbols: list[str] = []
    call_sites: list[str] = []

    for py_file in py_files:
        rel_path = str(py_file.relative_to(root)).replace("\\", "/")
        try:
            source = py_file.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source, filename=rel_path)
        except SyntaxError:
            continue

        local_bindings: set[str] = set()
        file_imports: list[str] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top_mod = alias.name.split(".", 1)[0].lower()
                    if top_mod in candidates_lower:
                        bound = alias.asname or alias.name.split(".", 1)[0]
                        local_bindings.add(bound)
                        file_imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    top_mod = node.module.split(".", 1)[0].lower()
                    if top_mod in candidates_lower:
                        for alias in node.names:
                            bound = alias.asname or alias.name
                            local_bindings.add(bound)
                            file_imports.append(f"{node.module}.{alias.name}")

        if not local_bindings:
            continue

        matched_files.append(rel_path)
        for sym in file_imports:
            if sym not in matched_symbols:
                matched_symbols.append(sym)

        # Inspect whether bound names are actually called or instantiated
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                root_name = None
                if isinstance(func, ast.Name):
                    root_name = func.id
                elif isinstance(func, ast.Attribute):
                    curr = func
                    while isinstance(curr, ast.Attribute):
                        curr = curr.value
                    if isinstance(curr, ast.Name):
                        root_name = curr.id
                if root_name and root_name in local_bindings:
                    site = f"{rel_path}:{getattr(node, 'lineno', 0)}"
                    if site not in call_sites:
                        call_sites.append(site)

    if call_sites:
        return ReachabilityEvidence(
            status=ReachabilityStatus.DIRECT_IMPORT_AND_CALL,
            is_potentially_reachable=True,
            matched_files=matched_files[:10],
            matched_symbols=matched_symbols[:15],
            call_sites=call_sites[:15],
            confidence="HIGH",
            explanation=(
                f"Python package '{package_name}' is directly imported and invoked "
                f"at {len(call_sites)} call site(s) across {len(matched_files)} file(s)."
            ),
        )

    if matched_files:
        return ReachabilityEvidence(
            status=ReachabilityStatus.DIRECT_IMPORT,
            is_potentially_reachable=True,
            matched_files=matched_files[:10],
            matched_symbols=matched_symbols[:15],
            confidence="MEDIUM",
            explanation=(
                f"Python package '{package_name}' is directly imported in {len(matched_files)} file(s), "
                f"though no direct top-level function call was matched statically."
            ),
        )

    declared = _python_direct_declared_packages(root)
    if _normalize_pypi_name(package_name) in declared:
        return ReachabilityEvidence(
            status=ReachabilityStatus.DECLARED_DIRECT_DEPENDENCY,
            is_potentially_reachable=False,
            confidence="MEDIUM",
            explanation=(
                f"'{package_name}' is declared in Python dependency manifests but never imported "
                f"in any of the {len(py_files)} scanned .py source file(s)."
            ),
        )

    return ReachabilityEvidence(
        status=ReachabilityStatus.TRANSITIVE_ONLY,
        is_potentially_reachable=False,
        confidence="MEDIUM",
        explanation=(
            f"'{package_name}' appears only as a transitive dependency with zero static imports "
            f"across {len(py_files)} scanned .py source file(s)."
        ),
    )


def _load_package_jsons(root: Path) -> list[tuple[str, dict]]:
    results: list[tuple[str, dict]] = []
    for pkg_json in root.rglob("package.json"):
        if any(part in SKIP_DIRS for part in pkg_json.parts):
            continue
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8", errors="ignore"))
            rel = str(pkg_json.relative_to(root)).replace("\\", "/")
            results.append((rel, data))
        except Exception:
            continue
    return results


def _analyze_npm_reachability(root: Path, package_name: str) -> ReachabilityEvidence:
    js_files = _iter_source_files(root, JS_EXTENSIONS)
    pkg_jsons = _load_package_jsons(root)

    if not js_files and not pkg_jsons:
        return ReachabilityEvidence(
            status=ReachabilityStatus.UNVERIFIED_LOCKFILE_ONLY,
            is_potentially_reachable=True,
            confidence="LOW",
            explanation=(
                f"No JS/TS source files or package.json found; cannot rule out reachability "
                f"for '{package_name}' from lockfile alone."
            ),
        )

    escaped_pkg = re.escape(package_name)
    # Match ES imports, CommonJS require(), and dynamic import() for exact pkg or subpath pkg/...
    es_import_re = re.compile(
        rf"""^\s*import\s+(?:(?P<bindings>[^;'"\n]+?)\s+from\s+)?['"](?P<spec>{escaped_pkg}(?:/[^'"]*)?)['"]""",
        re.MULTILINE,
    )
    cjs_require_re = re.compile(
        rf"""(?:(?:const|let|var)\s+(?P<bindings>[A-Za-z0-9_{{}},\s:$]+?)\s*=\s*)?require\(\s*['"](?P<spec>{escaped_pkg}(?:/[^'"]*)?)['"]\s*\)"""
    )
    dyn_import_re = re.compile(
        rf"""import\(\s*['"](?P<spec>{escaped_pkg}(?:/[^'"]*)?)['"]\s*\)"""
    )

    matched_files: list[str] = []
    matched_symbols: list[str] = []
    call_sites: list[str] = []
    config_hits: list[str] = []

    for js_file in js_files:
        rel_path = str(js_file.relative_to(root)).replace("\\", "/")
        text = js_file.read_text(encoding="utf-8", errors="ignore")
        bound_idents: set[str] = set()
        file_specs: list[str] = []

        for pattern in (es_import_re, cjs_require_re, dyn_import_re):
            for match in pattern.finditer(text):
                spec = match.group("spec")
                file_specs.append(spec)
                bindings = match.groupdict().get("bindings") or ""
                # Extract identifiers from default, namespace (* as x), or destructured ({ a, b: c })
                cleaned = re.sub(r"\*\s+as\s+", "", bindings)
                cleaned = re.sub(r"\b[A-Za-z_$][A-Za-z0-9_$]*\s+as\s+", "", cleaned)
                for ident in re.findall(r"\b[A-Za-z_$][A-Za-z0-9_$]*\b", cleaned):
                    if ident not in {"default", "type", "as", "from"}:
                        bound_idents.add(ident)

        if not file_specs:
            continue

        matched_files.append(rel_path)
        for s in file_specs:
            if s not in matched_symbols:
                matched_symbols.append(s)

        if js_file.name.startswith(JS_CONFIG_PREFIXES):
            config_hits.append(rel_path)

        lines = text.splitlines()
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith(("import ", "const ", "let ", "var ")) and (
                f"'{package_name}" in stripped or f'"{package_name}' in stripped
            ):
                continue
            for ident in bound_idents:
                if re.search(rf"\b{re.escape(ident)}(?:\.[A-Za-z0-9_$]+)?\s*\(", line):
                    site = f"{rel_path}:{idx}"
                    if site not in call_sites:
                        call_sites.append(site)

    # Check package.json direct declaration and CLI script invocations (e.g. "dev": "vite --host")
    declared_direct = False
    script_hits: list[str] = []
    cli_token = package_name.split("/")[-1]
    cli_pattern = re.compile(rf"(?:^|[\s&|;/(]){re.escape(cli_token)}(?:$|[\s&|;)])")

    for rel_pkg, data in pkg_jsons:
        for dep_section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            deps = data.get(dep_section)
            if isinstance(deps, dict) and package_name in deps:
                declared_direct = True
        scripts = data.get("scripts")
        if isinstance(scripts, dict):
            for script_name, cmd in scripts.items():
                if isinstance(cmd, str) and cli_pattern.search(cmd):
                    script_hits.append(f"{rel_pkg}:scripts.{script_name}")
                    if rel_pkg not in matched_files:
                        matched_files.append(rel_pkg)
                    sym = f"npm script '{script_name}': {cmd}"
                    if sym not in matched_symbols:
                        matched_symbols.append(sym)

    if call_sites:
        return ReachabilityEvidence(
            status=ReachabilityStatus.DIRECT_IMPORT_AND_CALL,
            is_potentially_reachable=True,
            matched_files=matched_files[:10],
            matched_symbols=matched_symbols[:15],
            call_sites=call_sites[:15],
            confidence="HIGH",
            explanation=(
                f"npm package '{package_name}' is directly imported and invoked at "
                f"{len(call_sites)} call site(s) across {len(matched_files)} file(s)."
            ),
        )

    if config_hits or script_hits:
        return ReachabilityEvidence(
            status=ReachabilityStatus.BUILD_OR_RUNTIME_CONFIG,
            is_potentially_reachable=True,
            matched_files=matched_files[:10],
            matched_symbols=matched_symbols[:15],
            call_sites=(config_hits + script_hits)[:15],
            confidence="HIGH",
            explanation=(
                f"npm package '{package_name}' is actively wired into build/runtime config or "
                f"npm scripts ({', '.join((config_hits + script_hits)[:3])})."
            ),
        )

    if matched_files:
        return ReachabilityEvidence(
            status=ReachabilityStatus.DIRECT_IMPORT,
            is_potentially_reachable=True,
            matched_files=matched_files[:10],
            matched_symbols=matched_symbols[:15],
            confidence="MEDIUM",
            explanation=(
                f"npm package '{package_name}' is imported in {len(matched_files)} source file(s)."
            ),
        )

    if not js_files:
        return ReachabilityEvidence(
            status=ReachabilityStatus.UNVERIFIED_LOCKFILE_ONLY,
            is_potentially_reachable=True,
            confidence="LOW",
            explanation=(
                f"No JS/TS source files present in target; cannot exclude reachability for '{package_name}'."
            ),
        )

    if declared_direct:
        return ReachabilityEvidence(
            status=ReachabilityStatus.DECLARED_DIRECT_DEPENDENCY,
            is_potentially_reachable=False,
            confidence="MEDIUM",
            explanation=(
                f"'{package_name}' is listed in package.json but never imported or invoked "
                f"across {len(js_files)} scanned JS/TS source file(s)."
            ),
        )

    return ReachabilityEvidence(
        status=ReachabilityStatus.TRANSITIVE_ONLY,
        is_potentially_reachable=False,
        confidence="MEDIUM",
        explanation=(
            f"'{package_name}' is present only as a transitive lockfile dependency with zero "
            f"direct imports across {len(js_files)} scanned JS/TS source file(s)."
        ),
    )


def analyze_reachability(target_dir: Path, ecosystem: str, package_name: str) -> ReachabilityEvidence:
    """Dispatch deterministic Tier-2 static reachability analysis by package ecosystem."""
    eco = ecosystem.strip().lower()
    if eco in {"pypi", "python"}:
        return _analyze_python_reachability(target_dir, package_name)
    if eco in {"npm", "node", "nodejs", "javascript", "typescript"}:
        return _analyze_npm_reachability(target_dir, package_name)

    return ReachabilityEvidence(
        status=ReachabilityStatus.UNVERIFIED_LOCKFILE_ONLY,
        is_potentially_reachable=True,
        confidence="LOW",
        explanation=(
            f"Static Tier-2 reachability for ecosystem '{ecosystem}' is not yet implemented; "
            f"conservatively treated as potentially reachable."
        ),
    )
