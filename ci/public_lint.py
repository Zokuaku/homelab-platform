#!/usr/bin/env python3
"""public_lint (EVOLUTION ev-45 Track B) - the last net before a repository is published. FAIL-CLOSED.

A public repository is permanent: clones, caches and archives outlive a deletion. This check
asks one question of a repository that is about to leave - does ANY object in it carry
something that identifies a person, a network, a company or a place? - and it asks it of the
whole history, never only of the tip: a value removed by a later commit is one click away.

It is a NET, not the reason a file is safe. Files reach a public tree through an allowlist
(scripts/public_export.py); this catches the mistake in the allowlist.

What is scanned (history mode, the default) - every object reachable from every ref:
  blobs     text: every rule. Binary (a NUL byte, a binary extension, or a text file carrying
            a base64 data URI): must be listed by sha256 in the repository's own
            .public-lint.yaml - a text scan cannot read a screenshot.
  trees     every file and directory name.
  commits   author and committer (tags: tagger) against the identity allowlist; their
            timestamps must carry the offset +0000 (git records the machine's time zone on
            every commit, and a time zone is a place - commit with TZ=UTC; a commit already
            published with an offset is accepted by its full id in .public-lint.yaml
            allow.timezone_commits); the message against every rule.

Two kinds of rule:
  private   literals and regexes from the denylist file. That file names what must never
            leave, so it is itself sensitive: it stays outside the public repository and
            nothing inside the repository can switch one of its rules off.
  shape     built in, default-deny: any IPv4 address outside the documentation ranges, any
            MAC address outside the documentation prefix, any 12-digit account number, any
            e-mail address outside the example domains. The repository's .public-lint.yaml
            may allow specific values - in the open, in a diff somebody reviews.

Findings are printed masked (rule, place, first two characters) so a job log never repeats the
value; --show prints it for a local fix.

Usage:
  python public_lint.py REPO --denylist FILE             # whole history, every ref
  python public_lint.py REPO --denylist FILE --staged    # the index + the identity the next
                                                         # commit would carry (pre-commit)
  python public_lint.py DIR  --denylist FILE --dir       # plain files on disk (an export)
  --push-url URL   also require the push target to be on the denylist file's push.allowed list
  PUBLIC_LINT_DENYLIST may name the denylist file instead of --denylist.

Exit codes: 0 clean | 1 findings | 2 the check could not run (no denylist, not a repository,
a shallow clone, a bad config, nothing to scan). Both non-zero codes block.
"""

import argparse
import hashlib
import ipaddress
import os
import re
import subprocess
import sys
import threading
from pathlib import Path

import yaml

CONFIG_NAME = ".public-lint.yaml"
MAX_PER_RULE = 5             # findings printed per rule per object; the rest are counted
MIN_LITERAL = 3              # a shorter literal matches half the alphabet
MIN_ALLOW_PREFIX = 8         # an allow entry wider than a /8 switches the IPv4 rule off

BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".tif", ".tiff", ".pdf", ".zip",
    ".gz", ".tgz", ".bz2", ".xz", ".7z", ".tar", ".jar", ".woff", ".woff2", ".ttf", ".otf",
    ".eot", ".mp3", ".mp4", ".mov", ".wav", ".docx", ".xlsx", ".pptx", ".odt", ".drawio",
}
DATA_URI = re.compile(r"data:[a-z]+/[a-z0-9.+-]+;base64,", re.I)
LFS_POINTER = "version https://git-lfs.github.com/spec/"

# RFC 5737 documentation ranges, loopback, the unspecified / wildcard-mask block and netmasks
DOC_NETS = tuple(ipaddress.ip_network(n) for n in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "127.0.0.0/8", "0.0.0.0/8", "255.0.0.0/8"))
DOC_MAC_PREFIX = "00005e0053"                      # RFC 7042 documentation range
DOC_MACS = {"0" * 12, "f" * 12}
DOC_ACCOUNTS = {"123456789012"} | {d * 12 for d in "0123456789"}
DOC_EMAIL_DOMAINS = ("example.com", "example.org", "example.net")
DOC_EMAIL_TLDS = ("example", "test", "invalid", "localhost")
DOC_EMAILS = {"git@github.com", "git@gitlab.com"}  # scp-style clone URLs read as addresses

IPV4 = re.compile(r"(?<!\w)(?<!\d\.)(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?!\w)(?!\.\d)")
MAC = re.compile(r"(?<![0-9A-Fa-f:-])[0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}"
                 r"(?![0-9A-Fa-f])(?![:-][0-9A-Fa-f])")
# the dotted form network gear prints (three groups of four); at least one hex LETTER is required
# below, or every dotted date and version would read as a MAC
MAC_DOTTED = re.compile(r"(?<![0-9A-Fa-f.])[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}(?![0-9A-Fa-f.])")
ACCOUNT = re.compile(r"(?<![0-9A-Za-z])\d{12}(?![0-9A-Za-z])")
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}")
SHAPE_RULES = ("ipv4", "mac", "account-id", "email")

GATE_KEYS = {"schema", "identity", "rules", "never_allow", "push"}
RULE_KEYS = {"id", "why", "literals", "regexes", "case_sensitive"}
CONFIG_KEYS = {"allow", "binaries"}
ALLOW_KEYS = {"ipv4", "mac", "account_ids", "emails", "timezone_commits"}


class GateError(Exception):
    """The check could not run. Exit 2 - never a pass."""


def mask(value):
    value = str(value)
    return value[:2] + "*" * max(len(value) - 2, 0)


def _unknown(found, allowed, where):
    if not isinstance(found, dict):
        raise GateError(f"{where}: expected a mapping")
    extra = sorted(set(found) - allowed)
    if extra:
        raise GateError(f"{where}: unknown key(s) {extra} - a misspelt key is a section that "
                        f"silently does nothing")


def _list(value, where):
    if value is None:
        return []
    if not isinstance(value, list):
        raise GateError(f"{where}: expected a list")
    return value


def _networks(values, where):
    nets = []
    for value in _list(values, where):
        try:
            nets.append(ipaddress.IPv4Network(str(value), strict=False))
        except ValueError:
            raise GateError(f"{where}: {value!r} is not an IPv4 network")
    return nets


class Gate:
    """The private denylist file: rules, the identity allowlist, what may never be allowed."""

    def __init__(self, path):
        try:
            doc = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        except OSError as e:
            raise GateError(f"denylist {path}: {e.__class__.__name__}")
        except yaml.YAMLError as e:
            raise GateError(f"denylist {path}: not valid YAML ({e.__class__.__name__})")
        if not isinstance(doc, dict) or doc.get("schema") != 1:
            raise GateError(f"denylist {path}: expected a mapping with schema: 1")
        _unknown(doc, GATE_KEYS, "denylist")

        self.rules = []          # (id, compiled pattern, [lower-case literals])
        for rule in _list(doc.get("rules"), "denylist rules"):
            _unknown(rule, RULE_KEYS, "denylist rule")
            rid = rule.get("id")
            literals = [str(x) for x in _list(rule.get("literals"), "denylist rule literals")]
            regexes = [str(x) for x in _list(rule.get("regexes"), "denylist rule regexes")]
            if not rid or not (literals or regexes):
                raise GateError(f"denylist rule {rid or '?'}: needs an id and at least one pattern")
            if rid in SHAPE_RULES or any(rid == r[0] for r in self.rules):
                raise GateError(f"denylist rule {rid}: the id is already taken")
            short = [x for x in literals if len(x) < MIN_LITERAL]
            if short:
                raise GateError(f"denylist rule {rid}: {len(short)} literal(s) shorter than "
                                f"{MIN_LITERAL} characters")
            parts = [re.escape(x) for x in literals] + [f"(?:{x})" for x in regexes]
            try:
                pattern = re.compile("|".join(parts), 0 if rule.get("case_sensitive") else re.I)
            except re.error as e:
                raise GateError(f"denylist rule {rid}: bad regex ({e})")
            if pattern.search(""):
                raise GateError(f"denylist rule {rid}: a pattern matches the empty string")
            self.rules.append((rid, pattern, [x.lower() for x in literals]))
        if not self.rules:
            raise GateError("denylist: no rules - an empty denylist is a dormant control")

        identity = doc.get("identity") or {}
        _unknown(identity, {"emails", "names"}, "denylist identity")
        self.emails = {str(x).lower() for x in _list(identity.get("emails"), "denylist identity.emails")}
        self.names = {str(x) for x in _list(identity.get("names"), "denylist identity.names")}
        if not self.emails:
            raise GateError("denylist: identity.emails is empty - the author check would pass nobody "
                            "or everybody")
        never = doc.get("never_allow") or {}
        _unknown(never, {"ipv4"}, "denylist never_allow")
        self.never_ipv4 = _networks(never.get("ipv4"), "denylist never_allow.ipv4")
        push = doc.get("push") or {}
        _unknown(push, {"allowed"}, "denylist push")
        try:
            self.push_allowed = [re.compile(str(x)) for x in _list(push.get("allowed"), "denylist push.allowed")]
        except re.error as e:
            raise GateError(f"denylist push.allowed: bad regex ({e})")


class RepoConfig:
    """The repository's own .public-lint.yaml: allowed shape values and listed binaries."""

    def __init__(self, text, gate):
        self.ipv4, self.macs, self.accounts, self.emails, self.binaries = [], set(), set(), set(), set()
        self.tz_commits = set()
        if text is None:
            return
        try:
            doc = yaml.safe_load(text) or {}
        except yaml.YAMLError as e:
            raise GateError(f"{CONFIG_NAME}: not valid YAML ({e.__class__.__name__})")
        if not isinstance(doc, dict):
            raise GateError(f"{CONFIG_NAME}: expected a mapping")
        _unknown(doc, CONFIG_KEYS, CONFIG_NAME)
        allow = doc.get("allow") or {}
        _unknown(allow, ALLOW_KEYS, f"{CONFIG_NAME} allow")
        self.ipv4 = _networks(allow.get("ipv4"), f"{CONFIG_NAME} allow.ipv4")
        for net in self.ipv4:
            if net.prefixlen < MIN_ALLOW_PREFIX:
                raise GateError(f"{CONFIG_NAME} allow.ipv4: {net} is wider than a /{MIN_ALLOW_PREFIX}")
            if any(net.overlaps(never) for never in gate.never_ipv4):
                raise GateError(f"{CONFIG_NAME} allow.ipv4: an entry overlaps a range the denylist "
                                f"says may never be allowed")
        self.macs = {re.sub(r"[^0-9a-f]", "", str(x).lower())
                     for x in _list(allow.get("mac"), f"{CONFIG_NAME} allow.mac")}
        self.accounts = {str(x) for x in _list(allow.get("account_ids"), f"{CONFIG_NAME} allow.account_ids")}
        self.emails = {str(x).lower() for x in _list(allow.get("emails"), f"{CONFIG_NAME} allow.emails")}
        # commits (or tags) already published with a time-zone offset, accepted one by one: a FULL
        # object id each, so the entry can never cover a commit that does not exist yet
        self.tz_commits = {str(x).lower() for x in
                           _list(allow.get("timezone_commits"), f"{CONFIG_NAME} allow.timezone_commits")}
        if any(not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", x) for x in self.tz_commits):
            raise GateError(f"{CONFIG_NAME} allow.timezone_commits: every entry is a full commit or tag id")
        for entry in _list(doc.get("binaries"), f"{CONFIG_NAME} binaries"):
            if not isinstance(entry, dict) or not re.fullmatch(r"[0-9a-f]{64}", str(entry.get("sha256", ""))):
                raise GateError(f"{CONFIG_NAME} binaries: every entry needs path:, sha256: (64 hex) and why:")
            if not entry.get("path") or not entry.get("why"):
                raise GateError(f"{CONFIG_NAME} binaries: every entry needs path:, sha256: (64 hex) and why:")
            self.binaries.add(entry["sha256"])


class Scanner:
    def __init__(self, gate, config, show=False):
        self.gate, self.config, self.show = gate, config, show
        self.findings = []       # (rule, scope, where, detail)

    def add(self, rule, scope, where, detail):
        self.findings.append((rule, scope, where, detail))

    def _value(self, value):
        return value if self.show else mask(value)

    def _email_allowed(self, address):
        address = address.lower()
        domain = address.rpartition("@")[2]
        return (address in DOC_EMAILS or address in self.gate.emails or address in self.config.emails
                or any(domain == d or domain.endswith("." + d) for d in DOC_EMAIL_DOMAINS)
                or domain.rpartition(".")[2] in DOC_EMAIL_TLDS)

    def matches(self, text, private_only=False):
        """(rule, offset, matched text) for every hit in text, in rule order."""
        for rid, pattern, _ in self.gate.rules:
            for m in pattern.finditer(text):
                yield rid, m.start(), m.group(0)
        if private_only:
            return
        for m in IPV4.finditer(text):
            octets = [int(g) for g in m.groups()]
            if max(octets) > 255:
                continue
            address = ipaddress.ip_address(".".join(str(o) for o in octets))
            denied = any(address in net for net in self.gate.never_ipv4)
            if denied or not any(address in net for net in DOC_NETS + tuple(self.config.ipv4)):
                yield "ipv4", m.start(), m.group(0)
        for m in list(MAC.finditer(text)) + [d for d in MAC_DOTTED.finditer(text) if re.search("[a-fA-F]", d.group(0))]:
            digits = re.sub(r"[^0-9a-f]", "", m.group(0).lower())
            if not (digits.startswith(DOC_MAC_PREFIX) or digits in DOC_MACS or digits in self.config.macs):
                yield "mac", m.start(), m.group(0)
        for m in ACCOUNT.finditer(text):
            if m.group(0) not in DOC_ACCOUNTS and m.group(0) not in self.config.accounts:
                yield "account-id", m.start(), m.group(0)
        for m in EMAIL.finditer(text):
            if not self._email_allowed(m.group(0)):
                yield "email", m.start(), m.group(0)

    def scan_text(self, text, scope, where, private_only=False, lines=True):
        seen = {}
        for rid, offset, value in self.matches(text, private_only):
            seen[rid] = seen.get(rid, 0) + 1
            if seen[rid] > MAX_PER_RULE:
                continue
            place = f"{where}:{text.count(chr(10), 0, offset) + 1}" if lines else where
            self.add(rid, scope, place, self._value(value))
        for rid, count in seen.items():
            if count > MAX_PER_RULE:
                self.add(rid, scope, where, f"+{count - MAX_PER_RULE} more")

    def scan_blob(self, data, path, scope, label):
        where = f"{label} {path}" if label else path
        digest = hashlib.sha256(data).hexdigest()
        binary = b"\0" in data or Path(path).suffix.lower() in BINARY_EXT
        if binary:
            if digest not in self.config.binaries:
                self.add("unlisted-binary", scope, where,
                         f"sha256 {digest} is not in {CONFIG_NAME} binaries")
            lowered = data.lower()
            for rid, _, literals in self.gate.rules:
                if any(x.encode("utf-8") in lowered or x.encode("utf-16-le") in lowered for x in literals):
                    self.add(rid, scope, where, "a denylisted literal inside a binary file")
            return
        text = data.decode("utf-8", errors="replace")
        if text.startswith(LFS_POINTER) or (Path(path).name == ".gitattributes" and "filter=lfs" in text):
            self.add("lfs-not-scanned", scope, where,
                     "Git LFS keeps the real content outside the repository, where this check cannot read it")
        if DATA_URI.search(text) and digest not in self.config.binaries:
            self.add("embedded-binary", scope, where,
                     f"a base64 data URI - list sha256 {digest} in {CONFIG_NAME} binaries once a human has looked")
        self.scan_text(text, scope, where)

    def scan_name(self, name, scope, where):
        self.scan_text(name, scope, f"{where} (a file name)", lines=False)

    def scan_ident(self, role, name, email, where, scope="history", offset=None):
        # git stamps every commit with the UTC offset of the machine that made it - a time zone,
        # which is a place. Public commits are made with TZ=UTC; any other offset is a finding.
        if offset is not None and offset != "+0000":
            self.add("commit-timezone", scope, where,
                     f"{role} timestamp carries the UTC offset {self._value(offset) if self.show else 'of a time zone'}"
                     f" - commit with TZ=UTC")
        if email.lower() not in self.gate.emails:
            self.add("commit-identity", scope, where,
                     f"{role} address {self._value(email)} is not on the identity allowlist")
        if self.gate.names and name not in self.gate.names:
            self.add("commit-identity", scope, where,
                     f"{role} name {self._value(name)} is not on the identity allowlist")
        self.scan_text(f"{name} {email}", scope, f"{where} ({role})", private_only=True, lines=False)


# ---------------------------------------------------------------- git plumbing

def git(repo, *args):
    try:
        r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True)
    except OSError as e:
        raise GateError(f"git did not start ({e.__class__.__name__})")
    if r.returncode != 0:
        lines = [ln for ln in r.stderr.decode("utf-8", "replace").splitlines() if ln.strip()]
        raise GateError(f"git {args[0]}: " + (lines[-1][:160] if lines else f"exit {r.returncode}"))
    return r.stdout


def read_objects(repo, oids):
    """(oid, type, bytes) for each oid, streamed through one `git cat-file --batch`."""
    proc = subprocess.Popen(["git", "-C", str(repo), "cat-file", "--batch"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    def feed():
        for oid in oids:
            proc.stdin.write(oid.encode("ascii") + b"\n")
        proc.stdin.close()

    threading.Thread(target=feed, daemon=True).start()
    for oid in oids:
        header = proc.stdout.readline().split()
        if len(header) != 3:
            proc.kill()
            raise GateError(f"object {oid[:12]} could not be read - an incomplete clone cannot be vouched for")
        data = proc.stdout.read(int(header[2]))
        if len(data) != int(header[2]) or proc.stdout.read(1) != b"\n":
            proc.kill()
            raise GateError(f"object {oid[:12]} was cut short - git stopped mid-stream")
        yield oid, header[1].decode("ascii"), data
    proc.wait()


def tree_entries(data, id_bytes):
    i = 0
    while i < len(data):
        space = data.index(b" ", i)
        nul = data.index(b"\0", space)
        yield data[space + 1:nul].decode("utf-8", errors="replace")
        i = nul + 1 + id_bytes


def parse_commit(data):
    """({role: (name, email, utc offset)}, message) from a raw commit or tag object. The offset
    is '' when the line carries none - which is itself not '+0000'."""
    head, _, message = data.partition(b"\n\n")
    idents = {}
    for line in head.split(b"\n"):
        role, _, rest = line.partition(b" ")
        if role in (b"author", b"committer", b"tagger"):
            m = re.match(rb"(.*?) ?<(.*?)>(?: -?\d+ ([+-]\d{4}))?", rest)
            idents[role.decode("ascii")] = ((m.group(1), m.group(2), m.group(3) or b"") if m else (rest, b"", b""))
    return ({k: (n.decode("utf-8", "replace"), e.decode("utf-8", "replace"), z.decode("ascii", "replace"))
             for k, (n, e, z) in idents.items()},
            message.decode("utf-8", errors="replace"))


def show_file(repo, spec):
    r = subprocess.run(["git", "-C", str(repo), "show", spec], capture_output=True)
    return r.stdout.decode("utf-8", errors="replace") if r.returncode == 0 else None


def require_repo(repo):
    git(repo, "rev-parse", "--git-dir")
    if git(repo, "rev-parse", "--is-shallow-repository").strip() == b"true":
        raise GateError("shallow clone - the history that is missing cannot be vouched for (fetch with depth 0)")


def scan_history(scanner, repo, tip):
    head = subprocess.run(["git", "-C", str(repo), "rev-parse", "-q", "--verify", "HEAD^{commit}"],
                          capture_output=True).returncode == 0
    # every ref AND the checkout: a pipeline checks out a detached commit that no branch in the
    # job's clone may point at. There is no option to scan less.
    revs = ["--all"] + (["HEAD"] if head else [])
    listing = git(repo, "rev-list", "--objects", *revs).decode("utf-8", errors="replace")
    names = {}
    for line in listing.splitlines():
        oid, _, name = line.partition(" ")
        names.setdefault(oid, name)
    if not names:
        raise GateError("nothing to scan - the repository has no commits")
    tip_ids = set()
    r = subprocess.run(["git", "-C", str(repo), "ls-tree", "-r", tip], capture_output=True)
    if r.returncode == 0:
        tip_ids = {ln.split()[2] for ln in r.stdout.decode("utf-8", "replace").splitlines() if ln.strip()}
    counts = {"commit": 0, "tag": 0, "tree": 0, "blob": 0}
    seen_names = set()           # every commit repeats its unchanged tree entries
    for oid, kind, data in read_objects(repo, list(names)):
        counts[kind] = counts.get(kind, 0) + 1
        short = oid[:8]
        if kind == "blob":
            scope = "tip" if oid in tip_ids else "history"
            scanner.scan_blob(data, names[oid] or oid, scope, f"blob {short}")
        elif kind == "tree":
            for entry in tree_entries(data, len(oid) // 2):
                if entry not in seen_names:
                    seen_names.add(entry)
                    scanner.scan_name(entry, "history", f"tree {short}")
        elif kind in ("commit", "tag"):
            idents, _ = parse_commit(data)
            for role, (name, email, offset) in idents.items():
                scanner.scan_ident(role, name, email, f"{kind} {short}",
                                   offset=None if oid in scanner.config.tz_commits else offset)
            # the WHOLE object, not the message alone: a merged tag (mergetag) and a signature
            # carry names and addresses in header lines the identity check never reads
            # (the three identity lines are left out: scan_ident has already judged them)
            head_text, sep, message = data.decode("utf-8", errors="replace").partition("\n\n")
            rest = [ln for ln in head_text.split("\n") if not ln.startswith(("author ", "committer ", "tagger "))]
            scanner.scan_text("\n".join(rest) + sep + message, "history", f"{kind} {short} message", lines=False)
    return (f"{counts['commit']} commit(s), {counts['tag']} tag(s), {counts['tree']} tree(s), "
            f"{counts['blob']} blob(s)")


def scan_staged(scanner, repo):
    entries = [e for e in git(repo, "ls-files", "-s", "-z").decode("utf-8", "replace").split("\0") if e]
    blobs = []
    for entry in entries:
        meta, _, path = entry.partition("\t")
        blobs.append((meta.split()[1], path))
    for (oid, path), (_, kind, data) in zip(blobs, read_objects(repo, [b[0] for b in blobs])):
        if kind != "blob":
            continue                              # a submodule link has no content here
        scanner.scan_blob(data, path, "staged", "")
        scanner.scan_name(path, "staged", path)
    for role, var in (("author", "GIT_AUTHOR_IDENT"), ("committer", "GIT_COMMITTER_IDENT")):
        m = re.match(r"(.*?) ?<(.*?)>(?: -?\d+ ([+-]\d{4}))?", git(repo, "var", var).decode("utf-8", "replace"))
        if not m:
            raise GateError(f"git var {var}: no identity is configured")
        scanner.scan_ident(role, m.group(1), m.group(2), "next commit", scope="staged", offset=m.group(3) or "")
    return f"{len(blobs)} staged file(s) + the next commit's identity"


def scan_dir(scanner, root):
    count = 0
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        if rel == ".git" or rel.startswith(".git/"):
            continue
        scanner.scan_name(path.name, "files", rel)
        if path.is_symlink():
            scanner.add("symlink", "files", rel, "a symbolic link - its target is not scanned")
        elif path.is_file():
            scanner.scan_blob(path.read_bytes(), rel, "files", "")
            count += 1
    if not count:
        raise GateError(f"nothing to scan - no files under {root}")
    return f"{count} file(s) on disk (no history, no commit identity)"


def run(target, denylist, mode="history", config_path=None, tip="HEAD", push_url=None,
        show=False):
    """Scan and return (findings, summary). Raises GateError when the check cannot run."""
    if not denylist:
        raise GateError("no denylist - pass --denylist or set PUBLIC_LINT_DENYLIST")
    gate = Gate(denylist)
    target = Path(target)
    if mode == "dir":
        if not target.is_dir():
            raise GateError(f"{target} is not a folder")
        text = (target / CONFIG_NAME).read_text(encoding="utf-8") if (target / CONFIG_NAME).is_file() else None
    else:
        require_repo(target)
        text = show_file(target, f":{CONFIG_NAME}" if mode == "staged" else f"{tip}:{CONFIG_NAME}")
    if config_path:
        try:
            text = Path(config_path).read_text(encoding="utf-8")
        except OSError as e:
            raise GateError(f"config {config_path}: {e.__class__.__name__}")
    scanner = Scanner(gate, RepoConfig(text, gate), show=show)
    if push_url is not None and not any(p.search(push_url) for p in gate.push_allowed):
        scanner.add("push-target", "push", "remote", "the push URL is not on the denylist file's push.allowed list")
    if mode == "dir":
        what = scan_dir(scanner, target)
    elif mode == "staged":
        what = scan_staged(scanner, target)
    else:
        what = scan_history(scanner, target, tip)
    return scanner.findings, f"{what}; {len(gate.rules)} private + {len(SHAPE_RULES)} shape rules"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("target", type=Path, nargs="?", default=Path("."))
    ap.add_argument("--denylist", type=Path, default=os.environ.get("PUBLIC_LINT_DENYLIST"))
    ap.add_argument("--config", type=Path, help=f"use this file instead of the repository's {CONFIG_NAME}")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--dir", action="store_true", help="scan plain files on disk, not git history")
    mode.add_argument("--staged", action="store_true", help="scan the index and the next commit's identity")
    ap.add_argument("--tip", default="HEAD", help="the revision findings are labelled 'tip' against")
    ap.add_argument("--push-url", help="also check the push target against push.allowed")
    ap.add_argument("--show", action="store_true", help="print matched values unmasked (local use only)")
    args = ap.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="backslashreplace")
    try:
        findings, summary = run(args.target, args.denylist,
                                mode="dir" if args.dir else "staged" if args.staged else "history",
                                config_path=args.config, tip=args.tip,
                                push_url=args.push_url, show=args.show)
    except GateError as e:
        print(f"public_lint: NOT RUN - {e}", file=sys.stderr)
        return 2
    except Exception as e:  # noqa: BLE001 - a crashed gate is a gate that did not run, said plainly
        print(f"public_lint: NOT RUN - the check crashed ({e.__class__.__name__}: {str(e)[:120]})", file=sys.stderr)
        return 2
    if not findings:
        print(f"public_lint: PASS - {summary}")
        return 0
    order = {"tip": 0, "staged": 0, "files": 0, "push": 0, "history": 1}
    for rule, scope, where, detail in sorted(findings, key=lambda f: (order.get(f[1], 2), f[0], f[2])):
        print(f"  {rule:<16} {scope:<8} {where}  {detail}")
    history_only = sum(1 for f in findings if f[1] == "history")
    print(f"public_lint: FAIL - {len(findings)} finding(s) in {summary}")
    if history_only:
        print(f"  {history_only} are in HISTORY: deleting the file does not remove them. Nothing has been "
              f"pushed yet if this is a pre-push run - rebuild the commits (or the repository), never "
              f"commit a fix on top.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
