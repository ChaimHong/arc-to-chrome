#!/usr/bin/env python3
"""arc-to-chrome — merge Arc browser data (logins, history, cookies) into Chrome on macOS.

Both browsers are Chromium: same SQLite schemas, same "v10" AES-128-CBC encryption,
different Keychain keys ("Arc Safe Storage" vs "Chrome Safe Storage").
This tool decrypts with Arc's key, re-encrypts with Chrome's key, and merges —
fully offline, and decrypted secrets never touch disk.

Safety properties:
  - strict PKCS#7 validation: wrong keys / corrupt blobs fail decryption instead
    of producing garbage that would be re-encrypted into Chrome
  - fail-closed round-trip verify: every inserted login/cookie is read back and
    decrypted with Chrome's key; any mismatch rolls the whole domain back
  - merge refuses to run while Chrome is running; --dry-run rehearses on copies
  - automatic backup of Chrome's DBs before a real merge

Commands:
    diff      preview what would be merged (read-only, safe while browsers run)
    merge     perform the merge (Chrome must be quit; use --dry-run to rehearse)
    selftest  crypto sanity checks (round-trip, padding tamper, wrong-key)
"""
import argparse
import hashlib
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import time
from contextlib import closing

from Crypto.Cipher import AES

ARC_DIR = os.path.expanduser("~/Library/Application Support/Arc/User Data/Default")
CHROME_DIR = os.path.expanduser("~/Library/Application Support/Google/Chrome/Default")
BACKUP_ROOT = os.path.expanduser("~/arc-to-chrome-backups")
CHROME_EPOCH_OFFSET = 11644473600  # seconds between 1601-01-01 and 1970-01-01

ARC_KEYCHAIN = "Arc Safe Storage"
CHROME_KEYCHAIN = "Chrome Safe Storage"

NAME_RE = re.compile(r"^[a-z_]+$")  # whitelist for table/column names in dynamic SQL
COOKIE_KEY_COLS = ("host_key", "top_frame_site_key", "has_cross_site_ancestor", "name",
                   "path", "source_scheme", "source_port")
DB_FILES = ("Login Data", "History", "Cookies")


class ToolError(Exception):
    pass


# ---------------------------------------------------------------- crypto

def get_key(service):
    """Read a Chromium Safe Storage secret from Keychain, derive the AES-128 key."""
    try:
        pw = subprocess.run(["security", "find-generic-password", "-s", service, "-w"],
                            capture_output=True, text=True, check=True).stdout.rstrip("\n")
    except subprocess.CalledProcessError:
        raise ToolError(f"cannot read Keychain item '{service}' — "
                        "please click Allow in the macOS prompt")
    return hashlib.pbkdf2_hmac("sha1", pw.encode(), b"saltysalt", 1003, 16)


def v10_decrypt(key, blob):
    """Decrypt a Chromium v10 blob with strict PKCS#7 validation.

    Returns plaintext bytes, or None for non-v10 input, malformed length,
    or padding that fails validation (the common case for a wrong key).
    A wrong key therefore lands in the caller's failure count instead of
    silently producing garbage plaintext.
    """
    if not blob or blob[:3] != b"v10":
        return None
    ct = blob[3:]
    if not ct or len(ct) % 16:
        return None
    pt = AES.new(key, AES.MODE_CBC, iv=b" " * 16).decrypt(ct)
    pad = pt[-1]
    if not 1 <= pad <= 16 or pt[-pad:] != bytes([pad]) * pad:
        return None
    return pt[:-pad]


def v10_encrypt(key, pt):
    pad = 16 - (len(pt) % 16)
    pt = pt + bytes([pad]) * pad
    return b"v10" + AES.new(key, AES.MODE_CBC, iv=b" " * 16).encrypt(pt)


# ---------------------------------------------------------------- db helpers

def chrome_running():
    return subprocess.run(["pgrep", "-x", "Google Chrome"],
                          capture_output=True).returncode == 0


def backup_db(src_path, dst_path, attempts=3):
    """Snapshot a browser SQLite DB. Returns "consistent" or "best-effort".

    First tries a lock-coordinated read (journal-aware, transactionally
    consistent) — this succeeds when the browser is closed, and fails with
    "database is locked" within the busy timeout when a running browser
    holds the write lock. Only then falls back to an immutable, lock-free
    read (no journal replay, may be slightly stale) so that diff/--dry-run
    still work while browsers run. Every snapshot is verified with
    quick_check and retried on a torn read.
    """
    for _ in range(attempts):
        if os.path.exists(dst_path):
            os.unlink(dst_path)
        mode = "consistent"
        try:
            with closing(sqlite3.connect(f"file:{src_path}?mode=ro", uri=True,
                                         timeout=2)) as src:
                src.execute("VACUUM INTO ?", (dst_path,))
        except sqlite3.OperationalError:
            mode = "best-effort"
            if os.path.exists(dst_path):
                os.unlink(dst_path)
            with closing(sqlite3.connect(f"file:{src_path}?mode=ro&immutable=1",
                                         uri=True)) as src:
                src.execute("VACUUM INTO ?", (dst_path,))
        with closing(sqlite3.connect(dst_path)) as chk:
            ok = chk.execute("PRAGMA quick_check").fetchone()[0] == "ok"
        if ok:
            os.chmod(dst_path, 0o600)
            return mode
    raise ToolError(f"could not snapshot {src_path} (database busy) — try again")


def check_name(kind, name):
    if not NAME_RE.match(name):
        raise ToolError(f"unexpected {kind} name: {name!r}")


def table_columns(conn, table):
    check_name("table", table)
    cols = [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]
    for c in cols:
        check_name("column", c)
    return cols


def insert_row(conn, table, row, cols):
    check_name("table", table)
    conn.execute(f"INSERT INTO {table} ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
                 [row.get(c) for c in cols])


def require_profile_files():
    for base, label in ((ARC_DIR, "Arc"), (CHROME_DIR, "Chrome")):
        for name in DB_FILES:
            p = os.path.join(base, name)
            if not os.path.exists(p):
                raise ToolError(f"{label} profile file not found: {p} "
                                f"(is {label} installed with a Default profile?)")


def backup_chrome_profile():
    dest = os.path.join(BACKUP_ROOT, time.strftime("%Y%m%d-%H%M%S"))
    os.makedirs(dest, mode=0o700)
    os.chmod(dest, 0o700)
    for name in DB_FILES:  # Chrome is quit here, so these are consistent snapshots
        backup_db(os.path.join(CHROME_DIR, name), os.path.join(dest, name))
    return dest


def cookie_key(d):
    return tuple(d[c] for c in COOKIE_KEY_COLS)


# ---------------------------------------------------------------- plan layer
# Read-only decision core shared by diff and merge: same rules, one implementation.
# Prepared rows carry decrypted plaintext ("_pt") in memory only.

def plan_logins(arc_path, chrome_path, arc_key):
    with closing(sqlite3.connect(arc_path)) as arc, \
         closing(sqlite3.connect(chrome_path)) as main:
        cols, arc_cols = table_columns(main, "logins"), table_columns(arc, "logins")
        existing = set(main.execute("SELECT signon_realm, username_value FROM logins"))
        rows, skipped, failed = [], 0, 0
        for row in arc.execute("SELECT * FROM logins WHERE blacklisted_by_user = 0"):
            d = dict(zip(arc_cols, row))
            if (d["signon_realm"], d["username_value"]) in existing:
                skipped += 1
                continue
            pt = v10_decrypt(arc_key, d["password_value"])
            # None = wrong key / corrupt blob; b"" = empty password (not worth
            # migrating). Both land in the "failed" count — reported in the
            # summary as "undecryptable/empty", never silently dropped.
            if not pt:
                failed += 1
                continue
            d = {k: v for k, v in d.items() if k in cols and k != "id"}
            d["_pt"] = pt
            rows.append(d)
        return {"rows": rows, "skipped": skipped, "failed": failed}


def iter_new_visits(arc_conn, arc_v_cols, urlmap, new_arc_ids, existing_visits, seen_new):
    """Single source of truth for visit dedupe rules (used by plan and apply)."""
    for row in arc_conn.execute("SELECT * FROM visits"):
        d = dict(zip(arc_v_cols, row))
        if d["url"] in urlmap:
            key = (urlmap[d["url"]], d["visit_time"])
            if key in existing_visits:
                continue
            existing_visits.add(key)
        elif d["url"] in new_arc_ids:
            key = (d["url"], d["visit_time"])
            if key in seen_new:
                continue
            seen_new.add(key)
        else:
            continue
        yield d


def plan_history(arc_path, chrome_path):
    with closing(sqlite3.connect(arc_path)) as arc, \
         closing(sqlite3.connect(chrome_path)) as main:
        url_cols = table_columns(main, "urls")
        if url_cols != table_columns(arc, "urls"):
            raise ToolError("urls schema mismatch between Arc and Chrome")
        arc_v_cols = table_columns(arc, "visits")
        existing_urls = {u: i for u, i in main.execute("SELECT url, id FROM urls")}
        urlmap, new_urls = {}, []
        arc_url_count = 0
        for row in arc.execute("SELECT * FROM urls"):
            d = dict(zip(url_cols, row))
            arc_url_count += 1
            if d["url"] in existing_urls:
                urlmap[d["id"]] = existing_urls[d["url"]]
            else:
                new_urls.append((d["id"], {k: v for k, v in d.items() if k != "id"}))
        new_arc_ids = {arc_id for arc_id, _ in new_urls}
        existing_visits = set(main.execute("SELECT url, visit_time FROM visits"))
        arc_visit_count = arc.execute("SELECT COUNT(*) FROM visits").fetchone()[0]
        new_visits = sum(1 for _ in iter_new_visits(
            arc, arc_v_cols, urlmap, new_arc_ids, existing_visits, set()))
        return {"new_urls": new_urls, "urlmap": urlmap,
                "new_visits": new_visits, "arc_v_cols": arc_v_cols,
                "arc_url_count": arc_url_count, "arc_visit_count": arc_visit_count}


def plan_cookies(arc_path, chrome_path, arc_key):
    with closing(sqlite3.connect(arc_path)) as arc, \
         closing(sqlite3.connect(chrome_path)) as main:
        cols = table_columns(main, "cookies")
        arc_cols = table_columns(arc, "cookies")
        if cols != arc_cols:
            raise ToolError("cookies schema mismatch between Arc and Chrome")
        chr_map = {}
        for row in main.execute(f"SELECT {','.join(COOKIE_KEY_COLS)}, last_update_utc "
                                "FROM cookies"):
            chr_map[tuple(row[:-1])] = row[-1]
        now = int((time.time() + CHROME_EPOCH_OFFSET) * 1e6)
        insert, overwrite, kept, expired, failed = [], [], 0, 0, 0
        # Arc stores encrypted_value with TEXT storage class; CAST forces bytes back
        sel = ", ".join(f"CAST({c} AS BLOB)" if c == "encrypted_value" else c
                        for c in arc_cols)
        for row in arc.execute(f"SELECT {sel} FROM cookies"):
            d = dict(zip(arc_cols, row))
            if d["expires_utc"] and d["expires_utc"] < now:
                expired += 1
                continue
            pt = v10_decrypt(arc_key, d["encrypted_value"])
            if pt is None:
                failed += 1
                continue
            d["_pt"] = pt
            k = cookie_key(d)
            if k in chr_map:
                if d["last_update_utc"] <= chr_map[k]:
                    kept += 1
                    continue
                overwrite.append(d)
            else:
                insert.append(d)
        return {"insert": insert, "overwrite": overwrite, "kept": kept,
                "expired": expired, "failed": failed, "cols": cols}


# ---------------------------------------------------------------- apply layer
# Write path used by merge (real targets) and --dry-run (scratch copies).
# Fail-closed: a failed round-trip verify rolls the whole domain back.

def apply_logins(plan, chrome_path, chr_key):
    inserted = 0
    with closing(sqlite3.connect(chrome_path)) as main:
        try:
            for d in plan["rows"]:
                pt = d["_pt"]
                row = {k: v for k, v in d.items() if k != "_pt"}
                row["password_value"] = v10_encrypt(chr_key, pt)
                insert_row(main, "logins", row, tuple(row))
                back = main.execute("SELECT password_value FROM logins "
                                    "WHERE id = last_insert_rowid()").fetchone()[0]
                if v10_decrypt(chr_key, back) != pt:
                    raise ToolError(
                        f"round-trip verify failed for {d['signon_realm']} — "
                        "logins rolled back, nothing was written")
                inserted += 1
        except Exception:
            main.rollback()
            raise
        main.commit()
        total = main.execute("SELECT COUNT(*) FROM logins").fetchone()[0]
    return (f"logins: +{inserted} new ({inserted}/{inserted} verify ok), "
            f"{plan['skipped']} already present, {plan['failed']} undecryptable/empty "
            f"| chrome total: {total}")


def apply_history(plan, arc_path, chrome_path):
    new_urls = new_visits = 0
    with closing(sqlite3.connect(arc_path)) as arc, \
         closing(sqlite3.connect(chrome_path)) as main:
        v_cols = table_columns(main, "visits")
        cur = main.cursor()
        urlmap = dict(plan["urlmap"])
        for arc_id, d in plan["new_urls"]:
            insert_row(cur, "urls", d, tuple(d))
            urlmap[arc_id] = cur.lastrowid  # exact arc-id -> fresh chrome-id mapping
            new_urls += 1
        existing_visits = set(cur.execute("SELECT url, visit_time FROM visits"))
        touched = set()
        for d in iter_new_visits(arc, plan["arc_v_cols"], urlmap, set(),
                                 existing_visits, set()):
            d["url"] = urlmap[d["url"]]
            vals = {}
            for k in v_cols:
                if k == "id":
                    continue
                v = d.get(k)
                # external reference chains (referrers, segments) don't map across DBs
                if k in ("from_visit", "segment_id", "originator_visit_id",
                         "originator_referring_visit", "originator_opener_visit", "app_id"):
                    v = 0
                elif k == "originator_cache_guid":
                    v = None
                vals[k] = v
            insert_row(cur, "visits", vals, tuple(vals))
            touched.add(d["url"])
            new_visits += 1
        for uid in touched:  # refresh aggregates on urls that gained visits
            cur.execute("""UPDATE urls SET
                visit_count = (SELECT COUNT(*) FROM visits v WHERE v.url = urls.id),
                last_visit_time = (SELECT MAX(v.visit_time) FROM visits v WHERE v.url = urls.id)
                WHERE id = ?""", (uid,))
        main.commit()
        tu = cur.execute("SELECT COUNT(*) FROM urls").fetchone()[0]
        tv = cur.execute("SELECT COUNT(*) FROM visits").fetchone()[0]
    return f"history: +{new_urls} urls -> {tu} total | +{new_visits} visits -> {tv} total"


def apply_cookies(plan, chrome_path, chr_key):
    with closing(sqlite3.connect(chrome_path)) as main:
        try:
            for d in plan["overwrite"]:
                main.execute("DELETE FROM cookies WHERE " +
                             " AND ".join(f"{c}=?" for c in COOKIE_KEY_COLS), cookie_key(d))
            for d in plan["overwrite"] + plan["insert"]:
                pt = d["_pt"]
                row = {k: v for k, v in d.items() if k in plan["cols"]}
                row["encrypted_value"] = v10_encrypt(chr_key, pt)
                insert_row(main, "cookies", row, plan["cols"])
                back = main.execute(
                    "SELECT encrypted_value FROM cookies WHERE " +
                    " AND ".join(f"{c}=?" for c in COOKIE_KEY_COLS), cookie_key(d)
                ).fetchone()[0]
                if v10_decrypt(chr_key, back) != pt:
                    raise ToolError(
                        f"round-trip verify failed for cookie {d['host_key']}{d['name']} "
                        "— cookies rolled back, nothing was written")
        except Exception:
            main.rollback()
            raise
        main.commit()
        total = main.execute("SELECT COUNT(*) FROM cookies").fetchone()[0]
    ins, ow = len(plan["insert"]), len(plan["overwrite"])
    xsite = sum(1 for d in plan["insert"] + plan["overwrite"]
                if d["has_cross_site_ancestor"] and not d["top_frame_site_key"])
    msg = (f"cookies: +{ins} new, {ow} overwritten (Arc fresher, {ins + ow}/{ins + ow} "
           f"verify ok), {plan['kept']} kept (Chrome fresher), {plan['expired']} expired, "
           f"{plan['failed']} undecryptable | chrome total: {total}")
    if xsite:
        msg += (f"\nnote: {xsite} imported third-party cookies will be dropped by Chrome "
                "on startup (usually trackers; not guaranteed to be login-free)")
    return msg


# ---------------------------------------------------------------- commands

def snapshot_set(tmp, base, names, modes):
    paths = {}
    for n in names:
        dst = os.path.join(tmp, f"{'arc' if base == ARC_DIR else 'chr'}_{n.replace(' ', '_')}")
        modes.add(backup_db(os.path.join(base, n), dst))
        paths[n] = dst
    return paths


def warn_if_best_effort(modes):
    if "best-effort" in modes:
        print("note: a browser is running, so some snapshots are best-effort "
              "(lock-free immutable reads, possibly slightly stale).\n"
              "      for a fully consistent migration, quit both Arc and Chrome first.")


def build_plans(what, arc_paths, chrome_paths, arc_key):
    plans = {}
    if "logins" in what:
        plans["logins"] = plan_logins(arc_paths["Login Data"],
                                      chrome_paths["Login Data"], arc_key)
    if "history" in what:
        plans["history"] = plan_history(arc_paths["History"], chrome_paths["History"])
    if "cookies" in what:
        plans["cookies"] = plan_cookies(arc_paths["Cookies"],
                                        chrome_paths["Cookies"], arc_key)
    return plans


def cmd_diff(_args):
    require_profile_files()
    arc_key = get_key(ARC_KEYCHAIN)  # one Keychain prompt, for decryptability stats
    with tempfile.TemporaryDirectory(prefix="arc-to-chrome-") as tmp:
        modes = set()
        arc_paths = snapshot_set(tmp, ARC_DIR, DB_FILES, modes)
        chr_paths = snapshot_set(tmp, CHROME_DIR, DB_FILES, modes)
        plans = build_plans({"logins", "history", "cookies"}, arc_paths, chr_paths, arc_key)

        p = plans["logins"]
        rows = p["rows"]
        total = len(rows) + p["skipped"] + p["failed"]
        print(f"logins: {total} in Arc ({p['failed']} undecryptable/empty), "
              f"{p['skipped']} already in Chrome -> {len(rows)} to merge")
        for d in rows[:30]:
            print(f"  + {d['signon_realm'][:60]:60} {d['username_value'][:30]}")
        if len(rows) > 30:
            print(f"  ... and {len(rows) - 30} more")

        p = plans["history"]
        print(f"\nhistory: {p['arc_url_count']} urls / {p['arc_visit_count']} visits "
              f"in Arc -> {len(p['new_urls'])} urls, {p['new_visits']} visits new to Chrome")

        p = plans["cookies"]
        print(f"\ncookies: {len(p['insert'])} new, {len(p['overwrite'])} fresher in Arc "
              f"(will overwrite), {p['kept']} fresher in Chrome (kept), "
              f"{p['expired']} expired (skipped), {p['failed']} undecryptable")
        warn_if_best_effort(modes)


def cmd_merge(args):
    what = set(args.what.split(","))
    unknown = what - {"logins", "history", "cookies"}
    if unknown:
        raise ToolError(f"unknown --what values: {sorted(unknown)}")
    if args.dry_run:
        print("dry-run: merging against scratch copies; Chrome profile untouched")
    elif chrome_running():
        raise ToolError("Chrome is running. Quit it completely (Cmd+Q) before merge, "
                        "or use --dry-run to rehearse safely.")
    require_profile_files()
    backup_dir = None
    if not args.dry_run and not args.no_backup:
        backup_dir = backup_chrome_profile()
        print(f"backed up Chrome profile DBs to {backup_dir}")

    arc_key = chr_key = None
    if what & {"logins", "cookies"}:
        arc_key = get_key(ARC_KEYCHAIN)
        chr_key = get_key(CHROME_KEYCHAIN)
    with tempfile.TemporaryDirectory(prefix="arc-to-chrome-") as tmp:
        modes = set()
        names = {"logins": "Login Data", "history": "History",
                 "cookies": "Cookies"}
        arc_paths = snapshot_set(tmp, ARC_DIR, [names[w] for w in what], modes)
        if args.dry_run:
            chr_paths = snapshot_set(tmp, CHROME_DIR, [names[w] for w in what], modes)
        else:
            chr_paths = {n: os.path.join(CHROME_DIR, n) for n in DB_FILES}
        warn_if_best_effort(modes)
        plans = build_plans(what, arc_paths, chr_paths, arc_key)
        try:
            if "logins" in what:
                print(apply_logins(plans["logins"], chr_paths["Login Data"], chr_key))
            if "history" in what:
                print(apply_history(plans["history"], arc_paths["History"],
                                    chr_paths["History"]))
            if "cookies" in what:
                print(apply_cookies(plans["cookies"], chr_paths["Cookies"], chr_key))
        except Exception:
            if backup_dir:
                print(f"\nmerge failed midway — some Chrome DBs may be partially merged.",
                      file=sys.stderr)
                print(f"to roll back: quit Chrome, then copy ALL files from\n"
                      f"  {backup_dir}\nback into\n  {CHROME_DIR}", file=sys.stderr)
            raise
    if args.dry_run:
        print("dry-run done: nothing was written to the Chrome profile")


def cmd_selftest(_args):
    key = os.urandom(16)
    for pt in (b"", b"a", b"sixteen_bytes!!!", os.urandom(100)):
        assert v10_decrypt(key, v10_encrypt(key, pt)) == pt
    assert v10_decrypt(key, b"plain") is None
    assert v10_decrypt(key, b"v10" + b"\x00" * 15) is None  # not multiple of 16
    # crafted invalid padding (declares pad=3, bytes not all 0x03) must fail
    bad = b"A" * 13 + b"\x01\x02\x03"
    ct = b"v10" + AES.new(key, AES.MODE_CBC, iv=b" " * 16).encrypt(bad)
    assert v10_decrypt(key, ct) is None
    # wrong keys must overwhelmingly fail strict PKCS#7
    trials = 1000
    enc = v10_encrypt(key, b"secret")
    passed = sum(1 for _ in range(trials)
                 if v10_decrypt(os.urandom(16), enc) is not None)
    assert passed / trials < 0.03, f"wrong-key false-success rate too high: {passed}/{trials}"
    print(f"selftest ok: round-trips pass; padding tamper rejected; "
          f"wrong-key false-success {passed}/{trials}")


def main():
    p = argparse.ArgumentParser(
        prog="arc_to_chrome",
        description="Merge Arc logins/history/cookies into Chrome (macOS, offline).")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("diff", help="preview what would be merged (read-only)")
    m = sub.add_parser("merge", help="perform the merge (Chrome must be quit)")
    m.add_argument("--what", default="logins,history,cookies",
                   help="comma-separated subset of: logins,history,cookies")
    m.add_argument("--dry-run", action="store_true",
                   help="run the full pipeline against scratch copies, write nothing")
    m.add_argument("--no-backup", action="store_true",
                   help="skip backing up Chrome's DBs first (gives up the rollback point; "
                        "does NOT bypass the Chrome-running guard)")
    sub.add_parser("selftest", help="crypto sanity checks")
    args = p.parse_args()
    try:
        {"diff": cmd_diff, "merge": cmd_merge, "selftest": cmd_selftest}[args.cmd](args)
    except ToolError as e:
        sys.exit(f"error: {e}")


if __name__ == "__main__":
    main()
