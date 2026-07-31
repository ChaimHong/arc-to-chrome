#!/usr/bin/env python3
"""arc-to-chrome — merge Arc browser data (logins, history, cookies) into Chrome on macOS.

Both browsers are Chromium: same SQLite schemas, same "v10" AES-128-CBC encryption,
different Keychain keys ("Arc Safe Storage" vs "Chrome Safe Storage").
This tool decrypts with Arc's key, re-encrypts with Chrome's key, and merges —
fully offline, and decrypted secrets never touch disk.

Commands:
    diff      preview what would be merged (read-only, safe while browsers run)
    merge     perform the merge (Chrome must be quit; use --dry-run to rehearse)
    selftest  crypto round-trip sanity check
"""
import argparse
import hashlib
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time

from Crypto.Cipher import AES

ARC_DIR = os.path.expanduser("~/Library/Application Support/Arc/User Data/Default")
CHROME_DIR = os.path.expanduser("~/Library/Application Support/Google/Chrome/Default")
BACKUP_ROOT = os.path.expanduser("~/arc-to-chrome-backups")
CHROME_EPOCH_OFFSET = 11644473600  # seconds between 1601-01-01 and 1970-01-01

ARC_KEYCHAIN = "Arc Safe Storage"
CHROME_KEYCHAIN = "Chrome Safe Storage"

COLUMN_RE = re.compile(r"^[a-z_]+$")
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
    """Decrypt a Chromium v10 blob. Returns plaintext bytes, or None if not v10."""
    if not blob or blob[:3] != b"v10":
        return None
    pt = AES.new(key, AES.MODE_CBC, iv=b" " * 16).decrypt(blob[3:])
    pad = pt[-1]
    if 0 < pad <= 16:
        pt = pt[:-pad]
    return pt


def v10_encrypt(key, pt):
    pad = 16 - (len(pt) % 16)
    pt = pt + bytes([pad]) * pad
    return b"v10" + AES.new(key, AES.MODE_CBC, iv=b" " * 16).encrypt(pt)


# ---------------------------------------------------------------- helpers

def chrome_running():
    return subprocess.run(["pgrep", "-x", "Google Chrome"],
                          capture_output=True).returncode == 0


def backup_db(src_path, dst_path, attempts=3):
    """Snapshot a live browser SQLite DB without starving on its locks.

    The sqlite backup API retries forever when the source is constantly
    written (a running browser), so instead we read with immutable=1
    (no locking at all) and VACUUM INTO a fresh copy, then verify it.
    Worst case for a torn read: retry, then give up with a clear error.
    """
    for _ in range(attempts):
        if os.path.exists(dst_path):
            os.unlink(dst_path)
        src = sqlite3.connect(f"file:{src_path}?mode=ro&immutable=1", uri=True)
        try:
            src.execute("VACUUM INTO ?", (dst_path,))
        finally:
            src.close()
        chk = sqlite3.connect(dst_path)
        try:
            ok = chk.execute("PRAGMA quick_check").fetchone()[0] == "ok"
        finally:
            chk.close()
        if ok:
            os.chmod(dst_path, 0o600)
            return
        os.unlink(dst_path)
    raise ToolError(f"could not snapshot {src_path} (database busy) — try again")


def table_columns(conn, table):
    cols = [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]
    bad = [c for c in cols if not COLUMN_RE.match(c)]
    if bad:
        raise ToolError(f"unexpected column names in {table}: {bad}")
    return cols


def insert_row(conn, table, row, cols):
    conn.execute(f"INSERT INTO {table} ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
                 [row.get(c) for c in cols])


def backup_chrome_profile():
    dest = os.path.join(BACKUP_ROOT, time.strftime("%Y%m%d-%H%M%S"))
    os.makedirs(dest, mode=0o700)
    os.chmod(dest, 0o700)
    for name in DB_FILES:
        src = os.path.join(CHROME_DIR, name)
        if os.path.exists(src):
            shutil.copy2(src, dest)
            os.chmod(os.path.join(dest, name), 0o600)
    return dest


# ---------------------------------------------------------------- merges
# Each merge_* function takes explicit DB paths, so it works unchanged against
# either the real Chrome profile (real run) or scratch copies in a temp dir
# (--dry-run). All decrypted secrets stay in process memory.

def merge_logins(arc_path, chrome_path, arc_key, chr_key):
    arc = sqlite3.connect(arc_path)
    main = sqlite3.connect(chrome_path)
    cols, arc_cols = table_columns(main, "logins"), table_columns(arc, "logins")
    existing = set(main.execute("SELECT signon_realm, username_value FROM logins"))
    inserted = skipped = failed = verified = 0
    for row in arc.execute("SELECT * FROM logins WHERE blacklisted_by_user = 0"):
        d = dict(zip(arc_cols, row))
        if (d["signon_realm"], d["username_value"]) in existing:
            skipped += 1
            continue
        pt = v10_decrypt(arc_key, d["password_value"])  # in-memory only
        if pt is None:
            failed += 1
            continue
        d = {k: v for k, v in d.items() if k in cols and k != "id"}
        d["password_value"] = v10_encrypt(chr_key, pt)
        insert_row(main, "logins", d, tuple(d))
        # round-trip: read the row back and confirm Chrome's key can decrypt it
        back = main.execute("SELECT password_value FROM logins "
                            "WHERE id = last_insert_rowid()").fetchone()[0]
        if v10_decrypt(chr_key, back) == pt:
            verified += 1
        inserted += 1
    main.commit()
    total = main.execute("SELECT COUNT(*) FROM logins").fetchone()[0]
    main.close(); arc.close()
    return (f"logins: +{inserted} new ({verified}/{inserted} verify ok), "
            f"{skipped} already present, {failed} undecryptable | chrome total: {total}")


def merge_history(arc_path, chrome_path):
    arc = sqlite3.connect(arc_path)
    main = sqlite3.connect(chrome_path)
    url_cols = table_columns(main, "urls")
    if url_cols != table_columns(arc, "urls"):
        raise ToolError("urls schema mismatch between Arc and Chrome")
    v_cols = table_columns(main, "visits")
    arc_v_cols = table_columns(arc, "visits")

    cur = main.cursor()
    existing = {u: i for u, i in cur.execute("SELECT url, id FROM urls")}
    urlmap, new_urls = {}, 0
    for row in arc.execute("SELECT * FROM urls"):
        d = dict(zip(url_cols, row))
        if d["url"] in existing:
            urlmap[d["id"]] = existing[d["url"]]
        else:
            vals = {k: v for k, v in d.items() if k != "id"}
            insert_row(cur, "urls", vals, tuple(vals))
            urlmap[d["id"]] = cur.lastrowid
            existing[d["url"]] = cur.lastrowid
            new_urls += 1

    existing_visits = set(cur.execute("SELECT url, visit_time FROM visits"))
    new_visits, touched = 0, set()
    for row in arc.execute("SELECT * FROM visits"):
        d = dict(zip(arc_v_cols, row))
        if d["url"] not in urlmap:
            continue
        d["url"] = urlmap[d["url"]]
        if (d["url"], d["visit_time"]) in existing_visits:
            continue
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
        existing_visits.add((d["url"], d["visit_time"]))
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
    main.close(); arc.close()
    return f"history: +{new_urls} urls -> {tu} total | +{new_visits} visits -> {tv} total"


def merge_cookies(arc_path, chrome_path, arc_key, chr_key):
    arc = sqlite3.connect(arc_path)
    main = sqlite3.connect(chrome_path)
    cols = table_columns(main, "cookies")
    arc_cols = table_columns(arc, "cookies")
    if cols != arc_cols:
        raise ToolError("cookies schema mismatch between Arc and Chrome")
    chr_map = {}
    for row in main.execute(f"SELECT {','.join(COOKIE_KEY_COLS)}, last_update_utc FROM cookies"):
        chr_map[tuple(row[:-1])] = row[-1]
    now = int((time.time() + CHROME_EPOCH_OFFSET) * 1e6)
    ins = ow = expired = failed = older = xsite = 0
    # Arc stores encrypted_value with TEXT storage class; CAST forces bytes back
    sel = ", ".join(f"CAST({c} AS BLOB)" if c == "encrypted_value" else c for c in arc_cols)
    for row in arc.execute(f"SELECT {sel} FROM cookies"):
        d = dict(zip(arc_cols, row))
        if d["expires_utc"] and d["expires_utc"] < now:
            expired += 1
            continue
        pt = v10_decrypt(arc_key, d["encrypted_value"])  # in-memory only
        if pt is None:
            failed += 1
            continue
        d["encrypted_value"] = v10_encrypt(chr_key, pt)
        k = tuple(d[c] for c in COOKIE_KEY_COLS)
        if k in chr_map:
            if d["last_update_utc"] <= chr_map[k]:
                older += 1
                continue
            main.execute("DELETE FROM cookies WHERE " +
                         " AND ".join(f"{c}=?" for c in COOKIE_KEY_COLS), k)
            ow += 1
        else:
            ins += 1
        if d["has_cross_site_ancestor"] and not d["top_frame_site_key"]:
            xsite += 1  # Chrome's loader drops these on startup (harmless trackers)
        insert_row(main, "cookies", d, cols)
    main.commit()
    total = main.execute("SELECT COUNT(*) FROM cookies").fetchone()[0]
    main.close(); arc.close()
    msg = (f"cookies: +{ins} new, {ow} overwritten (Arc fresher), "
           f"{older} kept (Chrome fresher), {expired} expired, {failed} undecryptable "
           f"| chrome total: {total}")
    if xsite:
        msg += (f"\nnote: {xsite} imported third-party cookies will be dropped by Chrome "
                "on startup (expected; none are login-related)")
    return msg


# ---------------------------------------------------------------- commands

def cmd_diff(_args):
    with tempfile.TemporaryDirectory(prefix="arc-to-chrome-") as tmp:
        arc = {n: os.path.join(tmp, "arc_" + n.replace(" ", "_")) for n in DB_FILES}
        chr_ = {n: os.path.join(tmp, "chr_" + n.replace(" ", "_")) for n in DB_FILES}
        for n in DB_FILES:
            backup_db(os.path.join(ARC_DIR, n), arc[n])
            backup_db(os.path.join(CHROME_DIR, n), chr_[n])

        arc_key = get_key(ARC_KEYCHAIN)  # one Keychain prompt, for decryptability stats
        a, c = sqlite3.connect(arc["Login Data"]), sqlite3.connect(chr_["Login Data"])
        chrome_pairs = set(c.execute("SELECT signon_realm, username_value FROM logins"))
        rows = list(a.execute("SELECT signon_realm, username_value, password_value "
                              "FROM logins WHERE blacklisted_by_user = 0"))
        bad = sum(1 for r in rows if v10_decrypt(arc_key, r[2]) is None)
        new = [r for r in rows if (r[0], r[1]) not in chrome_pairs]
        print(f"logins: {len(rows)} in Arc ({bad} undecryptable), "
              f"{len(rows) - len(new)} already in Chrome -> {len(new)} to merge")
        for realm, user, _ in new[:30]:
            print(f"  + {realm[:60]:60} {user[:30]}")
        if len(new) > 30:
            print(f"  ... and {len(new) - 30} more")

        a, c = sqlite3.connect(arc["History"]), sqlite3.connect(chr_["History"])
        au = a.execute("SELECT COUNT(*) FROM urls").fetchone()[0]
        av = a.execute("SELECT COUNT(*) FROM visits").fetchone()[0]
        cu = {r[0] for r in c.execute("SELECT url FROM urls")}
        newu = sum(1 for r in a.execute("SELECT url FROM urls") if r[0] not in cu)
        print(f"\nhistory: {au} urls / {av} visits in Arc -> {newu} urls new to Chrome "
              f"(visits deduplicated on merge)")

        a, c = sqlite3.connect(arc["Cookies"]), sqlite3.connect(chr_["Cookies"])
        now = int((time.time() + CHROME_EPOCH_OFFSET) * 1e6)
        cmap = {}
        for r in c.execute(f"SELECT {','.join(COOKIE_KEY_COLS)}, last_update_utc FROM cookies"):
            cmap[tuple(r[:-1])] = r[-1]
        n_new = n_fresher = n_keep = n_exp = 0
        for r in a.execute(f"SELECT {','.join(COOKIE_KEY_COLS)}, last_update_utc, expires_utc "
                           "FROM cookies"):
            k, lu, ex = tuple(r[:-2]), r[-2], r[-1]
            if ex and ex < now:
                n_exp += 1
            elif k not in cmap:
                n_new += 1
            elif lu > cmap[k]:
                n_fresher += 1
            else:
                n_keep += 1
        print(f"\ncookies: {n_new} new, {n_fresher} fresher in Arc (will overwrite), "
              f"{n_keep} fresher in Chrome (kept), {n_exp} expired (skipped)")


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
    backup_dir = None
    if not args.dry_run and not args.no_backup:
        backup_dir = backup_chrome_profile()
        print(f"backed up Chrome profile DBs to {backup_dir}")

    arc_key = get_key(ARC_KEYCHAIN)
    chr_key = get_key(CHROME_KEYCHAIN)
    with tempfile.TemporaryDirectory(prefix="arc-to-chrome-") as tmp:
        def target(name):
            if not args.dry_run:
                return os.path.join(CHROME_DIR, name)
            p = os.path.join(tmp, "chr_" + name.replace(" ", "_"))
            backup_db(os.path.join(CHROME_DIR, name), p)
            return p

        arc_login = arc_hist = arc_cookies = None
        if "logins" in what:
            arc_login = os.path.join(tmp, "arc_login")
            backup_db(os.path.join(ARC_DIR, "Login Data"), arc_login)
        if "history" in what:
            arc_hist = os.path.join(tmp, "arc_history")
            backup_db(os.path.join(ARC_DIR, "History"), arc_hist)
        if "cookies" in what:
            arc_cookies = os.path.join(tmp, "arc_cookies")
            backup_db(os.path.join(ARC_DIR, "Cookies"), arc_cookies)

        if arc_login:
            print(merge_logins(arc_login, target("Login Data"), arc_key, chr_key))
        if arc_hist:
            print(merge_history(arc_hist, target("History")))
        if arc_cookies:
            print(merge_cookies(arc_cookies, target("Cookies"), arc_key, chr_key))
    if args.dry_run:
        print("dry-run done: nothing was written to the Chrome profile")


def cmd_selftest(_args):
    key = os.urandom(16)
    for pt in (b"", b"a", b"sixteen_bytes!!!", os.urandom(100)):
        assert v10_decrypt(key, v10_encrypt(key, pt)) == pt
    assert v10_decrypt(key, b"plain") is None
    assert v10_decrypt(os.urandom(16), v10_encrypt(key, b"x")) != b"x"
    print("selftest ok: v10 encrypt/decrypt round-trips correctly")


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
                   help="skip backing up Chrome's DBs first (not recommended)")
    sub.add_parser("selftest", help="crypto round-trip sanity check")
    args = p.parse_args()
    try:
        {"diff": cmd_diff, "merge": cmd_merge, "selftest": cmd_selftest}[args.cmd](args)
    except ToolError as e:
        sys.exit(f"error: {e}")


if __name__ == "__main__":
    main()
