#!/usr/bin/env python3
"""Merge Arc logins + history + cookies into Chrome (macOS, both Chromium schema v70).

Usage:
    python3 arc_to_chrome.py snapshot        # copy Arc DBs to /tmp (Arc can stay open)
    python3 arc_to_chrome.py diff            # show which logins would be merged
    # ---- quit Chrome first ----
    python3 arc_to_chrome.py merge-logins
    python3 arc_to_chrome.py merge-history
    python3 arc_to_chrome.py merge-cookies
"""
import json, os, shutil, sqlite3, subprocess, sys, hashlib
from Crypto.Cipher import AES

ARC_DIR = os.path.expanduser("~/Library/Application Support/Arc/User Data/Default")
ARC_LOGIN = "/tmp/arc_login.db"
ARC_HIST = "/tmp/arc_hist.db"
CHROME_DIR = os.path.expanduser("~/Library/Application Support/Google/Chrome/Default")
CHROME_LOGIN = os.path.join(CHROME_DIR, "Login Data")
CHROME_HIST = os.path.join(CHROME_DIR, "History")


def cmd_snapshot():
    shutil.copy(os.path.join(ARC_DIR, "Login Data"), ARC_LOGIN)
    shutil.copy(os.path.join(ARC_DIR, "History"), ARC_HIST)
    os.chmod(ARC_LOGIN, 0o600)
    os.chmod(ARC_HIST, 0o600)
    print(f"snapshotted Arc Login Data + History to {ARC_LOGIN}, {ARC_HIST}")


def get_key(service):
    pw = subprocess.run(["security", "find-generic-password", "-s", service, "-w"],
                        capture_output=True, text=True, check=True).stdout.rstrip("\n")
    return hashlib.pbkdf2_hmac("sha1", pw.encode(), b"saltysalt", 1003, 16)


def v10_decrypt(key, blob):
    if not blob or blob[:3] != b"v10":
        return None
    ct = blob[3:]
    pt = AES.new(key, AES.MODE_CBC, iv=b" " * 16).decrypt(ct)
    pad = pt[-1]
    if isinstance(pad, str):
        pad = ord(pad)
    if 0 < pad <= 16:
        pt = pt[:-pad]
    return pt


def v10_encrypt(key, pt):
    pad = 16 - (len(pt) % 16)
    pt = pt + bytes([pad]) * pad
    return b"v10" + AES.new(key, AES.MODE_CBC, iv=b" " * 16).encrypt(pt)


def cmd_diff():
    arc_key = get_key("Arc Safe Storage")
    a = sqlite3.connect(ARC_LOGIN)
    subprocess.run(["cp", CHROME_LOGIN, "/tmp/c_login_diff.db"], check=True)
    c = sqlite3.connect("/tmp/c_login_diff.db")
    chrome_pairs = set(r for r in c.execute("select signon_realm, username_value from logins"))
    rows = list(a.execute("select * from logins where blacklisted_by_user=0"))
    cols = [d[0] for d in a.execute("select * from logins limit 0").description]
    new, skipped, bad = [], 0, 0
    for r in rows:
        d = dict(zip(cols, r))
        pt = v10_decrypt(arc_key, d["password_value"])
        if pt is None:
            bad += 1
            continue
        if (d["signon_realm"], d["username_value"]) in chrome_pairs:
            skipped += 1
            continue
        d["_plaintext"] = pt
        new.append(d)
    print(f"arc logins: {len(rows)} (undecryptable: {bad})")
    print(f"already in chrome: {skipped}  ->  to merge: {len(new)}")
    for d in new[:30]:
        print(f"  + {d['signon_realm'][:60]:60} {d['username_value'][:30]}")
    if len(new) > 30:
        print(f"  ... and {len(new)-30} more")
    with open("/tmp/arc_new_logins.json", "w") as f:
        json.dump([{k: (v.hex() if isinstance(v, bytes) else v) for k, v in d.items()} for d in new], f)
    os.chmod("/tmp/arc_new_logins.json", 0o600)


def cmd_merge_logins():
    chr_key = get_key("Chrome Safe Storage")
    new = json.load(open("/tmp/arc_new_logins.json"))
    db = sqlite3.connect(CHROME_LOGIN)
    cols = [r[1] for r in db.execute("PRAGMA table_info(logins)")]
    existing = set(r for r in db.execute("select signon_realm, username_value from logins"))
    inserted = skipped = 0
    for d in new:
        if (d["signon_realm"], d["username_value"]) in existing:
            skipped += 1
            continue
        pt = bytes.fromhex(d.pop("_plaintext"))
        d.pop("id", None)
        vals = {}
        for k, v in d.items():
            if k not in cols:
                continue
            if isinstance(v, str) and k in ("password_value", "form_data", "possible_username_pairs",
                                            "moving_blocked_for", "keychain_identifier"):
                try:
                    v = bytes.fromhex(v)
                except ValueError:
                    pass
            vals[k] = v
        vals["password_value"] = v10_encrypt(chr_key, pt)
        db.execute(f"insert into logins ({','.join(vals)}) values ({','.join('?'*len(vals))})",
                   list(vals.values()))
        inserted += 1
    db.commit()
    total = db.execute("select count(*) from logins").fetchone()[0]
    db.close()
    print(f"inserted: {inserted}, skipped(race): {skipped}, chrome total now: {total}")


def cmd_merge_history():
    arc = sqlite3.connect(ARC_HIST)
    main = sqlite3.connect(CHROME_HIST)
    arc_cols = [r[1] for r in arc.execute("PRAGMA table_info(urls)")]
    main_cols = [r[1] for r in main.execute("PRAGMA table_info(urls)")]
    assert arc_cols == main_cols, f"urls schema mismatch:\n{arc_cols}\n{main_cols}"
    v_cols = [r[1] for r in main.execute("PRAGMA table_info(visits)")]

    cur = main.cursor()
    existing = {}
    for u, i in cur.execute("select url, id from urls"):
        existing[u] = i
    urlmap = {}
    new_urls = 0
    arc_urls = list(arc.execute("select * from urls"))
    ac = [d[0] for d in arc.execute("select * from urls limit 0").description]
    for row in arc_urls:
        d = dict(zip(ac, row))
        if d["url"] in existing:
            urlmap[d["id"]] = existing[d["url"]]
        else:
            vals = {k: v for k, v in d.items() if k != "id"}
            cur.execute(f"insert into urls ({','.join(vals)}) values ({','.join('?'*len(vals))})",
                        list(vals.values()))
            urlmap[d["id"]] = cur.lastrowid
            existing[d["url"]] = cur.lastrowid
            new_urls += 1

    existing_visits = set()
    for u, t in cur.execute("select url, visit_time from visits"):
        existing_visits.add((u, t))
    avc = [d[0] for d in arc.execute("select * from visits limit 0").description]
    new_visits = 0
    touched = set()
    for row in arc.execute("select * from visits"):
        d = dict(zip(avc, row))
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
            # external ids (referrer chains, segments) don't map across DBs
            if k in ("from_visit", "segment_id", "originator_visit_id", "originator_referring_visit",
                     "originator_opener_visit", "originator_cache_guid", "app_id"):
                v = 0 if k != "originator_cache_guid" else None
            vals[k] = v
        cur.execute(f"insert into visits ({','.join(vals)}) values ({','.join('?'*len(vals))})",
                    list(vals.values()))
        existing_visits.add((d["url"], d["visit_time"]))
        touched.add(d["url"])
        new_visits += 1

    # refresh aggregates on urls that gained visits
    for uid in touched:
        cur.execute("""update urls set
            visit_count=(select count(*) from visits v where v.url=urls.id),
            last_visit_time=(select max(v.visit_time) from visits v where v.url=urls.id)
            where id=?""", (uid,))
    main.commit()
    tu = cur.execute("select count(*) from urls").fetchone()[0]
    tv = cur.execute("select count(*) from visits").fetchone()[0]
    print(f"urls: +{new_urls} -> {tu} total | visits: +{new_visits} -> {tv} total")
    main.close(); arc.close()


def cmd_merge_cookies():
    import time
    arc_key = get_key("Arc Safe Storage")
    chr_key = get_key("Chrome Safe Storage")
    arc = sqlite3.connect("file:" + os.path.expanduser(
        "~/Library/Application Support/Arc/User Data/Default/Cookies") + "?mode=ro&immutable=1", uri=True)
    main = sqlite3.connect(os.path.join(CHROME_DIR, "Cookies"))
    cols = [r[1] for r in main.execute("PRAGMA table_info(cookies)")]
    arc_cols = [r[1] for r in arc.execute("PRAGMA table_info(cookies)")]
    assert cols == arc_cols, "cookies schema mismatch"
    keycols = ["host_key", "top_frame_site_key", "has_cross_site_ancestor", "name",
               "path", "source_scheme", "source_port"]
    chr_map = {}
    for row in main.execute(f"select {','.join(keycols)}, last_update_utc from cookies"):
        chr_map[tuple(row[:-1])] = row[-1]
    now = int((time.time() + 11644473600) * 1e6)
    ins = ow = skipped = 0
    sel = ", ".join(f"CAST({c} AS BLOB)" if c == "encrypted_value" else c for c in arc_cols)
    for row in arc.execute(f"select {sel} from cookies"):
        d = dict(zip(arc_cols, row))
        if d["expires_utc"] and d["expires_utc"] < now:
            skipped += 1
            continue
        pt = v10_decrypt(arc_key, d["encrypted_value"])
        if pt is None:
            skipped += 1
            continue
        d["encrypted_value"] = v10_encrypt(chr_key, pt)
        k = tuple(d[c] for c in keycols)
        if k in chr_map:
            if d["last_update_utc"] <= chr_map[k]:
                skipped += 1
                continue
            main.execute("delete from cookies where " + " and ".join(f"{c}=?" for c in keycols), k)
            ow += 1
        else:
            ins += 1
        main.execute(f"insert into cookies ({','.join(cols)}) values ({','.join('?'*len(cols))})",
                     [d.get(c) for c in cols])
    main.commit()
    total = main.execute("select count(*) from cookies").fetchone()[0]
    print(f"cookies: +{ins} new, {ow} overwritten (arc fresher), {skipped} skipped, chrome total: {total}")
    main.close(); arc.close()


if __name__ == "__main__":
    {"snapshot": cmd_snapshot, "diff": cmd_diff, "merge-logins": cmd_merge_logins,
     "merge-history": cmd_merge_history, "merge-cookies": cmd_merge_cookies}[sys.argv[1]]()
