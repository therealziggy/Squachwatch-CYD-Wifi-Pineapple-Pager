# test/helpers/recon_db.sh — sourced by tests (NOT by run.sh, which sources only *_test.sh).
# sw_test_recon_db OUT.db ROW... writes a recon.db with the Pager's REAL ssid / wifi_device schema
# (docs/superpowers/P0-findings.md): bssid, mac and ssid are BLOBs and time is epoch seconds.
# Each ROW is "type,bssid,encryption,hidden,signal,age,name":
#   type        8 = beacon (access point), 4 = client
#   bssid       12 hex digits, no colons, as the Pager stores it
#   encryption  0 = open; a number = protected (17184063752 = WPA2 personal); "" = NULL
#   hidden      0 or 1
#   signal      dBm, e.g. -60
#   age         seconds before now (the row's "last seen")
#   name        LAST, so it may hold commas, pipes, tabs or line breaks; "hex:<digits>" = raw bytes
# Every row gets its own hash, so one radio can have several rows. Calling it again on the same
# file appends rows.
sw_test_recon_db() {
  python3 - "$@" <<'PY'
import sqlite3, sys, time
out, rows = sys.argv[1], sys.argv[2:]
con = sqlite3.connect(out)
con.executescript("""
CREATE TABLE IF NOT EXISTS wifi_device(hash INT PRIMARY KEY,scan INT,mac TEXT,time INT,signal INT,freq INT,packets INT,UNIQUE(hash) ON CONFLICT REPLACE);
CREATE TABLE IF NOT EXISTS ssid(hash INT PRIMARY KEY,wifi_device INT,scan INT,type INT,bssid TEXT,ssid BLOB,hidden INT,time INT,signal INT,freq INT,channel INT,encryption INT,UNIQUE(hash) ON CONFLICT REPLACE);
""")
now = int(time.time())
base = con.execute("SELECT count(*) FROM ssid").fetchone()[0]
for i, row in enumerate(rows):
    typ, bssid, enc, hidden, sig, age, name = row.split(",", 6)
    raw = bytes.fromhex(name[4:]) if name.startswith("hex:") else name.encode()
    h = base + i + 1
    ts = now - int(age)
    mac = bssid.encode()
    con.execute("INSERT INTO wifi_device VALUES(?,?,?,?,?,?,?)", (h, 1, mac, ts, int(sig), 2412, 1))
    con.execute("INSERT INTO ssid VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (h, h, 1, int(typ), b"" if typ == "4" else mac, raw, int(hidden), ts, int(sig), 2412, 1,
                 None if enc == "" else int(enc)))
con.commit()
PY
}
