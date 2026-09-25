#!/usr/bin/env python3
"""Build a recon.db-shaped fixture. Usage: build_fixture_db.py OUT.db"""
import sqlite3, sys, time
out = sys.argv[1]
con = sqlite3.connect(out)
con.executescript("""
DROP TABLE IF EXISTS ssid; DROP TABLE IF EXISTS wifi_device; DROP TABLE IF EXISTS scan;
CREATE TABLE scan(id INTEGER PRIMARY KEY, name TEXT, time INT);
CREATE TABLE wifi_device(hash TEXT PRIMARY KEY, mac TEXT, packets INT);
CREATE TABLE ssid(bssid TEXT, ssid TEXT, type INT, channel INT, freq INT,
                  signal INT, encryption INT, hidden INT, time INT, wifi_device TEXT);
""")
now = int(time.time())
con.execute("INSERT INTO scan VALUES(1,'fixture',?)", (now,))
# wifi_device rows keyed by hash (bssid stored as 12 hex chars, no colons, like recon.db)
devs = [("h_flock","70c94e112233",1200),
        ("h_old","001122334455",10),
        ("h_pine","aabbcc001122",300),
        ("h_home","1234569abcde",50),
        ("c_phone","f0f5a5445566",80)]
con.executemany("INSERT INTO wifi_device VALUES(?,?,?)", devs)
# ssid rows: type 8 = AP/beacon, 4 = client probe
rows = [
 ("70c94e112233","",8,6,2437,-40,0,0,now,"h_flock"),          # Flock camera AP
 ("aabbcc001122","MyPineappleNet",8,11,2462,-55,8,0,now,"h_pine"), # pineapple SSID
 ("1234569abcde","HomeWiFi",8,1,2412,-60,8,0,now,"h_home"),    # clean AP
 ("","",4,0,2437,-70,0,0,now,"c_phone"),                       # client probe: bssid EMPTY (real schema) -> MAC only via wifi_device join
 # STALE row, last seen 1h ago. Matches no signature, so it changes no detection
 # count; it exists so the recency window has something to actually filter out.
 ("001122334455","OldAP",8,1,2412,-75,8,0,now-3600,"h_old"),
]
con.executemany("INSERT INTO ssid VALUES(?,?,?,?,?,?,?,?,?,?)", rows)
con.commit(); con.close()
print("wrote", out)
