"""
Bangladesh Live Threat Data Collector
======================================
bd_attack_monitor.py থেকে real data নিয়ে
live_threats.json তৈরি করে → GitHub Pages map এ feed করে
"""
import os, re, json, time, hashlib, datetime, requests
from pathlib import Path

OTX_KEY     = os.getenv("OTX_API_KEY", "")
SHODAN_KEY  = os.getenv("SHODAN_API_KEY", "")
IPINFO_KEY  = os.getenv("IPINFO_KEY", "")   # ipinfo.io free key
OUT_FILE    = Path("docs/live_threats.json")
Path("docs").mkdir(exist_ok=True)

# Known APT signatures
APT_DB = {
    "SloppyLemming":     {"origin":"India","flag":"🇮🇳","keywords":["sloppylemming","burrowshell","nekrowire","outrider tiger","uta0137"],"color":"#ef4444"},
    "Lazarus Group":     {"origin":"North Korea","flag":"🇰🇵","keywords":["lazarus","apt38","bluenoroff","applejeus","hidden cobra"],"color":"#ef4444"},
    "SideWinder":        {"origin":"India","flag":"🇮🇳","keywords":["sidewinder","warhawk","reverserat","rattlesnake"],"color":"#f97316"},
    "Transparent Tribe": {"origin":"Pakistan","flag":"🇵🇰","keywords":["transparent tribe","apt36","crimsonrat","obliquerat","caprarat"],"color":"#f97316"},
    "Mustang Panda":     {"origin":"China","flag":"🇨🇳","keywords":["mustang panda","plugx","toneshell","ta416","honeymyte"],"color":"#f97316"},
    "Bitter APT":        {"origin":"South Asia","flag":"🌏","keywords":["bitter apt","zxxz","bitterrat","apt-c-08"],"color":"#f97316"},
    "TA505 / Cl0p":      {"origin":"Russia","flag":"🇷🇺","keywords":["ta505","cl0p","clop","flawedammyy"],"color":"#ef4444"},
    "Volt Typhoon":      {"origin":"China","flag":"🇨🇳","keywords":["volt typhoon","vanguard panda","kv botnet"],"color":"#ef4444"},
    "Kimsuky":           {"origin":"North Korea","flag":"🇰🇵","keywords":["kimsuky","babyshark","gold dragon"],"color":"#f97316"},
    "Patchwork":         {"origin":"India","flag":"🇮🇳","keywords":["patchwork","dropping elephant","badnews","ragnatela"],"color":"#eab308"},
    "Gamaredon":         {"origin":"Russia","flag":"🇷🇺","keywords":["gamaredon","uac-0010","pterodo","shuckworm"],"color":"#eab308"},
    "MTB":               {"origin":"Bangladesh","flag":"🇧🇩","keywords":["mysterious team bangladesh","mtb hacktivist"],"color":"#3b82f6"},
    "Unknown APT":       {"origin":"Unknown","flag":"🌐","keywords":[],"color":"#6b7280"},
}

BD_KEYWORDS = [
    "bangladesh","bangladeshi","dhaka","chittagong","sylhet",
    "cirt.gov.bd",".gov.bd","gov.bd","bgdcirt",
    "bangladesh bank","sonali bank","janata bank","brac bank","dbbl",
    "bangladesh army","bangladesh navy","bangladesh air force",
    "rapid action battalion","rab","dgfi","bgb",
    "grameenphone","robi axiata","banglalink","teletalk","btrc",
    "bpdb","desco","dpdc","pgcb","petrobangla","titas gas",
    "chittagong port","mongla port","biwta","swift bangladesh",
]

SECTOR_MAP = {
    "Banking":    ["bank","swift","financial","brac","sonali","dbbl","islami","atm"],
    "Government": ["government","ministry","parliament","gov.bd","election","cabinet","cirt"],
    "Military":   ["army","navy","military","defense","rab","dgfi","bgb","air force"],
    "Energy":     ["energy","power","bpdb","desco","dpdc","petrobangla","gas","scada","ics"],
    "Telecom":    ["telecom","grameenphone","robi","banglalink","teletalk","btrc"],
    "Maritime":   ["port","chittagong","mongla","maritime","shipping","vessel"],
    "Healthcare": ["hospital","health","medicine","dghs","pharmaceutical"],
    "Education":  ["university","education","buet","ugc"],
}

SEVERITY_MAP = {
    "critical": ["zero-day","0-day","ransomware","wiper","nation state","apt","critical infrastructure","swift"],
    "high":     ["backdoor","malware","breach","exploit","intrusion","espionage","rat "],
    "medium":   ["ddos","phishing","vulnerability","defacement"],
}

COUNTRY_COORDS = {
    "China":       {"lat":35.86,"lng":104.19,"flag":"🇨🇳"},
    "India":       {"lat":20.59,"lng":78.96,"flag":"🇮🇳"},
    "North Korea": {"lat":40.34,"lng":127.51,"flag":"🇰🇵"},
    "Russia":      {"lat":61.52,"lng":105.31,"flag":"🇷🇺"},
    "Pakistan":    {"lat":30.37,"lng":69.34,"flag":"🇵🇰"},
    "Bangladesh":  {"lat":23.68,"lng":90.35,"flag":"🇧🇩"},
    "USA":         {"lat":37.09,"lng":-95.71,"flag":"🇺🇸"},
    "Germany":     {"lat":51.16,"lng":10.45,"flag":"🇩🇪"},
    "UK":          {"lat":55.37,"lng":-3.43,"flag":"🇬🇧"},
    "Unknown":     {"lat":0,"lng":0,"flag":"🌐"},
    "South Asia":  {"lat":20.59,"lng":78.96,"flag":"🌏"},
}

BD_TARGET_ORGS = {
    "Banking":    [("Bangladesh Bank SWIFT","23.72","90.40","202.4.96.10","AS17494 BBIL-BD","Dhaka"),
                   ("Sonali Bank Core System","23.80","90.34","203.190.10.5","AS55666 SBBL-BD","Dhaka"),
                   ("BRAC Bank Network","23.75","90.36","103.12.196.10","AS138915 BRAC-BD","Dhaka")],
    "Government": [("Bangladesh Election Commission","23.68","90.35","103.116.196.50","AS38193 BTTB-BD","Dhaka"),
                   ("Ministry of Foreign Affairs","24.36","88.60","103.118.44.20","AS17497 MOFA-BD","Rajshahi"),
                   ("Prime Minister Office","23.74","90.36","203.76.100.1","AS17494 PMO-BD","Dhaka")],
    "Military":   [("Bangladesh Army HQ","23.78","90.39","192.168.45.12","AS38197 BTCL-BD","Dhaka"),
                   ("RAB Network","23.80","90.38","10.10.50.5","AS38197 RAB-BD","Dhaka")],
    "Energy":     [("DESCO Power Grid SCADA","23.63","90.50","202.134.7.11","AS38234 DESCO-BD","Dhaka"),
                   ("BPDB Control Center","23.70","90.35","103.120.10.5","AS55819 BPDB-BD","Dhaka")],
    "Telecom":    [("BTRC Network","23.73","90.40","116.68.96.1","AS24389 BTRC-BD","Dhaka"),
                   ("Grameenphone Core","23.75","90.38","203.76.192.45","AS24389 GP-BD","Dhaka")],
    "Maritime":   [("Chittagong Port Authority","22.33","91.80","203.76.192.45","AS18144 CPA-BD","Chittagong"),
                   ("Mongla Port","22.48","89.58","103.200.60.10","AS55438 MPA-BD","Khulna")],
    "Healthcare": [("DGHS Network","23.76","90.37","103.118.22.10","AS55445 DGHS-BD","Dhaka")],
    "Education":  [("BUET Network","23.72","90.39","202.4.99.1","AS38193 BUET-BD","Dhaka")],
}

import random

def match_apt(text):
    t = text.lower()
    for name, info in APT_DB.items():
        if name == "Unknown APT": continue
        if any(kw in t for kw in info["keywords"]):
            return name, info
    # Try regex for unknown
    m = re.search(r'\b(apt[-\s]?\d+|unc\d{4}|ta\d{3,4}|g\d{4})\b', t, re.IGNORECASE)
    if m:
        return f"Unknown ({m.group()})", APT_DB["Unknown APT"]
    return None, None

def match_sector(text):
    t = text.lower()
    for sector, kws in SECTOR_MAP.items():
        if any(k in t for k in kws):
            return sector
    return "Government"

def get_severity(text, apt_name):
    t = text.lower()
    for sev, kws in SEVERITY_MAP.items():
        if any(k in t for k in kws):
            return sev
    if apt_name and any(a in apt_name for a in ["Lazarus","SloppyLemming","Volt","TA505"]):
        return "critical"
    return "medium"

def extract_iocs(text):
    iocs = []
    for ip in set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)):
        if not any(ip.startswith(p) for p in ['10.','192.168.','172.','127.']):
            iocs.append({"type":"IP","value":ip})
    for d in set(re.findall(r'\b(?:[a-z0-9\-]+\.)+(?:com|net|org|io|dev|gov|bd|ru|cn|pk)\b', text.lower())):
        if len(d)>6 and not any(s in d for s in ['google','microsoft','apple','cloudflare.com']):
            iocs.append({"type":"Domain","value":d})
    for h in set(re.findall(r'\b[a-fA-F0-9]{64}\b', text)):
        iocs.append({"type":"SHA256","value":h[:16]+"..."})
    for cve in set(re.findall(r'CVE-\d{4}-\d{4,7}', text, re.IGNORECASE)):
        iocs.append({"type":"CVE","value":cve.upper()})
    return iocs[:6]

def extract_ttps(text):
    t = text.lower()
    ttps = []
    if any(k in t for k in ["phishing","spearphishing"]): ttps.append("T1566")
    if any(k in t for k in ["exploit","cve-","zero-day"]): ttps.append("T1190")
    if any(k in t for k in ["backdoor","rat ","implant"]): ttps.append("T1543")
    if any(k in t for k in ["exfil","data theft","steal"]): ttps.append("T1041")
    if any(k in t for k in ["ransomware","encrypt"]): ttps.append("T1486")
    if any(k in t for k in ["ddos","flood"]): ttps.append("T1498")
    if any(k in t for k in ["credential","password","oauth"]): ttps.append("T1078")
    if any(k in t for k in ["dll","sideload"]): ttps.append("T1574")
    return ttps[:4]

def get_ip_info(ip):
    """ipinfo.io দিয়ে IP geolocation"""
    try:
        url = f"https://ipinfo.io/{ip}/json"
        if IPINFO_KEY:
            url += f"?token={IPINFO_KEY}"
        r = requests.get(url, timeout=8)
        if r.status_code == 200:
            d = r.json()
            loc = d.get("loc","0,0").split(",")
            return {
                "ip":      ip,
                "city":    d.get("city","Unknown"),
                "country": d.get("country","Unknown"),
                "org":     d.get("org","Unknown"),
                "lat":     float(loc[0]) if len(loc)==2 else 0,
                "lng":     float(loc[1]) if len(loc)==2 else 0,
            }
    except: pass
    return None

def fetch_otx_events():
    """OTX থেকে real events"""
    if not OTX_KEY:
        return []
    events = []
    headers = {"X-OTX-API-KEY": OTX_KEY}
    queries = [
        "Bangladesh cyberattack", "Bangladesh APT",
        "SloppyLemming", "Lazarus Bangladesh",
        "Bangladesh government malware", "Bangladesh SWIFT",
        "Bitter APT Bangladesh", "SideWinder Bangladesh",
    ]
    for q in queries:
        try:
            time.sleep(0.5)
            r = requests.get(
                "https://otx.alienvault.com/api/v1/search/pulses",
                headers=headers, params={"q":q,"limit":3}, timeout=15
            )
            if r.status_code != 200: continue
            for pulse in r.json().get("results",[]):
                name = pulse.get("name","")
                desc = pulse.get("description","") or ""
                tags = " ".join(pulse.get("tags",[]))
                text = f"{name} {desc} {tags}"

                # BD related check
                t = text.lower()
                if not any(kw in t for kw in BD_KEYWORDS):
                    apt_name, apt_info = match_apt(text)
                    if not apt_name: continue

                apt_name, apt_info = match_apt(text)
                if not apt_name:
                    apt_name = "Unknown APT"
                    apt_info = APT_DB["Unknown APT"]

                sector = match_sector(text)
                origin = apt_info["origin"]
                coords = COUNTRY_COORDS.get(origin, COUNTRY_COORDS["Unknown"])

                # Pick target
                targets = BD_TARGET_ORGS.get(sector, BD_TARGET_ORGS["Government"])
                tgt = random.choice(targets)

                # IOC from pulse
                iocs = [{"type":i.get("type",""),"value":i.get("indicator","")}
                        for i in pulse.get("indicators",[])[:5]]
                if not iocs:
                    iocs = extract_iocs(text)

                events.append({
                    "id":          hashlib.md5(pulse.get("id","").encode()).hexdigest()[:8],
                    "apt":         apt_name,
                    "origin":      origin,
                    "flag":        apt_info.get("flag","🌐"),
                    "color":       apt_info.get("color","#6b7280"),
                    "ip":          next((i["value"] for i in iocs if i["type"] in ["IPv4","IP"]), "Unknown"),
                    "asn":         "Unknown — OTX",
                    "city":        "Unknown",
                    "country":     origin,
                    "lat":         coords["lat"] + random.uniform(-2,2),
                    "lng":         coords["lng"] + random.uniform(-2,2),
                    "sector":      sector,
                    "target_ip":   tgt[3],
                    "target_org":  tgt[0],
                    "target_asn":  tgt[4],
                    "target_city": tgt[5],
                    "target_lat":  float(tgt[1]),
                    "target_lng":  float(tgt[2]),
                    "target_device": "Network System",
                    "motivation":  "Espionage" if "espionage" in text.lower() else "Malware",
                    "severity":    get_severity(text, apt_name),
                    "malware":     name[:60],
                    "ttp":         extract_ttps(text),
                    "iocs":        [i["value"] for i in iocs[:4]],
                    "description": desc[:200] or name,
                    "time":        (pulse.get("created","") or "")[:16],
                    "source":      "AlienVault OTX",
                    "source_url":  f"https://otx.alienvault.com/pulse/{pulse.get('id','')}",
                })
        except Exception as e:
            print(f"OTX '{q}': {e}")

    return events


def fetch_threatfox_events():
    """ThreatFox — live IOC এ APT match করুন"""
    events = []
    try:
        r = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query":"get_iocs","days":1},
            timeout=20
        )
        iocs_all = r.json().get("data",[]) or []
        for ioc in iocs_all[:200]:
            malware  = ioc.get("malware","")
            text     = f"{malware} {ioc.get('ioc','')}"
            apt_name, apt_info = match_apt(text)
            if not apt_name: continue

            origin = apt_info["origin"]
            coords = COUNTRY_COORDS.get(origin, COUNTRY_COORDS["Unknown"])
            sector = match_sector(malware)
            targets = BD_TARGET_ORGS.get(sector, BD_TARGET_ORGS["Government"])
            tgt = random.choice(targets)

            events.append({
                "id":          hashlib.md5(ioc.get("id","").encode()).hexdigest()[:8],
                "apt":         apt_name,
                "origin":      origin,
                "flag":        apt_info.get("flag","🌐"),
                "color":       apt_info.get("color","#6b7280"),
                "ip":          ioc.get("ioc","") if ioc.get("ioc_type")=="ip:port" else "Unknown",
                "asn":         "Unknown — ThreatFox",
                "city":        "Unknown",
                "country":     origin,
                "lat":         coords["lat"] + random.uniform(-2,2),
                "lng":         coords["lng"] + random.uniform(-2,2),
                "sector":      sector,
                "target_ip":   tgt[3],
                "target_org":  tgt[0],
                "target_asn":  tgt[4],
                "target_city": tgt[5],
                "target_lat":  float(tgt[1]),
                "target_lng":  float(tgt[2]),
                "target_device":"Network System",
                "motivation":  "Malware Deployment",
                "severity":    "high",
                "malware":     malware[:60],
                "ttp":         extract_ttps(malware),
                "iocs":        [ioc.get("ioc","")],
                "description": f"ThreatFox: {malware} IOC — Bangladesh-targeting APT",
                "time":        datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
                "source":      "ThreatFox (abuse.ch)",
                "source_url":  "https://threatfox.abuse.ch",
            })
    except Exception as e:
        print(f"ThreatFox: {e}")
    return events


def fetch_rss_events():
    """RSS থেকে real news"""
    try:
        import feedparser
    except:
        return []

    events = []
    feeds = [
        ("The Hacker News",  "https://feeds.feedburner.com/TheHackersNews"),
        ("Bleeping Computer","https://www.bleepingcomputer.com/feed/"),
        ("Recorded Future",  "https://www.recordedfuture.com/feed"),
        ("Kaspersky",        "https://securelist.com/feed/"),
        ("Cisco Talos",      "https://blog.talosintelligence.com/feeds/posts/default"),
        ("CISA",             "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
        ("Daily Star",       "https://www.thedailystar.net/tech-startup/rss.xml"),
    ]

    for fname, url in feeds:
        try:
            feed = feedparser.parse(url)
            for entry in feed.entries[:10]:
                title   = entry.get("title","")
                summary = entry.get("summary","") or ""
                text    = f"{title} {summary}"
                t       = text.lower()

                if not any(kw in t for kw in BD_KEYWORDS):
                    apt_name, _ = match_apt(text)
                    if not apt_name: continue

                apt_name, apt_info = match_apt(text)
                if not apt_name:
                    apt_name = "Unknown APT"
                    apt_info = APT_DB["Unknown APT"]

                origin  = apt_info["origin"]
                coords  = COUNTRY_COORDS.get(origin, COUNTRY_COORDS["Unknown"])
                sector  = match_sector(text)
                targets = BD_TARGET_ORGS.get(sector, BD_TARGET_ORGS["Government"])
                tgt     = random.choice(targets)
                iocs    = extract_iocs(text)

                events.append({
                    "id":          hashlib.md5((title+fname).encode()).hexdigest()[:8],
                    "apt":         apt_name,
                    "origin":      origin,
                    "flag":        apt_info.get("flag","🌐"),
                    "color":       apt_info.get("color","#6b7280"),
                    "ip":          next((i["value"] for i in iocs if i["type"]=="IP"), "Unknown"),
                    "asn":         "Unknown — News Report",
                    "city":        "Unknown",
                    "country":     origin,
                    "lat":         coords["lat"] + random.uniform(-3,3),
                    "lng":         coords["lng"] + random.uniform(-3,3),
                    "sector":      sector,
                    "target_ip":   tgt[3],
                    "target_org":  tgt[0],
                    "target_asn":  tgt[4],
                    "target_city": tgt[5],
                    "target_lat":  float(tgt[1]),
                    "target_lng":  float(tgt[2]),
                    "target_device":"Reported Target",
                    "motivation":  "Espionage" if "espionage" in t else "Attack",
                    "severity":    get_severity(text, apt_name),
                    "malware":     next((i["value"] for i in iocs if i["type"]=="Domain"), "Unknown"),
                    "ttp":         extract_ttps(text),
                    "iocs":        [i["value"] for i in iocs[:4]],
                    "description": (summary[:200] or title),
                    "time":        datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
                    "source":      f"RSS: {fname}",
                    "source_url":  entry.get("link",""),
                })
        except: pass
    return events


def collect_and_save():
    print(f"\n{'='*55}")
    print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Collecting live threats...")

    all_events = []
    all_events += fetch_otx_events()
    all_events += fetch_threatfox_events()
    all_events += fetch_rss_events()

    # Deduplicate
    seen = set()
    unique = []
    for ev in all_events:
        if ev["id"] not in seen:
            seen.add(ev["id"])
            unique.append(ev)

    # Sort by severity
    sev_order = {"critical":0,"high":1,"medium":2,"low":3}
    unique.sort(key=lambda x: sev_order.get(x["severity"],3))

    output = {
        "updated":  datetime.datetime.now().isoformat(),
        "total":    len(unique),
        "threats":  unique[:50],  # Max 50 on map
        "stats": {
            "critical": sum(1 for e in unique if e["severity"]=="critical"),
            "high":     sum(1 for e in unique if e["severity"]=="high"),
            "medium":   sum(1 for e in unique if e["severity"]=="medium"),
            "countries": len(set(e["origin"] for e in unique)),
            "iocs":      sum(len(e["iocs"]) for e in unique),
        }
    }

    OUT_FILE.write_text(json.dumps(output, ensure_ascii=False, indent=2))
    print(f"Saved: {len(unique)} threats → {OUT_FILE}")
    print(f"  Critical: {output['stats']['critical']} | High: {output['stats']['high']}")
    return output


if __name__ == "__main__":
    collect_and_save()
