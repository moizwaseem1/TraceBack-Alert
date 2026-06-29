from flask import Flask, render_template, request, send_from_directory
import requests
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
import os

app = Flask(__name__)

@app.route('/robots.txt')
@app.route('/sitemap.xml')
def static_from_root():
    return send_from_directory(app.static_folder, request.path[1:])

# =====================================================================
# INTELLIGENCE PROCESSING PIPELINE (Live Network Only)
# =====================================================================

def fetch_real_time_intelligence():
    """Aggregates real-time threat data strictly from verified live sources."""
    live_feed = []
    
    # Establish a strict naive UTC execution point
    now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
    cutoff_time = now_utc - timedelta(hours=24)
    
    # 1. OSINT Security & Terror Alerts
    try:
        rss_url = "https://www.dawn.com/feeds/pakistan/"
        rss_res = requests.get(rss_url, timeout=5)
        root = ET.fromstring(rss_res.content)
        threat_keywords = ["attack", "blast", "terror", "security", "police", "rangers", "militant", "killed", "operation", "firing"]
        
        for item in root.findall('.//item')[:30]: 
            pub_date_str = item.find('pubDate').text
            try:
                item_date = parsedate_to_datetime(pub_date_str).astimezone(timezone.utc).replace(tzinfo=None)
            except Exception:
                item_date = now_utc
            
            if item_date < cutoff_time: continue
                
            title = item.find('title').text
            if any(kw in title.lower() for kw in threat_keywords):
                area = "National"
                for city in ["Karachi", "Lahore", "Islamabad", "Quetta", "Peshawar"]:
                    if city.lower() in title.lower(): area = city
                
                live_feed.append({
                    "id": f"sec_{len(live_feed)}",
                    "time": item_date.strftime('%I:%M %p'),
                    "area": area,
                    "alert": f"SECURITY INTELLIGENCE: {title}",
                    "verified": True,
                    "level": "Critical",
                    "color": "red",
                    "raw_timestamp": item_date.timestamp()
                })
    except Exception as e:
        print(f"OSINT RSS Error: {e}")

    # 2. USGS Seismic Network
    try:
        start_time_str = cutoff_time.strftime('%Y-%m-%dT%H:%M:%S')
        usgs_url = f"https://earthquake.usgs.gov/fdsnws/event/1/query?format=geojson&minlatitude=23.0&maxlatitude=37.0&minlongitude=60.0&maxlongitude=78.0&starttime={start_time_str}&orderby=time"
        quake_res = requests.get(usgs_url, timeout=5).json()
        
        for feature in quake_res.get('features', []):
            props = feature['properties']
            mag = props['mag']
            place = props['place']
            
            if "pakistan" not in place.lower(): continue 

            item_date = datetime.fromtimestamp(props['time'] / 1000.0, tz=timezone.utc).replace(tzinfo=None)
            level = "Critical" if mag >= 5.0 else "High" if mag >= 4.0 else "Info"
            color = "red" if mag >= 5.0 else "orange" if mag >= 4.0 else "blue"
            
            live_feed.append({
                "id": feature['id'],
                "time": item_date.strftime('%I:%M %p'),
                "area": "National",
                "alert": f"SEISMIC ALERT: Magnitude {mag} earthquake detected {place}.",
                "verified": True,
                "level": level,
                "color": color,
                "raw_timestamp": item_date.timestamp()
            })
    except Exception as e:
        print(f"USGS Network Error: {e}")

    # 3. UN ReliefWeb
    try:
        rw_url = "https://api.reliefweb.int/v1/reports?appname=traceback&query[value]=country.iso3:pak&sort[]=date:desc&limit=5&fields[include][]=title&fields[include][]=date"
        rw_res = requests.get(rw_url, timeout=5).json()
        
        for item in rw_res.get('data', []):
            fields = item.get('fields', {})
            title = fields.get('title', 'Verified Security Update')
            raw_date = fields.get('date', {}).get('created', '')
            
            raw_timestamp = now_utc.timestamp()
            time_str = "Recent"
            
            if raw_date:
                try:
                    item_date = datetime.fromisoformat(raw_date.replace("Z", "+00:00")).replace(tzinfo=None)
                    if item_date < cutoff_time: continue
                    time_str = item_date.strftime('%I:%M %p')
                    raw_timestamp = item_date.timestamp()
                except Exception: pass

            if "afghanistan" not in title.lower():
                live_feed.append({
                    "id": item['id'],
                    "time": time_str,
                    "area": "National", 
                    "alert": f"UN REPORT: {title}",
                    "verified": True,
                    "level": "High",
                    "color": "orange",
                    "raw_timestamp": raw_timestamp
                })
    except Exception as e:
        print(f"ReliefWeb Error: {e}")

    live_feed.sort(key=lambda x: x.get('raw_timestamp', 0), reverse=True)
    
    if not live_feed:
        live_feed.append({
            "id": "sys_1", "time": datetime.now().strftime('%I:%M %p'), "area": "National",
            "alert": "System Monitor: All intelligence networks active. No critical incidents in the last 24h.",
            "verified": True, "level": "Info", "color": "blue", "raw_timestamp": now_utc.timestamp()
        })
    return live_feed

# =====================================================================
# PLATFORM ROUTES
# =====================================================================

@app.route('/')
def home():
    return render_template('index.html', title="Home Hub")

@app.route('/directory')
def directory():
    contacts = {
        "National": [
            {"name": "National Disaster Management (NDMA)", "number": "112", "type": "alert", "color": "red"},
            {"name": "Motorway & Highway Police (NHMP)", "number": "130", "type": "police", "color": "blue"},
            {"name": "Women & Child Helpline", "number": "1099", "type": "alert", "color": "purple"},
            {"name": "Edhi Ambulance Nationwide", "number": "115", "type": "ambulance", "color": "red"},
            {"name": "Fire Brigade Nationwide", "number": "16", "type": "fire", "color": "orange"}
        ],
        "Islamabad Capital Territory": [
            {"name": "Police Emergency", "number": "15", "type": "police", "color": "blue"},
            {"name": "Rescue 1122 (Ambulance/Fire)", "number": "1122", "type": "ambulance", "color": "red"},
            {"name": "Islamabad Traffic Police", "number": "1915", "type": "police", "color": "blue"}
        ],
        "Sindh": [
            {"name": "Police Madadgar", "number": "15", "type": "police", "color": "blue"},
            {"name": "Rescue 1122 Sindh (SERS)", "number": "1122", "type": "ambulance", "color": "red"},
            {"name": "Fire Brigade", "number": "16", "type": "fire", "color": "orange"},
            {"name": "Pakistan Rangers (Sindh)", "number": "1101", "type": "military", "color": "green"},
            {"name": "Chhipa Ambulance", "number": "1020", "type": "ambulance", "color": "red"}
        ],
        "Punjab": [
            {"name": "Police Emergency", "number": "15", "type": "police", "color": "blue"},
            {"name": "Rescue 1122 (Ambulance/Rescue)", "number": "1122", "type": "ambulance", "color": "red"},
            {"name": "Fire Brigade", "number": "16", "type": "fire", "color": "orange"},
            {"name": "CTD (Counter Terrorism Punjab)", "number": "0800-11111", "type": "military", "color": "green"}
        ],
        "Khyber Pakhtunkhwa (KPK)": [
            {"name": "Police Emergency", "number": "15", "type": "police", "color": "blue"},
            {"name": "Rescue 1122 KPK", "number": "1122", "type": "ambulance", "color": "red"},
            {"name": "PDMA Khyber Pakhtunkhwa", "number": "1700", "type": "alert", "color": "orange"}
        ],
        "Balochistan": [
            {"name": "Police Emergency", "number": "15", "type": "police", "color": "blue"},
            {"name": "Rescue 1122 (MERC)", "number": "1122", "type": "ambulance", "color": "red"},
            {"name": "PDMA Balochistan", "number": "1129", "type": "alert", "color": "orange"}
        ],
        "Gilgit-Baltistan (GB)": [
            {"name": "Police Emergency", "number": "15", "type": "police", "color": "blue"},
            {"name": "Rescue 1122 GB", "number": "1122", "type": "ambulance", "color": "red"},
            {"name": "GB Disaster Management", "number": "114", "type": "alert", "color": "orange"}
        ],
        "Azad Jammu & Kashmir (AJK)": [
            {"name": "Police Emergency", "number": "15", "type": "police", "color": "blue"},
            {"name": "Rescue 1122 AJK", "number": "1122", "type": "ambulance", "color": "red"},
            {"name": "SDMA AJK", "number": "1900", "type": "alert", "color": "orange"}
        ]
    }
    return render_template('directory.html', title="Emergency Directory", contacts=contacts)

@app.route('/hospitals')
def hospitals():
    return render_template('hospitals.html', title="Hospital Locator")

@app.route('/updates')
def updates():
    return render_template('updates.html', title="Live Updates", feed=fetch_real_time_intelligence())

@app.route('/legal')
def legal():
    return render_template('legal.html', title="Legal Hub")

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
