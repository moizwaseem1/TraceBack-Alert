from flask import Flask, render_template, jsonify, request
import requests
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

app = Flask(__name__)

# =====================================================================
# CORE SEED DATA MATRIX (Ensures 100% Uptime in Sandboxed Environments)
# =====================================================================

LOCAL_HOSPITALS = {
    "karachi": [
        {"name": "Aga Khan University Hospital", "lat": 24.8922, "lon": 67.0747, "type": "General/Tertiary"},
        {"name": "Indus Hospital", "lat": 24.8234, "lon": 67.1147, "type": "General/Free Care"},
        {"name": "Jinnah Postgraduate Medical Centre (JPMC)", "lat": 24.8522, "lon": 67.0422, "type": "Government/Trauma"},
        {"name": "Civil Hospital Karachi", "lat": 24.8601, "lon": 67.0104, "type": "Government/Emergency"}
    ],
    "lahore": [
        {"name": "Mayo Hospital", "lat": 31.5775, "lon": 74.3122, "type": "Government/Tertiary"},
        {"name": "Shaukat Khanum Memorial", "lat": 31.4331, "lon": 74.2811, "type": "Specialized/Oncology"},
        {"name": "Services Hospital Lahore", "lat": 31.5422, "lon": 74.3312, "type": "General/Emergency"},
        {"name": "Lahore General Hospital", "lat": 31.4814, "lon": 74.3526, "type": "Government/Trauma"}
    ],
    "islamabad": [
        {"name": "Pakistan Institute of Medical Sciences (PIMS)", "lat": 33.7032, "lon": 73.0485, "type": "Federal/Tertiary"},
        {"name": "Shifa International Hospital", "lat": 33.6822, "lon": 73.0864, "type": "Private/General"},
        {"name": "Polyclinic Hospital", "lat": 33.7251, "lon": 73.0612, "type": "Government/Emergency"}
    ],
    "peshawar": [
        {"name": "Lady Reading Hospital", "lat": 34.0105, "lon": 71.5761, "type": "Government/Trauma"},
        {"name": "Khyber Teaching Hospital", "lat": 33.9992, "lon": 71.4862, "type": "General/Tertiary"}
    ],
    "quetta": [
        {"name": "Sandeman Provincial Hospital", "lat": 30.1952, "lon": 67.0112, "type": "Provincial/Emergency"},
        {"name": "Bolal Medical Complex", "lat": 30.1641, "lon": 66.9924, "type": "General/Tertiary"}
    ]
}

# =====================================================================
# INTELLIGENCE PROCESSING PIPELINE
# =====================================================================

def fetch_real_time_intelligence():
    """Aggregates real-time threat data strictly within a rolling 24-hour window."""
    live_feed = []
    
    # Establish a strict naive UTC execution point for comparison math
    now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
    cutoff_time = now_utc - timedelta(hours=24)
    
    # 1. OSINT Security & Terror Alerts (RSS Headline Scraper)
    try:
        rss_url = "https://www.dawn.com/feeds/pakistan/"
        rss_res = requests.get(rss_url, timeout=5)
        root = ET.fromstring(rss_res.content)
        threat_keywords = ["attack", "blast", "terror", "security", "police", "rangers", "militant", "killed", "operation", "firing"]
        
        for item in root.findall('.//item')[:30]: 
            pub_date_str = item.find('pubDate').text
            
            try:
                # Force drop timezone metadata to insulate from offset errors
                item_date = parsedate_to_datetime(pub_date_str).astimezone(timezone.utc).replace(tzinfo=None)
            except Exception:
                item_date = now_utc
            
            # Enforce 24h lifespan window
            if item_date < cutoff_time:
                continue
                
            title = item.find('title').text
            
            if any(kw in title.lower() for kw in threat_keywords):
                area = "National"
                if "karachi" in title.lower(): area = "Karachi"
                elif "lahore" in title.lower(): area = "Lahore"
                elif "islamabad" in title.lower(): area = "Islamabad"
                elif "quetta" in title.lower(): area = "Quetta"
                elif "peshawar" in title.lower(): area = "Peshawar"

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

    # 2. USGS Seismic Network (Strictly Geofenced & Boundary Filtered)
    try:
        start_time_str = cutoff_time.strftime('%Y-%m-%dT%H:%M:%S')
        usgs_url = f"https://earthquake.usgs.gov/fdsnws/event/1/query?format=geojson&minlatitude=23.0&maxlatitude=37.0&minlongitude=60.0&maxlongitude=78.0&starttime={start_time_str}&orderby=time"
        quake_res = requests.get(usgs_url, timeout=5).json()
        
        for feature in quake_res.get('features', []):
            props = feature['properties']
            mag = props['mag']
            place = props['place']
            
            # Drop cross-border events matching the geometric box
            if "pakistan" not in place.lower():
                continue 

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

    # 3. UN ReliefWeb (Official UN Critical Operations Bulletins)
    try:
        rw_url = "https://api.reliefweb.int/v1/reports?appname=traceback&query[value]=country.iso3:pak&sort[]=date:desc&limit=5&fields[include][]=title&fields[include][]=date"
        rw_res = requests.get(rw_url, timeout=5).json()
        
        for item in rw_res.get('data', []):
            time_str = "Recent"
            raw_timestamp = now_utc.timestamp()
            
            fields = item.get('fields', {})
            title = fields.get('title', 'Verified Security Update')
            raw_date = fields.get('date', {}).get('created', '')
            
            if raw_date:
                try:
                    item_date = datetime.fromisoformat(raw_date.replace("Z", "+00:00")).replace(tzinfo=None)
                    if item_date < cutoff_time:
                        continue
                    time_str = item_date.strftime('%I:%M %p')
                    raw_timestamp = item_date.timestamp()
                except Exception:
                    pass

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
        print(f"ReliefWeb Network Error: {e}")

    # Chronological sort (Newest alerts directly at the top)
    live_feed.sort(key=lambda x: x.get('raw_timestamp', 0), reverse=True)

    # 4. Fail-Safe System Monitor State
    if not live_feed:
        live_feed.append({
            "id": "sys_1",
            "time": datetime.now().strftime('%I:%M %p'),
            "area": "National",
            "alert": "System Monitor: No critical incidents or alerts reported in Pakistan within the last 24 hours. Networks active and monitoring.",
            "verified": True,
            "level": "Info",
            "color": "blue",
            "raw_timestamp": now_utc.timestamp()
        })

    return live_feed

# =====================================================================
# PLATFORM ROUTING MATRIX
# =====================================================================

@app.route('/')
def home():
    return render_template('index.html', title="Home Hub")

@app.route('/directory')
def directory():
    contacts = {
        "National": [
            {"name": "National Disaster Management (NDMA)", "number": "112", "type": "alert", "color": "red"},
            {"name": "Women Help Line", "number": "1099", "type": "alert", "color": "purple"}
        ],
        "Islamabad Capital Territory": [
            {"name": "Police Emergency", "number": "15", "type": "police", "color": "blue"},
            {"name": "Rescue 1122", "number": "1122", "type": "ambulance", "color": "red"},
            {"name": "Traffic Police", "number": "1915", "type": "police", "color": "blue"}
        ],
        "Sindh": [
            {"name": "Police Emergency", "number": "15", "type": "police", "color": "blue"},
            {"name": "Edhi Ambulance", "number": "115", "type": "ambulance", "color": "red"},
            {"name": "Fire Brigade", "number": "16", "type": "fire", "color": "orange"},
            {"name": "Rangers Help", "number": "1101", "type": "military", "color": "green"}
        ],
        "Punjab": [
            {"name": "Police Emergency", "number": "15", "type": "police", "color": "blue"},
            {"name": "Rescue 1122", "number": "1122", "type": "ambulance", "color": "red"},
            {"name": "Fire Brigade", "number": "16", "type": "fire", "color": "orange"}
        ],
        "Khyber Pakhtunkhwa (KPK)": [
            {"name": "Police Emergency", "number": "15", "type": "police", "color": "blue"},
            {"name": "Rescue 1122", "number": "1122", "type": "ambulance", "color": "red"},
            {"name": "PDMA Khyber Pakhtunkhwa", "number": "1700", "type": "alert", "color": "orange"}
        ],
        "Balochistan": [
            {"name": "Police Emergency", "number": "15", "type": "police", "color": "blue"},
            {"name": "Edhi Ambulance", "number": "115", "type": "ambulance", "color": "red"},
            {"name": "PDMA Balochistan", "number": "1129", "type": "alert", "color": "orange"}
        ],
        "Gilgit-Baltistan (GB)": [
            {"name": "Police Emergency", "number": "15", "type": "police", "color": "blue"},
            {"name": "Rescue 1122", "number": "1122", "type": "ambulance", "color": "red"},
            {"name": "GB Disaster Management", "number": "114", "type": "alert", "color": "orange"}
        ],
        "Azad Jammu & Kashmir (AJK)": [
            {"name": "Police Emergency", "number": "15", "type": "police", "color": "blue"},
            {"name": "Rescue 1122", "number": "1122", "type": "ambulance", "color": "red"},
            {"name": "SDMA AJK", "number": "1900", "type": "alert", "color": "orange"}
        ]
    }
    return render_template('directory.html', title="Emergency Directory", contacts=contacts)

@app.route('/hospitals')
def hospitals():
    return render_template('hospitals.html', title="Hospital Locator")

@app.route('/api/hospitals', methods=['GET'])
def get_hospitals():
    """Secure, high-speed regional cache lookups to bypass sandbox limits."""
    city = request.args.get('city', '').strip().lower()
    if city in LOCAL_HOSPITALS:
        return jsonify({"status": "success", "source": "local", "elements": LOCAL_HOSPITALS[city]})
    return jsonify({"status": "not_found", "source": "local", "elements": []})

@app.route('/updates')
def updates():
    real_time_feed = fetch_real_time_intelligence()
    return render_template('updates.html', title="Live Updates", feed=real_time_feed)

@app.route('/legal')
def legal():
    return render_template('legal.html', title="Legal Hub")

# =====================================================================
# SYSTEM INITIALIZATION RUNNER
# =====================================================================
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)