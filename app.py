"""
ForenRAG Autonomous Telemetry Collector & RAG Reasoning Agent
--------------------------------------------------------------
Autonomous forensic collector that receives real-time Wazuh webhooks,
consolidates attack sessions, traces Sysmon process trees via OpenSearch,
generates structured DFIR Evidence Packages (JSON), and automatically
triggers Phase 4 (ChromaDB RAG) & Phase 5 (Ollama Reasoning) report generation.
"""

import os
import time
import json
import base64
import urllib.request
import ssl
import threading
from datetime import datetime, timezone
from flask import Flask, request, jsonify
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# Configuration & Paths
OPENSEARCH_URL = os.getenv("OPENSEARCH_URL")
PASS_FILE = "/home/vboxuser/pass.txt"
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evidence_packages")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Severity Level Filter: Trigger ONLY on High / Critical Alerts (Level >= 12)
MIN_RULE_LEVEL = 12

SETTLING_WINDOW_SECONDS = 15.0
session_buckets = {}
bucket_lock = threading.Lock()

# ---------------------------------------------------------------------------
# 1. OpenSearch Authentication & REST Helper
# ---------------------------------------------------------------------------
def get_auth_header():
    user, pwd = "admin", "REDACTED_PASSWORD"
    if os.path.exists(PASS_FILE):
        with open(PASS_FILE, "r") as f:
            for line in f:
                if "User:" in line: user = line.split("User:", 1)[1].strip()
                elif "Password:" in line: pwd = line.split("Password:", 1)[1].strip()
    creds = base64.b64encode(f"{user}:{pwd}".encode('utf-8')).decode('utf-8')
    return f"Basic {creds}"

def query_opensearch(index_pattern, query_payload):
    url = f"{OPENSEARCH_URL}/{index_pattern}/_search"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    req = urllib.request.Request(
        url,
        data=json.dumps(query_payload).encode('utf-8'),
        headers={"Content-Type": "application/json", "Authorization": get_auth_header()},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, context=ctx) as response:
            return json.loads(response.read().decode('utf-8'))
    except Exception as e:
        print(f"[!] OpenSearch Query Error: {e}")
        return {}

# ---------------------------------------------------------------------------
# 2. Process Tree & Artifact Correlation Engine (Direct Lineage Focused)
# ---------------------------------------------------------------------------
def trace_process_tree(initial_guid, max_depth=5):
    """Recursively traces parent-child process lineage using Sysmon Event ID 1."""
    if not initial_guid: return []
    visited, process_nodes, queue = set(), [], [(initial_guid, 0)]
    
    GENERIC_SHELLS = ["explorer.exe", "svchost.exe", "lsass.exe", "services.exe", "winlogon.exe", "csrss.exe", "userinit.exe"]
    
    while queue:
        guid, depth = queue.pop(0)
        if guid in visited or depth > max_depth: continue
        visited.add(guid)
        
        q = {"query": {"bool": {"must": [{"term": {"agent.id": "002"}}, {"term": {"data.win.system.eventID": "1"}}, {"query_string": {"default_field": "data.win.eventdata.processGuid", "query": f'"{guid}"'}}]}}, "size": 1}
        res = query_opensearch("wazuh-archives-*", q)
        hits = res.get("hits", {}).get("hits", [])
        if hits:
            ev = hits[0]["_source"].get("data", {}).get("win", {}).get("eventdata", {})
            img = (ev.get("image") or "").lower()
            
            process_nodes.append({
                "process_guid": guid,
                "parent_process_guid": ev.get("parentProcessGuid"),
                "process_id": ev.get("processId"),
                "image": ev.get("image"),
                "command_line": ev.get("commandLine"),
                "user": ev.get("user"),
                "integrity_level": ev.get("integrityLevel"),
                "hashes": ev.get("hashes"),
                "timestamp": hits[0]["_source"].get("timestamp")
            })
            
            parent = ev.get("parentProcessGuid")
            if parent and parent not in visited: queue.append((parent, depth + 1))
            
            if not any(sh in img for sh in GENERIC_SHELLS):
                cq = {"query": {"bool": {"must": [{"term": {"agent.id": "002"}}, {"term": {"data.win.system.eventID": "1"}}, {"query_string": {"default_field": "data.win.eventdata.parentProcessGuid", "query": f'"{guid}"'}}]}}, "size": 20}
                c_res = query_opensearch("wazuh-archives-*", cq)
                for ch in c_res.get("hits", {}).get("hits", []):
                    c_guid = ch["_source"].get("data", {}).get("win", {}).get("eventdata", {}).get("processGuid")
                    if c_guid and c_guid not in visited: queue.append((c_guid, depth + 1))
                
    return process_nodes

def collect_artifacts(guids):
    """Correlates File Creations (EID 11) and Registry Set Values (EID 13)."""
    files, registry = [], []
    for g in guids:
        fq = {"query": {"bool": {"must": [{"term": {"agent.id": "002"}}, {"term": {"data.win.system.eventID": "11"}}, {"query_string": {"default_field": "data.win.eventdata.processGuid", "query": f'"{g}"'}}]}}, "size": 10}
        for hit in query_opensearch("wazuh-archives-*", fq).get("hits", {}).get("hits", []):
            ev = hit["_source"].get("data", {}).get("win", {}).get("eventdata", {})
            files.append({"process_guid": g, "image": ev.get("image"), "target_filename": ev.get("targetFilename"), "timestamp": hit["_source"].get("timestamp")})
            
        rq = {"query": {"bool": {"must": [{"term": {"agent.id": "002"}}, {"term": {"data.win.system.eventID": "13"}}, {"query_string": {"default_field": "data.win.eventdata.processGuid", "query": f'"{g}"'}}]}}, "size": 10}
        for hit in query_opensearch("wazuh-archives-*", rq).get("hits", {}).get("hits", []):
            ev = hit["_source"].get("data", {}).get("win", {}).get("eventdata", {})
            registry.append({"process_guid": g, "image": ev.get("image"), "target_object": ev.get("targetObject"), "details": ev.get("details"), "timestamp": hit["_source"].get("timestamp")})
            
    return {"file_creations": files, "registry_sets": registry}

# ---------------------------------------------------------------------------
# 3. Session Consolidation, Subfolder Creation & Automated RAG Pipeline
# ---------------------------------------------------------------------------
def finalize_session(parent_guid):
    with bucket_lock:
        session_data = session_buckets.pop(parent_guid, None)
    if not session_data: return

    start_t = time.time()
    alerts = session_data["alerts"]
    print(f"\n[+] Processing Consolidated Session [{parent_guid}] ({len(alerts)} alerts)...")
    
    primary_alert = alerts[-1]
    target_guid = primary_alert.get("process_guid") or parent_guid
    
    tree = trace_process_tree(target_guid)
    guids = [p["process_guid"] for p in tree] if tree else [target_guid]
    artifacts = collect_artifacts(guids)
    
    package = {
        "collection_timestamp": datetime.now(timezone.utc).isoformat(),
        "collection_latency_seconds": round(time.time() - start_t, 3),
        "trigger_alert": primary_alert,
        "process_tree": tree,
        "artifacts": artifacts,
        "all_session_alerts": alerts
    }
    
    # Sequential Incident ID Prefix: 001_incident_YYYYMMDD_HHMMSS_<MITRE_ID>
    existing_dirs = [d for d in os.listdir(OUTPUT_DIR) if os.path.isdir(os.path.join(OUTPUT_DIR, d))]
    next_idx = len(existing_dirs) + 1
    
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    mitre_ids = primary_alert.get("mitre_id", [])
    mitre_suffix = f"_{mitre_ids[0]}" if mitre_ids else ""
    folder_name = f"{next_idx:03d}_incident_{ts}{mitre_suffix}"
    
    incident_dir = os.path.join(OUTPUT_DIR, folder_name)
    os.makedirs(incident_dir, exist_ok=True)
    
    filepath = os.path.join(incident_dir, "evidence.json")
    with open(filepath, "w") as f: json.dump(package, f, indent=2)
        
    print(f"[✔] Generated Evidence Package: {filepath}")
    print(f"    - Nodes: {len(tree)} | Files: {len(artifacts['file_creations'])} | Registry: {len(artifacts['registry_sets'])} | Latency: {package['collection_latency_seconds']}s")

    # AUTOMATED PIPELINE: Automatically trigger Phase 4 RAG & Phase 5 Ollama Reasoning in background thread
    def run_automated_pipeline():
        try:
            print(f"[+] Automatically executing RAG & Ollama reasoning for {folder_name}...")
            from forenrag_reasoner import generate_forensic_report
            generate_forensic_report(filepath)
        except Exception as e:
            print(f"[!] Error executing automated RAG reasoning pipeline: {e}")

    threading.Thread(target=run_automated_pipeline, daemon=True).start()

# ---------------------------------------------------------------------------
# 4. Real-Time Webhook Listener
# ---------------------------------------------------------------------------
@app.route('/alert', methods=['POST'])
def handle_wazuh_alert():
    data = request.json or {}
    rule = data.get("rule", {})
    rule_level = int(rule.get("level", 0))

    if rule_level < MIN_RULE_LEVEL:
        return jsonify({"status": "ignored", "reason": f"Rule level {rule_level} below threshold ({MIN_RULE_LEVEL})"}), 200

    ev = data.get("data", {}).get("win", {}).get("eventdata", {})
    process_guid = ev.get("processGuid")
    parent_guid = ev.get("parentProcessGuid") or process_guid or "global_session"
    
    target_file = ev.get("targetFilename", "")
    if "__PSScriptPolicyTest" in target_file and not ev.get("commandLine"):
        return jsonify({"status": "ignored", "reason": "Benign PSScriptPolicyTest check"}), 200
    
    alert_summary = {
        "timestamp": data.get("timestamp"),
        "rule_id": rule.get("id"),
        "rule_level": rule_level,
        "rule_description": rule.get("description"),
        "mitre_id": rule.get("mitre", {}).get("id", []),
        "process_guid": process_guid,
        "parent_guid": parent_guid,
        "command_line": ev.get("commandLine")
    }

    with bucket_lock:
        if parent_guid in session_buckets:
            session_buckets[parent_guid]["timer"].cancel()
            session_buckets[parent_guid]["alerts"].append(alert_summary)
        else:
            session_buckets[parent_guid] = {"alerts": [alert_summary], "timer": None}

        timer = threading.Timer(SETTLING_WINDOW_SECONDS, finalize_session, args=[parent_guid])
        session_buckets[parent_guid]["timer"] = timer
        timer.start()

    print(f"[🚨 CRITICAL ALERT RECEIVED] Rule {rule.get('id')} (L{rule_level}): {rule.get('description')}")
    return jsonify({"status": "queued", "session": parent_guid}), 200

@app.route('/status', methods=['GET'])
def status(): return jsonify({"status": "running", "min_rule_level": MIN_RULE_LEVEL, "output_dir": OUTPUT_DIR}), 200

# ---------------------------------------------------------------------------
# 5. OpenSearch Live Alerts Poller (Severity-Driven Engine)
# ---------------------------------------------------------------------------
processed_alert_ids = set()

def seed_existing_alerts():
    try:
        q = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"agent.id": "002"}},
                        {"range": {"rule.level": {"gte": MIN_RULE_LEVEL}}}
                    ]
                }
            },
            "size": 100
        }
        res = query_opensearch("wazuh-alerts-*", q)
        for hit in res.get("hits", {}).get("hits", []):
            aid = hit.get("_id")
            if aid: processed_alert_ids.add(aid)
        print(f"[+] Seeded {len(processed_alert_ids)} historical alert IDs (Level >= {MIN_RULE_LEVEL}).")
    except Exception as e:
        print(f"[!] Error seeding alert IDs: {e}")

def start_opensearch_poller():
    print(f"[+] Starting Live OpenSearch Alerts Poller Thread (Filtering Level >= {MIN_RULE_LEVEL})...")
    seed_existing_alerts()
    while True:
        try:
            q = {
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"agent.id": "002"}},
                            {"range": {"rule.level": {"gte": MIN_RULE_LEVEL}}}
                        ],
                        "filter": [
                            {"range": {"timestamp": {"gte": "now-2m"}}}
                        ]
                    }
                },
                "sort": [{"timestamp": {"order": "desc"}}],
                "size": 10
            }
            res = query_opensearch("wazuh-alerts-*", q)
            hits = res.get("hits", {}).get("hits", [])
            for hit in hits:
                aid = hit.get("_id")
                if not aid or aid in processed_alert_ids: continue
                processed_alert_ids.add(aid)

                src = hit["_source"]
                ev = src.get("data", {}).get("win", {}).get("eventdata", {})
                pguid = ev.get("processGuid")
                cmd = ev.get("commandLine", "")
                parent_guid = ev.get("parentProcessGuid") or pguid or "global_session"
                rule = src.get("rule", {})
                rule_level = rule.get("level", 0)
                
                target_file = ev.get("targetFilename", "")
                if "__PSScriptPolicyTest" in target_file and not cmd:
                    continue

                alert_summary = {
                    "timestamp": src.get("timestamp"),
                    "rule_id": rule.get("id"),
                    "rule_level": rule_level,
                    "rule_description": rule.get("description"),
                    "mitre_id": rule.get("mitre", {}).get("id", []),
                    "process_guid": pguid,
                    "parent_guid": parent_guid,
                    "command_line": cmd
                }
                
                with bucket_lock:
                    if parent_guid in session_buckets:
                        session_buckets[parent_guid]["timer"].cancel()
                        session_buckets[parent_guid]["alerts"].append(alert_summary)
                    else:
                        session_buckets[parent_guid] = {"alerts": [alert_summary], "timer": None}

                    timer = threading.Timer(SETTLING_WINDOW_SECONDS, finalize_session, args=[parent_guid])
                    session_buckets[parent_guid]["timer"] = timer
                    timer.start()
                
                print(f"[🚨 CRITICAL ALERT DETECTED] Rule {rule.get('id')} (L{rule_level}): {rule.get('description')} | Cmd: {cmd[:70]}...")
        except Exception as e:
            print(f"[!] Poller Error: {e}")
        time.sleep(3.0)

if __name__ == '__main__':
    print(f"==================================================")
    print(f"   ForenRAG Automated Autonomous Agent")
    print(f"   Severity Filter: Wazuh Rule Level >= {MIN_RULE_LEVEL}")
    print(f"   Listening on: http://0.0.0.0:5000/alert")
    print(f"==================================================")
    poller_thread = threading.Thread(target=start_opensearch_poller, daemon=True)
    poller_thread.start()
    app.run(host="0.0.0.0", port=5000, debug=False)
