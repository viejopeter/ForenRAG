"""Collect Wazuh telemetry and generate forensic evidence packages."""

import base64
import json
import math
import os
import ssl
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from datetime import UTC, datetime

from dotenv import load_dotenv
from flask import Flask, jsonify, request

from technique_inference import derive_technique_metadata

load_dotenv()


class ConfigurationError(RuntimeError):
    """Raised when required collector configuration is missing or invalid."""


class OpenSearchQueryError(RuntimeError):
    """Raised when an OpenSearch request or response cannot be completed."""


def load_configuration():
    """Load and validate collector settings from the environment."""
    errors = []

    def required(name):
        value = os.getenv(name)
        if value is None or not value.strip():
            errors.append(f"{name} is required and must not be empty")
            return ""
        return value

    opensearch_url = required("OPENSEARCH_URL")
    opensearch_user = required("OPENSEARCH_USER")
    opensearch_password = required("OPENSEARCH_PASSWORD")
    agent_id = required("WAZUH_AGENT_ID")

    try:
        parsed_url = urllib.parse.urlparse(opensearch_url)
        if opensearch_url and (
            parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc
        ):
            errors.append("OPENSEARCH_URL must be an absolute HTTP or HTTPS URL")
    except ValueError as exc:
        errors.append(f"OPENSEARCH_URL is invalid: {exc}")

    try:
        min_rule_level = int(required("MIN_RULE_LEVEL"))
        if min_rule_level < 0:
            raise ValueError
    except ValueError:
        errors.append("MIN_RULE_LEVEL must be a non-negative integer")
        min_rule_level = 0

    try:
        settling_window_seconds = float(required("SETTLING_WINDOW_SECONDS"))
        if not math.isfinite(settling_window_seconds) or settling_window_seconds <= 0:
            raise ValueError
    except ValueError:
        errors.append("SETTLING_WINDOW_SECONDS must be a positive number")
        settling_window_seconds = 0.0

    try:
        request_timeout_seconds = float(
            os.getenv("OPENSEARCH_REQUEST_TIMEOUT_SECONDS", "30")
        )
        if not math.isfinite(request_timeout_seconds) or request_timeout_seconds <= 0:
            raise ValueError
    except ValueError:
        errors.append("OPENSEARCH_REQUEST_TIMEOUT_SECONDS must be a positive number")
        request_timeout_seconds = 30.0

    verify_tls_value = os.getenv("OPENSEARCH_VERIFY_TLS", "false").strip().lower()
    if verify_tls_value in {"1", "true", "yes", "on"}:
        verify_tls = True
    elif verify_tls_value in {"0", "false", "no", "off"}:
        verify_tls = False
    else:
        errors.append(
            "OPENSEARCH_VERIFY_TLS must be one of: true, false, 1, 0, yes, no, on, off"
        )
        verify_tls = False

    ca_bundle_value = os.getenv("OPENSEARCH_CA_BUNDLE", "").strip()
    ca_bundle = ca_bundle_value or None
    if verify_tls and ca_bundle and not os.path.isfile(os.path.expanduser(ca_bundle)):
        errors.append(
            f"OPENSEARCH_CA_BUNDLE does not exist or is not a file: {ca_bundle}"
        )

    if errors:
        details = "\n".join(f"- {error}" for error in errors)
        raise ConfigurationError(f"Invalid ForenRAG configuration:\n{details}")

    return (
        opensearch_url,
        opensearch_user,
        opensearch_password,
        agent_id,
        min_rule_level,
        settling_window_seconds,
        request_timeout_seconds,
        verify_tls,
        os.path.expanduser(ca_bundle) if ca_bundle else None,
    )


(
    OPENSEARCH_URL,
    OPENSEARCH_USER,
    OPENSEARCH_PASSWORD,
    DEFAULT_AGENT_ID,
    MIN_RULE_LEVEL,
    SETTLING_WINDOW_SECONDS,
    OPENSEARCH_REQUEST_TIMEOUT_SECONDS,
    OPENSEARCH_VERIFY_TLS,
    OPENSEARCH_CA_BUNDLE,
) = load_configuration()

app = Flask(__name__)

OUTPUT_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "evidence_packages"
)
FINALIZATION_MAX_RETRIES = 3
FINALIZATION_RETRY_SECONDS = 3.0
os.makedirs(OUTPUT_DIR, exist_ok=True)

session_buckets = {}
bucket_lock = threading.Lock()
incident_directory_lock = threading.Lock()


def get_auth_header():
    creds = base64.b64encode(
        f"{OPENSEARCH_USER}:{OPENSEARCH_PASSWORD}".encode()
    ).decode("utf-8")
    return f"Basic {creds}"


def query_opensearch(index_pattern, query_payload):
    url = f"{OPENSEARCH_URL}/{index_pattern}/_search"
    try:
        if OPENSEARCH_VERIFY_TLS:
            ctx = ssl.create_default_context(cafile=OPENSEARCH_CA_BUNDLE)
        else:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(
            url,
            data=json.dumps(query_payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": get_auth_header(),
            },
            method="POST",
        )
        with urllib.request.urlopen(
            req,
            context=ctx,
            timeout=OPENSEARCH_REQUEST_TIMEOUT_SECONDS,
        ) as response:
            return json.loads(response.read().decode("utf-8"))
    except (OSError, TypeError, ValueError) as exc:
        raise OpenSearchQueryError(
            f"OpenSearch query failed for index {index_pattern!r} at {url}: {exc}"
        ) from exc


def trace_process_tree(initial_guid, agent_id=None, max_depth=5):
    """Recursively traces parent-child process lineage using Sysmon Event ID 1."""
    if not initial_guid:
        return []
    agent_id = agent_id or DEFAULT_AGENT_ID
    visited, process_nodes, queue = set(), [], [(initial_guid, 0)]

    GENERIC_SHELLS = [
        "explorer.exe",
        "svchost.exe",
        "lsass.exe",
        "services.exe",
        "winlogon.exe",
        "csrss.exe",
        "userinit.exe",
    ]

    while queue:
        guid, depth = queue.pop(0)
        if guid in visited or depth > max_depth:
            continue
        visited.add(guid)

        q = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"agent.id": agent_id}},
                        {"term": {"data.win.system.eventID": "1"}},
                        {
                            "query_string": {
                                "default_field": "data.win.eventdata.processGuid",
                                "query": f'"{guid}"',
                            }
                        },
                    ]
                }
            },
            "size": 1,
        }
        res = query_opensearch("wazuh-archives-*", q)
        hits = res.get("hits", {}).get("hits", [])
        if hits:
            ev = hits[0]["_source"].get("data", {}).get("win", {}).get("eventdata", {})
            img = (ev.get("image") or "").lower()

            process_nodes.append(
                {
                    "process_guid": guid,
                    "parent_process_guid": ev.get("parentProcessGuid"),
                    "process_id": ev.get("processId"),
                    "image": ev.get("image"),
                    "command_line": ev.get("commandLine"),
                    "user": ev.get("user"),
                    "integrity_level": ev.get("integrityLevel"),
                    "hashes": ev.get("hashes"),
                    "timestamp": hits[0]["_source"].get("timestamp"),
                }
            )

            parent = ev.get("parentProcessGuid")
            if parent and parent not in visited:
                queue.append((parent, depth + 1))

            if not any(sh in img for sh in GENERIC_SHELLS):
                cq = {
                    "query": {
                        "bool": {
                            "must": [
                                {"term": {"agent.id": agent_id}},
                                {"term": {"data.win.system.eventID": "1"}},
                                {
                                    "query_string": {
                                        "default_field": "data.win.eventdata.parentProcessGuid",
                                        "query": f'"{guid}"',
                                    }
                                },
                            ]
                        }
                    },
                    "size": 20,
                }
                c_res = query_opensearch("wazuh-archives-*", cq)
                for ch in c_res.get("hits", {}).get("hits", []):
                    c_guid = (
                        ch["_source"]
                        .get("data", {})
                        .get("win", {})
                        .get("eventdata", {})
                        .get("processGuid")
                    )
                    if c_guid and c_guid not in visited:
                        queue.append((c_guid, depth + 1))

    return process_nodes


def collect_artifacts(guids, agent_id=None):
    """Correlates File Creations (EID 11) and Registry Set Values (EID 13)."""
    files, registry = [], []
    agent_id = agent_id or DEFAULT_AGENT_ID
    for g in guids:
        fq = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"agent.id": agent_id}},
                        {"term": {"data.win.system.eventID": "11"}},
                        {
                            "query_string": {
                                "default_field": "data.win.eventdata.processGuid",
                                "query": f'"{g}"',
                            }
                        },
                    ]
                }
            },
            "size": 10,
        }
        for hit in (
            query_opensearch("wazuh-archives-*", fq).get("hits", {}).get("hits", [])
        ):
            ev = hit["_source"].get("data", {}).get("win", {}).get("eventdata", {})
            files.append(
                {
                    "process_guid": g,
                    "image": ev.get("image"),
                    "target_filename": ev.get("targetFilename"),
                    "timestamp": hit["_source"].get("timestamp"),
                }
            )

        rq = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"agent.id": agent_id}},
                        {"term": {"data.win.system.eventID": "13"}},
                        {
                            "query_string": {
                                "default_field": "data.win.eventdata.processGuid",
                                "query": f'"{g}"',
                            }
                        },
                    ]
                }
            },
            "size": 10,
        }
        for hit in (
            query_opensearch("wazuh-archives-*", rq).get("hits", {}).get("hits", [])
        ):
            ev = hit["_source"].get("data", {}).get("win", {}).get("eventdata", {})
            registry.append(
                {
                    "process_guid": g,
                    "image": ev.get("image"),
                    "target_object": ev.get("targetObject"),
                    "details": ev.get("details"),
                    "timestamp": hit["_source"].get("timestamp"),
                }
            )

    return {"file_creations": files, "registry_sets": registry}


def get_root_ancestor_guid(process_guid, parent_guid, agent_id=None):
    """Resolve the root ancestor below the system logon shells."""
    current_guid = parent_guid or process_guid
    agent_id = agent_id or DEFAULT_AGENT_ID
    SYSTEM_SHELLS = {
        "explorer.exe",
        "userinit.exe",
        "winlogon.exe",
        "services.exe",
        "smss.exe",
    }
    visited = set()
    root_candidate = current_guid

    while current_guid and current_guid not in visited:
        visited.add(current_guid)
        q = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"agent.id": agent_id}},
                        {"term": {"data.win.system.eventID": "1"}},
                        {
                            "query_string": {
                                "default_field": "data.win.eventdata.processGuid",
                                "query": f'"{current_guid}"',
                            }
                        },
                    ]
                }
            },
            "size": 1,
        }
        hits = query_opensearch("wazuh-archives-*", q).get("hits", {}).get("hits", [])
        if not hits:
            break

        ev = hits[0]["_source"].get("data", {}).get("win", {}).get("eventdata", {})
        parent_img = os.path.basename(ev.get("parentImage", "")).lower()
        parent_guid_val = ev.get("parentProcessGuid")

        if parent_img in SYSTEM_SHELLS or not parent_guid_val:
            root_candidate = current_guid
            break

        root_candidate = current_guid
        current_guid = parent_guid_val

    return root_candidate


def finalize_session(parent_guid):
    with bucket_lock:
        session_data = session_buckets.pop(parent_guid, None)
    if not session_data:
        return

    start_t = time.time()
    alerts = session_data["alerts"]
    print(
        f"\n[INFO] Processing consolidated session [{parent_guid}] "
        f"({len(alerts)} alerts)..."
    )

    incident_dir = None
    temporary_filepath = None
    try:
        primary_alert = alerts[-1]
        target_guid = primary_alert.get("process_guid") or parent_guid

        tree = trace_process_tree(target_guid)
        guids = [p["process_guid"] for p in tree] if tree else [target_guid]
        artifacts = collect_artifacts(guids)
        technique_metadata = derive_technique_metadata(primary_alert, tree)

        package = {
            "collection_timestamp": datetime.now(UTC).isoformat(),
            "collection_latency_seconds": round(time.time() - start_t, 3),
            "trigger_alert": primary_alert,
            **technique_metadata,
            "process_tree": tree,
            "artifacts": artifacts,
            "all_session_alerts": alerts,
        }

        ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        analysis_techniques = technique_metadata["analysis_techniques"]
        mitre_suffix = f"_{analysis_techniques[0]}" if analysis_techniques else ""
        output_root = os.path.realpath(OUTPUT_DIR)

        with incident_directory_lock:
            existing_dirs = [
                name
                for name in os.listdir(OUTPUT_DIR)
                if os.path.isdir(os.path.join(OUTPUT_DIR, name))
            ]
            next_idx = len(existing_dirs) + 1

            while True:
                folder_name = f"{next_idx:03d}_incident_{ts}{mitre_suffix}"
                incident_dir = os.path.realpath(os.path.join(output_root, folder_name))
                if os.path.commonpath((output_root, incident_dir)) != output_root:
                    raise ValueError(
                        "Incident directory resolved outside evidence_packages"
                    )
                try:
                    os.mkdir(incident_dir)
                    break
                except FileExistsError:
                    next_idx += 1

        filepath = os.path.join(incident_dir, "evidence.json")
        with tempfile.NamedTemporaryFile(
            mode="w",
            dir=incident_dir,
            prefix=".evidence-",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_filepath = temporary_file.name
            json.dump(package, temporary_file, indent=2)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.replace(temporary_filepath, filepath)
        temporary_filepath = None
    except Exception as exc:  # noqa: BLE001 - retain the session after any failure
        if temporary_filepath:
            try:
                os.unlink(temporary_filepath)
            except FileNotFoundError:
                pass
        if incident_dir:
            try:
                os.rmdir(incident_dir)
            except OSError:
                pass

        retry_count = session_data.get("finalization_retry_count", 0) + 1
        session_data["finalization_retry_count"] = retry_count

        with bucket_lock:
            current_session = session_buckets.get(parent_guid)
            if current_session:
                current_timer = current_session.get("timer")
                if current_timer:
                    current_timer.cancel()
                session_data["alerts"].extend(current_session["alerts"])

            retry_timer = None
            if retry_count <= FINALIZATION_MAX_RETRIES:
                retry_timer = threading.Timer(
                    FINALIZATION_RETRY_SECONDS,
                    finalize_session,
                    args=[parent_guid],
                )
            session_data["timer"] = retry_timer
            session_buckets[parent_guid] = session_data
            if retry_timer:
                retry_timer.start()

        if retry_timer:
            print(
                f"[ERROR] Finalization failed for session [{parent_guid}]; "
                f"retry {retry_count} of {FINALIZATION_MAX_RETRIES} scheduled: {exc}"
            )
        else:
            print(
                f"[ERROR] Finalization failed for session [{parent_guid}] after "
                f"{FINALIZATION_MAX_RETRIES} retries; session retained: {exc}"
            )
        return

    print(f"[INFO] Generated evidence package: {filepath}")
    print(
        f"    Nodes: {len(tree)} | Files: {len(artifacts['file_creations'])} | "
        f"Registry: {len(artifacts['registry_sets'])} | "
        f"Latency: {package['collection_latency_seconds']}s"
    )

    def run_automated_pipeline():
        try:
            print(f"[INFO] Executing RAG and Ollama reasoning for {folder_name}...")
            from forenrag_reasoner import generate_forensic_report

            generate_forensic_report(filepath)
        except Exception as exc:  # noqa: BLE001 - isolate the background pipeline
            print(f"[ERROR] Automated RAG reasoning pipeline failed: {exc}")

    threading.Thread(target=run_automated_pipeline, daemon=True).start()


@app.route("/alert", methods=["POST"])
def handle_wazuh_alert():
    data = request.json or {}
    rule = data.get("rule", {})
    rule_level = int(rule.get("level", 0))

    if rule_level < MIN_RULE_LEVEL:
        return jsonify(
            {
                "status": "ignored",
                "reason": f"Rule level {rule_level} below threshold ({MIN_RULE_LEVEL})",
            }
        ), 200

    ev = data.get("data", {}).get("win", {}).get("eventdata", {})
    process_guid = ev.get("processGuid")
    parent_guid = ev.get("parentProcessGuid") or process_guid or "global_session"

    target_file = ev.get("targetFilename", "")
    if "__PSScriptPolicyTest" in target_file and not ev.get("commandLine"):
        return jsonify(
            {"status": "ignored", "reason": "Benign PSScriptPolicyTest check"}
        ), 200

    alert_summary = {
        "timestamp": data.get("timestamp"),
        "rule_id": rule.get("id"),
        "rule_level": rule_level,
        "rule_description": rule.get("description"),
        "mitre_id": rule.get("mitre", {}).get("id", []),
        "process_guid": process_guid,
        "parent_guid": parent_guid,
        "command_line": ev.get("commandLine"),
    }

    session_key = get_root_ancestor_guid(process_guid, parent_guid)

    with bucket_lock:
        if session_key in session_buckets:
            current_timer = session_buckets[session_key].get("timer")
            if current_timer:
                current_timer.cancel()
            session_buckets[session_key]["alerts"].append(alert_summary)
        else:
            session_buckets[session_key] = {"alerts": [alert_summary], "timer": None}

        timer = threading.Timer(
            SETTLING_WINDOW_SECONDS, finalize_session, args=[session_key]
        )
        session_buckets[session_key]["timer"] = timer
        timer.start()

    print(
        f"[INFO] Critical alert received: Rule {rule.get('id')} "
        f"(L{rule_level}): {rule.get('description')}"
    )
    return jsonify({"status": "queued", "session": session_key}), 200


@app.route("/status", methods=["GET"])
def status():
    return jsonify(
        {
            "status": "running",
            "min_rule_level": MIN_RULE_LEVEL,
            "output_dir": OUTPUT_DIR,
        }
    ), 200


processed_alert_ids = set()


def seed_existing_alerts():
    try:
        q = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"agent.id": DEFAULT_AGENT_ID}},
                        {"range": {"rule.level": {"gte": MIN_RULE_LEVEL}}},
                    ]
                }
            },
            "size": 100,
        }
        res = query_opensearch("wazuh-alerts-*", q)
        for hit in res.get("hits", {}).get("hits", []):
            aid = hit.get("_id")
            if aid:
                processed_alert_ids.add(aid)
        print(
            f"[INFO] Seeded {len(processed_alert_ids)} historical alert IDs "
            f"(Level >= {MIN_RULE_LEVEL})."
        )
    except Exception as exc:  # noqa: BLE001 - keep the poller available for retries
        print(f"[ERROR] Failed to seed alert IDs: {exc}")


def start_opensearch_poller():
    print(
        f"[INFO] Starting OpenSearch alert poller "
        f"(filtering Level >= {MIN_RULE_LEVEL})..."
    )
    seed_existing_alerts()
    while True:
        try:
            q = {
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"agent.id": DEFAULT_AGENT_ID}},
                            {"range": {"rule.level": {"gte": MIN_RULE_LEVEL}}},
                        ],
                        "filter": [{"range": {"timestamp": {"gte": "now-2m"}}}],
                    }
                },
                "sort": [{"timestamp": {"order": "desc"}}],
                "size": 10,
            }
            res = query_opensearch("wazuh-alerts-*", q)
            hits = res.get("hits", {}).get("hits", [])
            for hit in hits:
                aid = hit.get("_id")
                if not aid or aid in processed_alert_ids:
                    continue
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
                    "command_line": cmd,
                }

                session_key = get_root_ancestor_guid(pguid, parent_guid)

                with bucket_lock:
                    if session_key in session_buckets:
                        current_timer = session_buckets[session_key].get("timer")
                        if current_timer:
                            current_timer.cancel()
                        session_buckets[session_key]["alerts"].append(alert_summary)
                    else:
                        session_buckets[session_key] = {
                            "alerts": [alert_summary],
                            "timer": None,
                        }

                    timer = threading.Timer(
                        SETTLING_WINDOW_SECONDS, finalize_session, args=[session_key]
                    )
                    session_buckets[session_key]["timer"] = timer
                    timer.start()

                print(
                    f"[INFO] Critical alert detected: Rule {rule.get('id')} "
                    f"(L{rule_level}): {rule.get('description')} | Cmd: {cmd[:70]}..."
                )
        except Exception as exc:  # noqa: BLE001 - one bad response must not stop polling
            print(f"[ERROR] OpenSearch poller failed: {exc}")
        time.sleep(3.0)


if __name__ == "__main__":
    print("ForenRAG collector")
    print(f"Severity filter: Wazuh Rule Level >= {MIN_RULE_LEVEL}")
    print("Listening on: http://0.0.0.0:5000/alert")
    poller_thread = threading.Thread(target=start_opensearch_poller, daemon=True)
    poller_thread.start()
    app.run(host="0.0.0.0", port=5000, debug=False)
