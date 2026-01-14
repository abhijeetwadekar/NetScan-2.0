import pandas as pd
from cve_mapper import map_cve

def generate_report(scan_data):
    rows = []
    for item in scan_data:
        cve, severity, score = map_cve(item["service"], item["version"])
        rows.append({
            "Host": item["host"],
            "Port": item["port"],
            "Service": item["service"],
            "Version": item["version"],
            "CVE": cve,
            "Severity": severity
        })
    return pd.DataFrame(rows)