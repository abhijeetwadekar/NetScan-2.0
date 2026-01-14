def map_cve(service, version):
    # Mock CVE mapping for demo/hackathon use
    if service.lower() == "http":
        return ("CVE-2021-44228", "High", 9.8)
    return ("N/A", "Low", 0.0)