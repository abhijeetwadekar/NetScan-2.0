import nmap

def scan_network(target):
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments="-sV")

    hosts = nm.all_hosts()
    total_hosts = len(hosts)

    all_results = []

    for idx, host in enumerate(hosts):
        for proto in nm[host].all_protocols():
            for port in nm[host][proto]:
                svc = nm[host][proto][port]
                all_results.append({
                    "host": host,
                    "port": port,
                    "service": svc.get("name", ""),
                    "version": svc.get("version", "")
                })

        progress = int(((idx + 1) / total_hosts) * 100)

        # ✅ THIS IS IMPORTANT
        yield progress, all_results
