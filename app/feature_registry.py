"""Central registry for GODSEYE feature availability."""
FEATURES = {
"discovery": ["arp","nmap","neighbors","mdns_dns"],
"intelligence": ["device_correlation","vendor_enrichment","ip_history","findings","topology"],
"monitoring": ["website","dhcp","public_ip","pihole","unifi","snmp"],
"tools": ["diagnostics","wake_on_lan"],
"observability": ["alerts","events","prometheus"],
"automation": ["notifications","workflows","reports"],
}

def all_features():
    return [{"category":k,"features":v} for k,v in FEATURES.items()]
