"""Safe network diagnostics exposed to the GODSEYE troubleshooting layer."""
from __future__ import annotations
import ipaddress
import platform
import shutil
import socket
import subprocess
import time


def _run(cmd: list[str], timeout: float = 5) -> tuple[int, str, float]:
    started = time.monotonic()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or p.stderr).strip(), (time.monotonic() - started) * 1000
    except Exception as exc:
        return 1, str(exc), (time.monotonic() - started) * 1000


def ping(host: str, count: int = 4) -> dict:
    count = max(1, min(count, 10))
    binary = shutil.which("ping")
    if not binary:
        return {"ok": False, "error": "ping is not installed"}
    code, output, elapsed = _run([binary, "-c", str(count), "-W", "2", host], timeout=15)
    loss = None
    for line in output.splitlines():
        if "% packet loss" in line:
            try:
                loss = float(line.split("%", 1)[0].split()[-1])
            except ValueError:
                pass
    return {"ok": code == 0, "target": host, "packet_loss_percent": loss, "elapsed_ms": round(elapsed, 1), "raw": output[-2000:]}


def dns(host: str) -> dict:
    started = time.monotonic()
    try:
        answers = socket.getaddrinfo(host, None)
        ips = sorted({a[4][0] for a in answers})
        return {"ok": True, "host": host, "addresses": ips, "elapsed_ms": round((time.monotonic()-started)*1000, 1)}
    except Exception as exc:
        return {"ok": False, "host": host, "error": str(exc), "elapsed_ms": round((time.monotonic()-started)*1000, 1)}


def gateway() -> dict:
    code, output, elapsed = _run(["ip", "route", "show", "default"], timeout=3)
    gateway_ip = None
    if code == 0:
        parts = output.split()
        if "via" in parts:
            gateway_ip = parts[parts.index("via") + 1]
    return {"ok": bool(gateway_ip), "gateway": gateway_ip, "elapsed_ms": round(elapsed, 1), "raw": output}


def internet() -> dict:
    result = dns("example.com")
    if not result["ok"]:
        return {"ok": False, "stage": "dns", "details": result}
    g = gateway()
    if not g["ok"]:
        return {"ok": False, "stage": "gateway", "details": g}
    p = ping(g["gateway"], 2)
    if not p["ok"]:
        return {"ok": False, "stage": "gateway_ping", "details": p}
    return {"ok": True, "stage": "internet", "gateway": g["gateway"], "dns": result}


def diagnose_host(host: str) -> dict:
    result = {"target": host, "ping": ping(host), "dns": dns(host)}
    recommendations = []
    if not result["ping"]["ok"]:
        recommendations.append("Check power, Wi-Fi/Ethernet link, DHCP address, and whether the device blocks ICMP.")
    elif result["ping"].get("packet_loss_percent", 0) and result["ping"]["packet_loss_percent"] >= 10:
        recommendations.append("Packet loss is elevated; check Wi-Fi signal, cabling, AP health, and congestion.")
    if not result["dns"]["ok"]:
        recommendations.append("DNS lookup failed; check DHCP DNS settings and the router/DNS server.")
    result["recommendations"] = recommendations
    return result


def _private_target(host: str) -> str:
    host = host.strip()
    if not host or len(host) > 253:
        raise ValueError("Target is required")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        try:
            resolved = socket.gethostbyname(host)
            ip = ipaddress.ip_address(resolved)
        except Exception as exc:
            raise ValueError(f"Unable to resolve target: {exc}")
    if not (ip.is_private or ip.is_link_local):
        raise ValueError("GODSEYE tools are limited to private/link-local targets")
    return str(ip)


def traceroute(host: str, max_hops: int = 12) -> dict:
    target = _private_target(host)
    max_hops = max(1, min(int(max_hops), 30))
    binary = shutil.which("traceroute") or shutil.which("tracepath")
    if not binary:
        return {"ok": False, "target": target, "error": "traceroute or tracepath is not installed"}
    if binary.endswith("tracepath"):
        cmd = [binary, "-m", str(max_hops), target]
    else:
        cmd = [binary, "-n", "-m", str(max_hops), "-w", "1", target]
    code, output, elapsed = _run(cmd, timeout=max_hops + 5)
    return {"ok": code == 0, "target": target, "max_hops": max_hops,
            "elapsed_ms": round(elapsed, 1), "raw": output[-6000:]}


def port_scan(host: str, ports: str = "22,53,80,443,445,3389,8080,8443", timeout: int = 30) -> dict:
    target = _private_target(host)
    binary = shutil.which("nmap")
    if not binary:
        return {"ok": False, "target": target, "error": "nmap is not installed"}
    clean=[]
    for part in str(ports).split(','):
        part=part.strip()
        if not part:
            continue
        if '-' in part:
            bits=part.split('-',1)
            if len(bits)!=2 or not bits[0].isdigit() or not bits[1].isdigit():
                raise ValueError("Ports must be numbers or ranges")
            a,b=int(bits[0]),int(bits[1])
            if a<1 or b>65535 or a>b or b-a>64:
                raise ValueError("Port range is invalid or too large")
            clean.append(f"{a}-{b}")
        elif part.isdigit() and 1 <= int(part) <= 65535:
            clean.append(str(int(part)))
        else:
            raise ValueError("Ports must be between 1 and 65535")
    if not clean:
        raise ValueError("At least one port is required")
    if len(clean) > 64:
        raise ValueError("A maximum of 64 port entries is allowed")
    code, output, elapsed = _run([binary, "-Pn", "-n", "-sT", "--open", "-T3", "-p", ",".join(clean), target], timeout=max(10, min(int(timeout), 60)))
    open_ports=[]
    for line in output.splitlines():
        line=line.strip()
        if "/tcp" in line or "/udp" in line:
            parts=line.split()
            if len(parts)>=2 and parts[1] == "open":
                open_ports.append({"port":parts[0],"state":parts[1],"service":parts[2] if len(parts)>2 else ""})
    return {"ok": code == 0, "target": target, "ports": open_ports,
            "elapsed_ms": round(elapsed,1), "raw": output[-6000:]}


def device_info(host: str) -> dict:
    target = _private_target(host)
    result = {"ok": True, "target": target}
    try:
        result["reverse_dns"] = socket.gethostbyaddr(target)
    except Exception:
        result["reverse_dns"] = None
    code, output, _ = _run(["ip", "-j", "neigh", "show", target], timeout=3)
    if code == 0:
        try:
            result["neighbor"] = __import__('json').loads(output)
        except Exception:
            result["neighbor_raw"] = output
    else:
        result["neighbor"] = []
    result["ping"] = ping(target, 2)
    return result
