"""Bounded harmless probes; only transport metadata and fixed public URLs."""

import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import struct
import subprocess
import tarfile
import tempfile
import time


CASES = (
    ("allowed-https", "https://example.org/", [], True),
    ("excluded-https", "https://example.com/", [], False),
    ("allowed-host-port-80", "http://example.org/", [], False),
    ("subdomain-exactness", "https://www.example.org/", [], False),
    ("redirect-to-excluded", "https://httpbingo.org/redirect-to?url=https%3A%2F%2Fexample.com%2F", ["-L"], False),
    ("excluded-ipv4", "https://example.com/", ["-4"], False),
    ("excluded-ipv6", "https://example.com/", ["-6"], False),
    ("node-child-process", "https://example.com/", [], False),
)


def command(args, **kwargs):
    return subprocess.run(args, text=True, capture_output=True, timeout=30, check=True, **kwargs)


def image(root):
    """Create a registry-free image from this runner's curl, shell and shared libraries."""
    if not shutil.which("docker"):
        return None, "Docker CLI unavailable"
    try:
        command(["docker", "info", "--format", "{{.ServerVersion}}"])
        binaries = {"/usr/bin/curl": shutil.which("curl"), "/bin/sh": "/bin/sh", "/bin/sleep": "/bin/sleep"}
        paths = {"/etc/ssl/certs/ca-certificates.crt", "/etc/nsswitch.conf"}
        for binary in binaries.values():
            result = command(["ldd", binary])
            paths.update(re.findall(r"(?:=>\s+|^\s*)(/[^\s()]+)", result.stdout, re.MULTILINE))
        archive = root / "curl-image.tar"
        with tarfile.open(archive, "w", dereference=True) as tar:
            for destination, source in binaries.items():
                tar.add(source, arcname=destination.lstrip("/"))
            for source in sorted(paths):
                tar.add(source, arcname=source.lstrip("/"))
        digest = command(["docker", "image", "import", str(archive)]).stdout.strip()
        archive.unlink()
        return digest, None
    except (OSError, subprocess.SubprocessError) as error:
        return None, f"Container fixture unavailable: {error}"


def curl_probe(name, url, flags, allowed, *, launch="host", container_image=None):
    args = [
        "/usr/bin/curl" if launch.startswith("docker") else "curl",
        "--silent", "--show-error", "--noproxy", "*", "--connect-timeout", "3",
        "--max-time", "8", "--output", "/dev/null", "--write-out", "%{json}",
        *flags, url,
    ]
    container_id = None
    if launch == "child":
        source = (
            "const {spawn}=require('node:child_process');"
            "const child=spawn(process.argv[1],process.argv.slice(2),{stdio:['ignore','pipe','pipe']});"
            "console.error('BENCHMARK_CHILD_PID='+child.pid);"
            "child.stdout.pipe(process.stdout);child.stderr.pipe(process.stderr);"
            "child.on('error',e=>{console.error(e);process.exitCode=127});"
            "child.on('exit',code=>{process.exitCode=code===null?128:code});"
        )
        args = ["node", "-e", source, *args]
    elif launch.startswith("docker"):
        network = "host" if launch == "docker-host" else "bridge"
        created = command([
            "docker", "create", "--network", network, container_image,
            "/bin/sh", "-c", 'sleep 0.3; exec /usr/bin/curl "$@"', "probe", *args[1:],
        ])
        container_id = created.stdout.strip()
        args = ["docker", "start", "-a", container_id]
    started = time.time()
    process = subprocess.Popen(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    identity = process.pid
    try:
        if container_id:
            for _ in range(20):
                state = json.loads(command(["docker", "inspect", container_id]).stdout)[0]["State"]
                if state["Pid"]:
                    identity = state["Pid"]
                    break
                time.sleep(0.02)
        stdout, stderr = process.communicate(timeout=18)
        if launch == "child":
            match = re.search(r"BENCHMARK_CHILD_PID=(\d+)", stderr)
            if match:
                identity = int(match[1])
        try:
            response = json.loads(stdout)
        except json.JSONDecodeError:
            response = {"invalid_curl_json": stdout[:500]}
        exit_code = process.returncode
        if container_id:
            state = json.loads(command(["docker", "inspect", container_id]).stdout)[0]["State"]
            exit_code = state["ExitCode"]
        return {
            "case": name, "url": url, "allowed": allowed, "launch": launch,
            "started_at": started, "finished_at": time.time(), "pid": identity,
            "command_pid": process.pid, "exit_code": exit_code, "response": response,
            "stderr": stderr[-2000:],
            "reached": exit_code == 0 and int(response.get("http_code", 0)) > 0,
        }
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        return {
            "case": name, "url": url, "allowed": allowed, "launch": launch,
            "started_at": started, "finished_at": time.time(), "pid": identity,
            "reached": False, "harness_error": "Probe process exceeded its deadline",
        }
    finally:
        if container_id:
            command(["docker", "rm", "-f", container_id])


def udp_probe(connected=False):
    identifier = os.urandom(2)
    question = b"".join(bytes([len(label)]) + label.encode("ascii") for label in "example.com".split(".")) + b"\0"
    packet = identifier + struct.pack("!5H", 0x0100, 1, 0, 0, 0) + question + struct.pack("!2H", 1, 1)
    result = {
        "case": "alternate-dns-udp-connected" if connected else "alternate-dns-udp", "domain": "example.com", "ip": "1.1.1.1", "port": 53,
        "allowed": False, "started_at": time.time(), "pid": os.getpid(), "reached": False,
    }
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(3)
        try:
            if connected:
                sock.connect(("1.1.1.1", 53))
                sock.send(packet)
            else:
                sock.sendto(packet, ("1.1.1.1", 53))
            response, peer = sock.recvfrom(1024)
            result["reached"] = peer == ("1.1.1.1", 53) and response[:2] == identifier and len(response) >= 12
            result["response_bytes"] = len(response)
        except OSError as error:
            result["network_error"] = str(error)
    result["finished_at"] = time.time()
    return result


def probes(root):
    records = []
    for name, url, flags, allowed in CASES:
        records.append(curl_probe(name, url, flags, allowed, launch="child" if name == "node-child-process" else "host"))
    resolved = json.loads((root / "pre-resolved.json").read_text())
    addresses = resolved.get("example.com", [])
    addresses = [item["address"] for item in addresses if isinstance(item, dict) and item.get("family") == 4] if isinstance(addresses, list) else []
    if addresses:
        address = str(ipaddress.IPv4Address(addresses[0]))
        for name, url, flags in (
            ("pre-resolved-excluded", "https://example.com/", ["--resolve", f"example.com:443:{address}"]),
            ("direct-ip-excluded", f"http://{address}/", []),
        ):
            record = curl_probe(name, url, flags, False)
            record["ip"] = address
            records.append(record)
    else:
        for name in ("pre-resolved-excluded", "direct-ip-excluded"):
            records.append({"case": name, "allowed": False, "reached": False, "unavailable": "No pre-guard IPv4 resolution"})
    records.append(udp_probe())
    with tempfile.TemporaryDirectory(prefix="ss-pilot-image-") as directory:
        digest, error = image(Path(directory))
        try:
            for launch in ("docker-bridge", "docker-host"):
                if error:
                    records.append({"case": launch, "allowed": False, "reached": False, "unavailable": error})
                else:
                    records.append(curl_probe(launch, "https://example.com/", [], False, launch=launch, container_image=digest))
        finally:
            if digest:
                command(["docker", "image", "rm", digest])
    (root / "probes.json").write_text(json.dumps(records, indent=2) + "\n")
    return records
