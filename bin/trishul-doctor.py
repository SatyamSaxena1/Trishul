#!/usr/bin/env python3
"""Fail-closed, non-secret-printing preflight checks for Compose deployments."""

import hmac
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import urllib.parse
import urllib.request
import uuid

ROOT = Path(sys.argv[1]).resolve()
ENV_FILE = ROOT / ".env"
failures = 0


def result(ok, check_id, success, remediation):
    global failures
    label = "PASS" if ok else "FAIL"
    print(f"[{label}] {check_id} - {success if ok else remediation}")
    failures += not ok


def env_file(path):
    values = {}
    if not path.is_file():
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key.strip()):
            values[key.strip()] = value.strip().strip("'\"")
    return values


cfg = env_file(ENV_FILE)
cfg = {**cfg, **{k: v for k, v in os.environ.items() if k in cfg}}


def integer(name, default):
    try:
        return int(cfg.get(name, default))
    except ValueError:
        return default


result(ENV_FILE.is_file(), "CFG-ENV-001", "configuration file is present", "copy .env.example to .env and configure it")

cpu = os.cpu_count() or 0
minimum_cpu = integer("MIN_CPU_CORES", 4)
result(cpu >= minimum_cpu, "HOST-CPU-001", f"{cpu} CPU cores available (minimum {minimum_cpu})", f"provide at least {minimum_cpu} CPU cores (found {cpu})")
try:
    memory = int(next(x.split()[1] for x in Path("/proc/meminfo").read_text().splitlines() if x.startswith("MemTotal:"))) * 1024
except (OSError, StopIteration, ValueError):
    memory = 0
minimum_memory = integer("MIN_MEMORY_GIB", 8) * 1024**3
result(memory >= minimum_memory, "HOST-MEM-001", f"memory meets the {integer('MIN_MEMORY_GIB', 8)} GiB minimum", f"provide at least {integer('MIN_MEMORY_GIB', 8)} GiB memory")
free = shutil.disk_usage(ROOT).free
minimum_disk = integer("MIN_DISK_GIB", 20) * 1024**3
result(free >= minimum_disk, "HOST-DISK-001", f"free disk meets the {integer('MIN_DISK_GIB', 20)} GiB minimum", f"free at least {integer('MIN_DISK_GIB', 20)} GiB on the filesystem containing the deployment")

docker = shutil.which("docker")
result(bool(docker), "OCI-CLI-001", "Docker CLI is installed", "install a Docker CLI with the Compose v2 plugin")
compose_ok = False
if docker:
    proc = subprocess.run([docker, "compose", "version", "--short"], text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    version = re.search(r"(\d+)\.(\d+)\.(\d+)", proc.stdout)
    minimum = tuple(map(int, cfg.get("MIN_COMPOSE_VERSION", "2.20.0").split(".")))
    compose_ok = proc.returncode == 0 and bool(version) and tuple(map(int, version.groups())) >= minimum
result(compose_ok, "COMPOSE-VERSION-001", "Docker Compose meets the configured minimum", f"install Docker Compose {cfg.get('MIN_COMPOSE_VERSION', '2.20.0')} or newer")

sock_name = cfg.get("ROOTLESS_OCI_SOCKET", "")
rootful = sock_name in ("/var/run/docker.sock", "/run/docker.sock")
result(bool(sock_name) and not rootful, "OCI-ROOTFUL-001", "configured socket is not a known rootful Docker socket", "set ROOTLESS_OCI_SOCKET to the unprivileged user's Docker or Podman socket; rootful Docker is unsupported")
socket_ok = False
ownership_ok = False
behavior_ok = False
if sock_name and not rootful:
    try:
        details = os.stat(sock_name)
        socket_ok = stat.S_ISSOCK(details.st_mode)
        ownership_ok = details.st_uid == os.geteuid() and details.st_uid != 0
        client = socket.socket(socket.AF_UNIX)
        client.settimeout(3)
        client.connect(sock_name)
        client.sendall(b"GET /_ping HTTP/1.0\r\nHost: localhost\r\n\r\n")
        response = client.recv(1024)
        behavior_ok = b"200" in response.split(b"\r\n", 1)[0] and b"OK" in response
        client.close()
    except (OSError, ValueError):
        pass
result(socket_ok, "OCI-SOCKET-001", "runtime socket exists and is a Unix socket", "start rootless Docker/Podman and set ROOTLESS_OCI_SOCKET to its Unix socket")
result(ownership_ok, "OCI-OWNER-001", "runtime socket is owned by the invoking non-root user", "run doctor as the rootless runtime owner and ensure the socket is not owned by root")
result(behavior_ok, "OCI-PING-001", "runtime socket answered the OCI API ping", "enable the Docker-compatible API for the rootless Docker/Podman socket and verify the current user can connect")


def host(url):
    return urllib.parse.urlparse(url).hostname


hosts = [cfg.get("TRISHUL_HOSTNAME", "")]
for key in ("OIDC_ISSUER", "OIDC_JWKS_URL", "OIDC_DISCOVERY_URL", "S3_ENDPOINT_URL", "AI_ENDPOINT_URL"):
    if cfg.get(key):
        hosts.append(host(cfg[key]) or "")
unresolved = []
for hostname in sorted(set(filter(None, hosts))):
    try:
        socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        unresolved.append(hostname)
configured_hosts = list(filter(None, hosts))
result(bool(configured_hosts) and not unresolved, "NET-DNS-001", "configured hostnames resolve", "fix DNS for configured service hostnames: " + ", ".join(unresolved or ["no hostname configured"]))

cert, key = ROOT / "secrets/tls.crt", ROOT / "secrets/tls.key"
tls_ok = tls_match = False
openssl = shutil.which("openssl")
if openssl and cert.is_file() and key.is_file():
    expiry = subprocess.run([openssl, "x509", "-checkend", str(integer("TLS_MIN_VALID_DAYS", 30) * 86400), "-noout", "-in", str(cert)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    tls_ok = expiry.returncode == 0
    cert_pub = subprocess.run([openssl, "x509", "-pubkey", "-noout", "-in", str(cert)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    key_pub = subprocess.run([openssl, "pkey", "-pubout", "-in", str(key)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    tls_match = cert_pub.returncode == key_pub.returncode == 0 and hmac.compare_digest(cert_pub.stdout, key_pub.stdout)
result(tls_match, "TLS-PAIR-001", "TLS certificate matches its private key", "install a matching PEM certificate and private key in secrets/tls.crt and secrets/tls.key")
result(tls_ok, "TLS-EXPIRY-001", "TLS certificate is valid beyond the minimum lifetime", f"renew the certificate so it is valid for more than {integer('TLS_MIN_VALID_DAYS', 30)} days")


def context(ca_name):
    ca = cfg.get(ca_name, "")
    return ssl.create_default_context(cafile=ca or None)


def get_json(url, ca_name):
    with urllib.request.urlopen(url, timeout=8, context=context(ca_name)) as response:
        return json.load(response)


oidc_ok = False
try:
    issuer = cfg.get("OIDC_ISSUER", "").rstrip("/")
    discovery_url = cfg.get("OIDC_DISCOVERY_URL") or issuer + "/.well-known/openid-configuration"
    metadata = get_json(discovery_url, "OIDC_CA_BUNDLE")
    jwks_url = cfg.get("OIDC_JWKS_URL") or metadata.get("jwks_uri", "")
    keys = get_json(jwks_url, "OIDC_CA_BUNDLE").get("keys", [])
    configured_jwks = cfg.get("OIDC_JWKS_URL", "")
    browser = urllib.parse.urlparse(cfg.get("OIDC_BROWSER_ORIGIN", ""))
    oidc_ok = bool(
        issuer
        and issuer.startswith("https://")
        and cfg.get("OIDC_AUDIENCE")
        and cfg.get("OIDC_CLIENT_ID")
        and browser.scheme == "https"
        and browser.hostname
        and metadata.get("issuer", "").rstrip("/") == issuer
        and metadata.get("jwks_uri")
        and (not configured_jwks or configured_jwks == metadata["jwks_uri"])
        and keys
    )
except (OSError, ValueError, KeyError, json.JSONDecodeError):
    pass
result(oidc_ok, "OIDC-CONNECT-001", "OIDC discovery and JWKS are reachable and consistent", "verify OIDC_ISSUER, audience, client ID, discovery/JWKS URLs, CA trust, and that the JWKS contains keys")

# Use botocore when installed; it handles AWS SigV4 and S3-compatible path details.
s3_ok = False
try:
    import boto3
    client = boto3.client("s3", endpoint_url=cfg.get("S3_ENDPOINT_URL"), region_name=cfg.get("S3_REGION", "us-east-1"), aws_access_key_id=(ROOT / "secrets/s3_access_key").read_text().strip(), aws_secret_access_key=(ROOT / "secrets/s3_secret_key").read_text().strip(), verify=cfg.get("S3_CA_BUNDLE") or True)
    bucket = cfg["S3_BUCKET"]
    client.head_bucket(Bucket=bucket)
    object_key = ".trishul-doctor/" + str(uuid.uuid4())
    try:
        client.put_object(Bucket=bucket, Key=object_key, Body=b"trishul doctor\n")
        client.head_object(Bucket=bucket, Key=object_key)
        client.delete_object(Bucket=bucket, Key=object_key)
        object_key = None
        s3_ok = True
    finally:
        if object_key:
            client.delete_object(Bucket=bucket, Key=object_key)
except Exception:
    pass
result(s3_ok, "S3-RW-001", "S3 bucket allows head, disposable write, read metadata, and delete", "install boto3 and verify the S3 endpoint, CA, region, bucket, credentials, and write/delete policy")

required = "db_owner_password db_app_password redis_password s3_access_key s3_secret_key django_secret_key internal_ai_token metrics_token ai_endpoint_credential backup_key tls.crt tls.key".split()
placeholder = re.compile(r"(?i)(replace|changeme|example|placeholder|todo|dummy|password)")
secret_errors = []
for name in required:
    path = ROOT / "secrets" / name
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
        value = path.read_bytes()
        if not value or mode & 0o077 or (name not in ("tls.crt", "tls.key") and placeholder.search(value.decode("utf-8", "ignore"))):
            secret_errors.append(name)
    except OSError:
        secret_errors.append(name)
result(not secret_errors, "SECRET-FILES-001", "required secrets are present, private, and non-placeholder", "create non-placeholder values with mode 0600 for: " + ", ".join(secret_errors))

ai_enabled = cfg.get("AI_ENABLED", "true").lower() in ("1", "true", "yes")
ai_ok = not ai_enabled
if ai_enabled:
    endpoint = urllib.parse.urlparse(cfg.get("AI_ENDPOINT_URL", ""))
    allowed = {x.strip().lower() for x in cfg.get("AI_ENDPOINT_ALLOWLIST", "").split(",") if x.strip()}
    try:
        if endpoint.scheme == "https" and endpoint.hostname and endpoint.hostname.lower() in allowed:
            with socket.create_connection((endpoint.hostname, endpoint.port or 443), timeout=5) as raw:
                with context("AI_CA_BUNDLE").wrap_socket(raw, server_hostname=endpoint.hostname):
                    ai_ok = True
    except (OSError, ssl.SSLError):
        pass
result(ai_ok, "AI-ENDPOINT-001", "AI is disabled or its allowlisted HTTPS endpoint is reachable", "set an HTTPS AI_ENDPOINT_URL whose hostname is in AI_ENDPOINT_ALLOWLIST and verify DNS, routing, and AI_CA_BUNDLE")

image_names = "TRISHUL_IMAGE TRISHUL_EDGE_IMAGE TRISHUL_CONTROLLER_IMAGE TRISHUL_ANALYZER_IMAGE".split()
bad_images = [name for name in image_names if not re.search(r"@sha256:[0-9a-fA-F]{64}$", cfg.get(name, ""))]
result(not bad_images, "IMAGE-DIGEST-001", "release images are pinned by SHA-256 digest", "replace tags/placeholders with immutable name@sha256:<64 hex> references for: " + ", ".join(bad_images))

compose_valid = False
if docker and ENV_FILE.is_file():
    compose_valid = subprocess.run([docker, "compose", "--project-directory", str(ROOT), "--env-file", str(ENV_FILE), "-f", str(ROOT / "compose.yaml"), "config", "--quiet"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
result(compose_valid, "COMPOSE-CONFIG-001", "Compose configuration is valid", "run docker compose --env-file .env config and correct the reported configuration error")
port_ok = False
try:
    port = integer("HTTPS_PORT", 443)
    probe = socket.socket(socket.AF_INET6 if ":" in cfg.get("BIND_ADDRESS", "0.0.0.0") else socket.AF_INET)
    probe.bind((cfg.get("BIND_ADDRESS", "0.0.0.0"), port))
    probe.close()
    port_ok = True
except OSError:
    pass
result(port_ok, "PORT-HTTPS-001", "configured HTTPS port is available", "stop the process using HTTPS_PORT or configure another available port")

print(f"Doctor completed: {failures} failure(s)")
sys.exit(1 if failures else 0)
