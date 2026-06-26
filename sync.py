#!/usr/bin/env python3

import json
import os
import re
import sys
from typing import Dict, List, Optional, Union

import requests
import urllib3


VerifySetting = Union[bool, str]


def env(name: str, default: Optional[str] = None, required: bool = False) -> str:
    value = os.getenv(name, default)

    if required and not value:
        print(f"ERROR: missing required environment variable: {name}", file=sys.stderr)
        sys.exit(2)

    return value or ""


def env_bool(name: str, default: str = "false") -> bool:
    return env(name, default).strip().lower() in ("1", "true", "yes", "y", "on")


def env_int(name: str, default: str = "0") -> int:
    value = env(name, default)

    try:
        return int(value)
    except ValueError:
        print(f"ERROR: environment variable {name} must be an integer, got: {value}", file=sys.stderr)
        sys.exit(2)


# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

UNIFI_URL = env("UNIFI_URL", required=True).rstrip("/")
UNIFI_USERNAME = env("UNIFI_USERNAME", required=True)
UNIFI_PASSWORD = env("UNIFI_PASSWORD", required=True)
UNIFI_SITES = [s.strip() for s in env("UNIFI_SITES", "default").split(",") if s.strip()]

# TLS / PKI settings
UNIFI_VERIFY_SSL = env_bool("UNIFI_VERIFY_SSL", "true")
UNIFI_CA_BUNDLE = env("UNIFI_CA_BUNDLE", "")

LIBRENMS_URL = env("LIBRENMS_URL", required=True).rstrip("/")
LIBRENMS_TOKEN = env("LIBRENMS_TOKEN", required=True)
LIBRENMS_VERIFY_SSL = env_bool("LIBRENMS_VERIFY_SSL", "true")
LIBRENMS_CA_BUNDLE = env("LIBRENMS_CA_BUNDLE", "")

# Distributed poller support
LIBRENMS_POLLER_GROUP = env_int("LIBRENMS_POLLER_GROUP", "0")

# Hostname handling
# HOSTNAME_MODE=dns -> AP name becomes DNS name, optionally with HOSTNAME_DOMAIN
# HOSTNAME_MODE=ip  -> AP management IP is used
HOSTNAME_MODE = env("HOSTNAME_MODE", "dns").strip().lower()
HOSTNAME_DOMAIN = env("HOSTNAME_DOMAIN", "").strip()

# LibreNMS add behavior
DRY_RUN = env_bool("DRY_RUN", "true")
PING_FALLBACK = env_bool("PING_FALLBACK", "true")
FORCE_ADD = env_bool("FORCE_ADD", "false")

DEVICE_LOCATION = env("DEVICE_LOCATION", "")
OVERRIDE_SYSLOCATION = env_bool("OVERRIDE_SYSLOCATION", "false")

# SNMP settings
SNMP_VERSION = env("SNMP_VERSION", "v2c").strip().lower()
SNMP_COMMUNITY = env("SNMP_COMMUNITY", "")

SNMPV3_AUTHLEVEL = env("SNMPV3_AUTHLEVEL", "authPriv")
SNMPV3_AUTHNAME = env("SNMPV3_AUTHNAME", "")
SNMPV3_AUTHPASS = env("SNMPV3_AUTHPASS", "")
SNMPV3_AUTHALGO = env("SNMPV3_AUTHALGO", "SHA")
SNMPV3_CRYPTOPASS = env("SNMPV3_CRYPTOPASS", "")
SNMPV3_CRYPTOALGO = env("SNMPV3_CRYPTOALGO", "AES")


# -----------------------------------------------------------------------------
# TLS helpers
# -----------------------------------------------------------------------------

def request_verify_setting(enabled: bool, ca_bundle: str) -> VerifySetting:
    """
    Return the correct 'verify' value for requests.

    True  = use default CA bundle / certifi / REQUESTS_CA_BUNDLE if set
    False = disable TLS verification
    str   = use a specific CA bundle path
    """
    if not enabled:
        return False

    if ca_bundle:
        if not os.path.isfile(ca_bundle):
            raise RuntimeError(f"CA bundle file does not exist: {ca_bundle}")
        return ca_bundle

    return True


def describe_verify(name: str, enabled: bool, ca_bundle: str) -> str:
    if not enabled:
        return f"{name}: TLS verification DISABLED"

    if ca_bundle:
        return f"{name}: TLS verification enabled, CA bundle: {ca_bundle}"

    requests_ca_bundle = os.getenv("REQUESTS_CA_BUNDLE", "")
    ssl_cert_file = os.getenv("SSL_CERT_FILE", "")

    if requests_ca_bundle:
        return f"{name}: TLS verification enabled, REQUESTS_CA_BUNDLE={requests_ca_bundle}"

    if ssl_cert_file:
        return f"{name}: TLS verification enabled, SSL_CERT_FILE={ssl_cert_file}"

    return f"{name}: TLS verification enabled, default CA store"


UNIFI_VERIFY = request_verify_setting(UNIFI_VERIFY_SSL, UNIFI_CA_BUNDLE)
LIBRENMS_VERIFY = request_verify_setting(LIBRENMS_VERIFY_SSL, LIBRENMS_CA_BUNDLE)

if UNIFI_VERIFY is False or LIBRENMS_VERIFY is False:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# -----------------------------------------------------------------------------
# General helpers
# -----------------------------------------------------------------------------

def slugify(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    value = re.sub(r"-+", "-", value)
    return value.strip("-")


def librenms_headers() -> Dict[str, str]:
    return {
        "X-Auth-Token": LIBRENMS_TOKEN,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def validate_config() -> None:
    if HOSTNAME_MODE not in ("dns", "ip"):
        raise RuntimeError("HOSTNAME_MODE must be either 'dns' or 'ip'")

    if SNMP_VERSION not in ("v1", "v2c", "v3"):
        raise RuntimeError("SNMP_VERSION must be one of: v1, v2c, v3")

    if SNMP_VERSION in ("v1", "v2c") and not SNMP_COMMUNITY:
        raise RuntimeError("SNMP_COMMUNITY is required when SNMP_VERSION is v1 or v2c")

    if SNMP_VERSION == "v3":
        missing = []

        if not SNMPV3_AUTHNAME:
            missing.append("SNMPV3_AUTHNAME")
        if not SNMPV3_AUTHPASS:
            missing.append("SNMPV3_AUTHPASS")
        if not SNMPV3_CRYPTOPASS:
            missing.append("SNMPV3_CRYPTOPASS")

        if missing:
            raise RuntimeError(f"Missing required SNMPv3 variables: {', '.join(missing)}")


# -----------------------------------------------------------------------------
# UniFi API
# -----------------------------------------------------------------------------

def unifi_login(session: requests.Session) -> None:
    """
    Login to UniFi OS / CloudKey.

    Common CloudKey / UniFi OS endpoint:
      POST /api/auth/login
    """
    url = f"{UNIFI_URL}/api/auth/login"
    payload = {
        "username": UNIFI_USERNAME,
        "password": UNIFI_PASSWORD,
        "rememberMe": False,
    }

    response = session.post(
        url,
        json=payload,
        verify=UNIFI_VERIFY,
        timeout=30,
    )

    if response.status_code not in (200, 201):
        raise RuntimeError(
            f"UniFi login failed: HTTP {response.status_code}: {response.text[:300]}"
        )


def get_unifi_devices(session: requests.Session, site: str) -> List[Dict]:
    """
    Read devices from a UniFi Network site.

    Common CloudKey / UniFi OS endpoint:
      GET /proxy/network/api/s/<site>/stat/device
    """
    url = f"{UNIFI_URL}/proxy/network/api/s/{site}/stat/device"

    response = session.get(
        url,
        verify=UNIFI_VERIFY,
        timeout=60,
    )

    if response.status_code != 200:
        raise RuntimeError(
            f"UniFi device query failed for site '{site}': "
            f"HTTP {response.status_code}: {response.text[:300]}"
        )

    data = response.json()
    return data.get("data", [])


def is_unifi_ap(device: Dict) -> bool:
    """
    UniFi APs generally have type 'uap'.
    """
    return device.get("type") == "uap"


def get_ap_display_name(device: Dict) -> str:
    return (
        device.get("name")
        or device.get("hostname")
        or device.get("mac")
        or "UniFi AP"
    )


def device_hostname(device: Dict) -> Optional[str]:
    """
    Determine how LibreNMS should know the AP.

    HOSTNAME_MODE=dns:
      UniFi name 'AP Office 01' becomes:
        ap-office-01
      or, when HOSTNAME_DOMAIN is set:
        ap-office-01.example.local

    HOSTNAME_MODE=ip:
      Uses the AP management IP from UniFi.
    """
    if HOSTNAME_MODE == "ip":
        return device.get("ip")

    name = device.get("name") or device.get("hostname") or device.get("mac")

    if not name:
        return None

    host = slugify(name)

    if not host:
        return None

    if HOSTNAME_DOMAIN:
        return f"{host}.{HOSTNAME_DOMAIN.lstrip('.')}"

    return host


# -----------------------------------------------------------------------------
# LibreNMS API
# -----------------------------------------------------------------------------

def librenms_device_exists(hostname: str) -> bool:
    """
    Check whether a device already exists in LibreNMS.

    LibreNMS usually returns 200 for known devices.
    A missing device may return 404, and in some installations/API paths 500.
    """
    url = f"{LIBRENMS_URL}/api/v0/devices/{hostname}"

    response = requests.get(
        url,
        headers=librenms_headers(),
        verify=LIBRENMS_VERIFY,
        timeout=30,
    )

    if response.status_code == 200:
        try:
            payload = response.json()
            return payload.get("status") == "ok" and len(payload.get("devices", [])) > 0
        except Exception:
            # If LibreNMS says 200 but the payload is unexpected, be conservative.
            return True

    if response.status_code in (404, 500):
        return False

    raise RuntimeError(
        f"LibreNMS device lookup failed for {hostname}: "
        f"HTTP {response.status_code}: {response.text[:300]}"
    )


def build_librenms_add_payload(hostname: str, display_name: str) -> Dict:
    payload = {
        "hostname": hostname,
        "display_template": display_name,
        "poller_group": LIBRENMS_POLLER_GROUP,
        "ping_fallback": PING_FALLBACK,
        "force_add": FORCE_ADD,
    }

    if DEVICE_LOCATION:
        payload["location"] = DEVICE_LOCATION
        payload["override_sysLocation"] = OVERRIDE_SYSLOCATION

    if SNMP_VERSION in ("v1", "v2c"):
        payload["snmpver"] = SNMP_VERSION
        payload["community"] = SNMP_COMMUNITY

    elif SNMP_VERSION == "v3":
        payload.update(
            {
                "snmpver": "v3",
                "authlevel": SNMPV3_AUTHLEVEL,
                "authname": SNMPV3_AUTHNAME,
                "authpass": SNMPV3_AUTHPASS,
                "authalgo": SNMPV3_AUTHALGO,
                "cryptopass": SNMPV3_CRYPTOPASS,
                "cryptoalgo": SNMPV3_CRYPTOALGO,
            }
        )

    return payload


def redact_payload(payload: Dict) -> Dict:
    """
    Redact secrets before printing dry-run/debug output.
    """
    redacted = dict(payload)

    for key in (
        "community",
        "authpass",
        "cryptopass",
    ):
        if key in redacted and redacted[key]:
            redacted[key] = "***REDACTED***"

    return redacted


def librenms_add_device(hostname: str, display_name: str) -> None:
    payload = build_librenms_add_payload(hostname, display_name)

    if DRY_RUN:
        print(f"DRY-RUN would add {hostname}: {json.dumps(redact_payload(payload), sort_keys=True)}")
        return

    url = f"{LIBRENMS_URL}/api/v0/devices"

    response = requests.post(
        url,
        headers=librenms_headers(),
        json=payload,
        verify=LIBRENMS_VERIFY,
        timeout=120,
    )

    if response.status_code not in (200, 201):
        raise RuntimeError(
            f"LibreNMS add failed for {hostname}: "
            f"HTTP {response.status_code}: {response.text[:500]}"
        )

    print(f"ADDED {hostname}: {response.text[:300]}")


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

def print_startup_config() -> None:
    print("Starting UniFi → LibreNMS AP sync")
    print(f"UniFi URL: {UNIFI_URL}")
    print(f"UniFi sites: {', '.join(UNIFI_SITES)}")
    print(f"LibreNMS URL: {LIBRENMS_URL}")
    print(f"LibreNMS poller group: {LIBRENMS_POLLER_GROUP}")
    print(f"Hostname mode: {HOSTNAME_MODE}")

    if HOSTNAME_MODE == "dns":
        print(f"Hostname domain: {HOSTNAME_DOMAIN or '(none)'}")

    print(f"SNMP version: {SNMP_VERSION}")
    print(f"Ping fallback: {PING_FALLBACK}")
    print(f"Force add: {FORCE_ADD}")
    print(f"Dry-run: {DRY_RUN}")
    print(describe_verify("UniFi", UNIFI_VERIFY_SSL, UNIFI_CA_BUNDLE))
    print(describe_verify("LibreNMS", LIBRENMS_VERIFY_SSL, LIBRENMS_CA_BUNDLE))


def main() -> int:
    validate_config()
    print_startup_config()

    session = requests.Session()
    unifi_login(session)

    added = 0
    existing = 0
    skipped = 0
    found_aps_total = 0

    for site in UNIFI_SITES:
        print(f"Reading UniFi site: {site}")

        devices = get_unifi_devices(session, site)
        aps = [d for d in devices if is_unifi_ap(d)]
        found_aps_total += len(aps)

        print(f"Found {len(aps)} AP(s) in site {site}")

        for ap in aps:
            hostname = device_hostname(ap)
            display_name = get_ap_display_name(ap)

            if not hostname:
                print(f"SKIP AP without usable hostname/IP: {ap.get('mac', 'unknown-mac')}")
                skipped += 1
                continue

            if librenms_device_exists(hostname):
                print(f"EXISTS {hostname}")
                existing += 1
                continue

            librenms_add_device(hostname, display_name)
            added += 1

    print(
        "Done. "
        f"found_aps={found_aps_total}, "
        f"added={added}, "
        f"existing={existing}, "
        f"skipped={skipped}, "
        f"dry_run={DRY_RUN}"
    )

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        sys.exit(130)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
