import whois
import socket
import re
import dns.resolver
from ipwhois import IPWhois
import requests


def extract_phone(raw):

    try:

        match = re.search(
            r"Registrar Abuse Contact Phone:\s*(.+)",
            raw,
            re.IGNORECASE,
        )

        if match:
            return match.group(1)

    except:
        pass

    return None


def get_ip(domain):

    try:
        return socket.gethostbyname(domain)
    except:
        return None


def get_ip_info(ip):

    try:

        obj = IPWhois(ip)
        res = obj.lookup_rdap()

        return {
            "asn": res.get("asn"),
            "asn_description": res.get("asn_description"),
        }

    except:
        return {}


def get_location(ip):

    try:

        r = requests.get(f"http://ip-api.com/json/{ip}").json()

        return {
            "country": r.get("country"),
            "city": r.get("city"),
            "isp": r.get("isp")
        }

    except:
        return {}


def run_whois(domain):

    try:

        w = whois.whois(domain)

        raw = w.text

        phone = extract_phone(raw)

        ip = get_ip(domain)

        ip_info = get_ip_info(ip) if ip else {}

        location = get_location(ip) if ip else {}

        return {

            "domain": w.domain_name,
            "registrar": w.registrar,
            "whois_server": w.whois_server,

            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "updated_date": str(w.updated_date),

            "name_servers": w.name_servers,

            "status": w.status,

            "emails": w.emails,

            "phone": phone,

            "ip_address": ip,

            "ip_location": f'{location.get("country")} - {location.get("city")}',

            "isp": location.get("isp"),

            "asn": ip_info.get("asn"),
            "asn_description": ip_info.get("asn_description"),

            "raw": raw
        }

    except Exception as e:

        return {"error": str(e)}