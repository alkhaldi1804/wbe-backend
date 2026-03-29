import dns.resolver
from email_validator import validate_email, EmailNotValidError
import smtplib
import threading
import time
import random
import string

smtp_results = {}

# disposable domains list (basic list)
disposable_domains = {
    "mailinator.com",
    "tempmail.com",
    "10minutemail.com",
    "guerrillamail.com",
    "trashmail.com",
    "yopmail.com"
}


def smtp_check(email, mx_host):

    try:

        start = time.time()

        server = smtplib.SMTP(mx_host, 25, timeout=2)

        server.helo("wbetools.com")
        server.mail("check@wbetools.com")

        code, message = server.rcpt(email)

        latency = round(time.time() - start, 2)

        if code == 250:
            status = "Accepting Mail"
        else:
            status = "Mailbox not confirmed"

        server.quit()

    except Exception as e:

        latency = None
        status = "SMTP check failed"

    smtp_results[email]["status"] = status
    smtp_results[email]["latency"] = latency


def detect_catch_all(mx_host):

    try:

        random_user = ''.join(random.choices(string.ascii_lowercase, k=12))
        fake_email = f"{random_user}@example.com"

        server = smtplib.SMTP(mx_host, 25, timeout=5)

        server.helo("wbetools.com")
        server.mail("check@wbetools.com")

        code, _ = server.rcpt(fake_email)

        server.quit()

        if code == 250:
            return True
        else:
            return False

    except:
        return None


def check_email(email):

    try:
        v = validate_email(email)
        email = v.email
        format_valid = "VALID"
    except EmailNotValidError:

        return {
            "format": "INVALID",
            "domain": None,
            "mx": None,
            "disposable": None,
            "catch_all": None,
            "latency": None,
            "status": "Invalid Email Format"
        }

    domain = email.split("@")[1]

    try:
        mx_records = dns.resolver.resolve(domain, "MX")
        mx_host = str(mx_records[0].exchange)
    except:

        return {
            "format": format_valid,
            "domain": domain,
            "mx": None,
            "disposable": None,
            "catch_all": None,
            "latency": None,
            "status": "No MX records"
        }

    disposable = "YES" if domain in disposable_domains else "NO"

    catch_all = detect_catch_all(mx_host)

    if catch_all is True:
        catch_all = "YES"
    elif catch_all is False:
        catch_all = "NO"
    else:
        catch_all = "UNKNOWN"

    if email not in smtp_results:

        smtp_results[email] = {
            "status": "Checking SMTP...",
            "latency": None
        }

        thread = threading.Thread(
            target=smtp_check,
            args=(email, mx_host)
        )

        thread.start()

    return {

        "format": format_valid,
        "domain": domain,
        "mx": mx_host,
        "disposable": disposable,
        "catch_all": catch_all,
        "latency": smtp_results[email]["latency"],
        "status": smtp_results[email]["status"]

    }