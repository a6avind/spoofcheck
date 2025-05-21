#!/usr/bin/python3

import logging
import sys
from typing import List, Tuple

import emailprotectionslib.dmarc as dmarc_lib
import emailprotectionslib.spf as spf_lib
from colorama import Fore, Style
from colorama import init as color_init
from dns.exception import DNSException

logging.basicConfig(level=logging.INFO)


def output(message, level="info"):
    colors = {
        "good": Fore.GREEN + Style.BRIGHT + "[+]" + Style.RESET_ALL,
        "indifferent": Fore.BLUE + Style.BRIGHT + "[*]" + Style.RESET_ALL,
        "error": Fore.RED + Style.BRIGHT + "[-] !!! " + Style.NORMAL,
        "bad": Fore.RED + Style.BRIGHT + "[-]" + Style.RESET_ALL,
        "info": Fore.WHITE + Style.BRIGHT + "[*]" + Style.RESET_ALL,
    }
    print(colors[level], message)


def check_spf_redirect_mechanisms(spf_record: spf_lib.SpfRecord) -> bool:
    redirect_domain = spf_record.get_redirect_domain()
    if redirect_domain:
        output(f"Processing an SPF redirect domain: {redirect_domain}", "info")
        return is_spf_record_strong(redirect_domain)
    return False


def check_spf_include_mechanisms(spf_record: spf_lib.SpfRecord) -> bool:
    include_domain_list = spf_record.get_include_domains()
    for include_domain in include_domain_list:
        output(f"Processing an SPF include domain: {include_domain}", "info")
        if is_spf_record_strong(include_domain):
            return True
    return False


def is_spf_redirect_record_strong(spf_record: spf_lib.SpfRecord) -> bool:
    output(f"Checking SPF redirect domain: {spf_record.get_redirect_domain()}", "info")
    redirect_strong = spf_record._is_redirect_mechanism_strong()
    level = "bad" if redirect_strong else "indifferent"
    output(
        (
            "Redirect mechanism is strong"
            if redirect_strong
            else "Redirect mechanism is not strong"
        ),
        level,
    )
    return redirect_strong


def check_spf_include_redirect(spf_record: spf_lib.SpfRecord) -> bool:
    if spf_record.get_redirect_domain():
        if is_spf_redirect_record_strong(spf_record):
            return True
    return spf_record._are_include_mechanisms_strong()


def check_spf_all_string(spf_record: spf_lib.SpfRecord) -> bool:
    """Check if SPF all string is strong"""
    if spf_record.all_string:
        if spf_record.all_string in ["~all", "-all"]:
            output(
                f"SPF record contains an All item: {spf_record.all_string}",
                "indifferent",
            )
            return True
        else:
            output(f"SPF record All item is too weak: {spf_record.all_string}", "good")
    else:
        output("SPF record has no All string", "good")

    return check_spf_include_redirect(spf_record)


def is_spf_record_strong(domain: str) -> bool:
    try:
        spf_record = spf_lib.SpfRecord.from_domain(domain)
        if spf_record and spf_record.record:
            output("Found SPF record:", "info")
            output(str(spf_record.record), "info")
            if not check_spf_all_string(spf_record):
                if not check_spf_redirect_mechanisms(
                    spf_record
                ) and not check_spf_include_mechanisms(spf_record):
                    return False
        else:
            output(f"{domain} has no SPF record!", "good")
            return False
        return True
    except DNSException as e:
        output(f"DNS error while checking SPF: {str(e)}", "error")
        return False


def check_dmarc_extras(dmarc_record: dmarc_lib.DmarcRecord) -> None:
    if dmarc_record.pct and dmarc_record.pct != "100":
        output(
            f"DMARC pct is set to {dmarc_record.pct}% - might be possible",
            "indifferent",
        )
    if dmarc_record.rua:
        output(f"Aggregate reports will be sent: {dmarc_record.rua}", "indifferent")
    if dmarc_record.ruf:
        output(f"Forensics reports will be sent: {dmarc_record.ruf}", "indifferent")


def check_dmarc_policy(dmarc_record: dmarc_lib.DmarcRecord) -> bool:
    if dmarc_record.policy:
        if dmarc_record.policy in ["reject", "quarantine"]:
            output(f"DMARC policy set to {dmarc_record.policy}", "bad")
            return True
        else:
            output(f"DMARC policy set to {dmarc_record.policy}", "good")
    else:
        output("DMARC record has no Policy", "good")
    return False


def check_dmarc_org_policy(base_record: dmarc_lib.DmarcRecord) -> bool:
    try:
        org_record = base_record.get_org_record()
        if org_record and org_record.record:
            output("Found organizational DMARC record:", "info")
            output(str(org_record.record), "info")
            if org_record.subdomain_policy:
                if org_record.subdomain_policy == "none":
                    output(
                        f"Organizational subdomain policy set to {org_record.subdomain_policy}",
                        "good",
                    )
                elif org_record.subdomain_policy in ["quarantine", "reject"]:
                    output(
                        f"Organizational subdomain policy explicitly set to {org_record.subdomain_policy}",
                        "bad",
                    )
                    return True
            else:
                output(
                    "No explicit organizational subdomain policy. Defaulting to organizational policy",
                    "info",
                )
                return check_dmarc_policy(org_record)
        else:
            output("No organizational DMARC record", "good")
    except dmarc_lib.OrgDomainException:
        output("No organizational DMARC record", "good")
    except Exception as e:
        logging.exception(e)
    return False


def is_dmarc_record_strong(domain: str) -> bool:
    try:
        dmarc = dmarc_lib.DmarcRecord.from_domain(domain)
        if dmarc and dmarc.record:
            output("Found DMARC record:", "info")
            output(str(dmarc.record), "info")
            if check_dmarc_policy(dmarc):
                check_dmarc_extras(dmarc)
                return True
        elif dmarc.get_org_domain():
            output("No DMARC record found. Looking for organizational record", "info")
            return check_dmarc_org_policy(dmarc)
        else:
            output(f"{domain} has no DMARC record!", "good")
        return False
    except DNSException as e:
        output(f"DNS error while checking DMARC: {str(e)}", "error")
        return False


def check_domain(domain: str) -> Tuple[bool, bool, bool]:
    spf_strong = is_spf_record_strong(domain)
    dmarc_strong = is_dmarc_record_strong(domain)
    is_spoofable = not dmarc_strong
    return is_spoofable, spf_strong, dmarc_strong


if __name__ == "__main__":
    try:
        color_init()
        domain = sys.argv[1]
        is_spoofable, spf_strong, dmarc_strong = check_domain(domain)

        if is_spoofable:
            output(f"Spoofing possible for {domain}!", "good")
        else:
            output(f"Spoofing not possible for {domain}", "bad")

    except Exception as e:
        logger.exception("An unexpected error occurred")
        output(f"Error: {str(e)}", "error")
        sys.exit(1)
    except IndexError:
        output(f"Usage: {sys.argv[0]} [DOMAIN]", "error")
