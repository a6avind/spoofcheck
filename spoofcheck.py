#!/usr/bin/python3
import logging
import sys

import emailprotectionslib.dmarc as dmarc_lib
import emailprotectionslib.spf as spf_lib
from colorama import Fore, Style
from colorama import init as color_init

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


def check_spf_redirect_mechanisms(spf_record):
    redirect_domain = spf_record.get_redirect_domain()
    if redirect_domain:
        output(f"Processing an SPF redirect domain: {redirect_domain}", "info")
        return is_spf_record_strong(redirect_domain)
    return False


def check_spf_include_mechanisms(spf_record):
    include_domain_list = spf_record.get_include_domains()
    for include_domain in include_domain_list:
        output(f"Processing an SPF include domain: {include_domain}", "info")
        if is_spf_record_strong(include_domain):
            return True
    return False


def is_spf_redirect_record_strong(spf_record):
    output(f"Checking SPF redirect domain: {spf_record.get_redirect_domain()}", "info")
    redirect_strong = spf_record._is_redirect_mechanism_strong()
    output(
        (
            "Redirect mechanism is strong."
            if redirect_strong
            else "Redirect mechanism is not strong."
        ),
        "bad" if redirect_strong else "indifferent",
    )
    return redirect_strong


def are_spf_include_mechanisms_strong(spf_record):
    output("Checking SPF include mechanisms", "info")
    include_strong = spf_record._are_include_mechanisms_strong()
    output(
        (
            "Include mechanisms include a strong record"
            if include_strong
            else "Include mechanisms are not strong"
        ),
        "bad" if include_strong else "indifferent",
    )
    return include_strong


def check_spf_include_redirect(spf_record):
    if spf_record.get_redirect_domain():
        if is_spf_redirect_record_strong(spf_record):
            return True
    return are_spf_include_mechanisms_strong(spf_record)


def check_spf_all_string(spf_record):
    if spf_record.all_string:
        if spf_record.all_string in ["~all", "-all"]:
            output(
                f"SPF record contains an All item: {spf_record.all_string}",
                "indifferent",
            )
        else:
            output(f"SPF record All item is too weak: {spf_record.all_string}", "good")
            return check_spf_include_redirect(spf_record)
    else:
        output("SPF record has no All string", "good")
        return check_spf_include_redirect(spf_record)
    return True


def is_spf_record_strong(domain):
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


def get_dmarc_record(domain):
    dmarc = dmarc_lib.DmarcRecord.from_domain(domain)
    if dmarc and dmarc.record:
        output("Found DMARC record:", "info")
        output(str(dmarc.record), "info")
    return dmarc


def get_dmarc_org_record(base_record):
    org_record = base_record.get_org_record()
    if org_record:
        output("Found DMARC Organizational record:", "info")
        output(str(org_record.record), "info")
    return org_record


def check_dmarc_extras(dmarc_record):
    if dmarc_record.pct and dmarc_record.pct != "100":
        output(
            f"DMARC pct is set to {dmarc_record.pct}% - might be possible",
            "indifferent",
        )
    if dmarc_record.rua:
        output(f"Aggregate reports will be sent: {dmarc_record.rua}", "indifferent")
    if dmarc_record.ruf:
        output(f"Forensics reports will be sent: {dmarc_record.ruf}", "indifferent")


def check_dmarc_policy(dmarc_record):
    if dmarc_record.policy:
        if dmarc_record.policy in ["reject", "quarantine"]:
            output(f"DMARC policy set to {dmarc_record.policy}", "bad")
            return True
        else:
            output(f"DMARC policy set to {dmarc_record.policy}", "good")
    else:
        output("DMARC record has no Policy", "good")
    return False


def check_dmarc_org_policy(base_record):
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


def is_dmarc_record_strong(domain):
    dmarc = get_dmarc_record(domain)
    if dmarc and dmarc.record:
        if check_dmarc_policy(dmarc):
            check_dmarc_extras(dmarc)
            return True
    elif dmarc.get_org_domain():
        output("No DMARC record found. Looking for organizational record", "info")
        return check_dmarc_org_policy(dmarc)
    else:
        output(f"{domain} has no DMARC record!", "good")
    return False


if __name__ == "__main__":
    color_init()
    try:
        domain = sys.argv[1]
        spf_record_strength = is_spf_record_strong(domain)
        dmarc_record_strength = is_dmarc_record_strong(domain)
        if not dmarc_record_strength:
            output(f"Spoofing possible for {domain}!", "good")
        else:
            output(f"Spoofing not possible for {domain}", "bad")
    except IndexError:
        output(f"Usage: {sys.argv[0]} [DOMAIN]", "error")
