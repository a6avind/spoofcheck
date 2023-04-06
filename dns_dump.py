import dns.resolver
import sys
from colorama import Fore, Style

if len(sys.argv) != 2:
    domain = input("Enter domain name: ")
else:
    domain = sys.argv[1]

for record_type in ['A', 'AAAA', 'MX', 'NS', 'CNAME', 'SOA', 'TXT', 'PTR']:
    try:
        answer = dns.resolver.resolve(
            domain, record_type, raise_on_no_answer=False)
        if answer:
            print(Fore.GREEN + Style.BRIGHT +
                  "[*]" + Style.RESET_ALL, f"{record_type} records\n")
            for rdata in answer:
                print(rdata, end="\n\n")
    except Exception as e:
        print(Fore.RED + Style.BRIGHT + f"[*] {e}")
        break
