#!/usr/bin/env python3

import argparse
import subprocess
import sys
import os
from pathlib import Path

def run_cmd(cmd, capture_output=False, shell=True):
    """
    Helper function to run shell commands.
    By default, returns output if capture_output=True.
    """
    if capture_output:
        result = subprocess.run(cmd, shell=shell, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0 and result.stderr:
            print(f"[!] Error running command: {cmd}\n    {result.stderr}")
        return result.stdout.strip()
    else:
        subprocess.run(cmd, shell=shell, check=False)


def main():
    parser = argparse.ArgumentParser(
        description="OSINT/Passive Recon Script to gather subdomains for a given target."
    )
    parser.add_argument("target", help="Domain to enumerate subdomains from (e.g., example.com)")
    parser.add_argument("--wordlist", default="/opt/subdomains-top1million-110000.txt",
                        help="Path to a subdomain wordlist (default: /opt/subdomains-top1million-110000.txt)")
    parser.add_argument("--sources", default="sources.txt",
                        help="Path to sources file containing theHarvester search engines (one per line).")
    parser.add_argument("--output", default="final_subdomains.txt",
                        help="Name of final aggregated subdomain output file.")
    args = parser.parse_args()

    TARGET = args.target
    WORDLIST = args.wordlist
    SOURCES_FILE = args.sources
    FINAL_OUTPUT = args.output

    # ---------------------------------------------------
    # 1. Download subdomains from crt.sh
    #    "curl -s 'https://crt.sh/?q=${TARGET}&output=json' | jq -r '.[] | \"\(.name_value)\n\(.common_name)\"' | sort -u > ${TARGET}_crt.sh.txt"
    # ---------------------------------------------------
    crt_sh_file = f"{TARGET}_crt.sh.txt"
    print(f"[+] Pulling subdomains from crt.sh into {crt_sh_file}")
    crt_sh_cmd = (
        f'curl -s "https://crt.sh/?q={TARGET}&output=json" '
        f'| jq -r \'.[] | "\\(.name_value)\\n\\(.common_name)"\' '
        f'| sort -u > "{crt_sh_file}"'
    )
    run_cmd(crt_sh_cmd)

    # ---------------------------------------------------
    # 2. theHarvester on multiple sources from sources.txt
    #    "cat sources.txt | while read source; do theHarvester -d ${TARGET} -b $source -f ${source}_${TARGET}; done"
    # ---------------------------------------------------
    print("[+] Running theHarvester for each source in sources.txt...")
    if not Path(SOURCES_FILE).is_file():
        print(f"[!] Sources file {SOURCES_FILE} not found! Exiting.")
        sys.exit(1)

    with open(SOURCES_FILE, "r") as sf:
        for source in sf:
            source = source.strip()
            if source:
                print(f"    - Harvesting {source}")
                harvester_out_prefix = f"{source}_{TARGET}"
                harvester_cmd = f"theHarvester -d {TARGET} -b {source} -f {harvester_out_prefix}"
                run_cmd(harvester_cmd)

    # ---------------------------------------------------
    # 3. Extract subdomains from ALL JSON files from theHarvester
    #    "cat *.json | jq -r '.hosts[]' 2>/dev/null | cut -d':' -f 1 | sort -u > ${TARGET}_theHarvester.txt"
    # ---------------------------------------------------
    theharvester_output = f"{TARGET}_theHarvester.txt"
    print(f"[+] Extracting subdomains from all .json files into {theharvester_output}")
    # You can also refine this by only looking for files of the pattern "*_{TARGET}.json" if needed:
    extract_cmd = f"cat *.json 2>/dev/null | jq -r '.hosts[]' 2>/dev/null | cut -d':' -f 1 | sort -u > {theharvester_output}"
    run_cmd(extract_cmd)

    # ---------------------------------------------------
    # 4. Get the nameserver from 8.8.8.8 for the domain
    #    "dig ns @8.8.8.8 ${TARGET} +short"
    #    Then take the first IP address and store in NS_Server
    # ---------------------------------------------------
    print("[+] Querying NS record from 8.8.8.8...")
    dig_ns_cmd = f"dig ns @8.8.8.8 {TARGET} +short"
    ns_result = run_cmd(dig_ns_cmd, capture_output=True)
    if not ns_result:
        print("[!] Could not get NS from 8.8.8.8. Exiting.")
        sys.exit(1)

    # The NS record might look like "ns1.example.com.", "ns2.example.com."
    # We do a second dig to get IP from the first NS we found
    first_ns_domain = ns_result.splitlines()[0].strip()
    # Remove trailing '.' if it exists
    if first_ns_domain.endswith('.'):
        first_ns_domain = first_ns_domain[:-1]

    print(f"    Found NS domain: {first_ns_domain}")
    # Dig the IP from that nameserver
    ns_ip_cmd = f"dig A {first_ns_domain} +short"
    ns_ip_result = run_cmd(ns_ip_cmd, capture_output=True)
    if not ns_ip_result:
        print(f"[!] Could not resolve IP of NS {first_ns_domain}. Exiting.")
        sys.exit(1)

    NS_Server = ns_ip_result.splitlines()[0].strip()
    print(f"    Using NS_Server={NS_Server} for further DNS lookups...")

    # ---------------------------------------------------
    # 5. Download a wordlist to /opt if not already present
    #    "curl https://raw.githubusercontent.com/danielmiessler/SecLists/... -o /opt/subdomains-top1million-110000.txt"
    # ---------------------------------------------------
    # This is optional if you already have the wordlist. 
    # We'll assume the user sets --wordlist if they have it locally.
    # The below is just an example of how you might do it.
    if not Path(WORDLIST).is_file():
        print(f"[+] Downloading subdomain wordlist to {WORDLIST}...")
        download_cmd = (
            "curl -sSL "
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt "
            f"-o {WORDLIST}"
        )
        run_cmd(download_cmd)
    else:
        print(f"[+] Wordlist {WORDLIST} already exists. Skipping download.")

    # ---------------------------------------------------
    # 6. Bruteforce subdomains using dig and the discovered NS_Server
    #    "for sub in $(cat $WORDLIST); do dig $sub.${TARGET} @${NS_Server} | ... ; done"
    # ---------------------------------------------------
    brute_output = "subdomains_bruteforce.txt"
    print(f"[+] Bruteforcing subdomains with {WORDLIST}...")
    with open(WORDLIST, "r") as wf, open(brute_output, "w") as bf:
        for sub in wf:
            sub = sub.strip()
            if not sub:
                continue
            fqdn = f"{sub}.{TARGET}"
            # We run dig for each subdomain
            cmd = f"dig {fqdn} @{NS_Server} +short"
            dns_result = run_cmd(cmd, capture_output=True)
            # Filter out empties or lines with 'SOA', etc., if needed
            if dns_result:
                # Add some minimal checks: if it looks like an IP or a CNAME
                # We'll store "subdomain -> IP" or "subdomain -> CNAME" style
                bf.write(f"{fqdn}\n")

    # ---------------------------------------------------
    # 7. Aggregate all subdomains and remove duplicates
    #    We have the following files with subdomains:
    #    - {TARGET}_crt.sh.txt
    #    - {TARGET}_theHarvester.txt
    #    - subdomains_bruteforce.txt
    # ---------------------------------------------------
    aggregated_subdomains = set()

    def load_subdomains_from_file(filepath):
        results = set()
        if not Path(filepath).is_file():
            return results
        with open(filepath, "r") as f:
            for line in f:
                sd = line.strip().lower()
                if sd:
                    results.add(sd)
        return results

    # Load from crt.sh
    aggregated_subdomains.update(load_subdomains_from_file(crt_sh_file))
    # Load from theHarvester
    aggregated_subdomains.update(load_subdomains_from_file(theharvester_output))
    # Load from brute force
    aggregated_subdomains.update(load_subdomains_from_file(brute_output))

    # Remove obvious wildcards or placeholders if any (optional step)
    # e.g., removing *.domain.com lines or anything that obviously isn't a subdomain
    cleaned_subdomains = {sd for sd in aggregated_subdomains if not sd.startswith("*.")}

    # ---------------------------------------------------
    # 8. Output final deduplicated subdomains
    # ---------------------------------------------------
    print(f"[+] Writing final deduplicated subdomains to {FINAL_OUTPUT}")
    with open(FINAL_OUTPUT, "w") as f_out:
        for sd in sorted(cleaned_subdomains):
            f_out.write(sd + "\n")

    # Optional: Print them in a nice format to the screen
    print("\n[+] Final Subdomains Discovered:")
    for sd in sorted(cleaned_subdomains):
        print(f"    {sd}")

    print("\n[+] Done! Happy hacking.")

if __name__ == "__main__":
    main()
