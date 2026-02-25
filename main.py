import re
import time
import requests
import tldextract
import ipaddress
import os
from datetime import datetime

src_dir = "src/"
out_dir = "out/"

os.makedirs(f"{out_dir}openwrt", exist_ok=True)
os.makedirs(f"{out_dir}shadowrocket", exist_ok=True)


def log(msg: str) -> None:
    # ISO-like timestamp for easy grep in Kestra logs
    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | {msg}", flush=True)


class DomainProcessor:
    def __init__(self):
        self.direct: set = set()

        self.raw: dict = {}
        self.raw_v4: dict = {}
        self.raw_v6: dict = {}

        self.domains: dict = {}
        self.subnets_v4: dict = {}
        self.subnets_v6: dict = {}

    def _download_text(self, key: str, url: str, split_mode: str = "lines"):
        """
        Helper for logging downloads without changing behavior:
        - still uses requests.get(url) without timeout and without raise_for_status
        - returns list of lines (splitlines or split('\n')) to match original behavior
        """
        log(f"DOWNLOAD start: key={key} url={url}")
        t0 = time.time()
        response = requests.get(url)
        dt = time.time() - t0

        status = getattr(response, "status_code", None)
        length = len(getattr(response, "text", "") or "")
        log(f"DOWNLOAD done : key={key} status={status} bytes={length} elapsed={dt:.2f}s")

        if split_mode == "split_n":
            lines = response.text.split('\n')
        else:
            lines = response.text.splitlines()

        log(f"DOWNLOAD parse: key={key} lines={len(lines)}")
        return lines

    def get_raw_domains(self):
        """ function downloads blocked domains from different sources """
        log("STEP get_raw_domains: start")

        # antifilter list
        self.raw["antifilter"] = self._download_text(
            "antifilter",
            "https://community.antifilter.download/list/domains.lst",
            split_mode="split_n",
        )

        # ITDog list
        self.raw["ITDog"] = self._download_text(
            "ITDog",
            "https://raw.githubusercontent.com/itdoginfo/allow-domains/refs/heads/main/Russia/inside-raw.lst",
            split_mode="split_n",
        )

        # single list
        #self.raw["single"] = self._download_text(
        #    "single",
        #    "https://github.com/itdoginfo/allow-domains/raw/refs/heads/main/src/Russia-domains-inside-single.lst",
        #    split_mode="split_n",
        #)

        # af list
        af_path = f"{src_dir}domains.lst"
        log(f"FILE read start: {af_path}")
        with open(af_path) as file:
            self.raw["af"] = file.read().split('\n')
        log(f"FILE read done : {af_path} lines={len(self.raw['af'])}")

        # direct list
        direct_path = f"{src_dir}direct.lst"
        log(f"FILE read start: {direct_path}")
        with open(direct_path) as file:
            self.direct = set(file.read().split('\n')) - {''}
        log(f"FILE read done : {direct_path} entries={len(self.direct)}")

        log(f"STEP get_raw_domains: done sources={list(self.raw.keys())}")

    def get_raw_subnets(self):
        """ function downloads blocked subnets from different sources """
        log("STEP get_raw_subnets: start")

        url_v4 = (
            "https://iplist.opencck.org/?format=text&data=cidr4"
            "&site=discord.com&site=discord.gg&site=discord.media&site=telegram.org"
            "&site=whatsapp.com&site=instagram.com&site=facebook.com&site=rutracker.org"
        )
        url_v6 = (
            "https://iplist.opencck.org/?format=text&data=cidr6"
            "&site=discord.com&site=discord.gg&site=discord.media&site=telegram.org"
            "&site=whatsapp.com&site=instagram.com&site=facebook.com&site=rutracker.org"
        )

        # From https://iplist.opencck.org/
        self.raw_v4["subnets"] = self._download_text("subnets_v4", url_v4, split_mode="lines")
        self.raw_v6["subnets"] = self._download_text("subnets_v6", url_v6, split_mode="lines")

        log(
            "STEP get_raw_subnets: done "
            f"v4_lines={len(self.raw_v4.get('subnets', []))} "
            f"v6_lines={len(self.raw_v6.get('subnets', []))}"
        )

    def process_domains(self):
        """ processes domains to uniform standard """
        log("STEP process_domains: start")

        for key in self.raw:
            log(f"process_domains: source={key} raw_lines={len(self.raw[key])}")
            domains = set()

            for line in self.raw[key]:
                ext = tldextract.extract(line)
                if ext.suffix:
                    if re.search(r'[^а-я\-]', ext.domain):
                        domains.add(tldextract.extract(line.rstrip()).registered_domain)
                    if not ext.domain and ext.suffix:
                        domains.add("." + tldextract.extract(line.rstrip()).suffix)

            self.domains[key] = domains
            log(f"process_domains: source={key} normalized_domains={len(domains)}")

        log(f"STEP process_domains: done sources={len(self.domains)}")

    def process_subnets(self):
        """ processes subnets to uniform standard """
        log("STEP process_subnets: start")

        keys = set(self.raw_v4.keys()) | set(self.raw_v6.keys())
        log(f"process_subnets: keys={sorted(keys)}")

        for key in keys:
            v4 = self.raw_v4.get(key) or []
            v6 = self.raw_v6.get(key) or []
            subnets = v4 + v6

            log(f"process_subnets: key={key} total_lines={len(subnets)} (v4={len(v4)} v6={len(v6)})")

            invalid = 0
            for subnet_str in subnets:
                try:
                    subnet = ipaddress.ip_network(subnet_str)
                    if subnet.version == 4:
                        if not self.subnets_v4.get(key):
                            self.subnets_v4[key] = []
                        self.subnets_v4[key].append(subnet_str)
                    elif subnet.version == 6:
                        if not self.subnets_v6.get(key):
                            self.subnets_v6[key] = []
                        self.subnets_v6[key].append(subnet_str)
                except ValueError:
                    invalid += 1
                    print(f"Invalid subnet: {subnet_str}", flush=True)

            log(
                f"process_subnets: key={key} valid_v4={len(self.subnets_v4.get(key, []))} "
                f"valid_v6={len(self.subnets_v6.get(key, []))} invalid={invalid}"
            )

        log("STEP process_subnets: done")

    def handle_addresses(self):
        log("STEP handle_addresses: start")
        self.get_raw_subnets()
        self.get_raw_domains()
        self.process_subnets()
        self.process_domains()
        log("STEP handle_addresses: done")

    def nftables_out(self):
        log("STEP nftables_out: start")
        keys = set(self.raw_v4.keys()) | set(self.raw_v6.keys())

        out_domains_path = f"{out_dir}openwrt/vpn-domain.lst"
        log(f"FILE write start: {out_domains_path}")
        with open(out_domains_path, "w") as file:
            domains = set()
            domains_single = set(self.domains.get("single", []))

            for key in self.domains:
                if key != "single":
                    domains = domains | self.domains.get(key, [])

            domains = domains.union(domains_single)
            domains = domains - self.direct
            domains = sorted(domains)

            domains_lines_v4 = [
                # f"nftset=/{x}/6#inet#fw4#vpn_domains_v6\nnftset=/{x}/4#inet#fw4#vpn_domains"
                f"nftset=/{x}/4#inet#fw4#vpn_domains"
                for x in domains
            ]

            print(*domains_lines_v4, file=file, sep='\n')

        log(f"FILE write done : {out_domains_path} lines={len(domains_lines_v4)}")

        out_subnets_path = f"{out_dir}openwrt/vpn-subnet.lst"
        log(f"FILE write start: {out_subnets_path}")
        with open(out_subnets_path, "w") as file:
            for key in keys:
                v4 = self.raw_v4.get(key, [])
                v6 = self.raw_v6.get(key, [])

                # print(f"\n# {key} v4", *v4, f"\n# {key} v6", *v6, file=file, sep='\n')
                print(*v4, file=file, sep='\n')

        # approximate line count for diagnostics
        log(
            f"FILE write done : {out_subnets_path} "
            f"keys={len(keys)} v4_lines={len(self.raw_v4.get('subnets', []))} v6_lines={len(self.raw_v6.get('subnets', []))}"
        )
        log("STEP nftables_out: done")

    def shadowrocket_out(self):
        log("STEP shadowrocket_out: start")
        keys = set(self.raw_v4.keys()) | set(self.raw_v6.keys())

        out_ip_path = f"{out_dir}shadowrocket/shadowrocket-ip.list"
        log(f"FILE write start: {out_ip_path}")
        with open(out_ip_path, "w") as file:
            for key in keys:
                v4 = [f"IP-CIDR,{x}" for x in self.raw_v4.get(key, [])]
                v6 = [f"IP-CIDR,{x}" for x in self.raw_v6.get(key, [])]

                print(f"\n# {key} v4", *v4, f"\n# {key} v6", *v6, file=file, sep='\n')

        log(
            f"FILE write done : {out_ip_path} "
            f"keys={len(keys)} v4_lines={len(self.raw_v4.get('subnets', []))} v6_lines={len(self.raw_v6.get('subnets', []))}"
        )

        out_domain_path = f"{out_dir}shadowrocket/shadowrocket-domain.list"
        log(f"FILE write start: {out_domain_path}")
        with open(out_domain_path, "w") as file:
            domains = set()
            domains_single = set(self.domains.get("single", []))

            for key in self.domains:
                if key != "single":
                    domains = domains | self.domains.get(key, [])

            domains = domains.union(domains_single)
            domains = domains - self.direct
            domains = sorted(domains)

            domains_lines = [f"DOMAIN-SUFFIX,{x}" for x in domains]
            print(*domains_lines, file=file, sep='\n')

        log(f"FILE write done : {out_domain_path} lines={len(domains_lines)}")
        log("STEP shadowrocket_out: done")

    def validate_outputs(self):
        """
        Simple sanity checks to avoid pushing empty / broken outputs.
        Does not change normal behavior; only fails when outputs look wrong.
        """
        log("STEP validate_outputs: start")

        checks = [
            (f"{out_dir}openwrt/vpn-domain.lst", 10),
            (f"{out_dir}openwrt/vpn-subnet.lst", 5),
            (f"{out_dir}shadowrocket/shadowrocket-domain.list", 10),
            (f"{out_dir}shadowrocket/shadowrocket-ip.list", 5),
        ]

        for path, min_lines in checks:
            if not os.path.exists(path):
                raise RuntimeError(f"VALIDATION FAILED: missing file {path}")

            size = os.path.getsize(path)
            if size == 0:
                raise RuntimeError(f"VALIDATION FAILED: empty file {path}")

            with open(path, "r", encoding="utf-8", errors="replace") as f:
                lines = [ln for ln in (x.strip() for x in f) if ln]

            log(f"validate_outputs: {path} bytes={size} nonempty_lines={len(lines)}")

            if len(lines) < min_lines:
                raise RuntimeError(
                    f"VALIDATION FAILED: too few lines in {path} "
                    f"({len(lines)} < {min_lines})"
                )

            # quick "HTML error page" guard (e.g. 504 from upstream)
            head = "\n".join(lines[:20]).lower()
            if "<html" in head or "gateway time-out" in head or "openresty" in head:
                raise RuntimeError(f"VALIDATION FAILED: looks like HTML error content in {path}")

        log("STEP validate_outputs: OK")



def main():
    log("RUN start")
    proc = DomainProcessor()
    proc.handle_addresses()
    proc.shadowrocket_out()
    proc.nftables_out()

    # ✅ sanity check before returning success
    proc.validate_outputs()

    log("RUN done")
    return 0


if __name__ == "__main__":
    main()
