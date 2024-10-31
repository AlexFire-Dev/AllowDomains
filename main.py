import re
import requests
import tldextract
import ipaddress


src_dir = "src/"
out_dir = "out/"


class DomainProcessor:

    def __init__(self):
        self.direct: set = {}

        self.raw: dict = {}
        self.raw_v4: dict = {}
        self.raw_v6: dict = {}

        self.domains: dict = {}
        self.subnets_v4: dict = {}
        self.subnets_v6: dict = {}


    def get_raw_domains(self):
        """ function downloads blocked domains from different sources """

        # antifilter list
        response = requests.get("https://community.antifilter.download/list/domains.lst")
        self.raw["antifilter"] = response.text.split('\n')

        # ITDog list
        response = requests.get("https://github.com/itdoginfo/allow-domains/raw/refs/heads/main/src/Russia-domains-inside.lst")
        self.raw["ITDog"] = response.text.split('\n')

        # single list
        response = requests.get("https://github.com/itdoginfo/allow-domains/raw/refs/heads/main/src/Russia-domains-inside-single.lst")
        self.raw["single"] = response.text.split('\n')

        # af list
        with open(f"{src_dir}domains.lst") as file:
            self.raw["af"] = file.read().split('\n')

        # direct list
        with open(f"{src_dir}direct.lst") as file:
            self.direct = set(file.read().split('\n')) - {''}


    def get_raw_subnets(self):
        """ function downloads blocked subnets from different sources """

        # discord list
        # From https://iplist.opencck.org/
        self.raw_v4["discord"] = requests.get("https://iplist.opencck.org/?format=text&data=cidr4&site=discord.gg&site=discord.media").text.splitlines()
        self.raw_v6["discord"] = requests.get("https://iplist.opencck.org/?format=text&data=cidr6&site=discord.gg&site=discord.media").text.splitlines()


    def process_domains(self):
        """ processes domains to uniform standard """

        for key in self.raw:
            domains = set()

            for line in self.raw[key]:
                if tldextract.extract(line).suffix:
                    if re.search(r'[^а-я\-]', tldextract.extract(line).domain):
                        domains.add(tldextract.extract(line.rstrip()).registered_domain)
                    if not tldextract.extract(line).domain and tldextract.extract(line).suffix:
                        domains.add("." + tldextract.extract(line.rstrip()).suffix)

            self.domains[key] = domains


    def process_subnets(self):
        """ processes subnets to uniform standard """

        keys = set(self.raw_v4.keys()) | set(self.raw_v6.keys())

        for key in keys:
            subnets = self.raw_v4.get(key) + self.raw_v6.get(key)

            for subnet_str in subnets:
                try:
                    subnet = ipaddress.ip_network(subnet_str)
                    if subnet.version == 4:
                        if not self.subnets_v4.get(key): self.subnets_v4[key] = []
                        self.subnets_v4[key].append(subnet_str)
                    elif subnet.version == 6:
                        if not self.subnets_v6.get(key): self.subnets_v6[key] = []
                        self.subnets_v6[key].append(subnet_str)
                except ValueError:
                    print(f"Invalid subnet: {subnet_str}")

    def handle_addresses(self):
        self.get_raw_subnets()
        self.get_raw_domains()
        self.process_subnets()
        self.process_domains()


    def nftables_out(self):
        keys = set(self.raw_v4.keys()) | set(self.raw_v6.keys())

        with open(f"{out_dir}openwrt/vpn-domain.lst", "w") as file:
            domains = set()
            domains_single = set(self.domains.get("single"))

            for key in self.domains:
                if key != "single":
                    domains = domains | self.domains.get(key)

            domains = domains.union(domains_single)

            domains = domains - self.direct
            domains = sorted(domains)

            domains = [f"nftset=/{x}/6#inet#fw4#vpn_domains_v6\nnftset=/{x}/4#inet#fw4#vpn_domains" for x in domains]

            print(*domains, file=file, sep='\n')

        with open(f"{out_dir}openwrt/vpn-subnet.lst", "w") as file:
            for key in keys:
                v4 = self.raw_v4.get(key)
                v6 = self.raw_v6.get(key)

                print(f"\n# {key} v4", *v4, f"\n# {key} v6", *v6,
                      file=file, sep='\n'
                      )


    def shadowrocket_out(self):
        keys = set(self.raw_v4.keys()) | set(self.raw_v6.keys())

        with open(f"{out_dir}shadowrocket/shadowrocket-ip.list", "w") as file:
            for key in keys:
                v4 = [f"IP-CIDR,{x}" for x in self.raw_v4.get(key)]
                v6 = [f"IP-CIDR,{x}" for x in self.raw_v6.get(key)]

                print(f"\n# {key} v4", *v4, f"\n# {key} v6", *v6,
                      file=file, sep='\n'
                      )

        with open(f"{out_dir}shadowrocket/shadowrocket-domain.list", "w") as file:
            domains = set()
            domains_single = set(self.domains.get("single"))

            for key in self.domains:
                if key != "single":
                    domains = domains | self.domains.get(key)

            domains = domains.union(domains_single)

            domains = domains - self.direct
            domains = sorted(domains)

            domains = [f"DOMAIN-SUFFIX,{x}" for x in domains]

            print(*domains, file=file, sep='\n')


def main():
    proc = DomainProcessor()
    proc.handle_addresses()
    proc.shadowrocket_out()
    proc.nftables_out()
    return 0


if __name__ == "__main__":
    main()
