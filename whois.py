import socket
import re
from collections import namedtuple

Pattern = namedtuple("Pattern", "netname, origin, country")


class Information:
    whois_servers = {
        "ripe": Pattern("netname", "origin", "country"),
        "afrinic": Pattern("netname", "origin", "country"),
        "lacnic": Pattern("NetName", "OriginAS", "Country"),
        "arin": Pattern("NetName", "OriginAS", "Country"),
        "apnic": Pattern("netname", "origin", "country")
    }

    def __init__(self, ip, port=43):
        self.servers_name = [x.upper() for x in Information.whois_servers.keys()]
        self.buffer_size = 4096
        self.response = ""
        self.name = ""
        self.as_number = ""
        self.country = ""
        self.ip = ip
        self.port = port

    def get_info(self):
        for site in Information.whois_servers:
            self.get_info_from_server(site)
            pattern = Information.whois_servers[site]
            regex = "(?<={}:).+"
            try:
                self.name = re.search(regex.format(pattern.netname), self.response).\
                    group().replace(" ", "")
                self.as_number = re.search(regex.format(pattern.origin), self.response). \
                    group().replace(" ", "")
                self.country = re.search(regex.format(pattern.country), self.response). \
                    group().replace(" ", "")
                for name in self.servers_name:
                    if name in self.name:
                        raise AttributeError
                    else:
                        continue
                return
            except AttributeError:
                self.name = ""
                self.as_number = ""
                self.country = ""
                continue

    def get_info_from_server(self, site):
        self.response = ""
        with socket.create_connection(
            ("whois.{name}.net".format(name=site), self.port)) as sock:
            sock.settimeout(1)
            if site == "arin":
                sock.sendall(b"n " + self.ip.encode() + b'\r\n')
            elif site == "afrinic":
                sock.sendall(b"r < " + self.ip.encode() + b"\r\n")
            else:
                sock.sendall(self.ip.encode() + b'\r\n')
            while True:
                buf = sock.recv(self.buffer_size).decode()
                if not buf:
                    break
                self.response += buf
