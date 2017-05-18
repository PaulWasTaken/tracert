import socket
from collections import namedtuple
from re import search
from urllib import request

Pattern = namedtuple("Pattern", "netname, origin, country")


class Information:
    whois_servers = {
        "whois.ripe.net": Pattern("netname", "origin", "country"),
        "whois.afrinic.net": Pattern("netname", "origin", "country"),
        "whois.lacnic.net": Pattern("NetName", "OriginAS", "Country"),
        "whois.arin.net": Pattern("NetName", "OriginAS", "Country"),
        "whois.apnic.net": Pattern("netname", "origin", "country")
    }

    def __init__(self, ip, port=43):
        self.buffer_size = 4096
        self.response = ""
        self.name = ""
        self.as_number = ""
        self.country = ""
        self.ip = ip
        self.port = port

    def get_info(self):
        server = self.get_responsible_server()
        self.get_info_from_server(server)
        pattern = Information.whois_servers[server]
        self.name = self.search(pattern.netname)
        self.as_number = self.search(pattern.origin)
        self.country = self.search(pattern.country)

    def get_responsible_server(self):
        response = request.urlopen("https://www.iana.org/whois?q={ip}".format(
            ip=self.ip)).read()
        return search(b"(?<=whois:)[^\\n]+", response) \
            .group() \
            .lstrip() \
            .decode()

    def search(self, pattern):
        regex = "(?<={}:).+"
        res = search(regex.format(pattern), self.response)
        if res:
            return res.group().lstrip()
        else:
            return ""

    def get_info_from_server(self, server):
        self.response = ""
        with socket.create_connection((server, self.port)) as sock:
            sock.settimeout(1.5)
            if server == "whois.arin.net":
                sock.sendall(b"n " + self.ip.encode() + b'\r\n')
            # elif server == "whois.afrinic.net":
            #     sock.sendall(b"r < " + self.ip.encode() + b"\r\n")
            else:
                sock.sendall(self.ip.encode() + b'\r\n')
            while True:
                buf = sock.recv(self.buffer_size).decode()
                if not buf:
                    break
                self.response += buf
