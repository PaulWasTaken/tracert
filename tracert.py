import argparse
import socket
import string
import struct
import re
from ipaddress import IPv4Address, ip_address
from whois import Information


def main(args):
    for address in args.addresses:
        if not valid_addr(address):
            continue
        try:
            trace(socket.gethostbyname(address))
        except KeyboardInterrupt:
            print("Stopped")


def valid_addr(address):
    try:
        ip_address(address)
        return True
    except ValueError:
        try:
            socket.gethostbyname(address)
            return True
        except socket.gaierror:
            return False


def trace(address):
    max_hops = 30
    ttl = 1
    port = 54321
    buffer = 1536
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                             socket.IPPROTO_ICMP)
        sock.settimeout(1.5)
    except OSError:
        print("You should run it with administrator rights.")
        return
    while True:
        try:
            sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
            sock.sendto(struct.pack("!BBHHH", 8, 0, 26648, 1, 331) +
                        string.ascii_lowercase.encode(), (address, port))
            _, addr = sock.recvfrom(buffer)
            if not IPv4Address(addr[0]).is_private:
                info = Information(addr[0])
                info.get_info()
                print(form_report(
                    ttl, addr[0], info.name, info.as_number, info.country))
            else:
                print(form_report(ttl, addr[0], "local"))
        except socket.timeout:
            print(form_report(ttl, "*"))
        except OSError:
            print("{} is invalid".format(address))
            addr = (address, None)
        finally:
            if addr[0] == address or ttl >= max_hops:
                print("FINISHED FOR {address}\r\n".format(address=address))
                break
            ttl += 1
    sock.shutdown(0)
    sock.close()


def form_report(number, address, name="", as_number="", country=""):
    output = "{number}.  {ip}\r\n".format(number=number, ip=address)
    try:
        number = re.search("\d+$", as_number).group()
        output += " " + number
    except AttributeError:
        pass
    output += ", ".join([elem for elem in [name, as_number, country] if elem])
    output += "\r\n"
    return output


def create_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("addresses", help="Addresses you want to trace.",
                        nargs='*')
    return parser


if __name__ == "__main__":
    p = create_parser()
    main(p.parse_args())
