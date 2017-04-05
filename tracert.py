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
        trace(socket.gethostbyname(address))


def valid_addr(address):
    try:
        ip_address(address)
        return True
    except ValueError:
        pattern_dns = r'^[a-zA-Z_0-9-]+\.[a-zA-Z-0-9]+\.[a-zA-Z-]+$'
        if not re.search(pattern_dns, address):
            print("Wrong address: {}".format(address))
            return False
        return True


def trace(address):
    max_hops = 30
    ttl = 1
    port = 54321
    buffer = 1536
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                             socket.IPPROTO_ICMP)
        sock.settimeout(1)
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
                output = form_report(info, ttl, addr[0])
                print(output)
            else:
                print("{number}.  {ip}\r\nlocal\r\n".format(number=ttl, ip=addr[0]))
        except socket.timeout:
            print("{number}.  *\r\n\r\n".format(number=ttl))
        finally:
            if addr[0] == address or ttl > max_hops:
                print("FINISHED FOR {address}\r\n".format(address=address))
                break
            ttl += 1
    sock.shutdown(0)
    sock.close()


def form_report(info, number, address):
    output = "{number}.  {ip}\r\n".format(number=number, ip=address)
    if info.name:
        output += info.name
    if info.as_number:
        try:
            number = re.search("\d+$", info.as_number).group()
            output += " " + number
        except AttributeError:
            output += " " + info.as_number
    if info.country:
        output += " " + info.country
    output += "\r\n"
    return output


def create_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("addresses", help="Addresses you want to trace.", nargs='*')
    return parser


if __name__ == "__main__":
    p = create_parser()
    main(p.parse_args())
