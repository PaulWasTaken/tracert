import argparse
import socket
import string
import struct
import re
from sys import platform
from ipaddress import IPv4Address, ip_address
from whois import Information


def main(args):
    for address in args.addresses:
        if not valid_addr(address):
            print("%s is not valid." % address)
            continue
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                 socket.IPPROTO_ICMP)
            sock.settimeout(1.5)
            trace(socket.gethostbyname(address), sock)
            print("FINISHED FOR {address}\r\n".format(address=address))
        except KeyboardInterrupt:
            print("Stopped")
            break
        except OSError as e:
            if platform == "win32":
                win_oserror_handler(e, address)
            else:
                print(e)
            break


def win_oserror_handler(exception, address):
    code = exception.errno
    if code == 10049:
        print("%s is invalid." % address)
    elif code == 10013:
        print("You should run it with administrator rights.")
    else:
        print("Unknown return code.")


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


def trace(address, sock):
    max_hops = 30
    ttl = 1
    port = 54321
    buffer = 1536
    addr = None
    while not (addr == address or ttl >= max_hops):
        sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        sock.sendto(struct.pack("!BBHHH", 8, 0, 26648, 1, 331) +
                    string.ascii_lowercase.encode(), (address, port))
        try:
            addr = sock.recvfrom(buffer)[1][0]
            if not IPv4Address(addr).is_private:
                info = Information(addr)
                info.get_info()
                print_report(
                    ttl, addr, info.name, info.as_number, info.country)
            else:
                print_report(ttl, addr, "local")
        except socket.timeout:
            print_report(ttl, "*")
        ttl += 1
    sock.shutdown(0)
    sock.close()


def print_report(number, address, name="", as_number="", country=""):
    output = "{number}.  {ip}\r\n".format(number=number, ip=address)
    try:
        as_ = re.search("\d+$", as_number).group()
    except AttributeError:
        as_ = as_number
    data = ", ".join([elem for elem in [name, as_, country] if elem])
    if data:
        output += data + "\r\n"
    print(output)


def create_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("addresses", help="Addresses you want to trace.",
                        nargs='*')
    return parser


if __name__ == "__main__":
    p = create_parser()
    main(p.parse_args())
