import argparse
from scapy.all import *
from ipaddress import IPv4Network
from IPy import IP as IP_check
import socket
import concurrent.futures

#This section defines arguments
usage_example = '''Usage examples
sudo python3 scanner.py -t 10.10.10.10 -d -nP  <-- this will detect if 10.10.10.10 is alive without ICMP
sudo python3 scanner.py -t 10.10.10.0/24 -d  <-- this will detect alive hosts on the 10.10.10.0/24 network by using arp, icmp and a port scan
sudo python3 scanner.py -tF ip_list -p all  <-- this will read the ip_list file to get target IPs and scan for all open ports
sudo python3 scanner.py -t 10.10.10.10 -p 21,22,25,80,443,445 -w ports  <-- This will scan the ports listed on the 10.10.10.10 host and write the output to a file called ports

Recommendation - First do a detect with the ping-only option if you are in an entire subnet, then scan for common ports. There is some slowness I am working on in all the options. This is not meant to replace nmap but be used in a place where nmap cannot be. Good luck!'''

parser = argparse.ArgumentParser(epilog=usage_example, formatter_class=argparse.RawDescriptionHelpFormatter)
targ_group = parser.add_mutually_exclusive_group(required=True)
targ_group.add_argument('-t', '--targs', help='This is a target or list of targets. Lists can be in cidr notation or a range. ie 192.168.0.0/24 or 192.168.0.1-40.')
targ_group.add_argument('-tF', '--targFile', help='This is a file that is a list of targets, 1 on each line.')
ping_group = parser.add_mutually_exclusive_group()
ping_group.add_argument('-nP', '--no_ping', nargs='?', const=True, default=False, help='Do other checks but do not ping the target.')
ping_group.add_argument('-pO', '--ping_only', nargs='?', const=True, default=False, help='Only ping the host to check if it is alive. Skip all other checks.')
method_group = parser.add_mutually_exclusive_group(required=True)
method_group.add_argument('-d', '--detect', nargs='?', const=True, default=False, help='This is the detect option to find alive IPs. You can change some of the default behavior with the no ping and ping only options. Ex: python3 scanner.py -t 192.168.1.1-45 -d -nP')
method_group.add_argument('-p', '--port_scan', help='Scan for open ports. This accepts one single port, a range spaced with a dash (55-65), comma separated list(21,80,443) or the keyword all(-p all).')
parser.add_argument('-w', '--write', help ='Provide a file to write the results to or else they will be written to standard out.')

args = parser.parse_args()

#---------------------THE SECTION BELOW DEALS WITH TARGET DEFINING---------------------------


#Make the target/s in a useable format
def targ_parse(targs):
    targets = []
    if '/' not in targs and '-' not in targs:
        try:
            if IP_check(targs):
                targets.append(targs)
                return targets
        except:
            print('That doesn\'t appear to be a useable IP format.')
    elif '/' in targs:
        for ip in IPv4Network(targs):
            if str(ip).split('.')[3] == '0' or str(ip).split('.')[3] == '255':
                continue
            targets.append(str(ip))
        return targets
    elif '-' in targs:
        split_by_dash = targs.split('-')
        start = split_by_dash[0].split('.')[3]
        end = split_by_dash[1]
        for i in range(int(start), int(end)+1):
            arg_split = targs.split('.')
            addr = arg_split[0] + '.' + arg_split[1] + '.' + arg_split[2] + '.' + str(i) 
            targets.append(addr)
        return targets
    else:
        print('That doesn\'t appear to be a useable IP format.')

#Take in the file and parse the IPs from it
def targ_file_parse(targ_file):
    targets = []
    try:
        infile = open(targ_file)
        for ip in infile:
            try:
                if IP_check(ip.strip()): 
                    targets.append(ip.strip())
            except Exception as ex:
                print('Error with the format of the IPs in the file.\n', ex)
                exit()
        infile.close()
    except Exception as ex:
        print('Something was wrong with the file input.\n', ex)
    return targets

#-----------------------THIS SECTION HANDLES ALIVE CHECKING--------------------
#ARP for the target
def arp_check(target):
    arp_success, arp_no = arping(target, verbose=False)
    if arp_success:
        if arp_success[0][1].op == 2:
            return True

#Check for open ports for an alive target, used both in the detect and the port scan options
def port_touch(target, port):
    probe = IP(dst=target)/TCP(dport=port, flags='S')
    ack = sr1(probe, timeout=1, verbose=False)    
    if ack:
        if ack[0][1].flags == 'SA':
            return port

#Try to ping the target
def ping_touch(target):
    ping_probe = IP(dst=target)/ICMP()
    ping_recv = sr1(ping_probe, timeout=2, verbose=False)
    if ping_recv:
        if ping_recv.type == 0:
            return True


#This function will check for alives with some combination of an arp request, ping and/or port sweep. It calls all the alive checking functions created above
def check_for_alive(target, no_ping = False, ping_only = False):
    port_list = [22,80,443,445]
    if no_ping:
        arp_alive = arp_check(target)
        if arp_alive:
            return target
        for port in port_list:
            ports_open = port_touch(target, port)
            if ports_open:
                return target
    elif ping_only:
        arp_alive = arp_check(target)
        if arp_alive:
            return target
        ping_reply = ping_touch(target)
        if ping_reply:    
            return target
    else:
        arp_alive = arp_check(target)
        if arp_alive:
            return target
        ping_reply = ping_touch(target)
        if ping_reply:
            return target
        for port in port_list:
            ports_open = port_touch(target, port)
            if ports_open:
                return target

#------------------------------THIS SECTION HANDLES PORT SCANNING------------------
#This function handles user input about what ports to scan
def port_parse(port_list):
    ports = []
    if 'all' in port_list:
        for port in range(65536):
            ports.append(int(port))
        return ports
    elif '-' in port_list:
        start, end = port_list.split('-')
        for port in range(int(start), (int(end)+1)):
            ports.append(int(port))
        return ports
    elif ',' in port_list:
        ports_isolated = port_list.split(',')
        for port in ports_isolated:
            ports.append(int(port))
        return ports
    elif int(port_list) in range(65536):
        ports.append(int(port_list))
        return ports
    else:
        print('There is an error with the port you specified.')
        exit()

#-----------------------------THIS SECTION HANDLES OUTPUT----------------------
def std_out(content):
    if type(content) == list:
        content.sort()
        for ip in content:
            print(ip)
    elif type(content) == dict:
        for key in content:
            print(key + ':', end='')
            for port in content[key]:
                print(' ' + str(port), end='')
            print()


def write_file(filename, content):
    try:
        with open(filename, 'w') as infile:
            print('opening ' + filename)
            if type(content) == list:
                content.sort()
                for line in content:
                    infile.write(line + '\n')
                infile.close()
            elif type(content) == dict:
                for key in content:
                    infile.write(key + ':')
                    for port in content[key]:
                        infile.write(' ' + str(port))
                    infile.write('\n')
                infile.close()
    except Exception as ex:
        print(ex)

#------------------------------HERE IS MAIN--------------------------------------

#do main things here, like calling things
def main():
    targets = []
    alive_targets = []
    ports_to_check = []

#The first thing we do is parse the target entry
    if args.targs:
        targets = targ_parse(args.targs)
    elif args.targFile:
        targets = targ_file_parse(args.targFile)

#Next we run through the detect phase of the flag is given
    if args.detect:
        threads = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:  #<-- find the way to determine max threads on a system and use that info to determine the max_workers input
            for i in range(len(targets)):
                threads.append(executor.submit(check_for_alive, targets[i], args.no_ping, args.ping_only))
            concurrent.futures.wait(threads)
            for thread in threads:
                if type(thread.result()) == str:
                    alive_targets.append(thread.result())

#This is the port scan if that flag is given
    if args.port_scan:
        results = {}
        alive_targets = targets[:]
        ports_to_check = (port_parse(args.port_scan))
        for target in alive_targets:
            threads = []
            open_ports = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
                for port in ports_to_check:
                    threads.append(executor.submit(port_touch, target, port))
                concurrent.futures.wait(threads)
                for thread in threads:
                    if type(thread.result()) == int:
                        open_ports.append(thread.result())
            if len(open_ports) > 0:
                results[target] = open_ports

#Write the results, either to a file or stdout
    if args.write:
        if args.detect:
            write_file(args.write, alive_targets)
        elif args.port_scan:
            write_file(args.write, results)
    elif not args.write:
        if args.detect:
            std_out(alive_targets)
        elif args.port_scan:
            std_out(results)

if __name__ == '__main__':
    main()
    
