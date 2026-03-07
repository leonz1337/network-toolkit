#! /bin/python

import socket
import threading
import sys
import argparse
from queue import Queue

def get_args():
    parser = argparse.ArgumentParser(description="Multi-threaded Port Scanner")
    parser.add_argument("-t","--target",dest="target",required=True,help="Target IP or domain e.g 127.0.0.1 or scanme.nmap.org")
    parser.add_argument("-p","--ports",dest="ports",default="1-1024",help="Port range (default: 1-1024)")
    parser.add_argument("-w","--threads",dest="threads",type=int,default=100,help="Number of Threads (default: 100)")
    
    args = parser.parse_args()
    return args

print_lock = threading.Lock()

def resolve_target(target):
    
    try:
        socket.inet_aton(target)
        return target  
        
    except socket.error:
    
        try:
            ip = socket.gethostbyname(target)
            print(f"[*] Resolved {target} to {ip}")
            return ip
        except socket.gaierror:
            print(f"[-] Cannot resolve {target}")
            sys.exit(1)

def scan_port(target,port):
    s = socket.socket()
    s.settimeout(1)
    try:
        if s.connect_ex((target,port))== 0:
            banner = s.recv(1024).decode()
            with print_lock:
                print(f"[+]{target}:{port} is OPEN with {banner}")
                s.close()

    except Exception:
        pass

def threader(target,q):
    while True:
        port = q.get()
        scan_port(target,port)
        q.task_done()
        
import requests

RED = "\033[91m"
GREEN = "\033[92m"
CYAN = "\033[96m"
RESET = "\033[0m"


def check_internetdb(ip):
    print(f"\n{CYAN}[*] Querying Shodan InternetDB...{RESET}")

    url = f"https://internetdb.shodan.io/{ip}"

    try:
        r = requests.get(url, timeout=10)

        if r.status_code != 200:
            print(f"{RED}[-] InternetDB query failed{RESET}")
            return

        data = r.json()

        print(f"\n{CYAN}Host:{RESET} {ip}")
        print(f"{GREEN}Ports:{RESET} {data.get('ports', [])}")
        print(f"{GREEN}Hostnames:{RESET} {data.get('hostnames', [])}")

        print(f"\n{CYAN}Detected Software (CPE):{RESET}")
        for cpe in data.get("cpes", []):
            print(" ", cpe)

        vulns = data.get("vulns", [])

        if vulns:
            print(f"\n{RED}Known Vulnerabilities:{RESET}")
            for v in vulns:
                print(" ", v)
        else:
            print(f"\n{GREEN}No vulnerabilities listed in InternetDB{RESET}")

    except Exception as e:
        print("Error:", e)

        
def main():
    args = get_args()
    target_input = args.target
    target = resolve_target(target_input)
    try:
        start_port, end_port = map(int, args.ports.split("-"))
    except:
        print("[-] Invalid Port range. use format: 1-100")
        sys.exit()
            
    q = Queue()

    for i in range(args.threads):
        t = threading.Thread(target=threader,args=(target,q))
        t.daemon = True
        t.start()
        
    print(f"[*]Starting scan on {target} using threads...")

    for port in range(start_port,end_port+1):
        q.put(port)
    q.join()
    print("[*]Finished Scanning....")
    check_internetdb(target)

if __name__ == "__main__":
    main()
