#! /bin/python

import socket
import threading
import sys
import argparse
from queue import Queue
import requests

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
            service = get_service(port)
            with print_lock:
                 if banner:
                      print(f"[+] {target}:{port} OPEN ({service}) {banner}")
                      s.close()
                 else:
                      print(f"[+] {target}:{port} OPEN | {banner}")
                      s.close()
            

    except Exception:
        pass
        
def get_service(port):
    try:
        return socket.getservbyport(port)
    except:
        return "unknown"

def threader(target,q):
    while True:
        port = q.get()
        scan_port(target,port)
        q.task_done()
        
def check_internetdb(ip):
    print(f"[*] Querying Shodan InternetDB...")

    url = f"https://internetdb.shodan.io/{ip}"

    try:
        r = requests.get(url, timeout=10)

        if r.status_code != 200:
            print(f"[-] InternetDB query failed")
            return

        data = r.json()

        print(f"[*]Host: {ip}")
        print(f"[*]Ports: {data.get('ports', [])}")
        print(f"[*]Hostnames: {data.get('hostnames', [])}")

        print(f"[+]Detected Software (CPE):")
        for cpe in data.get("cpes", []):
            print(" ", cpe)

        

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
