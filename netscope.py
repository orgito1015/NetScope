import os
import socket
import subprocess
import platform
import psutil
import requests
import time
import json
import dns.resolver
import paramiko
from scapy.all import sniff, IP, ICMP
from ping3 import ping
from urllib.request import urlopen
from scapy.layers.inet import TCP

# Ping Tool
def ping_tool(ip):
    print(f"Pinging {ip}...")
    response = ping(ip)
    if response is None:
        print(f"Request timed out for {ip}")
    else:
        print(f"Reply from {ip}: time={response * 1000:.2f} ms")

# Traceroute Tool
def traceroute_tool(host):
    print(f"Tracerouting {host}...")
    result = subprocess.run(['traceroute', host], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        print(result.stdout.decode())
    else:
        print(f"Error: {result.stderr.decode()}")

# Network Scanner
def network_scanner(network):
    print(f"Scanning network: {network}...")
    result = subprocess.run(['nmap', '-sn', network], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        print(result.stdout.decode())
    else:
        print(f"Error: {result.stderr.decode()}")

# Port Scanner
def port_scanner(ip, ports):
    print(f"Scanning ports on {ip}...")
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            print(f"Port {port} is open")
        else:
            print(f"Port {port} is closed")
        sock.close()

# Bandwidth Monitor
def bandwidth_monitor():
    print("Monitoring bandwidth usage...")
    prev_sent = psutil.net_io_counters().bytes_sent
    prev_recv = psutil.net_io_counters().bytes_recv
    time.sleep(1)
    curr_sent = psutil.net_io_counters().bytes_sent
    curr_recv = psutil.net_io_counters().bytes_recv
    print(f"Upload: {(curr_sent - prev_sent) / 1024:.2f} KB/s")
    print(f"Download: {(curr_recv - prev_recv) / 1024:.2f} KB/s")

# DNS Lookup Tool
def dns_lookup(domain):
    print(f"Performing DNS lookup for {domain}...")
    result = dns.resolver.resolve(domain, 'A')
    for ipval in result:
        print(f"IP Address: {ipval.to_text()}")

# Packet Sniffer
def packet_sniffer():
    print("Starting packet sniffer...")
    sniff(filter="ip", prn=lambda x: x.summary(), count=10)

# HTTP Request Simulator
def http_request_simulator(url, method='GET'):
    print(f"Sending {method} request to {url}...")
    response = requests.request(method, url)
    print(f"Response Status Code: {response.status_code}")
    print(f"Response Headers: {response.headers}")
    try:
        print(f"Response Body (first 500 bytes):\n{response.text[:500]}")
    except Exception:
        pass

# IP Geolocation Tool
def ip_geolocation(ip):
    print(f"Fetching geolocation for {ip}...")
    response = requests.get(f"http://ip-api.com/json/{ip}")
    data = response.json()
    print(f"Country: {data.get('country')}")
    print(f"City: {data.get('city')}")
    print(f"ISP: {data.get('isp')}")

# SSH Client
def ssh_client(host, username, password):
    print(f"Connecting to {host} via SSH...")
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, username=username, password=password)
        stdin, stdout, stderr = ssh.exec_command('hostname')
        print(stdout.read().decode())
        ssh.close()
    except Exception as e:
        print(f"SSH Connection failed: {e}")

# Proxy Server (Simple Example)
def proxy_server():
    print("Proxy server not implemented in this example.")

# Network Performance Tester
def network_performance_tester():
    print("Testing network performance...")
    ping_tool("8.8.8.8")

# Wi-Fi Signal Strength Analyzer
def wifi_signal_analyzer():
    print("Wi-Fi signal strength analyzer not implemented in this example.")

# SSL/TLS Certificate Checker
def ssl_tls_checker(url):
    print(f"Checking SSL/TLS certificate for {url}...")
    try:
        import ssl
        from urllib.request import urlopen
        context = ssl.create_default_context()
        with urlopen(url, context=context) as conn:
            cert = conn.getpeercert()
            print(f"Certificate subject: {cert.get('subject')}")
            print(f"Certificate issuer: {cert.get('issuer')}")
    except Exception as e:
        print(f"Error: {e}")

# Main Program with Menu
def main():
    while True:
        print("\nNetScope Network Toolkit Menu:")
        print("1. Ping Tool")
        print("2. Traceroute Tool")
        print("3. Network Scanner")
        print("4. Port Scanner")
        print("5. Bandwidth Monitor")
        print("6. DNS Lookup Tool")
        print("7. Packet Sniffer")
        print("8. HTTP Request Simulator")
        print("9. IP Geolocation Tool")
        print("10. SSH Client")
        print("11. Network Performance Tester")
        print("12. SSL/TLS Certificate Checker")
        print("13. Exit")

        choice = input("Select a tool (1-13): ")

        if choice == '1':
            ip = input("Enter IP address to ping: ")
            ping_tool(ip)
        elif choice == '2':
            host = input("Enter host to traceroute: ")
            traceroute_tool(host)
        elif choice == '3':
            network = input("Enter network (e.g., 192.168.1.0/24): ")
            network_scanner(network)
        elif choice == '4':
            ip = input("Enter IP address to scan ports: ")
            ports = list(map(int, input("Enter ports (comma-separated): ").split(',')))
            port_scanner(ip, ports)
        elif choice == '5':
            bandwidth_monitor()
        elif choice == '6':
            domain = input("Enter domain to look up: ")
            dns_lookup(domain)
        elif choice == '7':
            packet_sniffer()
        elif choice == '8':
            url = input("Enter URL to simulate request: ")
            method = input("Enter HTTP method (GET, POST, PUT, DELETE): ").upper()
            http_request_simulator(url, method)
        elif choice == '9':
            ip = input("Enter IP address for geolocation: ")
            ip_geolocation(ip)
        elif choice == '10':
            host = input("Enter host for SSH: ")
            username = input("Enter username: ")
            password = input("Enter password: ")
            ssh_client(host, username, password)
        elif choice == '11':
            network_performance_tester()
        elif choice == '12':
            url = input("Enter URL to check SSL certificate: ")
            ssl_tls_checker(url)
        elif choice == '13':
            print("Exiting NetScope Network Toolkit...")
            break
        else:
            print("Invalid choice, please try again.")

if __name__ == "__main__":
    main()
