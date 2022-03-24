import psutil
import time
import asyncio
import subprocess
import threading
import requests
import math
import sys

from datetime import datetime

try:
    webhook = sys.argv[1]
except IndexError:
    webhook = None

try:
    hostname = sys.argv[2]
except IndexError:
    hostname = None

async def monitor():
    if webhook == None:
        print("No webhook specified. Exiting.")
        print("Usage: monitor.py <webhook> <hostname>")
        return
    if hostname == None:
        print("No hostname specified. Exiting.")
        print("Usage: monitor.py <webhook> <hostname>")
        return    
    while True:
        current_in = get_bandwidth()
        await send_stat(current_in)
        time.sleep(1)

async def send_stat(value):
    # check if a tcpdump is active
    if threading.active_count() > 1:
        # print("TCPdump is active. Skipping attack detection.")
        return
    if value > 2000:
        print(f"DDoS attack detected: {value} PPS")
        threading.Thread(target=tcpdump).start()
        while True:
            if not check_if_still_under_attack():
                print("DDoS attack ended.")
                break


def check_if_still_under_attack():
    current_bandwidth = get_bandwidth()
    print(f"Current network traffic stats: {current_bandwidth} PPS")
    if current_bandwidth > 2000:
        return True
    else:
        if threading.active_count() > 0:
            return False
        embed = {
            "title": f"Attack ended on {hostname}",
            "description": f"The attack on {hostname} has ended.",
            "color": "5763719"
        }
        data = {
            "embeds": [
                embed
            ]
        }
        headers = {
            "Content-Type": "application/json"
        }
        requests.post(webhook, json=data, headers=headers)
        return False


def get_bandwidth():
    net1_in = psutil.net_io_counters().packets_recv

    time.sleep(1)

    net2_in = psutil.net_io_counters().packets_recv

    if net1_in > net2_in:
        current_in = 0
    else:
        current_in = net2_in - net1_in

    return current_in


def get_bandwidth_bytes():
    net1_in = psutil.net_io_counters().bytes_recv

    time.sleep(1)

    net2_in = psutil.net_io_counters().bytes_recv

    if net1_in > net2_in:
        current_in = 0
    else:
        current_in = net2_in - net1_in

    return current_in

def tcpdump():
    now = datetime.now()
    # run command
    fileTime = now.strftime("%m-%d-%Y--%H:%M:%S")
    dump = subprocess.Popen(['/usr/sbin/tcpdump', 'inbound', '-i', 'eth0', '-n',
                            '-s0', '-c', '10000', 'and', 'ip', '-w', f'/root/tcpdumps/{fileTime}.pcap'])
    while True:
        if not check_if_still_under_attack():
            # stop tcpdump
            dump.kill()
            return
        if dump.poll() is not None:
            print("TCPdump finished. Sending to Courvix for analysis.")
            break
    # send to courvix
    capture_file = open(f'/root/tcpdumps/{fileTime}.pcap', 'rb')
    analysis = requests.post(
        "https://api.courvix.com/attack/analyze", files={'capture': capture_file}).json()

    embed = {
        "title": f"Attack detected on {hostname}",
        "description": f"An attack has been detected on {hostname}. Traffic belongs to " + str(analysis['network_count']) + " networks and there are " + str(analysis["ip_count"]) + " unique IP addresses. We are attempting mitigations.",
        "color": "15548997",

        "fields": [
            {
                "name": "TCP Dump Location",
                "value": "/root/tcpdumps/" + fileTime,
            },
            {
                "name": "Attack type(s)",
                "value": analysis['attack_type']
            },
            {
                "name": "IP Spoofing?",
                "value": analysis['spoofing']
            },
            {
                "name": "Packets Per Second",
                "value": f"{get_bandwidth()} PPS"
            },
            {
                "name": "Bandwidth",
                "value": convert_size(get_bandwidth_bytes())
            },
            {
                "name": "CPU Usage",
                "value": f"{psutil.cpu_percent(interval=None)}%"
            }
        ]
    }
    data = {
        "embeds": [
            embed
        ]
    }
    headers = {
        "Content-Type": "application/json"
    }
    requests.post(webhook, json=data, headers=headers)
    return

def convert_size(size_bytes):
   if size_bytes == 0:
       return "0B"
   size_name = ("B", "KB", "MB", "GB", "TB")
   i = int(math.floor(math.log(size_bytes, 1024)))
   p = math.pow(1024, i)
   s = round(size_bytes / p, 2)
   return "%s %s/s" % (s, size_name[i])

asyncio.run(monitor())
