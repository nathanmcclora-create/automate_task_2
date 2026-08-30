#!/usr/bin/env python3
import time
import requests

GNS3_SERVER = "http://localhost:3080"
PROJECT_ID = "980fb060-20d5-4268-8ba6-f215a2b4f9c3"

SERVER_NODES = ["DNS1", "DNS2", "API", "DB", "SMTP", "SVR1", "SVR2"]
ROUTER_NODE = "ROUTER1" # dhcp service
SWITCH_NODES = ["SW1", "SW2", "SW3", "SW4"]
DHCP_CLIENT_NODES = ["PC1", "PC2", "PC3", "PC4", "WEBTERM"]

DELAY_AFTER_DHCP_START = 120  # seconds

session = requests.Session()

def get_nodes():
    r = session.get(f"{GNS3_SERVER}/v2/projects/{PROJECT_ID}/nodes")
    r.raise_for_status()
    return r.json()

def find_node_by_name(nodes, name):
    for node in nodes:
        if node["name"] == name:
            return node
    raise ValueError(f"Node not found: {name}")

def start_node(node_id, node_name):
    r = session.post(f"{GNS3_SERVER}/v2/projects/{PROJECT_ID}/nodes/{node_id}/start")
    r.raise_for_status()
    print(f"Started: {node_name}")

def print_green(msg):
    print(f"\033[92m{'\n' + msg}\033[0m")

def main():
    nodes = get_nodes()

    print_green("Starting network switches...")
    for name in SWITCH_NODES:
        node = find_node_by_name(nodes, name)
        start_node(node["node_id"], node["name"])

    print_green("Starting server nodes...")
    for name in SERVER_NODES:
        node = find_node_by_name(nodes, name)
        start_node(node["node_id"], node["name"])

    print_green("Starting network router and dhcp...")
    dhcp_node = find_node_by_name(nodes,ROUTER_NODE)
    start_node(dhcp_node["node_id"], dhcp_node["name"])

    interval = 5
    remaining = DELAY_AFTER_DHCP_START

    print(f"Waiting {DELAY_AFTER_DHCP_START} seconds for DHCP service to come up...")
    while remaining > 0:
        print(f"  ⏳ {remaining} seconds remaining...")
        sleep_time = min(interval, remaining)
        time.sleep(sleep_time)
        remaining -= sleep_time

    print("Done waiting for DHCP service.")

    print_green("\nStarting DHCP clients...")
    for name in DHCP_CLIENT_NODES:
        node = find_node_by_name(nodes, name)
        start_node(node["node_id"], node["name"])

    print_green("GNS3 network startup complete.")

if __name__ == "__main__":
    main()