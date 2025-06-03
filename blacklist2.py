import time
import re
import socket
import os
import logging # For better logging

# --- Configuration Constants ---
# Location of Suricata's fast.log file
FAST_LOG_PATH = '/var/log/suricata/fast.log'
# IP address of the Ryu controller
CONTROLLER_IP = '127.0.0.1'
# Port on the controller used to receive blacklist IPs
CONTROLLER_PORT = 9999
# Interval (in seconds) to check for new log lines if none are immediately available
LOG_POLL_INTERVAL = 1

# --- Setup Logging ---
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)

def extract_ips_from_line(line):
    """
    Extracts source and destination IPv4 addresses from a Suricata fast.log line.

    Args:
        line (str): A single line from the fast.log file.

    Returns:
        tuple: A tuple containing (source_ip, destination_ip) if found,
               otherwise (None, None).
    """
    # Regex to capture IPv4 addresses possibly followed by port numbers
    # (e.g., 192.168.1.10:12345 -> 10.0.0.1:80)
    match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)? -> (\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?', line)
    if match:
        return match.group(1), match.group(2)
    return None, None

def send_to_controller(ip_address):
    """
    Sends a blacklisted IP address to the Ryu controller via TCP.

    Args:
        ip_address (str): The IP address to send.
    """
    if not ip_address:
        return # Don't send empty IPs

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((CONTROLLER_IP, CONTROLLER_PORT))
            s.sendall(ip_address.encode('utf-8')) # Explicitly encode as UTF-8
            logger.info("[+] Successfully sent IP to controller: %s", ip_address)
    except ConnectionRefusedError:
        logger.error("[!] Connection refused: Is the Ryu controller running and listening on %s:%d?", CONTROLLER_IP, CONTROLLER_PORT)
    except socket.timeout:
        logger.error("[!] Connection timed out when sending IP %s to controller.", ip_address)
    except Exception as e:
        logger.error("[!] Failed to send IP %s to controller: %s", ip_address, e)

def monitor_fast_log():
    """
    Continuously monitors Suricata's fast.log file for new alerts
    and sends new source IPs to the Ryu controller.
    """
    logger.info("[*] Starting to monitor Suricata fast.log: %s", FAST_LOG_PATH)
    # Using a set for efficient O(1) average time complexity lookups
    seen_ips = set()

    # Check if log file exists before attempting to open
    if not os.path.exists(FAST_LOG_PATH):
        logger.critical("Error: Suricata fast.log not found at %s. Please check the path.", FAST_LOG_PATH)
        return

    try:
        # Open the log file and seek to the end, similar to 'tail -f'
        with open(FAST_LOG_PATH, 'r', encoding='utf-8', errors='ignore') as f:
            f.seek(0, os.SEEK_END) # Go to the end of the file

            while True:
                line = f.readline()
                if not line:
                    # No new lines, wait a bit and try again
                    time.sleep(LOG_POLL_INTERVAL)
                    continue

                # Clean up the line (remove newline characters)
                clean_line = line.strip()
                if not clean_line: # Skip empty lines
                    continue

                src_ip, _ = extract_ips_from_line(clean_line)

                if src_ip: # Ensure an IP was actually extracted
                    if src_ip not in seen_ips:
                        seen_ips.add(src_ip)
                        logger.info("[*] New source IP detected: %s", src_ip)
                        send_to_controller(src_ip)
                    else:
                        logger.debug("Source IP %s already seen, skipping.", src_ip)
                else:
                    logger.debug("No valid IP found in line: %s", clean_line)

    except FileNotFoundError:
        logger.critical("Failed to open %s. Make sure Suricata is running and logging to this path.", FAST_LOG_PATH)
    except PermissionError:
        logger.critical("Permission denied to read %s. Please check file permissions.", FAST_LOG_PATH)
    except Exception as e:
        logger.critical("An unexpected error occurred during log monitoring: %s", e)

if __name__ == '__main__':
    monitor_fast_log()
