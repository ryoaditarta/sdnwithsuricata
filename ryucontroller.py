#!/usr/bin/env python3
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4

import threading
import re
import logging
import time
import os

# --- Constants ---
FLOW_PRIORITY_DEFAULT = 0
FLOW_PRIORITY_LEARNED_MAC = 10
FLOW_PRIORITY_BLACKLIST = 65535 # Maximum priority for effective blocking

DEFAULT_BLACKLIST_DURATION = 60 # Blacklist duration in seconds
BLACKLIST_CLEANUP_INTERVAL = 30 # Interval for cleaning up expired IPs
SURICATA_FAST_LOG = "/var/log/suricata/fast.log" # Ensure this path is correct!


class SimpleSwitchWithBlacklist(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitchWithBlacklist, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.blacklist = {} # Dictionary: {ip_address: expiration_timestamp}
        self.blacklist_lock = threading.Lock()
        
        # New: Set to keep track of IPs currently actively blocked (for logging purposes)
        self.current_active_blacklist_ips = set() 

        # Set the main logging level to INFO for concise output.
        self.logger.setLevel(logging.INFO) 
        self.logger.info("[*] SimpleSwitchWithBlacklist Controller Started.")

        # Start thread to monitor Suricata fast.log
        threading.Thread(target=self._monitor_suricata_fastlog, daemon=True).start()
        self.logger.info("[*] Suricata fast.log monitor thread started.")

        # Start thread to periodically clean up the blacklist
        blacklist_cleanup_thread = threading.Thread(target=self._cleanup_blacklist_periodically)
        blacklist_cleanup_thread.daemon = True
        blacklist_cleanup_thread.start()
        self.logger.info("[*] Blacklist cleanup thread started (interval %d seconds)", BLACKLIST_CLEANUP_INTERVAL)

    def _monitor_suricata_fastlog(self):
        """
        Monitors Suricata's fast.log for alerts by polling the file.
        This method is more robust against buffering issues and log rotations than 'tail -F'.
        """
        ip_port_regex = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?)\b')
        
        self.logger.info("[*] Monitoring Suricata fast.log: %s", SURICATA_FAST_LOG)

        if not os.path.exists(SURICATA_FAST_LOG):
            self.logger.error(f"[!] Suricata fast.log not found at: {SURICATA_FAST_LOG}. Make sure Suricata is running and configured to log to this path.")
            return

        last_position = 0
        try:
            with open(SURICATA_FAST_LOG, 'r') as f:
                f.seek(0, os.SEEK_END)
                last_position = f.tell()
            self.logger.info("[*] Initial fast.log size: %d bytes. Starting to monitor for new lines.", last_position)

            while True:
                time.sleep(0.5) 

                with open(SURICATA_FAST_LOG, 'r') as f:
                    f.seek(0, os.SEEK_END)
                    current_position = f.tell()
                    
                    if current_position < last_position:
                        self.logger.warning("[!] fast.log was truncated. Resetting read position to 0.")
                        last_position = 0

                    if current_position > last_position:
                        f.seek(last_position)
                        new_lines = f.readlines()
                        
                        last_position = f.tell()

                        if not new_lines:
                            continue

                        for line in new_lines:
                            line = line.strip()
                            if not line:
                                continue 

                            if "ALERT" in line.upper() or "SID:" in line.upper():
                                # self.logger.info(f"[!] Detected potential alert line from Suricata: {line}") # This is still useful, but can be verbose

                                found_ips_with_ports = ip_port_regex.findall(line)

                                if found_ips_with_ports:
                                    ips_to_consider = set()
                                    for ip_with_port in found_ips_with_ports:
                                        ip_only = ip_with_port.split(":")[0]
                                        ips_to_consider.add(ip_only)
                                    
                                    if ips_to_consider:
                                        for ip in ips_to_consider:
                                            expiration_time = time.time() + DEFAULT_BLACKLIST_DURATION
                                            with self.blacklist_lock:
                                                # Check if the IP is already in our active blacklist set
                                                if ip not in self.current_active_blacklist_ips:
                                                    # This is a NEW IP to blacklist or has just expired and now re-blacklisted
                                                    self.blacklist[ip] = expiration_time
                                                    self.current_active_blacklist_ips.add(ip) # Add to active set
                                                    self.logger.warning(f"[!!!] IP BLACKLISTED: {ip} for {DEFAULT_BLACKLIST_DURATION} seconds (expires at {time.ctime(expiration_time)}). Alert Line: {line}") # Log only once here
                                                    
                                                    if not self.datapaths:
                                                        self.logger.error("[!] No datapaths connected. Cannot install blacklist flow for %s.", ip)
                                                        continue

                                                    for dp_id, dp in self.datapaths.items():
                                                        self._add_blacklist_flow(dp, ip)
                                                else:
                                                    # IP is already in active blacklist, just extend duration if needed
                                                    if self.blacklist[ip] < expiration_time:
                                                        self.blacklist[ip] = expiration_time
                                                        # self.logger.debug(f"[*] IP {ip} already blacklisted, extending duration to {DEFAULT_BLACKLIST_DURATION} seconds (new expires at {time.ctime(expiration_time)}).")
                                                    # Otherwise, no action or log needed as it's already blacklisted with a longer expiration

        except Exception as e:
            self.logger.error(f"[!] Failed to monitor fast.log: {e}", exc_info=True)


    def _cleanup_blacklist_periodically(self):
        """
        Periodically cleans up expired IPs from the blacklist and removes their flow rules.
        """
        while True:
            time.sleep(BLACKLIST_CLEANUP_INTERVAL)
            now = time.time()
            expired_ips = []

            with self.blacklist_lock:
                # Find all expired IPs
                expired_ips = [ip for ip, expiration_time in self.blacklist.items() if now > expiration_time]

                # Remove expired IPs from the blacklist dictionary and the active set
                for ip in expired_ips:
                    del self.blacklist[ip]
                    if ip in self.current_active_blacklist_ips:
                        self.current_active_blacklist_ips.remove(ip) # Remove from active set
                    self.logger.info("[*] IP %s unblacklisted (expired from memory).", ip) 

            if expired_ips:
                for dp_id, datapath in list(self.datapaths.items()):
                    for ip in expired_ips:
                        self._remove_blacklist_flow(datapath, ip)


    def _add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id is not None:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                     match=match, instructions=inst, buffer_id=buffer_id,
                                     command=ofproto.OFPFC_ADD)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                     match=match, instructions=inst,
                                     command=ofproto.OFPFC_ADD)
        datapath.send_msg(mod)
        

    def _add_blacklist_flow(self, datapath, ip_address):
        parser = datapath.ofproto_parser
        actions = [] 

        match_src = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_address)
        self._add_flow(datapath, FLOW_PRIORITY_BLACKLIST, match_src, actions)
        self.logger.info(">>> Blacklist flow (src=%s, priority=%d) installed on datapath %d.", # Changed to INFO
                             ip_address, FLOW_PRIORITY_BLACKLIST, datapath.id)

        match_dst = parser.OFPMatch(eth_type=0x0800, ipv4_dst=ip_address)
        self._add_flow(datapath, FLOW_PRIORITY_BLACKLIST, match_dst, actions)
        self.logger.info(">>> Blacklist flow (dst=%s, priority=%d) installed on datapath %d.", # Changed to INFO
                             ip_address, FLOW_PRIORITY_BLACKLIST, datapath.id)

    def _remove_blacklist_flow(self, datapath, ip_address):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match_src = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_address)
        mod_src = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE,
                                     out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                                     priority=FLOW_PRIORITY_BLACKLIST, match=match_src)
        datapath.send_msg(mod_src)
        self.logger.info("Removed blacklist flow (src=%s) from datapath %d.", ip_address, datapath.id) 

        match_dst = parser.OFPMatch(eth_type=0x0800, ipv4_dst=ip_address)
        mod_dst = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE,
                                     out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                                     priority=FLOW_PRIORITY_BLACKLIST, match=match_dst)
        datapath.send_msg(mod_dst)
        self.logger.info("Removed blacklist flow (dst=%s) from datapath %d.", ip_address, datapath.id) 


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.datapaths[datapath.id] = datapath
        self.mac_to_port.setdefault(datapath.id, {})

        self.logger.info("[*] Switch connected: datapath_id=0x%x", datapath.id)

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                           ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, FLOW_PRIORITY_DEFAULT, match, actions)
        self.logger.info("Default flow (priority %d) added to datapath %d.", FLOW_PRIORITY_DEFAULT, datapath.id)

        # Re-apply existing (non-expired) blacklist rules to the newly connected switch
        with self.blacklist_lock:
            now = time.time()
            for ip, expiration_time in self.blacklist.items():
                if now < expiration_time:
                    self._add_blacklist_flow(datapath, ip)
                    # Add to current_active_blacklist_ips if it's an existing active blacklist
                    self.current_active_blacklist_ips.add(ip) 
                    self.logger.info("Applied existing blacklist rule for %s to new switch %d (expires at %s).",
                                     ip, datapath.id, time.ctime(expiration_time))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if not eth:
            return

        dst_mac = eth.dst
        src_mac = eth.src
        dpid = datapath.id

        actions = [] 
        data = None  

        ip4 = pkt.get_protocol(ipv4.ipv4)
        if ip4:
            with self.blacklist_lock:
                now = time.time()
                is_blacklisted = False
                # Check against the blacklist dictionary to see if the IP is effectively blacklisted
                if ip4.src in self.blacklist and now < self.blacklist[ip4.src]:
                    is_blacklisted = True
                if ip4.dst in self.blacklist and now < self.blacklist[ip4.dst]:
                    is_blacklisted = True

                if is_blacklisted:
                    # Log this only if the packet is being dropped by the controller itself
                    self.logger.warning("[!] Packet from/to blacklisted IP dropped (controller-level fallback): %s -> %s on datapath %d", ip4.src, ip4.dst, dpid)
                    return 

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port

        out_port = self.mac_to_port[dpid].get(dst_mac)

        if out_port is not None:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
            actions = [parser.OFPActionOutput(out_port)]
            self._add_flow(datapath, FLOW_PRIORITY_LEARNED_MAC, match, actions, msg.buffer_id)

            data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None

        else: 
            out_port = ofproto.OFPP_FLOOD
            actions = [parser.OFPActionOutput(out_port)]
            data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                   in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
