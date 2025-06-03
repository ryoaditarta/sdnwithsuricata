from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4

import threading
import socket
import logging
import time # Import time for timestamp operations

# --- Constants ---
BLACKLIST_LISTEN_PORT = 9999
FLOW_PRIORITY_DEFAULT = 0
FLOW_PRIORITY_BLACKLIST = 100
FLOW_PRIORITY_LEARNED_MAC = 10

# Default blacklist duration in seconds (e.g., 5 minutes)
DEFAULT_BLACKLIST_DURATION = 60 # 5 * 60 seconds

# Interval for checking expired IPs (e.g., every 30 seconds)
BLACKLIST_CLEANUP_INTERVAL = 30

class SimpleSwitchWithBlacklist(app_manager.RyuApp):
    """
    A Ryu OpenFlow 1.3 controller that functions as a learning switch
    with dynamic IP blacklisting capabilities.

    It listens on a specific port for IP addresses to add to a blacklist,
    and then installs flow rules to drop traffic from/to blacklisted IPs.
    Blacklisted IPs can have a defined duration.
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitchWithBlacklist, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        # Stores {ip_address: expiration_timestamp}
        self.blacklist = {}
        self.blacklist_lock = threading.Lock()

        self.logger.setLevel(logging.INFO)

        # Start socket listener in a separate thread
        blacklist_listener_thread = threading.Thread(target=self._listen_for_blacklist)
        blacklist_listener_thread.daemon = True
        blacklist_listener_thread.start()
        self.logger.info("[*] Blacklist listener thread started on port %d", BLACKLIST_LISTEN_PORT)

        # Start blacklist cleanup thread
        blacklist_cleanup_thread = threading.Thread(target=self._cleanup_blacklist_periodically)
        blacklist_cleanup_thread.daemon = True
        blacklist_cleanup_thread.start()
        self.logger.info("[*] Blacklist cleanup thread started (interval %d seconds)", BLACKLIST_CLEANUP_INTERVAL)

    def _listen_for_blacklist(self):
        """
        Listens on BLACKLIST_LISTEN_PORT for incoming IP addresses to blacklist.
        The message format expected is "IP_ADDRESS:DURATION_SECONDS" (e.g., "172.16.1.2:60").
        If DURATION_SECONDS is not provided, DEFAULT_BLACKLIST_DURATION will be used.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(('0.0.0.0', BLACKLIST_LISTEN_PORT))
                sock.listen(5)
                self.logger.info("[*] Waiting for IP blacklist from external source (e.g., Suricata) on port %d...", BLACKLIST_LISTEN_PORT)

                while True:
                    conn, addr = sock.accept()
                    with conn:
                        self.logger.info("[*] Connection received from %s", addr[0])
                        try:
                            received_data = conn.recv(1024).decode('utf-8').strip()
                            if received_data:
                                parts = received_data.split(':')
                                ip_to_blacklist = parts[0]
                                duration = DEFAULT_BLACKLIST_DURATION
                                if len(parts) > 1:
                                    try:
                                        duration = int(parts[1])
                                    except ValueError:
                                        self.logger.warning("Invalid duration received for %s. Using default duration %d.", ip_to_blacklist, duration)

                                expiration_time = time.time() + duration

                                with self.blacklist_lock:
                                    if ip_to_blacklist not in self.blacklist or self.blacklist[ip_to_blacklist] < expiration_time:
                                        self.blacklist[ip_to_blacklist] = expiration_time
                                        self.logger.warning("[!] IP added to blacklist: %s for %d seconds (expires at %s)",
                                                            ip_to_blacklist, duration, time.ctime(expiration_time))
                                        # Apply blocking rules on all connected switches for the new blacklisted IP
                                        for dp_id, datapath in self.datapaths.items():
                                            self._add_blacklist_flow(datapath, ip_to_blacklist)
                                    else:
                                        self.logger.info("[+] IP %s already blacklisted and expiration is later.", ip_to_blacklist)
                        except Exception as e:
                            self.logger.error("Error processing blacklist connection from %s: %s", addr[0], e)
        except OSError as e:
            self.logger.critical("Failed to start blacklist listener socket on port %d: %s", BLACKLIST_LISTEN_PORT, e)
        except Exception as e:
            self.logger.critical("An unexpected error occurred in blacklist listener: %s", e)

    def _cleanup_blacklist_periodically(self):
        """
        Periodically checks the blacklist for expired IPs and removes them.
        Removes associated flow rules from switches.
        """
        while True:
            time.sleep(BLACKLIST_CLEANUP_INTERVAL)
            now = time.time()
            expired_ips = []

            with self.blacklist_lock:
                for ip, expiration_time in self.blacklist.items():
                    if now > expiration_time:
                        expired_ips.append(ip)

                for ip in expired_ips:
                    del self.blacklist[ip]
                    self.logger.info("[*] IP %s unblacklisted (expired).", ip)
                    # Remove flow rules for this IP from all datapaths
                    for dp_id, datapath in self.datapaths.items():
                        self._remove_blacklist_flow(datapath, ip)

    def _add_flow(self, datapath, priority, match, actions, buffer_id=None):
        """
        Helper function to add a flow entry to a datapath.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst, buffer_id=buffer_id)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
        self.logger.debug("Flow added to datapath %d: Priority %d, Match %s, Actions %s",
                         datapath.id, priority, match, actions)

    def _add_blacklist_flow(self, datapath, ip_address):
        """
        Installs flow rules on the datapath to drop traffic from/to a blacklisted IP.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [] # Empty actions means drop the packet

        # Rule 1: Drop packets from the blacklisted IP
        match_src = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_address)
        self.logger.warning("Installing flow to drop traffic from %s on datapath %d", ip_address, datapath.id)
        self._add_flow(datapath, FLOW_PRIORITY_BLACKLIST, match_src, actions)

        # Rule 2: Drop packets to the blacklisted IP
        match_dst = parser.OFPMatch(eth_type=0x0800, ipv4_dst=ip_address)
        self.logger.warning("Installing flow to drop traffic to %s on datapath %d", ip_address, datapath.id)
        self._add_flow(datapath, FLOW_PRIORITY_BLACKLIST, match_dst, actions)

    def _remove_blacklist_flow(self, datapath, ip_address):
        """
        Removes flow rules associated with a blacklisted IP from a datapath.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Remove flow for packets from the blacklisted IP
        match_src = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_address)
        mod_src = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE,
                                    out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                                    priority=FLOW_PRIORITY_BLACKLIST, match=match_src)
        datapath.send_msg(mod_src)
        self.logger.info("Removed flow to drop traffic from %s on datapath %d", ip_address, datapath.id)

        # Remove flow for packets to the blacklisted IP
        match_dst = parser.OFPMatch(eth_type=0x0800, ipv4_dst=ip_address)
        mod_dst = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE,
                                    out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                                    priority=FLOW_PRIORITY_BLACKLIST, match=match_dst)
        datapath.send_msg(mod_dst)
        self.logger.info("Removed flow to drop traffic to %s on datapath %d", ip_address, datapath.id)


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Handles initial connection and capabilities of an OpenFlow switch.
        Installs a default flow rule to send unmatched packets to the controller.
        """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Store the datapath object
        self.datapaths[datapath.id] = datapath
        self.mac_to_port.setdefault(datapath.id, {})

        self.logger.info("Switch connected: datapath_id=0x%x", datapath.id)

        # Install table-miss flow entry (priority 0)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                           ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, FLOW_PRIORITY_DEFAULT, match, actions)

        # Apply existing (non-expired) blacklist rules to the newly connected switch
        with self.blacklist_lock:
            now = time.time()
            for ip, expiration_time in self.blacklist.items():
                if now < expiration_time: # Only apply if not expired yet
                    self._add_blacklist_flow(datapath, ip)
                    self.logger.info("Applied existing blacklist rule for %s to new switch %d (expires at %s)",
                                     ip, datapath.id, time.ctime(expiration_time))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        Handles Packet-In events from the switch (packets sent to the controller).
        Performs blacklist check and learning switch functionality.
        """
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if not eth:
            self.logger.debug("Received non-Ethernet packet, dropping.")
            return

        dst_mac = eth.dst
        src_mac = eth.src
        dpid = datapath.id

        self.logger.debug("Packet-in from datapath_id=0x%x in_port=%d src_mac=%s dst_mac=%s",
                         dpid, in_port, src_mac, dst_mac)

        # 1. Blacklist Check (at controller for first packet of a flow)
        ip4 = pkt.get_protocol(ipv4.ipv4)
        if ip4:
            with self.blacklist_lock:
                now = time.time()
                is_blacklisted = False
                if ip4.src in self.blacklist and now < self.blacklist[ip4.src]:
                    is_blacklisted = True
                if ip4.dst in self.blacklist and now < self.blacklist[ip4.dst]:
                    is_blacklisted = True

                if is_blacklisted:
                    self.logger.warning("[!] Packet from/to blacklisted IP dropped (controller-level fallback): %s -> %s", ip4.src, ip4.dst)
                    return

        # 2. MAC Learning and Flow Installation (for legitimate traffic)
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port

        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]

            self.logger.debug("Learned: dpid=%x, src_mac=%s -> in_port=%d, dst_mac=%s -> out_port=%d",
                             dpid, src_mac, in_port, dst_mac, out_port)

            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
            actions = [parser.OFPActionOutput(out_port)]
            self._add_flow(datapath, FLOW_PRIORITY_LEARNED_MAC, match, actions, msg.buffer_id)

            data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None

        else:
            out_port = ofproto.OFPP_FLOOD
            self.logger.debug("Unknown destination MAC %s on datapath %x, flooding.", dst_mac, dpid)
            actions = [parser.OFPActionOutput(out_port)]
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                   in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
