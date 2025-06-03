from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4

import threading
import socket
import logging # Import logging module for better output control

# --- Constants ---
# Port for receiving IP blacklist from external source (e.g., Suricata)
BLACKLIST_LISTEN_PORT = 9999
# Default flow entry priority (lowest)
FLOW_PRIORITY_DEFAULT = 0
# Priority for blocking rules (higher than default, lower than specific forwarding)
FLOW_PRIORITY_BLACKLIST = 100
# Priority for learned MAC forwarding rules
FLOW_PRIORITY_LEARNED_MAC = 10

class SimpleSwitchWithBlacklist(app_manager.RyuApp):
    """
    A Ryu OpenFlow 1.3 controller that functions as a learning switch
    with dynamic IP blacklisting capabilities.

    It listens on a specific port for IP addresses to add to a blacklist,
    and then installs flow rules to drop traffic from/to blacklisted IPs.
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitchWithBlacklist, self).__init__(*args, **kwargs)
        self.mac_to_port = {}  # Stores MAC address to port mappings for each datapath
        self.datapaths = {}    # Stores connected datapath objects (switches)
        self.blacklist = set() # Shared set for blacklisted IP addresses
        self.blacklist_lock = threading.Lock() # Lock for thread-safe access to blacklist

        # Use Ryu's logger for better logging
        self.logger.setLevel(logging.INFO)

        # Start socket listener in a separate thread
        # It's set as daemon so it exits when the main application exits.
        blacklist_thread = threading.Thread(target=self._listen_for_blacklist)
        blacklist_thread.daemon = True
        blacklist_thread.start()
        self.logger.info("[*] Blacklist listener thread started on port %d", BLACKLIST_LISTEN_PORT)

    def _listen_for_blacklist(self):
        """
        Listens on BLACKLIST_LISTEN_PORT for incoming IP addresses to blacklist.
        This runs in a separate thread.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Allow reusing address
                sock.bind(('0.0.0.0', BLACKLIST_LISTEN_PORT))
                sock.listen(5)
                self.logger.info("[*] Waiting for IP blacklist from external source (e.g., Suricata) on port %d...", BLACKLIST_LISTEN_PORT)

                while True:
                    conn, addr = sock.accept()
                    with conn:
                        self.logger.info("[*] Connection received from %s", addr[0])
                        try:
                            # Receive data, decode with UTF-8 to match sender, and strip whitespace
                            ip_to_blacklist = conn.recv(1024).decode('utf-8').strip() # Explicit UTF-8 decoding
                            if ip_to_blacklist:
                                # Ensure thread-safe access to the blacklist set
                                with self.blacklist_lock:
                                    if ip_to_blacklist not in self.blacklist:
                                        self.blacklist.add(ip_to_blacklist)
                                        self.logger.warning("[!] IP added to blacklist: %s", ip_to_blacklist)
                                        # Apply blocking rules on all connected switches for the new blacklisted IP
                                        for dp_id, datapath in self.datapaths.items():
                                            self._add_blacklist_flow(datapath, ip_to_blacklist)
                                    else:
                                        self.logger.info("[+] IP %s already in blacklist.", ip_to_blacklist)
                        except Exception as e:
                            self.logger.error("Error processing blacklist connection from %s: %s", addr[0], e)
        except OSError as e:
            self.logger.critical("Failed to start blacklist listener socket on port %d: %s", BLACKLIST_LISTEN_PORT, e)
        except Exception as e:
            self.logger.critical("An unexpected error occurred in blacklist listener: %s", e)

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
        match_src = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_address) # 0x0800 is EtherType for IPv4
        self.logger.warning("Installing flow to drop traffic from %s on datapath %d", ip_address, datapath.id)
        self._add_flow(datapath, FLOW_PRIORITY_BLACKLIST, match_src, actions)

        # Rule 2: Drop packets to the blacklisted IP
        match_dst = parser.OFPMatch(eth_type=0x0800, ipv4_dst=ip_address)
        self.logger.warning("Installing flow to drop traffic to %s on datapath %d", ip_address, datapath.id)
        self._add_flow(datapath, FLOW_PRIORITY_BLACKLIST, match_dst, actions)

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
        # This rule sends any packet not matched by other flows to the controller.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                           ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, FLOW_PRIORITY_DEFAULT, match, actions)

        # Apply existing blacklist rules to the newly connected switch
        with self.blacklist_lock:
            for ip in self.blacklist:
                self._add_blacklist_flow(datapath, ip)
                self.logger.info("Applied existing blacklist rule for %s to new switch %d", ip, datapath.id)

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
            with self.blacklist_lock: # Ensure thread-safe access to blacklist
                if ip4.src in self.blacklist or ip4.dst in self.blacklist:
                    self.logger.warning("[!] Packet from/to blacklisted IP dropped (controller-level fallback): %s -> %s", ip4.src, ip4.dst)
                    # If a flow mod for this IP wasn't already installed, this drop at controller level serves as a fallback.
                    # No PacketOut is sent, effectively dropping the packet.
                    return

        # 2. MAC Learning and Flow Installation (for legitimate traffic)
        self.mac_to_port.setdefault(dpid, {})
        # Learn a MAC address to its port on this datapath
        self.mac_to_port[dpid][src_mac] = in_port

        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
            self.logger.debug("Learned: dpid=%x, src_mac=%s -> in_port=%d, dst_mac=%s -> out_port=%d",
                              dpid, src_mac, in_port, dst_mac, out_port)
            
            # Add a flow entry to the switch to handle future packets for this specific flow
            # This reduces subsequent Packet-In events for known flows.
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
            actions = [parser.OFPActionOutput(out_port)]
            self._add_flow(datapath, FLOW_PRIORITY_LEARNED_MAC, match, actions, msg.buffer_id)

            # If a buffer_id exists, the switch has the packet, so no need to send data
            # If buffer_id is OFP_NO_BUFFER, the controller received the full packet,
            # so we must send it back with the PacketOut.
            data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None

        else:
            # If destination MAC is unknown, flood the packet
            out_port = ofproto.OFPP_FLOOD
            self.logger.debug("Unknown destination MAC %s on datapath %x, flooding.", dst_mac, dpid)
            actions = [parser.OFPActionOutput(out_port)]
            data = msg.data # Always send data for flood as no flow rule is added

        # Send the packet out instruction to the switch
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
