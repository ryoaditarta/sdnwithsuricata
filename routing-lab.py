#!/usr/bin/env python3

from mininet.net import Mininet
from mininet.node import Node, RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.topo import Topo
from mininet.log import setLogLevel, info

import argparse
import shutil
import time
from pathlib import Path

class LinuxRouter(Node):
    def config(self, **params):
        super().config(**params)
        self.cmd('sysctl -w net.ipv4.ip_forward=1')
        self.cmd('/usr/lib/frr/zebra -A 127.0.0.1 -s 90000000 -f /etc/frr/frr.conf -d')
        self.cmd('/usr/lib/frr/staticd -A 127.0.0.1 -f /etc/frr/frr.conf -d')
        self.cmd('/usr/lib/frr/ospfd -A 127.0.0.1 -f /etc/frr/frr.conf -d')
        self.cmd('/usr/lib/frr/bgpd -A 127.0.0.1 -f /etc/frr/frr.conf -d')
        self.cmd('/usr/lib/frr/frr-reload.py --reload /etc/frr/frr.conf')

    def terminate(self):
        self.cmd('killall zebra staticd ospfd ospf6d bgpd pathd pimd pim6d ldpd isisd nhrpd vrrpd fabricd')
        super().terminate()

class OSPFLab(Topo):
    def generate_config(self, router_name, path):
        router = {"name": router_name}
        path = path % router
        template_path = Path("Template/router") 
        Path(path).mkdir(exist_ok=True, parents=True)

        for file in template_path.iterdir():
            shutil.copy(file, path)

        with open(path + "/frr.conf", "w") as f:
            f.write(f"hostname {router_name}\n")

        with open(path + "/vtysh.conf", "w") as f:
            f.write(f"hostname {router_name}\n")

    def parse_argument(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("-g", "--generateConfig", help="Generate router config files", action="store_true")
        parser.add_argument("-v", "--verbose", help="Enable verbose logging", action="store_true")
        parser.add_argument("-c", "--config", dest="config_dir", default="config_ospf_lab", help="Config directory")
        return parser.parse_args()

    def build(self, *args, **kwargs):
        flags = self.parse_argument()
        if flags.verbose:
            setLogLevel('info')

        config_path = flags.config_dir + "/%(name)s"
        privateDirs = [
            '/var/log',
            ('/etc/frr', config_path),
            '/var/run',
            '/var/mn'
        ]

        # Hosts
        for i in range(1, 6):
            self.addHost(f'H{i}', ip=f"172.16.1.{i+1}/24", defaultRoute="via 172.16.1.1")
        self.addHost('SURICATA', ip="172.16.1.7/24", defaultRoute="via 172.16.1.1")
        self.addHost('SRV1', ip="172.16.2.2/24", defaultRoute="via 172.16.2.1")
        self.addHost('SRV2', ip="172.16.2.3/24", defaultRoute="via 172.16.2.1")

        # Switches (NO namespace!)
        self.addSwitch('S1', cls=OVSKernelSwitch)
        self.addSwitch('S2', cls=OVSKernelSwitch)

        # Routers
        self.addNode("R1", cls=LinuxRouter, ip=None, privateDirs=privateDirs)
        self.addNode("R2", cls=LinuxRouter, ip=None, privateDirs=privateDirs)

        # Links
        self.addLink("S1", "R1", intfName2="eth1")
        for i in range(1, 6):
            self.addLink("S1", f"H{i}", intfName2=f"eth{i+1}")
        self.addLink("S1", "SURICATA", intfName2="eth7")

        self.addLink("R1", "R2", intfName1="eth0", intfName2="eth0")
        self.addLink("S2", "R2", intfName2="eth1")
        self.addLink("S2", "SRV1", intfName2="eth2")
        self.addLink("S2", "SRV2", intfName2="eth3")  # fixed: SRV2 harus eth3 (bukan eth2 lagi)

        confdir = Path(config_path % {"name": ""})
        if not flags.generateConfig and not confdir.exists():
            print("Configuration directory not found. Generating config by default.")
            flags.generateConfig = True

        if flags.generateConfig:
            for n in self.nodes():
                if "cls" in self.nodeInfo(n) and self.nodeInfo(n)["cls"].__name__ == "LinuxRouter":
                    self.generate_config(n, config_path)

        super().build(*args, **kwargs)

if __name__ == '__main__':
    start = time.time()
    print("This is the topology for the OSPF lab")
    print("=" * 40)

    topo = OSPFLab()
    net = Mininet(topo=topo, switch=OVSKernelSwitch, controller=None)
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)
    print("Finished initializing network in:", time.time() - start, "seconds")

    try:
        net.start()
        s1 = net.get('S1')
        s1.cmd('ovs-vsctl -- set Bridge S1 mirrors=@m -- --id=@s1eth2 get Port S1-eth2 -- --id=@idsport get Port S1-eth7 -- --id=@m create Mirror name=m0 select-all=true output-port=@idsport')
        CLI(net)
    finally:
        stop_start = time.time()
        net.stop()
        print("Finished stopping network in:", time.time() - stop_start, "seconds")
