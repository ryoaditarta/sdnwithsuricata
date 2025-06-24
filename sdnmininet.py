#!/usr/bin/env python3

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.topo import Topo
from mininet.log import setLogLevel, info

class SDNSuricataTopo(Topo):
    def build(self):
        # Switch
        s1 = self.addSwitch('S1')

        # Hosts
        h1 = self.addHost('H1', ip='10.0.0.1/24')
        srv1 = self.addHost('SRV1', ip='10.0.0.2/24')
        suricata = self.addHost('SURICATA', ip='10.0.0.254/24')

        # Links
        self.addLink(h1, s1)
        self.addLink(srv1, s1)
        self.addLink(suricata, s1)

if __name__ == '__main__':
    setLogLevel('info')

    topo = SDNSuricataTopo()
    net = Mininet(topo=topo, controller=None, switch=OVSKernelSwitch)
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)

    net.start()

    s1 = net.get('S1')
    # Ambil nama port untuk masing-masing
    intf_h1 = s1.connectionsTo(net.get('H1'))[0][0].name
    intf_srv1 = s1.connectionsTo(net.get('SRV1'))[0][0].name
    intf_suricata = s1.connectionsTo(net.get('SURICATA'))[0][0].name

    # Mirror traffic dari H1 dan SRV1 ke SURICATA
    mirror_cmd = (
        f"ovs-vsctl -- --id=@{intf_h1} get Port {intf_h1} "
        f"-- --id=@{intf_srv1} get Port {intf_srv1} "
        f"-- --id=@{intf_suricata} get Port {intf_suricata} "
        f"-- --id=@m create Mirror name=m0 "
        f"select-dst-port=@{intf_h1},@{intf_srv1} "
        f"select-src-port=@{intf_h1},@{intf_srv1} "
        f"output-port=@{intf_suricata} "
        f"-- set Bridge S1 mirrors=@m"
    )
    s1.cmd(mirror_cmd)

    print("\n=== Port mirroring is active: traffic between H1 <-> SRV1 is mirrored to SURICATA ===\n")
    CLI(net)
    net.stop()

