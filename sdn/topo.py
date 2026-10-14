#!/usr/bin/env python3
"""
PropGuard: Mininet Multi-Zone Topology
Simulates DMZ, Workstations, and Database subnets over an L2 OpenFlow fabric.
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info

class PropGuardTopo(Topo):
    def build(self):
        s_dmz = self.addSwitch('s1', protocols='OpenFlow13')
        s_corp = self.addSwitch('s2', protocols='OpenFlow13')
        s_core = self.addSwitch('s3', protocols='OpenFlow13')

        # Core aggregation links
        self.addLink(s_dmz, s_core)
        self.addLink(s_corp, s_core)

        # DMZ Hosts (/16 subnet)
        h_web = self.addHost('h1', ip='10.0.1.10/16', mac='00:00:00:00:01:10')
        h_dns = self.addHost('h2', ip='10.0.1.20/16', mac='00:00:00:00:01:20')
        self.addLink(h_web, s_dmz)
        self.addLink(h_dns, s_dmz)

        # Corporate Workstations (/16 subnet)
        h_ws1 = self.addHost('h3', ip='10.0.2.10/16', mac='00:00:00:00:02:10')
        h_ws2 = self.addHost('h4', ip='10.0.2.20/16', mac='00:00:00:00:02:20')
        self.addLink(h_ws1, s_corp)
        self.addLink(h_ws2, s_corp)

        # Critical Core & Quarantine Sink (/16 subnet)
        h_db   = self.addHost('h5', ip='10.0.3.10/16', mac='00:00:00:00:03:10')
        h_sink = self.addHost('h6', ip='10.0.3.99/16', mac='00:00:00:00:03:99')
        self.addLink(h_db, s_core)
        self.addLink(h_sink, s_core)

def run():
    topo = PropGuardTopo()
    net = Mininet(
        topo=topo,
        switch=OVSSwitch,
        controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6653),
        autoSetMacs=True
    )
    net.start()
    info("\n*** PropGuard Multi-Zone Network Started (OpenFlow 1.3 on port 6653)\n")
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()
