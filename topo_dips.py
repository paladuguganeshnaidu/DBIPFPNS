#!/usr/bin/env python3
"""Mininet topology for a basic DIPS experiment.

Nodes:
- attacker: simulated adversary host
- legit: benign user traffic generator
- prod: production service node
- decoy: deception/honeypot node
"""

from mininet.topo import Topo


class DIPSTopo(Topo):
    def build(self) -> None:
        switch = self.addSwitch("s1")

        attacker = self.addHost("attacker", ip="10.0.0.10/24")
        legit = self.addHost("legit", ip="10.0.0.20/24")
        prod = self.addHost("prod", ip="10.0.0.30/24")
        decoy = self.addHost("decoy", ip="10.0.0.40/24")

        self.addLink(attacker, switch)
        self.addLink(legit, switch)
        self.addLink(prod, switch)
        self.addLink(decoy, switch)


topos = {"dips": (lambda: DIPSTopo())}
