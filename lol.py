#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call

def myNetwork():

    net = Mininet( topo=None,
                   build=False,
                   ipBase='10.0.0.0/8')

    info( '*** Adding controller\n' )
    c0=net.addController(name='c0',
                      controller=RemoteController,
                      ip='127.0.0.1',
                      protocol='tcp',
                      port=6653)

    info( '*** Add switches\n')
    s2 = net.addSwitch('s2', cls=OVSKernelSwitch)
    s1 = net.addSwitch('s1', cls=OVSKernelSwitch)
    r3 = Host('r3', inNamespace=False, ip='0.0.0.0')
    # r3 = Host('r3', inNamespace=False, ip='10.0.0.1')
    # r3 = net.addHost('r3', cls=Host, ip='10.0.0.1/8')
    r3.cmd('sysctl -w net.ipv4.ip_forward=1')

    info( '*** Add hosts\n')
    diel = net.addHost('diel', cls=Host, ip='10.0.1.2/16', defaultRoute='0.0.0.0', mac='00:00:00:00:00:01')

    alice = net.addHost('alice', cls=Host, ip='10.0.2.2/16', defaultRoute='0.0.0.0', mac='00:00:00:00:00:02')
    bob = net.addHost('bob', cls=Host, ip='10.0.2.3/16', defaultRoute='0.0.0.0', mac='00:00:00:00:00:03')

    info( '*** Add links\n')
    net.addLink(r3, s1)
    net.addLink(r3, s2)

    net.addLink(s1, diel)
    net.addLink(s2, bob)
    net.addLink(s2, alice)

    info( '*** Starting network\n')
    net.build()
    info( '*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()

    info( '*** Starting switches\n')
    net.get('s2').start([c0])
    net.get('s1').start([c0])

    info( '*** Post configure switches and hosts\n')
    r3.cmd('xterm &')
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNetwork()

