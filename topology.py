#!/usr/bin/python2

"""
Create a simple topology with a NAT router at the top
by Gustavo Diel


        router
          |
        switch
       /      \
      s1      s2
      |      /  \
    diel   alice bob
"""

from argparse import ArgumentParser
from subprocess import call

from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.net import Mininet
from mininet.node import Host, Node
from mininet.node import OVSKernelSwitch
from mininet.node import RemoteController

parser = ArgumentParser(description='Cleans Mininet and initiates TCC topology.')
parser.add_argument('IP', metavar='ip', type=str, help="Floodlight's IP", default='192.168.56.1', const='192.168.56.1', nargs='?')

args = parser.parse_args()

# ##               ## #
# Controller Settings #
# ##               ## #

controller_ip = args.IP
controller_port = 6653

# ################


def start_nat_router(root, external_interface='eth1', subnet='10.0/16' ):
    """
    Start NAT/Forwarding between Mininet and external network.
    :param root: The router node
    :param external_interface: Node's interface with external access
    :param subnet: Mininet's subnet
    """

    info('*** Starting NAT on node {}, interface: {} with subnet {}\n'.format(root, external_interface, subnet))

    # Identify the interface connecting to mininet's network
    local_interface = root.defaultIntf()

    # remove current rules
    root.cmd('iptables -F')
    root.cmd('iptables -t nat -F')

    # Create entries for traffic
    root.cmd('iptables -P INPUT ACCEPT')
    root.cmd('iptables -P OUTPUT ACCEPT')
    root.cmd('iptables -P FORWARD DROP')

    # Do the NAT
    root.cmd('iptables -I FORWARD -i {} -d {} -j DROP'.format(local_interface, subnet))
    root.cmd('iptables -A FORWARD -i {} -s {} -j ACCEPT'.format(local_interface, subnet))
    root.cmd('iptables -A FORWARD -i {} -d {} -j ACCEPT'.format(external_interface, subnet))
    root.cmd('iptables -t nat -A POSTROUTING -o {} -j MASQUERADE'.format(external_interface))

    # Remove unwanted forwarding
    root.cmd('iptables -I FORWARD -s 10.0.1.0/8 -d 10.0.2.0/8 -j DROP')
    root.cmd('iptables -I FORWARD -s 10.0.2.0/8 -d 10.0.1.0/8 -j DROP')

    # Disable forwarding of internal hosts
    root.cmd('iptables -I INPUT -s 10.0.2.0/8 -d 10.0.1.0/8 -j DROP'.format(local_interface, subnet))
    root.cmd('iptables -I FORWARD -i {} -d {} -j DROP'.format(local_interface, subnet))

    # Enable IPv4 Forwarding
    root.cmd('sysctl net.ipv4.ip_forward=1')


def stop_nat_router(root):
    """
    Stop NAT/Forwarding
    :param root: The router node
    """
    root.cmd('iptables -F')
    root.cmd('iptables -t nat -F')

    # Disable forwarding
    root.cmd('sysctl net.ipv4.ip_forward=0')


def fix_network_manager(root, interface):
    """
    Prevents NetworkManager from messing with the interface, providing the manual config
    :param root: NAT node
    :param interface: Interface's name
    """

    interface_file = '/etc/network/interfaces'
    line = '\niface {} inet manual\n'.format(interface)
    config = open(interface_file).read()
    if line not in config:
        print('Adding {} to {}\n'.format(line.strip(), interface_file))
        with open(interface_file, 'a') as file:
            file.write(line)

    root.cmd('service network-manager restart')


def connect_to_internet(network, interface='eth1', switch='s1', node_ip='10.0.0.1', subnet='10.0.0.0/8'):
    """
    Configure NAT to connect to Internet.
    :param network: Mininet's network
    :param interface: Interface connecting to Internet
    :param switch: Switch to connect to Root Namespace
    :param node_ip: Address for interface in Root Namespace
    :param subnet: Mininet's Subnet
    :return Node with Internet access
    """

    switch = network.get(switch)
    prefix_length = subnet.split('/')[1]

    info('*** Connecting to Internet with interface {}, switch {}, node IP {}, and subnet {}\n'.format(interface, switch, node_ip, subnet))

    # Create node in root namespace
    node = Node('root', isNamespace=False)
    fix_network_manager(node, 'root-{}'.format(interface))

    # Create link for switch and node
    link = network.addLink(node, switch)
    link.intf1.setIP(node_ip, prefixLen=prefix_length)

    # Start network with included node
    network.start()

    start_nat_router(node, interface)

    for host in network.hosts:
        # host.cmd('ip route flush root 0/0')
        host.cmd('route add -net {} dev {}'.format(subnet, host.defaultIntf()))
        host.cmd('route add default gw {}'.format(node_ip))

    return node


def TCCTopology():
    net = Mininet(topo=None,
                  build=False,
                  ipBase='10.0.0.0/8')

    info('*** Adding controller at {}\n'.format(controller_ip))
    controller = net.addController(name='c0',
                                   controller=RemoteController,
                                   ip=controller_ip,
                                   port=controller_port,
                                   protocol='tcp')

    info('*** Adding Switches\n')
    switch_1 = net.addSwitch('s1', cls=OVSKernelSwitch)
    switch_2 = net.addSwitch('s2', cls=OVSKernelSwitch)
    switch_3 = net.addSwitch('s3', cls=OVSKernelSwitch)

    info('*** Adding Hosts\n')
    diel = net.addHost('diel', cls=Host, ip='10.0.1.2', defaultRoute=None)
    alice = net.addHost('alice', cls=Host, ip='10.0.2.2', defaultRoute=None)
    bob = net.addHost('bob', cls=Host, ip='10.0.2.3', defaultRoute=None)

    info('*** Adding links\n')
    net.addLink(switch_1, switch_2)
    net.addLink(switch_1, switch_3)

    net.addLink(switch_2, diel)

    net.addLink(switch_3, alice)
    net.addLink(switch_3, bob)

    info('*** Starting controller\n')
    controller.start()

    info('*** Starting switches\n')
    net.get('s1').start([controller])
    net.get('s2').start([controller])
    net.get('s3').start([controller])

    info('*** Post configure switches and hosts\n')

    net.build()
    net.start()

    return net


if __name__ == '__main__':
    call(['mn', '-c'])
    setLogLevel( 'info')
    net = TCCTopology()
    # Configure and start NATted connectivity
    info('*** Starting network!\n')
    nat_node = connect_to_internet( net )
    info('*** NAT Rotuer added: {}\n'.format(nat_node))
    info("*** Hosts are running and should have internet connectivity")
    info("*** Type 'exit' or control-D to shut down network")
    CLI( net )
    # Shut down NAT
    stop_nat_router( nat_node )
    net.stop()
