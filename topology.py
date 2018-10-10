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
parser.add_argument('IP', metavar='ip', type=str, help="Floodlight's IP", default='127.0.0.1', const='127.0.0.1', nargs='?')

args = parser.parse_args()

# ##               ## #
# Controller Settings #
# ##               ## #

controller_ip = args.IP
controller_port = 6653

# ################### #


def start_nat_router(root, external_interface='enp0s3', subnet='10.0.0.0/16', local_interface=None):
    """
    Start NAT/Forwarding between Mininet and external network.
    :param root: The router node
    :param external_interface: Node's interface with external access
    :param subnet: Mininet's subnet
    """

    # Identify the interface connecting to mininet's network
    if not local_interface:
        local_interface = root.defaultIntf()

    info('*** Starting NAT on node {}, interface: {} to interface {} with subnet {}\n'.format(root, external_interface, local_interface, subnet))

    # Do the NAT
    root.cmd('iptables -I FORWARD -i {} -d {} -j DROP'.format(local_interface, subnet))
    root.cmd('iptables -A FORWARD -i {} -s {} -j ACCEPT'.format(local_interface, subnet))
    root.cmd('iptables -A FORWARD -o {} -d {} -j ACCEPT'.format(local_interface, subnet))
    root.cmd("iptables -t nat -A POSTROUTING -s {} '!' -d {} -j MASQUERADE".format(subnet, subnet))


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


def connect_to_internet(network, interface='enp0s3', node_ip='10.0.0.1', subnet='10.0.0.0/8'):
    """
    Configure NAT to connect to Internet.
    :param network: Mininet's network
    :param interface: Interface connecting to Internet
    :param node_ip: Address for interface in Root Namespace
    :param subnet: Mininet's Subnet
    :return Node with Internet access
    """
    prefix_length = subnet.split('/')[1]

    # Create node in root namespace
    node = Node('root', inNamespace=False)


    # remove current rules
    node.cmd('iptables -F')
    node.cmd('iptables -t nat -F')

    # Create entries for traffic
    node.cmd('iptables -P INPUT ACCEPT')
    node.cmd('iptables -P OUTPUT ACCEPT')
    node.cmd('iptables -P FORWARD DROP')

    # Enable IPv4 Forwarding
    node.cmd('sysctl net.ipv4.ip_forward=1')

    for sw in ['s1', 's2']:
        switch = network.get(sw)
        interface_to_add = 'root-eth0'

        if sw == 's2':
            node_ip = '10.0.0.2'
            interface_to_add = 'root-eth1'


        info('*** Connecting to Internet with interface {}, switch {}, node IP {}, and subnet {}\n'.format(interface, switch, node_ip, subnet))

        fix_network_manager(node, interface_to_add)

        # Create link for switch and node
        link = network.addLink(node, switch)
        link.intf1.setIP(node_ip, prefixLen=prefix_length)
        info(link.intf1)

    # Start network with included node
    network.start()

    start_nat_router(node, interface, local_interface='root-eth0')
    start_nat_router(node, interface, local_interface='root-eth1')

    node.cmd('route add -net 10.0.1.0/24 dev root-eth0')
    node.cmd('route add -net 10.0.2.0/24 dev root-eth1')

    for host in network.hosts:
        if host.name == 'diel':
            node_ip = '10.0.0.1'
        else:
            node_ip = '10.0.0.2'

        info('*** Configuring host {} to GW: {}\n'.format(host, node_ip))
        host.cmd('ip route flush root 0/0')
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

    info('*** Adding Hosts\n')
    diel = net.addHost('diel', cls=Host, ip='10.0.1.2/24', defaultRoute=None, mac='00:00:00:00:01:02')
    alice = net.addHost('alice', cls=Host, ip='10.0.2.2/24', defaultRoute=None, mac='00:00:00:00:02:02')
    bob = net.addHost('bob', cls=Host, ip='10.0.2.3/24', defaultRoute=None, mac='00:00:00:00:02:03')

    info('*** Adding links\n')

    net.addLink(switch_1, diel)

    net.addLink(switch_2, alice)
    net.addLink(switch_2, bob)

    info('*** Starting controller\n')
    controller.start()

    info('*** Starting switches\n')
    switch_1.start([controller])
    switch_2.start([controller])

    info('*** Post configure switches and hosts\n')

    net.build()

    return net


if __name__ == '__main__':
    call(['mn', '-c'])
    setLogLevel( 'info')
    net = TCCTopology()
    # Configure and start NATted connectivity
    info('*** Starting network!\n')
    nat_node = connect_to_internet( net )
    info('*** NAT Rotuer added: {}\n'.format(nat_node))
    info("*** Hosts are running and should have internet connectivity\n")
    info("*** Type 'exit' or control-D to shut down network\n")
    nat_node.cmd('xterm &')
    CLI( net )
    # Shut down NAT
    stop_nat_router( nat_node )
    net.stop()
