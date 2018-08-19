#!/usr/bin/python

from subprocess import call

from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.net import Mininet
from mininet.node import Host, Node
from mininet.node import OVSKernelSwitch
from mininet.node import RemoteController

# ##               ## #
# Controller Settings #
# ##               ## #

controller_ip = raw_input('Insert the IP addres or press ENTER for the default (192.168.56.1)\n') or '192.168.56.1'
controller_port = 6653

# ################


def start_nat_router(node, interface='eth0', subnet='10.0.0.0/8'):
    """
    Start NAT/Forwarding between Mininet and external network.
    :param node: The router node
    :param interface: Node's interface with external access
    :param subnet: Mininet's subnet
    """

    info('*** [NAT] Starting NAT on node {}, interface: {} with subnet {}\n'.format(node, interface, subnet))

    # Identify the interface connecting to mininet's network
    local_interface = node.defaultIntf()

    # remove current rules
    node.cmd('iptables -F')
    node.cmd('iptables -t nat -F')

    # Create entries for traffic
    node.cmd('iptables -P INPUT ACCEPT')
    node.cmd('iptables -P OUTPUT ACCEPT')
    node.cmd('iptables -P FORWARD DROP')

    # Do the NAT
    node.cmd('iptables -I FORWARD -i {} -d {} -j DROP'.format(local_interface, subnet))
    node.cmd('iptables -A FORWARD -i {} -d {} -j ACCEPT'.format(local_interface, subnet))
    node.cmd('iptables -A FORWARD -i {} -s {} -j ACCEPT'.format(interface, subnet))
    node.cmd('iptables -t nat -A POSTROUTING -o {} -j MASQUERADE'.format(interface))

    # Enable IPv4 Forwarding
    node.cmd('sysctl net.ipv4.ip_forward=1')


def stop_nat_router(node):
    """
    Stop NAT/Forwarding
    :param node: The router node
    """
    node.cmd('iptables -F')
    node.cmd('iptables -t nat -F')

    # Disable forwarding
    node.cmd('sysctl net.ipv4.ip_forward=0')


def fix_network_manager(node, interface):
    """
    Prevents NetworkManager from messing with the interface, providing the manual config
    :param node: NAT node
    :param interface: Interface's name
    """

    interface_file = '/etc/network/interfaces'
    line = '\niface {} inet manual\n'.format(interface)
    config = open(interface_file).read()
    if line not in config:
        print('Adding {} to {}\n'.format(line.strip(), interface_file))
        with open(interface_file, 'a') as f:
            f.write(line)

    node.cmd('service network-manager restart')


def connect_to_internet(network, interface='eth0', switch='s1', node_ip='10.0.0.0.254', subnet='10.0.0.0/8'):
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
    routes = [subnet]

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
        host.cmd('ip route flush root 0/0')
        host.cmd('route add -net {} dev {}'.format(subnet, host.defaultIntf()))
        host.cmd('route add default gw {}'.format(node_ip))

    return node


def TCCTopology():
    net = Mininet(topo=None,
                  build=False,
                  ipBase='10.0.0.0/8')

    info('*** Adding controller at {}\n'.format(controller_ip))
    controller = net.addController(name='Floodlight Controller',
                                   controller=RemoteController,
                                   ip=controller_ip,
                                   port=controller_port,
                                   protocol='tcp')

    info('*** Adding Switches\n')
    switch_1 = net.addSwitch('s1', cls=OVSKernelSwitch)
    switch_2 = net.addSwitch('s2', cls=OVSKernelSwitch)
    switch_3 = net.addSwitch('s3', cls=OVSKernelSwitch)

    info('*** Adding Hosts\n')
    diel = net.addHost('diel', cls=Host, ip='10.0.0.2', defaultRoute=None)
    alice = net.addHost('alice', cls=Host, ip='10.0.1.2', defaultRoute=None)
    bob = net.addHost('bob', cls=Host, ip='10.0.1.3', defaultRoute=None)

    info('*** Adding links\n')
    net.addLink(switch_1, switch_2)
    net.addLink(switch_1, switch_3)

    net.addLink(switch_2, diel)

    net.addLink(switch_3, alice)
    net.addLink(switch_3, bob)

    info('*** Starting network!\n')
    node_nat = connect_to_internet(net, interface='enp0s8')

    info('*** NAT Rotuer added: {}\n'.format(node_nat))

    info('*** Starting controller\n')
    controller.start()

    info('*** Starting switches\n')
    net.get('s1').start([controller])
    net.get('s2').start([controller])
    net.get('s3').start([controller])

    info('*** Post configure switches and hosts')

    CLI(net)

    net.stop()


if __name__ == '__main__':
    call(['mn', '-c'])
    setLogLevel('info')
    TCCTopology()
