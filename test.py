#!/usr/bin/python

"""
Example to create a Mininet topology and connect it to the internet via NAT
through eth0 on the host.
Glen Gibb, February 2011
(slight modifications by BL, 5/13)
"""

from argparse import ArgumentParser

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

#################################
def startNAT( root, inetIntf='eth1', subnet='10.0/16' ):
    """Start NAT/forwarding between Mininet and external network
    root: node to access iptables from
    inetIntf: interface for internet access
    subnet: Mininet subnet (default 10.0/8)="""

    # Identify the interface connecting to the mininet network
    localIntf =  root.defaultIntf()

    # Flush any currently active rules
    root.cmd( 'iptables -F' )
    root.cmd( 'iptables -t nat -F' )

    # Create default entries for unmatched traffic
    root.cmd( 'iptables -P INPUT ACCEPT' )
    root.cmd( 'iptables -P OUTPUT ACCEPT' )
    root.cmd( 'iptables -P FORWARD DROP' )

    # Configure NAT
    root.cmd( 'iptables -I FORWARD -i', localIntf, '-d', subnet, '-j DROP' )
    root.cmd( 'iptables -A FORWARD -i', localIntf, '-s', subnet, '-j ACCEPT' )
    root.cmd( 'iptables -A FORWARD -i', inetIntf, '-d', subnet, '-j ACCEPT' )
    root.cmd( 'iptables -t nat -A POSTROUTING -o ', inetIntf, '-j MASQUERADE' )

    # Instruct the kernel to perform forwarding
    root.cmd( 'sysctl net.ipv4.ip_forward=1' )

def stopNAT( root ):
    """Stop NAT/forwarding between Mininet and external network"""
    # Flush any currently active rules
    root.cmd( 'iptables -F' )
    root.cmd( 'iptables -t nat -F' )

    # Instruct the kernel to stop forwarding
    root.cmd( 'sysctl net.ipv4.ip_forward=0' )

def fixNetworkManager( root, intf ):
    """Prevent network-manager from messing with our interface,
       by specifying manual configuration in /etc/network/interfaces
       root: a node in the root namespace (for running commands)
       intf: interface name"""
    cfile = '/etc/network/interfaces'
    line = '\niface %s inet manual\n' % intf
    config = open( cfile ).read()
    if line not in config:
        print('*** Adding', line.strip(), 'to', cfile)
        with open( cfile, 'a' ) as f:
            f.write( line )
        # Probably need to restart network-manager to be safe -
        # hopefully this won't disconnect you
        root.cmd( 'service network-manager restart' )

def connectToInternet( network, switch='s1', rootip='10.254', subnet='10.0/16'):
    """Connect the network to the internet
       switch: switch to connect to root namespace
       rootip: address for interface in root namespace
       subnet: Mininet subnet"""
    switch = network.get( switch )
    prefixLen = subnet.split( '/' )[ 1 ]

    # Create a node in root namespace
    root = Node( 'root', inNamespace=False )

    # Prevent network-manager from interfering with our interface
    fixNetworkManager( root, 'root-eth0' )

    # Create link between root NS and switch
    link = network.addLink( root, switch )
    link.intf1.setIP( rootip, prefixLen )

    # Start network that now includes link to root namespace
    network.start()

    # Start NAT and establish forwarding
    startNAT( root )

    # Establish routes from end hosts
    for host in network.hosts:
        host.cmd( 'ip route flush root 0/0' )
        host.cmd( 'route add -net', subnet, 'dev', host.defaultIntf() )
        host.cmd( 'route add default gw', rootip )

    return root

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
    diel = net.addHost('diel', cls=Host, ip='10.0.0.2', defaultRoute=None)
    alice = net.addHost('alice', cls=Host, ip='10.0.1.2', defaultRoute=None)
    bob = net.addHost('bob', cls=Host, ip='10.0.1.3', defaultRoute=None)

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
    setLogLevel( 'info')
    net = TCCTopology()
    # Configure and start NATted connectivity
    info('*** Starting network!\n')
    rootnode = connectToInternet( net )
    info('*** NAT Rotuer added: {}\n'.format(rootnode))
    print("*** Hosts are running and should have internet connectivity")
    print("*** Type 'exit' or control-D to shut down network")
    rootnode.cmd("xterm &")
    CLI( net )
    # Shut down NAT
    stopNAT( rootnode )
    net.stop()
