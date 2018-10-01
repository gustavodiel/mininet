#!/usr/bin/python

"""
This script will create a Mininet topology as follows:
        C
        |  NAT
        | /
        S
       / \
      S   S
    /     / \
   D     A   B

On this VM, the interface with Internet connectivity is enp0s3.
Gustavo Diel, 2018
(Based on mininet's NAT example)
"""

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call

#################################
def startNAT( root, inetIntf='enp0s3', subnet='10.0.0.0/16' ):
    """Start NAT/forwarding between Mininet and external network
    root: node to access iptables from
    inetIntf: interface for internet access
    subnet: Mininet subnet (default 10.0.0.0/16)="""

    print("*** Configuring NAT Host\n")

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
    print( 'sysctl net.ipv4.ip_forward=1\n' )

def stopNAT( root ):
    """Stop NAT/forwarding between Mininet and external network"""

    print("*** Stopping NAT\n")

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
    if ( line ) not in config:
        print '*** Adding', line.strip(), 'to', cfile
        with open( cfile, 'a' ) as f:
            f.write( line )
    # Probably need to restart network-manager to be safe -
    # hopefully this won't disconnect you
    root.cmd( 'service network-manager restart' )

def connectToInternet( network, switch='s1', rootip='10.0.0.1', subnet='10.0.0.0/16'):
    """Connect the network to the internet
       switch: switch to connect to root namespace
       rootip: address for interface in root namespace
       subnet: Mininet subnet"""

    print("*** Creating NAT Host on switch %s on ip %s" % (switch, rootip))

    switch = network.get( switch )
    prefixLen = subnet.split( '/' )[ 1 ]
    routes = [ subnet ]  # host networks to route to

    # Create a node in root namespace
    root = Node( 'root', inNamespace=False )
    #root = net.addHost('root')
    # Prevent network-manager from interfering with our interface
    fixNetworkManager( root, 'root-enp0s3' )

    # Create link between root NS and switch
    link = network.addLink( root, switch )
    link.intf1.setIP( rootip, prefixLen )

    # Start network that now includes link to root namespace
    network.start()

    # Start NAT and establish forwarding
    startNAT( root )

    # Establish routes from end hosts
    for host in network.hosts:
        print("*** Setting up host %s" % host)

        #host.cmd( 'ip route flush root 0/0' )
        #print( 'ip route flush root 0/0' )

        host.cmd( 'route add -net', subnet, 'dev', host.defaultIntf() )
        print( 'route add -net %s dev %s'  %(subnet, host.defaultIntf()) )

        host.cmd( 'route add default gw', rootip )
        print( 'route add default gw %s' % rootip )

        print("\n")

    return root

def configureHost(host):
    """
        This function is used to configure each and every host (Except the NAS host)
    """

    print("*** Configuring Host %s" % host)

    # Enable SSH
    host.cmd("/usr/sbin/sshd -D &")

def myCustomTopo():
    """
        This function will create our topology.
        It returns the topology object
    """

    print("*** Generating Custom Topology")

    net = Mininet( topo=None,
                   build=False)
                   #ipBase='10.0.0.0/8')

    cIP = '192.168.56.1'
    print( '*** Adding controller. Ip: %s\n' % cIP )
    controller=net.addController(name='controller',
                      controller=RemoteController,
                      ip=cIP,
                      protocol='tcp',
                      port=6653)

    print( '*** Adding switches\n')
    s1 = net.addSwitch('s1', cls=OVSKernelSwitch)
    s2 = net.addSwitch('s2', cls=OVSKernelSwitch)
    s3 = net.addSwitch('s3', cls=OVSKernelSwitch)

    print( '*** Adding hosts\n')
    host_diel = net.addHost('diel', cls=Host, ip='10.0.1.2/24', defaultRoute=None)
    host_alice = net.addHost('alice', cls=Host, ip='10.0.2.2/24', defaultRoute=None)
    host_bob = net.addHost('bob', cls=Host, ip='10.0.2.3/24', defaultRoute=None)

    for host in net.hosts:
        configureHost(host)

    print( '*** Adding links\n')
    net.addLink(s1, s3)
    net.addLink(host_diel, s2)
    net.addLink(s2, s1)
    net.addLink(s3, host_alice)
    net.addLink(s3, host_bob)

    return net


if __name__ == '__main__':
    net = myCustomTopo()
    # Configure and start NATted connectivity
    rootnode = connectToInternet( net )
    #net.start()
    print "*** Hosts are running and should have internet connectivity"
    print "*** Type 'exit' or control-D to shut down network"
    rootnode.cmd('xterm &')
    CLI( net )
    # Shut down NAT
    stopNAT( rootnode )
net.stop()
