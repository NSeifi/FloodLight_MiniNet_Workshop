"""Custom topology: FatTree

Here I am going to create a Fattree topology with switches that are assumed to
have k ports. So each would be connected to k/2 hosts and k/2 other switches.
The number of core switches is (k/2)^2.
The topology would receive k as a parameter when used by command mn.

k-port switches
Total number of switches = 5 * (k ^ 2) / 4
Number of Pods = k
Number of switches per each Pod = k
Number of switches per each tier of a Pod = k / 2
Number of all the switches in edge and aggregation tier = k * k / 2
Number of hosts per each edge switch = k / 2
Total number of core switches = (k / 2) ^ 2
"""

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSKernelSwitch , UserSwitch
from mininet.cli import CLI
from mininet.node import Node
from mininet.log import setLogLevel, info
from mininet.link import TCLink
from time import sleep

def startNAT( root, inetIntf='eth0', subnet='10.0/8' ):
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
    if ( line ) not in config:
        print '*** Adding', line.strip(), 'to', cfile
        with open( cfile, 'a' ) as f:
            f.write( line )
    # Probably need to restart network-manager to be safe -
    # hopefully this won't disconnect you
    root.cmd( 'service network-manager restart' )

def connectToInternet( network, switch='s31', rootip='10.254', subnet='10.0/8'):
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

def fattree():

    "FatTree Topology with k-port switches."

    net = Mininet( controller=RemoteController, switch=OVSKernelSwitch, autoSetMacs=True, link=TCLink )

    edgeSwitches = []
    aggregateSwitches = []
    coreSwitches = []
    hosts = []
    k = 4
    VMs = 2
    bandwidth = 2
    switchCounter = 1
    contrllerIPAddress = '127.0.0.1'

    info( '*** Adding controller\n' )
    net.addController( 'c0', controller=RemoteController, ip=contrllerIPAddress, port=6653 )
    info( '*** Remote Controller with IP Address ' + str(contrllerIPAddress) + ' added.\n' )

    info( '\n\n*** Adding edge switches and hosts\n' )
    # Add edge switches
    for i in range(1, (k * k / 2) + 1):
	eS = net.addSwitch("s1" + str(switchCounter))
	edgeSwitches.append(eS)
	info( str(eS) + ' ' )
	switchCounter = switchCounter + 1
        # Add hosts per each edge switch
        for j in range(1, (k / 2) * VMs + 1):
	    h = net.addHost("h" + str((i - 1) * (k / 2) * VMs + j))
	    hosts.append(h)
	    info( str(h) + ' ' )

    info( '\n\n*** Adding aggregate and core switches\n' )
    # Add aggregate switches
    switchCounter = 1
    for i in range(1, (k * k / 2) + 1):
	aS = net.addSwitch("s2" + str(switchCounter))
        aggregateSwitches.append(aS)
	info( str(aS) + ' ' )
	switchCounter = switchCounter + 1
    # Add core switches
    switchCounter = 1
    for i in range(1, pow(k / 2, 2) + 1):
	cS = net.addSwitch("s3" + str(switchCounter))
        coreSwitches.append(cS)
	info( str(cS) + ' ' )
	switchCounter = switchCounter + 1

    info( '\n\n*** Creating links\n' )
    # Add links between hosts and edge switches
    # The first for loop, loops for the number of edge switches
    hostCounter = 0
    for i in range(0, k * k / 2):
	for j in range(0, k * VMs / 2):
	    connectingHost = hosts[hostCounter + j]
	    connectingSwitch = edgeSwitches[i]
       	    net.addLink( connectingHost, connectingSwitch, bw=bandwidth )
            info( '(' + str(connectingHost) + ',' + str(connectingSwitch) + ') ')
	hostCounter = hostCounter + (k * VMs / 2)
    # Add links between edge switches and aggregate switches
    # The first for loop, loops for the number of pods
    info( '\n\n' )
    for i in range(0, k):
	# The second loop, loops for the number of edge switches per pod
	for j in range(0, k / 2):
            # The third loop, loops for the number of aggregate switches per pod and connects each edge switch to all the aggregate switches
	    for l in range(0, k / 2):
		connectingSwitch1 = edgeSwitches[(i * k / 2) + j]
		connectingSwitch2 = aggregateSwitches[(i * k / 2) + l]
		net.addLink( connectingSwitch1, connectingSwitch2, bw=bandwidth )
                info( '(' + str(connectingSwitch1) + ',' + str(connectingSwitch2) + ') ')
    # Add links between aggregate switches and core switches        
    numOfCSs = pow(k / 2, 2)
    # The first for loop, loops for the number of pods
    info( '\n\n' )
    for i in range(0, k):
	localCSAddition = 0
	# The second loop, loops for the number of aggregation switches per pod
	for j in range(0, k / 2):
	    # The third loop, loops for the number of links connecting each aggregation switch to core switches.
	    for l in range(0, k / 2):
		connectingSwitch1 = aggregateSwitches[(i * k / 2) + j]
                connectingSwitch2 = coreSwitches[localCSAddition]
		net.addLink( connectingSwitch1, connectingSwitch2, bw=bandwidth )
                info( '(' + str(connectingSwitch1) + ',' + str(connectingSwitch2) + ') ')
		localCSAddition = localCSAddition + 1

    info( '\n\n' )
    info( '*** Starting network\n')
#    net.start()

#   Configure and start NATted connectivity
    rootnode = connectToInternet( net )

    info( '*** Running CLI\n' )
    CLI( net )

#    info( '*** Ping all nodes' )
#    net.pingAll()

    info( '*** Stopping network\n' )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    fattree()

