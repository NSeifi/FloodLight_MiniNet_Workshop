from mininet.topo import Topo

class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )
	
        # Add hosts and switches
        H1 = self.addHost( 'h1' )
        H2 = self.addHost( 'h2' )
        S1 = self.addSwitch( 's1' )
        S2 = self.addSwitch( 's2' )
        S3 = self.addSwitch( 's3' )
        S4 = self.addSwitch( 's4' )
        SwitchList = (S1,S2,S3,S4)

        # Add links
        for i in range( 0 , len(SwitchList)):
                for j in range( i+1 , len(SwitchList)):
                        self.addLink(SwitchList[i] , SwitchList[j])
        self.addLink(H1, S1)
        self.addLink(H2, S3)


topos = { 'mytopo': ( lambda: MyTopo() ) }

