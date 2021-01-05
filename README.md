# OVN BGP Agent

BGP Agent to expose VMs through BGP on OVN environments.

This agent exposes through BGP either the IPs of VMs on provider networks
or the FIPs associated to VMs on tenant networks.

## How it works

This agent is meant to be executed in all the OpenStack compute nodes
(assuming they are connected to the BGP peers) and ensures that each VM
connected to the local chassis (i.e., local hypervisor) gets its IP advertised
through BGP if:
- VM is created on a provider network
- VM has a FIP associated to it (note the IP exposed is the FIP, not the VM IP
on the tenant network)
- VM is created on tenant network and `expose_tenant_networks = True`

The way the agent advertises the routes is by adding an IP to a predefined
(dummy) interface associated to a vrf. Then it relies on Zebra to do the BGP
advertisement, as Zebra detects the addition/deletion of the IP on the local
interface and create/deletes and advertises/withdraw the route.

On top of that, to redirect the traffic once on the node where the VM is to
the ovn network, the agent creates a rule to redirect the traffic to the VM
IP through the ovs bridge (e.g., br-ex):

        $ ip rule
        0:      from all lookup local
        1000:   from all lookup [l3mdev-table]
        *32000:  from all to 172.24.4.92 lookup br-ex*
        *32000:  from all to 172.24.4.220 lookup br-ex*
        *32000:  from all to 10.0.0.64/26 lookup br-ex*
        32766:  from all lookup main
        32767:  from all lookup default

        $ ip route show table br-ex
        *default dev br-ex proto static*

And, in order to properly handle traffic from VMs without FIPs to either
VMs on provider networks or VM with FIPs, the agent also needs to ensure
traffic is redirected to the ovs bridge on the node that has the router
gateway port for that provider network (i.e., cr-lrp port). This is done
by the agent by ensuring proper ARP handling by adding the next:

        $ sudo ip nei replace CR_LRP_PORT_IP lladdr CR_LRP_PORT_MAC dev br-ex nud permanent

NOTE:

- The use of ip rules can be deactivated (setting `use_rules = False`), with
extra requirements from the configuration side, see subsection about
configuration without ip rules.
- Exposing VMs on tenant network is only supported if ip rules is used, i.e.,
if `use_rules = True`.
- The VMs on tenant networks are exposed through the ovn node where the 
gateway port is located (i.e., the cr-lrp port). That means the traffic
will go to it first, and then through the geneve tunnel to the node where
the VM is.
- Exposing VMs on tenant networks can be deacticated (setting
`expose_tenant_network = False`).



### Pre Requisites:

The agent requires some configuration on the OpenStack nodes:
- FRR installed on the node, with zebra and bgpd daemons enabled.
Also, with VRF support enabled: `--vrfwnetns` option at zebra_options on
`/etc/frr/daemons`

- FRR configured to expose `/32` IPs from the provider network IP range, e.g:

        cat > /etc/frr/frr.conf <<EOF
        frr version 7.0
        frr defaults traditional
        hostname worker1
        no ipv6 forwarding
        !
        router bgp 64999
        bgp router-id 99.99.1.1
        bgp log-neighbor-changes
        neighbor eth1 interface remote-as 64999
        !
        address-family ipv4 unicast
        redistribute connected
        neighbor eth1 route-map out_32_prefixes out
        neighbor eth1 allowas-in origin
        neighbor eth1 prefix-list in_32_prefixes in
        exit-address-family
        !
        ip prefix-list out_32_prefixes permit 172.24.4.0/24 ge 32
        ip prefix-list out_32_prefixes permit 99.99.1.0/24 ge 32
        ip prefix-list out_32_prefixes permit 99.99.2.0/24 ge 32
        !
        ip protocol bgp route-map out_32_prefixes
        !
        route-map out_32_prefixes permit 10
        match ip address prefix-list out_32_prefixes
        set src 99.99.1.1
        !
        line vty
        !
        EOF

  Note this assumes that:
  - The AS is 64999
  - The peers are on the same AS, meaning iBGP
  - Loopback IP for this node is `99.99.1.1`
  - It allows to advertise to other OpenStack compute nodes the Loopback IPs on
   `99.99.1.0/24` and `99.99.2.0/24`
  - Provider Network IP ranges to expose are in `172.24.4.0/24`
  - It usese BGP Unnumbered (though IPv6 link-local)

- Configuration of the loopback device IP:

        sudo ip addr add 99.99.1.1/32 dev lo

- And if connected to a leaf (in a spine-leaf setup), we should also have
configuration related to the connection of the server to the leaf(s) (ToRs),
e.g.:

        sudo ip addr add 100.65.1.2/30 dev eth1

- And add a default route through it by using the Loopback IP:

        sudo ip r a 0.0.0.0/0 src 99.99.1.1 nexthop via 100.65.1.1 dev eth1

- The ovs br-ex bridge needs to be configured with proxy_arp as well as with
an IP to properly handle the traffic:

        sudo ovs-vsctl add-br br-ex
        sudo ip l s dev br-ex up
        sudo ip a a 1.1.1.1/32 dev br-ex
        sudo sysctl -w net.ipv4.conf.all.rp_filter=0
        sudo sysctl -w net.ipv4.conf.br-ex.proxy_arp=1
        sudo sysctl -w net.ipv4.ip_forward=1
        sudo ip r a 172.24.4.1 via 99.99.1.1 #(loopback device IP)

- The routing table for each bridge mapping needs to be created with the
bridge name associated to it, for instance, as root do:

        # echo 200 br-ex >> /etc/iproute2/rt_tables


- All this should lead to a routing table like this on the compute nodes:

        $ ip ro
        default src 99.99.1.1
                nexthop via 100.65.1.1 dev eth1 weight 1
        100.65.1.0/30 dev eth1 proto kernel scope link src 100.65.1.2
        172.24.4.1 via 99.99.1.1 dev lo

        $ ip ro sh table br-ex
        default dev br-ex proto static

        $ ip rule ls
        0:      from all lookup local
        1000:   from all lookup [l3mdev-table]
        *32000:  from all to 172.24.4.92 lookup br-ex*
        *32000:  from all to 172.24.4.220 lookup br-ex*
        *32000:  from all to 10.0.0.64/26 lookup br-ex*
        32766:  from all lookup main
        32767:  from all lookup default

### How to run it

As a python script on the compute nodes:

    $ python setup.py install
    $ sudo bgp-agent
    Starting BGP Agent...
    Loaded chassis 51c8480f-c573-4c1c-b96e-582f9ca21e70.
    BGP Agent Started...
    Ensuring VRF configuration for advertising routes
    Configuring br-ex default rule and routing tables for each provider network
    Found routing table for br-ex with: ['201', 'br-ex']
    Sync current routes.
    Add BGP route for logical port with ip 172.24.4.226
    Add BGP route for FIP with ip 172.24.4.199
    Add BGP route for CR-LRP Port 172.24.4.221
    ....


### Configuration without IP Rules

If the agent wants to be used without IP Rules, and therefore with the need of
having FRR injecting BGP routes into the local tables, the next extra steps
need to be done:
- Set `use_rules = False` on the `main` method before running the bgp agent.

- Configure FRR to also obtain routes by removing from the `frr.conf` config
file the next:

        !neighbor eth1 prefix-list in_32_prefixes in

- Ensure the br-ex ovs bridge has an IP from the provider network. For
instance, assuming the provider network CIDR is 172.24.4.0/24, then set
something like:

        sudo ip a a 172.24.4.66/24 dev br-ex

## Current limitations
- Only exposes IPv4 IPs.
- Tenant networks VM IPs are exposed only if `use_rules` is enabled.


## Future enhancements
- Add support for IPv6.
- Allow to configure some parameters instead of make them constants.
- Add different modes, in case only certain nodes are allowed to run the
agent, i.e., only certain nodes are connected to the BGP peers.
