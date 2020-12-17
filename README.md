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

The way the agent advertises the routes is by adding an IP to a predefined
(dummy) interface associated to a vrf. Then it relies on Zebra to do the BGP
advertisement, as Zebra detects the addition/deletion of the IP on the local
interface and create/deletes and advertises/withdraw the route.

### Pre Requisites:

The agent requires some configuration on the OpenStack nodes:
- FRR installed on the node, with zebra and bgpd daemons enabled. Also, with VRF support enabled: `--vrfwnetns` option at zebra_options on `/etc/frr/daemons`
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
  - It allows to discover other OpenStack compute nodes with Loopback IPs on
   `99.99.1.0/24` and `99.99.2.0/24`
  - Provider Network IP ranges to expose are in `172.24.4.0/24`
  - It usese BGP Unnumbered (though IPv6 link-local)

- Configuration of the loopback device IP:

        sudo ip addr add 99.99.1.1/32 dev lo

- And if connected to a leaf (in a spine-leaf setup), we should also have
configuration related to the connection of the server to the leaf(s) (ToRs),
e.g.:

        sudo ip addr add 100.65.1.2/30 dev eth1

- The ovs br-ex bridge needs to be configured with proxy_arp as well as with
an IP to properly handle the traffic:

        sudo ovs-vsctl add-br br-ex
        sudo ip l s dev br-ex up
        sudo ip a a 172.24.4.66/24 dev br-ex
        sudo sysctl -w net.ipv4.conf.all.rp_filter=0
        sudo sysctl -w net.ipv4.conf.br-ex.proxy_arp=1
        sudo sysctl -w net.ipv4.ip_forward=1
        sudo ip r a 172.24.4.1 via 99.99.1.1 #(loopback device IP)

### How to run it

As a python script on the compute nodes:

    $ sudo python3 bgp_agent.py
    Starting BGP Agent...
    Loaded chassis 1db1fa27-cd55-47ed-b91e-62d1f61cf3a6.
    BGP Agent Started...
    Configuring br-ex default rule
    Sync current routes...
    Add BGP route for logical port with ip 172.24.4.69
    Add BGP route for FIP with ip 172.24.4.169
    Add BGP route for CR-LRP Port 172.24.4.221
    ...

## Current limitations
- Only exposes IPv4 IPs.
- It does not exposes tenant networks VM IPs.

## Future enhancements
- Add support for IPv6.
- Allow to expose VM IPs on tenant networks (without FIPs).
- Allow to configure some parameters instead of make them constants
- Add different modes, in case only certain nodes are allowed to run the
agent, i.e., only certain nodes are connected to the BGP peers.
