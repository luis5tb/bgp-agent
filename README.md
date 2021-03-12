# OVN BGP Agent

BGP Agent targets to expose VMs/Containers through BGP on OVN environments.

It provides a multi driver implementation that allows you to configure it
for specific infrastructure running on OVN, for instance for OpenStack or
Kubernetes/OpenShift, and define what events it should react to.
For instance, in OpenStack case:
- To VMs being created on provider networks
- To VMs with attached floating ips
- (optionally) Any VM on tenant networks assuming no IP overlap between tenants

And for Kubernetes/OpenShift it could be:
- Services of LoadBalancer type being created

A common driver API is defined exposing the next methods:
- expose_IP and withdraw_IP: used to expose/withdraw IPs for local ovn ports,
  such as local VMs or Pods.
- expose_remote_IP and withdraw_remote_IP: use to expose/withdraw IPs through
  the local node when the VM/Pod are running on a different node. For example
  for VMs on tenant networks where the traffic needs to be injected through
  the OVN router gateway port.
- expose_subnet and withdraw_subnet: used to expose/withdraw subnets through
  the local node.

Note only the code (i.e., driver and specific watcher) for OpenStack is there
at the moment. If used, this agent exposes through BGP the IPs of VMs on
provider networks and the FIPs associated to VMs on tenant networks, as well
as the VM IPs on the provider networks (if the specific watcher event is
configured).

## How it works: OpenStack case

This agent is meant to be executed in all the OpenStack compute nodes
(assuming they are connected to the BGP peers) and ensures that each VM
connected to the local chassis (i.e., local hypervisor) gets its IP advertised
through BGP if:
- VM is created on a provider network
- VM has a FIP associated to it (note the IP exposed is the FIP, not the VM IP
on the tenant network)
- VM is created on tenant network and `expose_tenant_networks` is set to `True`
on the config file, as well as the required watcher_events are enabled: 
`SubnetRouterAttachedEvent`, `SubnetRouterDetachedEvent`,
`TenantPortCreatedEvent`, `TenantPortDeletedEvent`.

The way the agent advertises the routes is by adding an IP to a predefined
(dummy) interface associated to a vrf so that default routing table is not
affected. Then it relies on Zebra to do the BGP advertisement, as Zebra
detects the addition/deletion of the IP on the local interface and
create/deletes and advertises/withdraw the route.

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
        *172.24.4.220 dev br-ex scope link*
        *10.0.0.64/26 via 172.24.4.220 dev br-ex*
        

And, in order to properly handle traffic from VMs without FIPs to either
VMs on provider networks or VM with FIPs, the agent also needs to ensure
traffic is redirected to the ovs bridge on the node that has the router
gateway port for that provider network (i.e., cr-lrp port). This is done
by the agent by ensuring proper ARP handling by adding the next:

        $ sudo ip nei replace CR_LRP_PORT_IP lladdr CR_LRP_PORT_MAC dev br-ex nud permanent

NOTE:
- The VMs on tenant networks are exposed through the ovn node where the
gateway port is located (i.e., the cr-lrp port). That means the traffic
will go to it first, and then through the geneve tunnel to the node where
the VM is.
- Exposing VMs on tenant networks can be deacticated by setting
`expose_tenant_networks` to `False` and removing the related watcher_events:
`SubnetRouterAttachedEvent`, `SubnetRouterDetachedEvent`,
`TenantPortCreatedEvent`, `TenantPortDeletedEvent`.


### Watcher Events:

The OVN-BGP Agent watches the OVN Southbound Database, and the above mentioned actions are triggered based on the events detected. The agent is reacting to the next events, all of them by watching the Port_Binding OVN table:

- `PortBindingChassisCreatedEvent` and `PortBindingChassisDeletedEvent`:
Detects when a port of type “” or “chassisredirect” gets attached to an OVN
chassis. This is the case for VM ports on the provider networks, VM ports on
tenant networks which have a FIP associated, and neutron gateway router ports
(CR-LRPs). In this case the ip rules are created for the specific IP of the
port as well as (BGP) exposed through the ovn dummy interface. For the CR-LRP
case, extra rules for its associated subnets are created, as well as the extra
routes for the ovs provider bridges routing table (e.g., br-ex). These events
call the driver_api `expose_IP` and `withdraw_IP`.
- `FIPSetEvent` and `FIPUnsetEvent`: Detects when a patch port gets its
`nat_addresses` field updated (e.g., action related to FIPs NATing).
If that so, and the associated VM port is on the local chassis the event is
processed by the agent and the required ip rule gets created and also the IP
is (BGP) exposed through the ovn dummy interface.  These events call the
driver_api `expose_IP` and `withdraw_IP`.
- `SubnetRouterAttachedEvent` and `SubnetRouterDetachedEvent`: Detects when
a “LRP” patch port gets created or deleted. This means a subnet is attached
to a router. If the chassis is the one having the CR-LRP port for that router
where the port is getting created, then the event is processed by the agent
and the ip rules for exposing the network are created as well as the related
routes in the ovs provider bridge routing table (e.g., br-ex). These events
call the driver_api `expose_subnet` and `withdraw_subnet`.
- `TenantPortCreatedEvent` and `TenantPortDeletedEvent`: Detects when a port
of type “” gets updated or deleted. If that port is not on a provider network
and the chassis where the event is detected has the LRP for the network where
that port is located (meaning is the node with the CR-LRP for the router where
the port’s network is connected to), then the event is processed and the port
IP is (BGP) exposed. As in this case the IPs are exposed through the node with
the CR-LRP port, these events call the driver_api `expose_remote_IP` and
`withdraw_remote_IP`.

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
        neighbor eth1 allowas-in origin
        neighbor eth1 prefix-list only-host-prefixes out
        exit-address-family
        !
        ip prefix-list only-default permit 0.0.0.0/0
        ip prefix-list only-host-prefixes permit 0.0.0.0/0 ge 32
        !
        ip protocol bgp route-map rm-only-default
        !
        route-map rm-only-default permit 10
        match ip address prefix-list only-default
        set src 99.99.1.1
        !
        line vty
        !
        EOF


  Note this assumes that:
  - The AS is 64999
  - The peers are on the same AS, meaning iBGP
  - Loopback IP for this node is `99.99.1.1`
  - Only exposes /32 IPs
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
        sudo sysctl -w net.ipv6.conf.br-ex.proxy_ndp=1
        sudo sysctl -w net.ipv6.conf.all.forwarding=1
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
        172.24.4.220 dev br-ex scope link
        10.0.0.64/26 via 172.24.4.220 dev br-ex

        $ ip rule ls
        0:      from all lookup local
        1000:   from all lookup [l3mdev-table]
        32000:  from all to 172.24.4.92 lookup br-ex
        32000:  from all to 172.24.4.220 lookup br-ex
        32000:  from all to 10.0.0.64/26 lookup br-ex
        32766:  from all lookup main
        32767:  from all lookup default

### How to run it

As a python script on the compute nodes:

    $ python setup.py install
    $ cat bgp-agent.conf
    [DEFAULT]
    debug=True
    reconcile_interval=120
    expose_tenant_networks=True
    watcher_handler=osp_watcher
    watcher_events=PortBindingChassisCreatedEvent,PortBindingChassisDeletedEvent,FIPSetEvent,FIPUnsetEvent,SubnetRouterAttachedEvent,SubnetRouterDetachedEvent,TenantPortCreatedEvent,TenantPortDeletedEvent,ChassisCreateEvent
    watcher_tables=Port_Binding,Datapath_Binding,SB_Global,Chassis
    driver=osp_ovn_driver

    $ sudo bgp-agent --config-dir bgp-agent.conf
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


Note the configuration file can be changed based on needs, like enabling/disabling logging.