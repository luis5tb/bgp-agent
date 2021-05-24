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

Note only the code (i.e., drivers and specific watchers) for OpenStack is there
at the moment. There are two different drivers for OpenStack:
- osp_ovn_bgp_driver: this driver exposes through BGP the IPs of VMs on provider
  networks and the FIPs associated to VMs on tenant networks, as well as the VM
  IPs on the tenant networks if the `expose_tenant_network` config option is set
  to `True`. The code is on the driver file `ovn_bgp_driver.py`, and the watcher
  that it uses is `bgp_watcher.py`.
- osp_ovn_evpn_driver: this driver exposes through EVPN the IPs of the VMs on the
  tenant networks, based on the provider information related to the `RT` and `VNI`
  to use for the EVPN. The code is on the driver file `ovn_evpn_driver.py`, and
  the watcher that it uses is `evpn_watcher.py`.


## How it works: OpenStack BGP case

This agent is meant to be executed in all the OpenStack compute nodes
(assuming they are connected to the BGP peers) and ensures that each VM
connected to the local chassis (i.e., local hypervisor) gets its IP advertised
through BGP if:
- VM is created on a provider network
- VM has a FIP associated to it (note the IP exposed is the FIP, not the VM IP
on the tenant network)
- VM is created on tenant network and `expose_tenant_networks` is set to `True`
on the config file.

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
`expose_tenant_networks` to `False`.


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
    driver=osp_ovn_bgp_driver

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



## How it works: OpenStack EVPN case

This agent is meant to be executed in all the OpenStack compute nodes
(assuming they are connected to the BGP peers) and ensures that each VM
connected to the local chassis (i.e., local hypervisor) gets its IP advertised
through the proper EVPN if:
- VM is on a network that is tagged to be exposed through EVPN (i.e., with the
  proper RT and VNI information) and the router the network is connected too
  also has that tag.


The way the agent advertises the VMs is by creating a VRF associated to the 
Neutron Router Gateway Port (i.e., the CR-LRP OVN port on the SB DB), based on
the VNI information it has annotated. More specifically, it:
- Creates a VRF device, with routing table matching the VNI number/id
- Creates a Bridge device, associated to the VRF device
- Creates a VXLAN device, associated to the Bridge device, with the local IP as
  the Loopback IP, and the vxlan id matching the VNI number/id
- Creates a dummy device, connected to the VRF, that will be use to expose the
  IPs through BGP (EVPN)

Once that is done, it needs to connect that to the OVN overlay by:
- Adding the VRF device to the provider OVS bridge (e.g., br-ex)
- Adding extra ovs flows to the provider OVS bridge, so that the traffic out
  from OVN is differentiated depending on the router gateway port and network
  CIDR it comes from. This allows to either send the traffic through the VRF
  device or through the standard OVN path (kernel).

        cookie=0x3e6, duration=222.137s, table=0, n_packets=0, n_bytes=0, priority=1000,ip,in_port="patch-provnet-c",dl_src=fa:16:3e:74:e6:3b,nw_src=20.0.0.0/24 actions=mod_dl_dst:f2:ff:65:5b:82:4f,output:"vrf-1001"
        cookie=0x0, duration=452321.235s, table=0, n_packets=2637, n_bytes=238529, priority=0 actions=NORMAL


Then, the way the agent advertises the routes is by adding an IP to the dummy
device created that was associated to a vrf. Then it relies on Zebra to do the
BGP advertisement, as Zebra detects the addition/deletion of the IP on the local
interface and create/deletes and advertises/withdraw the route. With this, to
expose a VM IP belonging to a tenant network, it needs to:
- Add the VM IP into the dummy device
- Ensure the local route added for that IP pointing to the dummy device is deleted
  so that traffic can be redirected to the OVS provider bridge
- Add ip route to redirect the traffic towards that subnet CIDR to OVS provider
  bridge, through the CR-LRP port IP, on the VRF routing table (e.g., 1001):

        $ ip route show vrf vrf-1001
        unreachable default metric 4278198272 
        * 20.0.0.0/24 via 172.24.100.225 dev br-ex* 
        * 172.24.100.225 dev br-ex scope link*


NOTE:
- The VMs on tenant networks are exposed through the ovn node where the
gateway port is located (i.e., the cr-lrp port). That means the traffic
will go to it first, and then through the geneve tunnel to the node where
the VM is.


### Watcher Events:

The OVN-BGP Agent watches the OVN Southbound Database, and the above mentioned
actions are triggered based on the events detected. The agent is reacting to
the next events for the EVPN driver, all of them by watching the Port_Binding
OVN table:

- `PortBindingChassisCreatedEvent` and `PortBindingChassisDeletedEvent`:
Detects when a port of type “chassisredirect” gets attached to an OVN
chassis. This is the case for the neutron gateway router ports (CR-LRPs).
In this case the ip is added to the dummy device associated to the VRF
if that port has VNI/RT information tagged. Also the ip route is added
to the VRF routing table pointing to the OVS provider bridge if the destination
IP is the CR-LRP one. If there are networks attached to the router, and they are
also exposed, then extra routes and ovs-flows (as explained above) are created
too. These events call the driver_api `expose_IP` and `withdraw_IP`.
- `SubnetRouterAttachedEvent` and `SubnetRouterDetachedEvent`: Detects when
a patch port (whose peer is the “LRP” patch port) gets created or deleted.
This means a subnet is attached to a router. If the chassis is the one having
the CR-LRP port for that router where the port is getting created, as the
port has VNI/RF information tagged, then the event is processed by the agent
and the ip routes related to the subnet CIDR are added on the respective VRF
routing table. In addition extra ovs flows are added to the OVN provider bridge
to ensure traffic differentiation between different subnets. These events
call the driver_api `expose_subnet` and `withdraw_subnet`.
- `TenantPortCreatedEvent` and `TenantPortDeletedEvent`: Detects when a port
of type “” gets updated or deleted. If the chassis where the event is detected
has the LRP for the network where that port is located (meaning is the node with the CR-LRP for the router where the port’s network is connected to), then the event is processed and the port IP is added to the dummy device associated to the respective
VRF. These events call the driver_api `expose_remote_IP` and
`withdraw_remote_IP`.

### Pre Requisites:

The agent requires some configuration on the OpenStack nodes:
- FRR installed on the node, with zebra and bgpd daemons enabled.
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

- Also, with `l2vpn evpn` enabled. As well as with the next option
  so that the default (ECMP) route can be used to resolve VRF routes,
  allowing its addition to the kernel routing: `ip nht resolve-via-default`

        ip nht resolve-via-default
    
        router bgp 64999
        address-family l2vpn evpn
        neighbor uplink activate
        advertise-all-vni
        advertise ipv4 unicast
        neighbor uplink allowas-in origin
        exit-address-family    


- And, until this is automated by the daemon, it is also needed to configure
  the required VNI/VRFs. For example, if we want to allow VRF with VNI 1001 we
  need: 

      vrf red
      vni 1001
      exit-vrf

      router bgp 64999 vrf red
      address-family ipv4 unicast
      redistribute connected
      exit-address-family
      address-family l2vpn evpn
      advertise ipv4 unicast
      exit-address-family


All this should lead to a routing table like this on the compute nodes:

        $ ip ro
        default src 99.99.1.1
                nexthop via 100.65.1.1 dev eth1 weight 1
        100.65.1.0/30 dev eth1 proto kernel scope link src 100.65.1.2
        172.24.4.1 via 99.99.1.1 dev lo

        $ ip ro sh vrf red
        unreachable default metric 4278198272 
        20.0.0.0/24 via 172.24.100.225 dev br-ex
        172.24.100.225 dev br-ex scope link


### How to run it

As a python script on the compute nodes:

    $ python setup.py install
    $ cat bgp-agent.conf
    [DEFAULT]
    debug=True
    reconcile_interval=120
    driver=osp_ovn_evpn_driver

    $ sudo bgp-agent --config-dir bgp-agent.conf
    Starting BGP Agent...
    Loaded chassis 51c8480f-c573-4c1c-b96e-582f9ca21e70.
    BGP Agent Started...
    ....
