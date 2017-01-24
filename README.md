# SR-NFV_connector

We consider a Service Function Chaining scenario supported by IPv6 Segment Routing. In our scenario, a Service Chain is an ordered set of Virtual Network Functions (VNFs) and each VNF is represented by its IPv6 address. We assume that VNFs are hosted in "NFV nodes". 

The SR-NFV_connector module is used in a Linux NFV node in order to support legacy VNFs (i.e. "SR-unaware" VNFs). 

The SR-NFV_connector allows introducing SR-unaware VNFs in a Service Chain implemented with IPv6 Segment Routing. It removes the Segment Routing encapsulation before handing the packets to the VNF and properly reinserts the SR encapsulation to the packets processed by the VNF. 

## Chaining of SR-unaware VNFs 

In order to replicate the experiment of chaining of SR-unaware VNFs by using the SR_NFV_Connector, we provide a simple VirtualBox testbed using vagrant.

The testbed is composed of three Virtual Machines (VMs) that represent SR ingress node, NFV node, and SR egress node: 

**SR ingress node:** processes incoming packets, classifies them, and enforces a per-flow VNF chain; the list of VNF identifiers is applied by encapsulating the original packets in a new IPv6 packets with a SRH reporting as segment list the ordered list of addresses of the given VNFs

**SR egress node:** removes the SR encapsulation and forwards the inner packet toward its final destination. This allows the final destination to correctly process the original packet.

**NFV node:** is capable of processing SR-encapsulated packets and passing them to the SR/VNF connector.

The ingress node can also be used to generate traffic (either simple ICMP packets  or by means of iperf), this traffic will be encapsulated in SR packets (with outer header IPv6 header and SRH).

The NFV node has a VNF running inside a network namespace. The VNF is SR-unaware which means that it has to receive the packets without SR encapsulation. 

The SR_NFV_Connector,  which runs as a kernel module, is used to de-encapsulate the packets, by removing the SR encapsulation, before sending them to the VNF.

The VNF processes the packet (in this scenario the VNF just forwards the packet) and sends it back again to the SR_NFV_Connector which will re-insert the SR encapsulation to the packet before sending it to the egress node.

The egress node removes SR encapsulation from packets and sends them towards the final destination.

### Testbed Setup 

clone the SR-NFV_connector repository in your machine: 

```
$ git clone https://github.com/amsalam20/SR-NFV_connector
$ cd  SR-NFV_connector
```
Add the sr_nfv_connector vagrant box:
```
$ vagrant box add sr-vnf url 
```
start the testbed:
```
$ vagrant up 
```
It  takes a bit of time …. please be patient 

#### Verifying functionality of SR-NFV_connector and its ability to de-encapsulate and re-encapsulate packets

Log into the VM of ingress node: 
```
$ vagrant ssh ingress 
```
You can a have a look at the routing table of ingress node and see the configuration of SR encapsulation  
```
$ ip -6 route 
```
As a simple example, the ingress node is used to generate icmp traffic
```
$ ping6  CCCC:2 
```
#### To see packets received by VNF after being de-encapsulated by SR-NFV_connector

Open a new terminal and log into the NFV node:
```
$ vagrant ssh nfv 
```
The VNF is running inside network namespace to get inside the VNF:
```
$ ip netns exec vnf1 bash 
```
Capture the received packets. Packets are received as normal IPv6 packets with next header icmp6 (no SR encapsulation):
```
$ tcpdump -vvv
``` 
#### To see packets with SR encapsulation before being de-encapasulated by SR-NFV_connector (or after SR encapsulation being  reinserted to packets coming form the VNF)

Open a new terminal and log into the NFV node:
```
$ vagrant ssh nfv
```
capture packets on either eth1 or eth2. Packets will be in SR encapsulation: 
```
$ tcpdump -i eth1 -vvv
```
or ;
```
$ tcpdump -i eth2 -vvv
```
### Notes 
In the ingress node you can generate any kind of traffic using iperf or any other  traffic generator. We choose icmp packets in the scenario here for simplicity.

You can customize resources assigned to any of the VMs by modifying the Vagrantfile 

```
 virtualbox.memory = "1024"
 virtualbox.cpus = "1"
```

You can customize the configuration of ingress node, NFV node , or egress node by modifying the scripts in the vagrant folder.

