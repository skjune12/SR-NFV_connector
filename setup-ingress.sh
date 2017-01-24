#!/bin/bash

#configuration of ingress node interfaces 
ifconfig eth1 up
ip -6 addr add AAAA::2/64 dev eth1

# segment routing encapsulation of ingress node
ip -6 route add cccc::2/128 via aaaa::1 encap seg6 mode encap segs BBBB::2,CCCC::2

# static routing configuration of ingress node
ip -6 route add BBBB::/64 via AAAA::1

exit
