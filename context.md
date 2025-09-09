
#################################################################
##############
shopt -s nullglob
Kimi AI 生成
. /etc/sysconfig/rc
. ${rc_functions}
. /etc/rc.d/init.d/networking/functions.network
eval $(/usr/local/bin/readhash /var/ipfire/wireguard/settings)
interfaces() {
local id
local enabled
local type
local _rest
local IFS=','
# wg0 will always be created for roadwarrior
echo "wg0"
while read -r id enabled type _rest; do
# Skip peers that are not enabled
[ "${enabled}" = "on" ] || continue
# Skip anything that isn't a net-to-net connection
[ "${type}" = "net" ] || continue
echo "wg${id}"
done < /var/ipfire/wireguard/peers
return 0
}
interface_is_rw() {
local intf="${1}"
[ "${intf}" = "wg0" ]
}
setup_interface() {
local intf="${1}"
# Create the interface if it does not exist
if [ ! -d "/sys/class/net/${intf}" ]; then
ip link add "${intf}" type wireguard || return $?
fi
Kimi AI 生成
# Set up the interface
ip link set "${intf}" up
# Set the MTU
if [ -n "${MTU}" ]; then
ip link set "${intf}" mtu "${MTU}" || return $?
fi
# Load the configuration into the kernel
wg syncconf "${intf}" <(generate_config "${intf}") || return
$?
return 0
}
cleanup_interfaces() {
local interfaces=( "$(interfaces)" )
local intf
for intf in /sys/class/net/wg[0-9]*; do
[ -d "${intf}" ] || continue
# Remove the path
intf="${intf##*/}"
local found=0
local i
for i in ${interfaces[@]}; do
if [ "${intf}" = "${i}" ]; then
found=1
break
fi
done
if [ "${found}" -eq 0 ]; then
ip link del "${intf}"
fi
done
return 0
Kimi AI 生成
}
# Replaces 0.0.0.0/0 with 0.0.0.0/1 and 128.0.0.0/1 so that we
can route all traffic
# through a WireGuard tunnel.
expand_subnets() {
local subnet
for subnet in $@; do
case "${subnet}" in
0.0.0.0/0|0.0.0.0/0.0.0.0)
echo -n "0.0.0.0/1,"
echo -n "128.0.0.0/1,"
;;
*)
echo -n "${subnet},"
;;
esac
done
return 0
}
generate_config() {
local intf="${1}"
# Flush all previously set routes
ip route flush dev "${intf}"
local IFS=','
local id
local enabled
Kimi AI 生成
local type
local name
local pubkey
local privkey
local port
local endpoint_addr
local endpoint_port
local remote_subnets
local remarks
local local_subnets
local psk
local keepalive
local local_address
local _rest
# Handles the special case of the RW interface
if interface_is_rw "${intf}"; then
echo "[Interface]"
echo "PrivateKey = ${PRIVATE_KEY}"
# Optionally set the port
if [ -n "${PORT}" ]; then
echo "ListenPort = ${PORT}"
fi
# Add the client pool
if [ -n "${CLIENT_POOL}" ]; then
ip route add "${CLIENT_POOL}" dev "${intf}"
fi
while read -r id enabled type name pubkey privkey port
endpoint_addr endpoint_port \
remote_subnets remarks local_subnets psk
keepalive local_address _rest; do
# Skip peers that are not hosts or not enabled
Kimi AI 生成
[ "${type}" = "host" ] || continue
[ "${enabled}" = "on" ] || continue
echo "[Peer]"
echo "PublicKey = ${pubkey}"
# Set PSK (if set)
if [ -n "${psk}" ]; then
echo "PresharedKey = ${psk}"
fi
# Set routes
if [ -n "${remote_subnets}" ]; then
echo "AllowedIPs = ${remote_subnets//|/, }"
fi
echo # newline
done < /var/ipfire/wireguard/peers
return 0
fi
local local_subnet
local remote_subnet
while read -r id enabled type name pubkey privkey port
endpoint_addr endpoint_port \
remote_subnets remarks local_subnets psk keepalive
local_address _rest; do
# Check for the matching connection
[ "${type}" = "net" ] || continue
[ "${intf}" = "wg${id}" ] || continue
# Skip peers that are not enabled
[ "${enabled}" = "on" ] || continue
# Update the interface alias
ip link set "${intf}" alias "${name}"
# Flush any addresses
ip addr flush dev "${intf}"
Kimi AI 生成
# Assign the local address
if [ -n "${local_address}" ]; then
ip addr add "${local_address}" dev "${intf}"
# Apply MASQUERADE
iptables -t nat -A WGNAT -o "${intf}" -j MASQUERADE
fi
echo "[Interface]"
if [ -n "${privkey}" ]; then
echo "PrivateKey = ${privkey}"
fi
# Optionally set the port
if [ -n "${port}" ]; then
echo "ListenPort = ${port}"
# Open the port
iptables -A WGINPUT -p udp --dport "${port}" -j
ACCEPT
fi
echo "[Peer]"
echo "PublicKey = ${pubkey}"
# Set PSK (if set)
if [ -n "${psk}" ]; then
echo "PresharedKey = ${psk}"
fi
# Set endpoint
if [ -n "${endpoint_addr}" ]; then
echo "Endpoint = ${endpoint_addr}${endpoint_port:+:}$
{endpoint_port}"
fi
# Set routes
if [ -n "${remote_subnets}" ]; then
echo "AllowedIPs = ${remote_subnets//|/, }"
Kimi AI 生成
# Apply the routes
local_subnets=( "${local_subnets//|/,}" )
remote_subnets=( "${remote_subnets//|/,}" )
# Find an IP address of the firewall that is inside
the routed subnet
local src="$(ipfire_address_in_networks "$
{local_subnets[@]}")"
for remote_subnet in $(expand_subnets "$
{remote_subnets[@]}"); do
local args=(
"${remote_subnet}" "dev" "${intf}"
)
# Add the preferred source if we found one
if [ -n "${src}" ]; then
args+=( "src" "${src}" )
fi
ip route add "${args[@]}"
done
# Add a direct host route to the endpoint
if [ -s "/var/ipfire/red/remote-ipaddress" ]; then
ip route add table wg \
"${endpoint_addr}" via "$(</var/ipfire/red/
remote-ipaddress)"
fi
fi
# Set keepalive
if [ -n "${keepalive}" ]; then
echo "PersistentKeepalive = ${keepalive}"
fi
# Set blocking rules
for local_subnet in ${local_subnets//|/ }; do
Kimi AI 生成
for remote_subnet in ${remote_subnets//|/ }; do
iptables -I WGBLOCK \
-s "${remote_subnet}" -d "${local_subnet}" -j
RETURN
done
done
# There will only be one match, so we can break as soon
we get here
break
done < /var/ipfire/wireguard/peers
}
reload_firewall() {
# Flush all previous rules
iptables -F WGINPUT
iptables -t nat -F WGNAT
if [ "${ENABLED}" = "on" ]; then
iptables -A WGINPUT -p udp --dport "${PORT}" -j ACCEPT
fi
iptables -F WGBLOCK
# Don't block any traffic from Roadwarrior peers
if [ -n "${CLIENT_POOL}" ]; then
iptables -A WGBLOCK -s "${CLIENT_POOL}" -i wg0 -j RETURN
iptables -A WGBLOCK -d "${CLIENT_POOL}" -o wg0 -j RETURN
fi
# Block all other traffic
iptables -A WGBLOCK -j REJECT --reject-with icmp-admin-
prohibited
# Flush any custom routes
ip route flush table wg 2>/dev/null
Kimi AI 生成
# Ensure that the table is being looked up
if ! ip rule | grep -q "lookup wg"; then
ip rule add table wg
fi
}
wg_start() {
local failed=0
local intf
# Find all interfaces
local interfaces=( "$(interfaces)" )
# Shut down any unwanted interfaces
cleanup_interfaces
# Reload the firewall
reload_firewall
# Setup all interfaces
for intf in ${interfaces[@]}; do
setup_interface "${intf}" || failed=1
done
return ${failed}
}
wg_stop() {
local intf
# Reload the firewall
ENABLED=off reload_firewall
for intf in /sys/class/net/wg[0-9]*; do
ip link del "${intf##*/}"
done
return 0
}
case "${1}" in
start)
Kimi AI 生成
if [ "${ENABLED}" != "on" ]; then
exit 0
fi
boot_mesg "Starting WireGuard VPN..."
wg_start; evaluate_retval
;;
stop)
boot_mesg "Stopping WireGuard VPN..."
wg_stop; evaluate_retval
;;
reload)
boot_mesg "Reloading WireGuard VPN..."
wg_start; evaluate_retval
;;
restart)
${0} stop
sleep 1
${0} start
;;
*)
echo "Usage: ${0} {start|stop|reload|restart}"
exit 1
;;
esac
[root@ipfire ~]#
Our goal is to understand what it takes for the wireguard service to be launched.
Analyse the function of the above wireguard service script. Provide a insightful
explanation of the logic for each service command
Kimi AI 生成
Kimi:
WireGuard-service script – how every command is executed
The file is a SysV-style init script (/etc/rc.d/init.d/wireguard) that is
executed by
start, stop, reload, or restart.
Below you can see what must be true before the script will actually do anything,
followed by the exact flow for every argument.
1. Pre-conditions – “will the script even run?”
File / variable Meaning
/var/ipfire/wireguard/settings Key-value file that is
read with readhash.
Must contain
ENABLED=on or every
start/reload/restart call
exits immediately.
/var/ipfire/wireguard/peers CSV table describing
every peer. Only lines
where enabled=on are
considered.
$interfaces() function Builds the list of
interfaces that must
exist (wg0 plus every
net-to-net peer that is
enabled). If no
interfaces are returned,
the script will simply
delete any dangling wg*
interfaces and return.
Kimi AI 生成
2. Command-by-command walk-through
start
boot_mesg "Starting WireGuard VPN..."
wg_start; evaluate_retval
• If ENABLED is not on → exit 0 immediately.
• wg_start (detailed below) brings the tunnels up.
• evaluate_retval prints the red/green status line shown on the console.
stop
boot_mesg "Stopping WireGuard VPN..."
wg_stop; evaluate_retval
• Calls ENABLED=off reload_firewall – flushes the firewall chains and
removes the wg routing table rule.
• Deletes every existing wg* interface (ip link del …).
• Returns 0 always.
reload
boot_mesg "Reloading WireGuard VPN..."
wg_start; evaluate_retval
• Same code path as start, but because it is invoked while the daemon is
already running it is effectively a hot reload:
– unwanted interfaces are deleted
– firewall rules are rebuilt
– wanted interfaces are re-created/re-configured in place.
• No process restart; only kernel objects and iptables rules are updated.
Kimi AI 生成
restart
${0} stop
sleep 1
${0} start
• Pure convenience: a sequential stop followed by start.
Kimi AI 生成
3. The helper functions in detail
Kimi AI 生成
Function Purpose
interfaces() Builds the list of expected
interfaces: wg0 (road-warrior
server) plus one interface for
every enabled net-to-net peer
(wg<id>).
cleanup_interfaces() Walks /sys/class/net/
wg[0-9]*. Every interface that is
not in the list returned by
interfaces() is deleted.
reload_firewall() Re-creates three custom iptables
chains: WGINPUT, WGNAT,
WGBLOCK. Opens the listen-port (if
enabled) and adds MASQUERADE
rules. Adds/updates an ip rule
that makes table wg routable.
setup_interface(intf) - Creates the interface if it does
not yet exist (ip link add …
type wireguard). - Brings it up,
sets MTU. - Generates the live
configuration via wg syncconf …
<(generate_config …).
Kimi AI 生成
Function Purpose
generate_config(intf) expand_subnets() Prints the INI-style stanza that wg
syncconf consumes. Handles
two very different cases: a)
Road-warrior server (wg0) –
uses global PRIVATE_KEY, PORT,
CLIENT_POOL; iterates over peers
of type host. b) Net-to-net
client (wg<id>) – uses per-peer
fields (privkey, pubkey,
endpoint_addr,
remote_subnets, …). Adds
routes, iptables rules, and
optional PSK / keep-alive.
Special hack to replace the single
default route 0.0.0.0/0 by
0.0.0.0/1 and 128.0.0.0/1 so
that the default route can still be
overridden later.
4. Quick visual summary
+------------------+
start --------->| ENABLED = on ? |---No--> exit 0
+------------------+
| Yes
v
Kimi AI 生成
+------------------+
| wg_start |
+------------------+
|
+----------------+----------------+
| |
+-----v-----+ +------v------+
| cleanup | delete stale wg* | reload | rebuild firewall
| interfaces| | firewall |
+-----------+ +-------------+
| |
| |
+------------+--------------------+
|
v
+----------------+
| for intf in … |
| setup_interface|
Kimi AI 生成
 +----------------+
stop ---------------> wg_stop ---------------> flush firewall +
delete all wg*
reload -------------> wg_start (same as start, but already
running)
restart ------------> stop → sleep 1 → start
5. Take-away checklist
To have WireGuard actually start on IPFire you need:
1. ENABLED=on in /var/ipfire/wireguard/settings.
2. At least one enabled peer (road-warrior host or net-to-net connection) in /
var/ipfire/wireguard/peers.
3. Valid key material and matching subnets/ports in those files.
If any of the above is missing, the script exits quietly or only performs cleanup.
User:
explain in detail how the generate_config(intf) works and why
Kimi:
generate_config() is the heart of the script: it builds the live WireGuard
configuration that will be pushed into the kernel via wg syncconf.
It is executed once per interface (wg0, wg1, …) inside a process-substitution file
<(generate_config intf) so the wg tool receives a normal INI-style
configuration on stdin.
Kimi AI 生成
Below is a line-by-line / paragraph-by-paragraph explanation of what it does and
why it has to be done this way.
1. Preamble – localising the peer table
local IFS=','
local id enabled type name pubkey privkey port endpoint_addr
endpoint_port \
remote_subnets remarks local_subnets psk keepalive
local_address _rest
• Why:
/var/ipfire/wireguard/peers is a CSV file. Setting IFS=',' and
declaring locals allows the classic read trick to split every comma-
separated column into its own shell variable.
2. Fast path – road-warrior server (wg0)
if interface_is_rw "${intf}"; then
interface_is_rw is literally [ "${intf}" = "wg0" ].
Therefore the whole first branch is only executed for wg0, the road-warrior
server.
2.1 Interface section
[Interface]
PrivateKey = ${PRIVATE_KEY}
ListenPort = ${PORT} # only if PORT is non-empty
• Why:
This is the server side; its private key lives in the global settings file.
The port is optional because the admin might have left the default (51820)
or disabled incoming sessions.
Kimi AI 生成
2.2 Client pool route
if [ -n "${CLIENT_POOL}" ]; then
ip route add "${CLIENT_POOL}" dev "${intf}"
fi
• Why:
IPFire hands out addresses to road-warrior clients from a dedicated pool
(e.g. 10.100.0.0/24).
Adding the route here ensures the kernel knows where those addresses
live even though they are never enumerated in AllowedIPs.
2.3 Iterate over peers of type host
while read …; do
[ "${type}"
= "host" ] || continue
= "on" ] || continue
[ "${enabled}"
• Why:
The same file contains net-to-net peers and road-warrior hosts. We only
want the latter for wg0.
For every matching host the script prints
[Peer]
PublicKey = <pubkey>
PresharedKey = <psk> # only if set
AllowedIPs = <remote_subnets> # comma-separated list
• Why:
AllowedIPs on the server side is what the client is allowed to source
traffic from – typically a single /32 address out of the pool or a split-tunnel
subnet list.
PresharedKey is optional extra symmetric encryption.
Kimi AI 生成
3. Net-to-net client branch (wg1, wg2, …)
If the interface is not wg0, the script assumes it is a net-to-net connection
whose numeric suffix matches the peer id (wg3 ↔ id=3).
It therefore scans the same CSV file until it finds the single line whose type=net
and intf=wg${id}.
3.1 Cosmetic & plumbing
ip link set "${intf}" alias "${name}"
ip addr flush dev "${intf}"
• Why:
Makes ip link show wg1 print a human-readable comment (alias), and
guarantees no stale IPv4/IPv6 addresses remain.
3.2 Interface section (client side)
[Interface]
PrivateKey = <privkey> # per-peer key, not the global one
ListenPort = <port> # optional local listen port
• Why:
In a net-to-net setup each side has its own key pair; the private key is
taken from the peer entry.
3.3 Peer section
[Peer]
PublicKey = <pubkey>
PresharedKey = <psk>
Endpoint = <endpoint_addr>[:port]
AllowedIPs = <remote_subnets>
PersistentKeepalive = <keepalive> # if non-empty
• Why:
This is the remote side of the tunnel.
AllowedIPs here is all networks that live behind the peer – the local
Kimi AI 生成
firewall will send traffic for those prefixes into the tunnel.
Endpoint is the public address/port to reach the peer;
PersistentKeepalive keeps NAT mappings alive.
3.4 Routing & NAT
iptables -t nat -A WGNAT -o "${intf}" -j MASQUERADE
• Why:
Net-to-net usually means the local LAN is reachable through the tunnel;
we need SNAT so return traffic comes back correctly.
3.5 Populating the routing table
local_subnets=( "${local_subnets//|/,}" )
remote_subnets=( "${remote_subnets//|/,}" )
• local_subnets – networks behind this firewall that we want to expose.
• remote_subnets – networks behind the peer.
src=$(ipfire_address_in_networks "${local_subnets[@]}")
for subnet in $(expand_subnets "${remote_subnets[@]}"); do
ip route add "$subnet" dev "$intf" src "$src"
done
• Why:
The helper expand_subnets deals with the special case 0.0.0.0/0.
The src parameter forces the kernel to choose the correct source address
when multiple IPs exist on the firewall.
3.6 Optional policy-routing for the endpoint
if [ -s /var/ipfire/red/remote-ipaddress ]; then
ip route add table wg "${endpoint_addr}" via "$(<...)"
fi
• Why:
Kimi AI 生成
If the peer is reached through the default gateway on the RED interface,
we add a separate routing table (wg) that policy-routes the WireGuard
UDP traffic itself out of RED. This prevents routing loops when the tunnel
default-route changes.
3.7 Per-subnet blocking rules
iptables -I WGBLOCK -s <remote_subnet> -d <local_subnet> -j
RETURN
• Why:
IPFire’s GUI allows blocking certain traffic between subnets. The WGBLOCK
chain is evaluated before the final REJECT; each explicit RETURN lets
matching traffic bypass the block.
4. Termination
After the correct peer line is found and processed the script does:
break
• Why:
There is only one net-to-net peer per interface; once we printed its config
we can stop reading the file.
Kimi AI 生成
Summary – why the function looks the way it does
Requirement How generate_config fulfils it
One single file for
all peers
Two fundamentally
different roles
Server (wg0)
needs all host
peers
Client (wg<id>)
needs exactly one
net peer
Routes / NAT /
firewall must be
updated atomically
wg syncconf
CSV with common columns; IFS=',' parsing
Split into two code branches (intf = wg0 ?)
Loop over entire file, print [Peer] for every host
Loop until id matches, then break
Done inline while we already know the subnets
Function prints to stdout; process substitution feeds
expects INI on
wg
stdin
Thus generate_config() is not only a “config generator”; it is the single place
that converts IPFire’s flat CSV database into a fully functioning WireGuard tunnel
including routes, NAT, policy-routing and firewall rules.
User:
explain 3.6 in detail so I understand the insight and reasoning of the
implementation
var/ipfire/red/remote-ipaddress -> contains the gateway for the network ppp0
connects to
Kimi:
Kimi AI 生成
3.6 The “endpoint host-route” trick – detailed explanation
if [ -s "/var/ipfire/red/remote-ipaddress" ]; then
ip route add table wg \
"${endpoint_addr}" via "$(</var/ipfire/red/remote-
ipaddress)"
fi
The file /var/ipfire/red/remote-ipaddress is written by IPFire whenever the
RED interface comes up.
If RED is PPPoE/PPP, the file contains the single IP address of the remote PPP
peer – i.e. the default gateway that PPP0 uses.
For DHCP or static RED the file contains the gateway handed out by the ISP.
The concrete scenario
• IPFire has two uplinks:
– RED (PPPoE, DHCP, or static) – used for normal Internet traffic.
– WireGuard – an encrypted tunnel whose endpoint is somewhere on
the public Internet (say 198.51.100.42).
• The WireGuard interface (wg1) is configured to carry all traffic
(AllowedIPs = 0.0.0.0/0) – a “full-tunnel” or “redirect-gateway” setup.
What happens without the extra route
1. Kernel wants to send the first encrypted UDP packet to the WireGuard
endpoint (198.51.100.42).
2. FIB lookup for 198.51.100.42 now matches the new default route that
was just installed via wg1.
3. Packet is routed into wg1 → encrypted → UDP payload is again
198.51.100.42 → routed into wg1 …
Infinite loop; tunnel never comes up.
The fix – split the routing decision
We need a single host route that says:
Kimi AI 生成
“To reach the WireGuard peer itself, use the real Internet uplink (RED).”
That is exactly what the one-liner does:
• ip route add table wg 198.51.100.42 via <PPP-gateway>
– installs only for destination 198.51.100.42.
• The route lives in routing table wg (not the main table).
• A previous rule (ip rule add table wg) ensures only WireGuard-
generated traffic consults this table.
Resulting packet flow
Packet type Routing table consulted Outgoing interface
Handshake /
table wg RED (ppp0/ethX)
data to
WireGuard
endpoint
Any other
main table wg1 (encrypted)
traffic (LAN,
Internet)
Why use a separate table instead of the main table?
• The main table is going to contain the tunnel’s default route (0.0.0.0/0
→ wg1).
• Adding a host route in the main table would be overwritten by the broader
default route.
• A dedicated table keeps policy-routing isolated and survives later ip
route replace operations done elsewhere.
Why read the gateway from /var/ipfire/red/remote-ipaddress?
• The PPP/DHCP-assigned gateway is not guaranteed to be the same
every time the link bounces.
• IPFire already writes the current value into that file, so the script always
uses the live next-hop without hard-coding anything.
Kimi AI 生成
Mini example
Assume:
• RED is PPPoE, gateway 203.0.113.1 written into /var/ipfire/red/
remote-ipaddress.
• WireGuard peer endpoint 198.51.100.42.
After the route is added:
# ip route show table wg
198.51.100.42 via 203.0.113.1 dev ppp0
# ip route | grep default
default dev wg1 scope link
WireGuard handshake packets leave via ppp0; everything else is tunnelled
through wg1.
User:
I am not familiar with routing … explain what exactly is happening with this rule
# ip route show table wg
198.51.100.42 via 203.0.113.1 dev ppp0
Kimi:
Think of the routing table as the kernel’s address book.
When the kernel has a packet to send, it looks in the address book and asks:
“For this destination IP, which next hop and which network card
(interface) should I use?”
Kimi AI 生成
The rule line-by-line
198.51.100.42
• Destination IP we are talking about (the WireGuard peer).
via 203.0.113.1
• Next hop (gateway) to reach that destination.
The packet is not put directly on the wire with 198.51.100.42 in the
Ethernet frame; instead it is sent to the MAC address that belongs to
203.0.113.1 (the ISP router).
That router then forwards it further toward 198.51.100.42.
dev ppp0
• Send it out of interface ppp0 (the PPPoE link).
What the rule really means
“If you ever need to send anything to 198.51.100.42, hand the packet
to the ISP router at 203.0.113.1 using the PPPoE link.”
Because this route is placed in table wg, only traffic that the kernel has explicitly
marked (via an ip rule) will consult this table.
Normal traffic uses the main table, whose default route now points into the
WireGuard tunnel.
User:
ah I see !!! this way you say … the traffic to the wireguard endpoint is the carrier
to the VPN traffic so it must go via ppp0 !!!!
Kimi:
Exactly — you nailed it!
Kimi AI 生成
• The hand-shake, key-exchange, and encrypted payload packets that
form the WireGuard tunnel itself must travel in the clear over the real
Internet link (ppp0).
• Once the tunnel is established, all the user data gets wrapped inside
those encrypted packets and disappears into the tunnel interface (wg1).
So the route is there to make sure:
“Packets whose job is to build and maintain the VPN ride on ppp0;
packets that are merely passengers inside the VPN ride on wg1.”
User:
is the rule lookup wg is triggered only by wireguard traffic ? if yes, how does it
know it is wg traffic and which part of the service script set this up ?
Kimi:
Short answer: No.
The rule
ip rule add table wg
does not say “only WireGuard traffic should use the table”; it simply adds a
generic rule that makes table wg part of the routing policy.
Whoever created that rule (or any later packet) decides what traffic actually hits
it.
1. Who adds the rule?
Inside the service script you will find:
reload_firewall() {
...
# Ensure that the table is being looked up
if ! ip rule | grep -q "lookup wg"; then
Kimi AI 生成
ip rule add table wg
fi
}
reload_firewall is executed on every start, reload, or restart.
So the script itself inserts the rule once when WireGuard is enabled.
2. What does the rule look like?
Because the script does not supply any selector, the kernel defaults to the all-
zero selector:
0: from all lookup wg
In other words: every packet, regardless of source, destination, or firewall
mark, will consult table wg after the main table but before the default table.
3. Why doesn’t this break everything?
• Table wg contains only the single host route
198.51.100.42 via 203.0.113.1 dev ppp0.
• For any destination other than 198.51.100.42 the lookup in table wg fails
(no matching route), so the kernel continues to the next rule (main), where
the normal routes live.
• Therefore the extra table affects only the WireGuard endpoint address; all
other traffic is unaffected.
4. Could we restrict it to WireGuard traffic only?
Yes. A more precise rule would be:
ip rule add to 198.51.100.42 table wg
or, using a firewall mark:
iptables -t mangle -A OUTPUT -p udp --dport 51820 \
Kimi AI 生成
-j MARK --set-mark 0x100
ip rule add fwmark 0x100 table wg
The current script chooses the simplest possible solution: one host route in a
generic table that is consulted by every packet, but whose only matching route is
the WireGuard endpoint.
User:
I want to tunnel all my blue0 traffic over a wireguard tunnel using a NordVPN
configuration profile. The green0 traffic should continue routing via ppp0 and
remain unaffected once the tunnel is up.
I have configured an ipfire net-to-net tunnel that when is activated forms the wg3
interface When the tunnel is active I run the following commands from ipfire
console
# ip addr show | grep wg
54: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 qdisc noqueue
state UNKNOWN group default qlen 1000
57: wg3: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 qdisc noqueue
state UNKNOWN group default qlen 1000
inet 10.5.0.2/32 scope global wg3
# curl --interface wg3 https://ipinfo.io/ip
156.167.93.133
# iptables -L WGBLOCK -v -n
Chain WGBLOCK (2 references)
pkts bytes target prot opt in out source
Kimi AI 生成
destination
0 0 RETURN all -- * * 0.0.0.0/0
192.168.2.0/24
0 0 RETURN all -- wg0 * 10.0.0.0/24
0.0.0.0/0
0 0 RETURN all -- * wg0 0.0.0.0/0
10.0.0.0/24
4 4912 REJECT all -- * * 0.0.0.0/0
0.0.0.0/0 reject-with icmp-admin-prohibited
Chain WGINPUT (1 references)
pkts bytes target prot opt in out source
destination
0 0 ACCEPT udp -- * * 0.0.0.0/0
0.0.0.0/0 udp dpt:51820
0 0 ACCEPT udp -- * * 0.0.0.0/0
0.0.0.0/0 udp dpt:61147
# iptables -t nat -L WGNAT -v -n
Chain WGNAT (1 references)
pkts bytes target prot opt in out source
destination
22 1378 MASQUERADE all -- * wg3 0.0.0.0/0
0.0.0.0/0
[root@ipfire ~]# ip rule list all
0: from all lookup local
32764: from all lookup wg
32765: from all lookup static
32766: from all lookup main
Kimi AI 生成
32767: from all lookup default
[root@ipfire ~]# ip route list table wg
156.67.94.180 via 212.69.63.54 dev ppp0
[root@ipfire ~]# ip route list table main
0.0.0.0/1 dev wg3 scope link src 192.168.2.1
128.0.0.0/1 dev wg3 scope link src 192.168.2.1
10.0.0.0/24 dev wg0 scope link
default via 212.69.63.54 dev ppp0
192.168.1.0/24 dev green0 proto kernel scope link src 192.168.1.1
192.168.2.0/24 dev blue0 proto kernel scope link src 192.168.2.1
212.69.63.54 dev ppp0 proto kernel scope link src 212.69.35.2
I expect a this point the traffic from blue0 to be tunnelled via wg3 to the internet
and back Instead all traffic from green0 (lan) and blue0 (wlan) are dropped by the
firewall
13:15:03 DROP_FORWARD green0 TCP 192.168.1.75
54.216.30.15 55329
443(HTTPS) f4:d4:88:92:08:58
13:15:03 DROP_FORWARD blue0 TCP 192.168.2.5
142.251.30.101 55347
443(HTTPS) f4:d4:88:92:09:50
green0 traffic matching 192.168.1.0/24 should not be routed via wireguard,
however it gets dropped. What could cause the traffic to be dropped once the
wireguard tunnel is up ? Provide indepth explanation particularly how the
WGBLOCK and WGINPUT chains are able to intercept green0 traffic
Kimi:
Kimi AI 生成
What happens when the tunnel comes up
Action Result
the script installs a default route
via wg3 (0.0.0.0/1 +
128.0.0.0/1) → all new traffic is
steered toward wg3
it also adds the host-route
156.67.94.180 via
212.69.63.54 dev ppp0 in table
wg, so only the hand-shake to the
NordVPN server still uses ppp0
nothing in the routing tables
distinguishes green0
(192.168.1.0/24) from blue0
(192.168.2.0/24) – both networks
are now behind a default route
that points into the tunnel
firewall rules (WGBLOCK, WGINPUT)
are not interface-specific; they are
evaluated after the routing
decision, so they will see the
packets after the kernel has
already decided to send them to
wg3
How the firewall chains intercept the packets
1. Where the chains are hooked
FORWARD ─┬─► WGBLOCK ─┬─► …
│ │
Kimi AI 生成
│ └─► REJECT
│
└─► normal FORWARD rules …
• WGBLOCK is jumped to from the FORWARD chain (see /etc/sysconfig/
firewall or the custom rules IPFire adds).
• WGINPUT is jumped to from the INPUT chain (only packets to the firewall
itself).
Important: both chains live in the filter table; they do not decide where
the packet is routed, only whether it is allowed to continue.
2. What each rule does
WGBLOCK (filter/FORWARD)
Rule Meaning
RETURN all * * 0.0.0.0/0
192.168.2.0/24
allow packets to blue0 (destination
is blue LAN)
RETURN all wg0 * 10.0.0.0/24
0.0.0.0/0
allow road-warrior clients to leave
RETURN all * wg0 0.0.0.0/0
10.0.0.0/24
allow packets into road-warrior
clients
REJECT all * * 0.0.0.0/0
drop everything else
0.0.0.0/0
WGINPUT (filter/INPUT)
Only UDP handshake packets to the listening ports (51820, 61147) are accepted;
everything else destined to the firewall itself is dropped.
Why green0 and blue0 traffic is dropped
1. A packet from 192.168.1.75 (green0) or 192.168.2.5 (blue0) wants to
reach 54.216.30.15 (Internet).
Kimi AI 生成
2. Routing decision: because the two /1 routes cover the whole IPv4 space,
the packet is routed out of wg3.
3. The packet now traverses FORWARD → WGBLOCK.
4. None of the first three RETURN rules match:
– rule 1 only matches destined-to-blue0 traffic (destination
192.168.2.0/24) – we are going out to the Internet → no match.
– rules 2 & 3 only apply when the interface is wg0 – we are on wg3 →
no match.
5. The final REJECT rule catches the packet → DROP_FORWARD is logged.
Exactly the same happens for blue0 traffic, because the blue LAN is not
mentioned in any RETURN rule either.
The fix
You have to tell the firewall which traffic is allowed to use the tunnel.
Add explicit RETURN rules in WGBLOCK (or create a separate chain) for the two
networks:
# allow blue0 to use the NordVPN tunnel
iptables -I WGBLOCK 1 -s 192.168.2.0/24 -o wg3 -j RETURN
# allow green0 to keep using the normal WAN (ppp0)
iptables -I WGBLOCK 1 -s 192.168.1.0/24 -o ppp0 -j RETURN
and optionally block green0 from entering the tunnel:
iptables -A WGBLOCK -s 192.168.1.0/24 -o wg3 -j REJECT
After these rules the packets will hit an early RETURN, skip the final REJECT, and
be forwarded according to the routing decision already made.
Kimi AI 生成
User:
The ipfire design and implementation for net-2-net use cases does not support
my goal which is to tunnel blue0 traffic to the internet over a wireguard VPN
tunnel.
Given
# ip addr show | grep wg
54: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 qdisc noqueue
state UNKNOWN group default qlen 1000
57: wg3: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 qdisc noqueue
state UNKNOWN group default qlen 1000
inet 10.5.0.2/32 scope global wg3
# curl --interface wg3 https://ipinfo.io/ip
156.167.93.133
# iptables -L WGBLOCK -v -n
Chain WGBLOCK (2 references)
pkts bytes target prot opt in out source
destination
0 0 RETURN all -- * * 0.0.0.0/0
192.168.2.0/24
0 0 RETURN all -- wg0 * 10.0.0.0/24
0.0.0.0/0
0 0 RETURN all -- * wg0 0.0.0.0/0
10.0.0.0/24
4 4912 REJECT all -- * * 0.0.0.0/0
Kimi AI 生成
0.0.0.0/0 reject-with icmp-admin-prohibited
Chain WGINPUT (1 references)
pkts bytes target prot opt in out source
destination
0 0 ACCEPT udp -- * * 0.0.0.0/0
0.0.0.0/0 udp dpt:51820
0 0 ACCEPT udp -- * * 0.0.0.0/0
0.0.0.0/0 udp dpt:61147
# iptables -t nat -L WGNAT -v -n
Chain WGNAT (1 references)
pkts bytes target prot opt in out source
destination
22 1378 MASQUERADE all -- * wg3 0.0.0.0/0
0.0.0.0/0
[root@ipfire ~]# ip rule list all
0: from all lookup local
32764: from all lookup wg
32765: from all lookup static
32766: from all lookup main
32767: from all lookup default
[root@ipfire ~]# ip route list table wg
156.67.94.180 via 212.69.63.54 dev ppp0
[root@ipfire ~]# ip route list table main
0.0.0.0/1 dev wg3 scope link src 192.168.2.1
128.0.0.0/1 dev wg3 scope link src 192.168.2.1
Kimi AI 生成
10.0.0.0/24 dev wg0 scope link
default via 212.69.63.54 dev ppp0
192.168.1.0/24 dev green0 proto kernel scope link src 192.168.1.1
192.168.2.0/24 dev blue0 proto kernel scope link src 192.168.2.1
212.69.63.54 dev ppp0 proto kernel scope link src 212.69.35.2
Propose a solution that meets the above stated goal with minimum adjustments
to the above resulting configuration. Apply the minimum necessary changes
while reuse available rules, routes & tables that form part of ipfire WG
architecture/design. Justify why the solution is NOT a net-to-net solution
anymore, that is, hence traffic initiated from internet MUST NOT reach ipfire;
Justify why the solution preserves local services such as DHCP & DNS, and not
break routing between local networks Provide a list commands for now so I can
validate the solution. Explain the minimum changes to successfuly run curl --
interface wg3 https://ipinfo.io/ip
Kimi:
✅ Goal re-statement
• Only traffic that originates from blue0 (192.168.2.0/24) must be
NATed through wg3 to the Internet.
• Green0 (192.168.1.0/24) and local services (DHCP, DNS, inter-LAN)
must stay untouched and continue to use ppp0.
• No unsolicited packets from the Internet must be able to reach IPFire
through the tunnel – therefore the setup is no longer a net-to-net
scenario (we deliberately break the return path).
Kimi AI 生成
🎯 Key observations
Item Observation
wg3 already exists and works (curl
succeeds when forced via --
interface wg3).
IPFire’s generated net-to-net routes
(0.0.0.0/1 and 128.0.0.0/1)
pull everything into wg3.
WGBLOCK has a final REJECT that
drops any packet not explicitly
allowed.
WGNAT already contains a
MASQUERADE rule for traffic
leaving wg3.
Kimi AI 生成
🧩 Minimal change strategy
Step Why it is required
1. Remove the global “catch-all”
default routes (0.0.0.0/1,
128.0.0.0/1) from main table.
2. Add a single policy-rule:
packets from 192.168.2.0/24 →
lookup a new table (bluevpn).
3. Install only one route in that
table: default dev wg3.
Stops green0 & local services from
being forced into the tunnel.
Keeps routing decision source-
based, re-using the existing ip
rule mechanism.
Makes blue0 traffic exit via
NordVPN; everyone else keeps the
original default via ppp0.
Lets the traffic actually leave and
return.
4. Insert two permit rules in
WGBLOCK so packets from/into blue0
are not rejected.
No other chains, tables, or firewall rules are touched.
🧪 Commands to execute (run once, order matters)
# 1. Remove the global /1 routes that the net-to-net script added
ip route del 0.0.0.0/1
ip route del 128.0.0.0/1
# 2. Create a new routing table (numeric id 200 is free)
echo "200 bluevpn" >> /etc/iproute2/rt_tables
# 3. Add the default route for the new table
Kimi AI 生成
ip route add default dev wg3 table bluevpn
# 4. Policy-rule: packets *from* blue0 → use table bluevpn
ip rule add from 192.168.2.0/24 lookup bluevpn prio 32000
# 5. Allow blue0 traffic to leave / return through the tunnel
iptables -I WGBLOCK 1 -s 192.168.2.0/24 -j RETURN
iptables -I WGBLOCK 1 -d 192.168.2.0/24 -j RETURN
🧾 Quick validation
# still works
curl --interface wg3 https://ipinfo.io/ip
# now blue0 clients automatically use wg3
curl https://ipinfo.io/ip # run from a blue0 client
# should return the NordVPN address (156.167.93.133)
# green0 clients still use the original WAN
curl https://ipinfo.io/ip # run from a green0 client
# should return your ISP address
Kimi AI 生成
🛡 Why this is NOT a net-to-net solution anymore
• No AllowedIPs include the public Internet → the remote NordVPN peer
will not route incoming packets back to IPFire.
• No DNAT / port-forward rules exist → unsolicited traffic dies at NordVPN’s
side.
• The return path is effectively one-way (outbound NAT only).
🏠 Why local services keep working
• DHCP and DNS daemons listen on green0/blue0; traffic within those
subnets never hits the FORWARD chain.
• Inter-LAN traffic (192.168.1.x ↔ 192.168.2.x) uses the directly-
connected routes (dev green0, dev blue0) and never reaches the
default route.
• Source-based rule (from 192.168.2.0/24) affects only traffic that
originates from blue0; green0 packets still follow the original default via
ppp0.
User:
critically assess this solution
# 1. Remove split default routes from main table (stops routing
all traffic via wg3)
ip route del 0.0.0.0/1 dev wg3
ip route del 128.0.0.0/1 dev wg3
# 2. Create policy routing for blue0 traffic
# Add blue0 network to routing table 100
Kimi AI 生成
echo "100 blue_table" >> /etc/iproute2/rt_tables
# Add routes for blue0 traffic
ip route add 192.168.2.0/24 dev blue0 table blue_table
ip route add 0.0.0.0/1 dev wg3 table blue_table
ip route add 128.0.0.0/1 dev wg3 table blue_table
# Add policy rule to route blue0 traffic via blue_table
ip rule add from 192.168.2.0/24 table blue_table
# 3. Adjust firewall rules
# Remove rule allowing incoming traffic to blue0
iptables -D WGBLOCK 1
# Add rule allowing blue0 traffic to exit via wg3
iptables -I WGBLOCK 1 -s 192.168.2.0/24 -o wg3 -j RETURN
# 4. Ensure local services remain accessible
# Add rules to allow DHCP/DNS traffic to bypass tunnel
iptables -I WGBLOCK 2 -p udp --dport 53 -j ACCEPT # DNS
iptables -I WGBLOCK 3 -p udp --dport 67:68 -j ACCEPT # DHCP
# 5. Flush route cache to apply changes
Kimi AI 生成
ip route flush cache
Kimi:
Critical review of the proposed commands
1. Removing the two /1 routes
✅ Correct – they were forcing all traffic into wg3.
⚠ Side-effect: the NordVPN host route (table wg) is still present, so only
handshake packets will keep working.
2. New table “blue_table”
✅ Good idea – source-based policy routing is the right tool.
3. Routes inside blue_table
🔴 Over-complicated – you do not need
ip route add 192.168.2.0/24 dev blue0 table blue_table
because that network is directly connected; the kernel already knows how
to reach it.
🔴 Redundant /1 routes – you only need one default route (default
dev wg3).
the new table.
Using two /1 routes again re-creates the same “catch-all” problem inside
4. Firewall rules
🔴 Deletes rule 1 blindly – you assume the first rule is “allow to-blue0”; if
the list ever changes you remove the wrong rule.
🔴 DNS / DHCP rules – they are not needed in WGBLOCK (FORWARD
chain).
DHCP and DNS traffic to the firewall itself is handled by INPUT/OUTPUT,
not FORWARD.
Kimi AI 生成
Inter-LAN traffic stays on the local interfaces and never reaches
FORWARD.
Therefore these two rules only add clutter and potential security holes.
5. Route-cache flush
✅ Harmless but unnecessary on modern kernels.
Minimal, corrected command set
# 1. Remove the global /1 routes
ip route del 0.0.0.0/1
ip route del 128.0.0.0/1
# 2. Create and populate the new policy-routing table
echo "100 blue" >> /etc/iproute2/rt_tables
ip route add default dev wg3 table blue
# 3. Policy rule: packets *originating* from blue0 → use table
blue
ip rule add from 192.168.2.0/24 table blue prio 32000
# 4. Allow blue0 traffic to leave/return through the tunnel
iptables -I WGBLOCK 1 -s 192.168.2.0/24 -j RETURN
iptables -I WGBLOCK 2 -d 192.168.2.0/24 -j RETURN
Nothing else is necessary:
Kimi AI 生成
• DNS/DHCP for blue0 clients still works – the daemons listen on
192.168.2.1, traffic never leaves the box.
• green0 keeps the original default route → unaffected.
User:
curl –interface wg3 https://ipinfo.io/ip
curl: (7) Failed to connect to ipinfo.io port 443 after 3118 ms: Could not connect
to server
ping 10.5.0.2
PING 10.5.0.2 (10.5.0.2) 56(84) bytes of data. 64 bytes from 10.5.0.2:
icmp_seq=1 ttl=64 time=0.184 ms 64 bytes from 10.5.0.2: icmp_seq=2 ttl=64
time=0.183 ms 64 bytes from 10.5.0.2: icmp_seq=3 ttl=64 time=0.240 ms ^C
10
.5.
0.
2
pi
ng
st
ati
sti
cs
—
Kimi AI 生成
3
pa
ck
et
s
tr
an
s
mi
tte
d,
3
re
ce
iv
ed
,
0
%
pa
ck
et
lo
ss
,
ti
m
e
20
70
m
s Kimi AI 生成
# .
/
ve
rif
y.
sh
Kimi AI 生成
=
=
ro
ut
es
de
fa
ult
de
v
w
g3
sc
op
e
lin
k
15
6.
67
.9
4.
18
0
vi
a
21
2.
69
.6
3.
25 Kimi AI 生成
pe
er
:
U
6z
z+
5
N
u
O
0
Fl
W
kp
D
E
K
7x
C
gg
m
yh
4
D
J
wj
w
d0
et
Zx
F
nh Kimi AI 生成
=
=
=
=
he
re
ar
e
th
e
te
st
re
su
lts
Kimi:
Kimi AI 生成
🔍 What the test is telling us
Symptom Meaning
curl --interface wg3
https://ipinfo.io/ip fails
Encrypted packets leave wg3 but
never receive a reply.
ping 10.5.0.2 works The inside of the tunnel (IPFire ↔
NordVPN) is fine.
tracepath 8.8.8.8 shows only
ISP hops
Return traffic is not coming back
through the tunnel.
allowed ips: 0.0.0.0/0 on our
side only
NordVPN is happy to send us
packets for any destination, but it
will only forward outbound traffic if
the source address it sees is one
of the addresses it assigned to
us (here 10.5.0.2/32).
🎯 Root cause
NordVPN (like almost every commercial VPN) expects source NAT to be done
with the address it leased to the client.
Your current MASQUERADE rule is correct, but nothing guarantees the packets
actually pick 10.5.0.2 as their source.
Because the tunnel interface has no globally-routable address on IPFire’s side
other than 10.5.0.2, traffic sourced from 192.168.2.x (blue0) or even from the
firewall itself (when you run curl --interface wg3) is silently dropped by
NordVPN once it leaves their server.
✅ Quick fix – force the right source address
# 1. Explicitly set the source address on the default route
inside the blue-vpn table
Kimi AI 生成
ip route change default dev wg3 src 10.5.0.2 table blue-vpn
# 2. Flush the route cache so the change takes effect immediately
ip route flush cache
That single change tells the kernel:
“Every packet that policy-routing decides to send via table blue-vpn
must use 10.5.0.2 as its source address.”
🧪 Re-test
curl --interface wg3 https://ipinfo.io/ip
# should now return 156.167.93.133 (the NordVPN address)
curl https://ipinfo.io/ip # from a blue0 client
# should also return 156.167.93.133
🧩 Why nothing else is needed
• Encryption & handshake were already working (latest handshake 2 min
ago).
• NAT rule (MASQUERADE) is already in place; the only missing piece was the
source address selection.
User:
== routes default dev wg3 scope link src 10.5.0.2 156.67.94.180 via
212.69.63.25 dev ppp0 default via 212.69.63.25 dev ppp0 10.0.0.0/24 dev wg0
Kimi AI 生成
scope link 192.168.1.0/24 dev green0 proto kernel scope link src 192.168.1.1
192.168.2.0/24 dev blue0 proto kernel scope link src 192.168.2.1 212.69.63.25
dev ppp0 proto kernel scope link src 212.69.35.2 == rules 0: from all lookup local
32763: from 192.168.2.0/24 lookup blue-vpn 32764: from all lookup wg 32765:
from all lookup static 32766: from all lookup main 32767: from all lookup default
== iptables Chain WGBLOCK (2 references) pkts bytes target prot opt in out
source destination 0 0 RETURN all – wg3 * 0.0.0.0/0 192.168.2.0/24 0 0
RETURN all – * wg3 192.168.2.0/24 0.0.0.0/0 0 0 RETURN all – wg0 *
10.0.0.0/24 0.0.0.0/0 0 0 RETURN all – * wg0 0.0.0.0/0 10.0.0.0/24 135 34621
REJECT all – * * 0.0.0.0/0 0.0.0.0/0 reject-with icmp-admin-prohibited Chain
WGNAT (1 references) pkts bytes target prot opt in out source destination 16
1228 MASQUERADE all – * wg3 0.0.0.0/0 0.0.0.0/0 == wireguard interface: wg3
public key: HllFyhuBQGOBpKhF78DmuLeYDtcGxHVvHU62jOuirC4= private
key: (hidden) listening port: 61147
peer: U6zz+5NuO0FlWkpDEK7xCggmyh4DJwjwd0etZxFnhhI= endpoint:
156.67.94.180:51820 allowed ips: 0.0.0.0/0 latest handshake: 18 seconds ago
transfer: 82.52 KiB received, 82.91 KiB sent persistent keepalive: every 2
minutes, 5 seconds 11: wg3: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu
1420 qdisc noqueue state UNKNOWN group default qlen 1000 link/none inet
10.5.0.2/32 scope global wg3 valid_lft forever preferred_lft forever curl: (7) Failed
to connect to ipinfo.io port 443 after 3084 ms: Could not connect to server curl:
(7) Failed to connect to ipinfo.io port 443 after 3058 ms: Could not connect to
server curl: (28) Failed to connect to ipinfo.io port 443 after 19700 ms: Could not
connect to server ====
doesn’t work
Kimi:
curl --interface wg3 … is still failing even though the handshake is fresh,
which tells us the encrypted packets leave IPFire, reach NordVPN, but the
return path is blocked.
Kimi AI 生成
Below is a systematic checklist you can run now to expose the exact failure
point.
Run each numbered command in the order shown and copy the output back.
When the failing step is identified we will apply the one-line fix that matches the
symptom.
1. Is the tunnel really passing packets in both directions?
# send 10 ICMP echo requests out of wg3
ping -I wg3 -c 10 8.8.8.8
2. What does a tcpdump on wg3 show while we ping?
Open a second shell and run:
tcpdump -n -i wg3
then run the ping again in the first shell.
Look for exactly the pattern:
• outbound packets: IP 10.5.0.2 > 8.8.8.8
• inbound packets: IP 8.8.8.8 > 10.5.0.2
If only outbound packets are seen, NordVPN is dropping them (source
address / NAT issue).
If both directions are seen, the problem is inside IPFire (routing, RP-filter,
firewall).
3. Is reverse-path filtering stopping the replies?
sysctl net.ipv4.conf.all.rp_filter
sysctl net.ipv4.conf.wg3.rp_filter
If either prints 1, disable it temporarily:
Kimi AI 生成
sysctl -w net.ipv4.conf.wg3.rp_filter=0
sysctl -w net.ipv4.conf.all.rp_filter=0
then repeat the ping.
4. Does the main table still contain an earlier default that beats wg3?
ip route get 8.8.8.8
The first line must show:
8.8.8.8 dev wg3 src 10.5.0.2
If it shows via 212.69.63.25 dev ppp0, the policy rule is not being consulted.
5. Is conntrack dropping the flows?
conntrack -L | grep 8.8.8.8
If you see entries in state UNREPLIED or none at all, packets are not coming back.
6. Quick “firewall off” test (temporary)
iptables -I WGBLOCK 1 -j ACCEPT
If curl --interface wg3 https://ipinfo.io/ip now succeeds, the
problem is purely in WGBLOCK.
If it still fails, the problem is outside the firewall (NordVPN side).
Please run steps 1-6 and post the output (or “works / fails” for each).
Once we see which step breaks, we will give you the minimal one-line change
to resolve it.
User:
Kimi AI 生成
ip route get 8.8.8.8
8.8.8.8 via 212.69.63.25 dev ppp0 src 212.69.35.2 uid 0
ping -I wg3 -c 10 8.8.8.8 only outbound packets are seen, NordVPN is dropping
them
curl –interface wg3 https://ipinfo.io/ip
22:24:20.022380 IP 10.5.0.2.60976 > 34.117.59.81.443: Flags [S], seq
3822735545, win 42780, options [mss 1380,sackOK,TS val 2250759945 ecr
0,nop,wscale 9], length 0 22:24:20.082444 IP 34.117.59.81.443 >
10.5.0.2.60976: Flags [S.], seq 1254543968, ack 3822735546, win 65535,
options [mss 1380,sackOK,TS val 1939669412 ecr 2250759945,nop,wscale 9],
length 0 22:24:21.085310 IP 10.5.0.2.60976 > 34.117.59.81.443: Flags [S], seq
3822735545, win 42780, options [mss 1380,sackOK,TS val 2250761008 ecr
0,nop,wscale 9], length 0 22:24:21.104923 IP 34.117.59.81.443 >
10.5.0.2.60976: Flags [S.], seq 1254543968, ack 3822735546, win 65535,
options [mss 1380,sackOK,TS val 1939670436 ecr 2250759945,nop,wscale 9],
length 0 22:24:21.144170 IP 34.117.59.81.443 > 10.5.0.2.60976: Flags [S.], seq
1254543968, ack 3822735546, win 65535, options [mss 1380,sackOK,TS val
1939670474 ecr 2250759945,nop,wscale 9], length 0 22:24:22.108250 IP
10.5.0.2.60976 > 34.117.59.81.443: Flags [S], seq 3822735545, win 42780,
options [mss 1380,sackOK,TS val 2250762031 ecr 0,nop,wscale 9], length 0
avoid sysctl -w net.ipv4.conf.wg3.rp_filter=0
Kimi:
Kimi AI 生成
🔍 What the new evidence shows
Observation Meaning
ip route get 8.8.8.8 ➜ via
212.69.63.25 dev ppp0
tcpdump -i wg3 sees both
directions (SYN and SYN-ACK)
No 3-way-handshake completion
(only repeated SYN)
Policy rule for blue0 is not being
consulted; main table is winning.
WireGuard link itself is fine;
packets leave encrypted and come
back decrypted.
Return packets are being
dropped inside IPFire after
decryption.
🎯 Root cause (in one sentence)
Packets that come back into wg3 are being routed through ppp0
instead of back to the originating host, so the TCP stack never
sees the SYN-ACK and keeps retransmitting.
💡 Minimal fix – one-line policy rule repair
The policy rule priority is too low.
Rule 32763 is after the main-table lookup (32766), so the kernel finds the default
via ppp0 and uses it.
Move the rule above main:
ip rule del from 192.168.2.0/24 table blue-vpn
ip rule add from 192.168.2.0/24 table blue-vpn prio 100
or simply raise the priority to any number < 32766:
ip rule add from 192.168.2.0/24 table blue-vpn prio 1000
Kimi AI 生成
✅ Quick verification
# 1. Apply the fix
ip rule add from 192.168.2.0/24 table blue-vpn prio 1000
# 2. Check order
ip rule | grep blue-vpn
# should show priority 1000 (before 32766)
# 3. Test again
curl --interface wg3 https://ipinfo.io/ip
Expected result: HTTP 200 and the NordVPN public IP.
📝 Why nothing else is needed
• rp_filter was already skipped (per your request).
• Firewall rules are already allowing traffic in both directions via WGBLOCK.
• Handshake is fresh (18 s ago).
• Return packets are reaching the host (seen on wg3) – they just need
the correct routing rule to be delivered to the local TCP stack.
User:
curl –interface wg3 https://ipinfo.io/ip
22:30:44.887518 IP 34.117.59.81.443 > 10.5.0.2.35242: Flags [S.], seq
1495431925, ack 3454559943, win 65535, options [mss 1380,sackOK,TS val
1940054218 ecr 2251139644,nop,wscale 9], length 0 22:30:46.876174 IP
10.5.0.2.35242 > 34.117.59.81.443: Flags [S], seq 3454559942, win 42780,
Kimi AI 生成
options [mss 1380,sackOK,TS val 2251146799 ecr 0,nop,wscale 9], length 0
22:30:46.894076 IP 34.117.59.81.443 > 10.5.0.2.35242: Flags [S.], seq
1495431925, ack 3454559943, win 65535, options [mss 1380,sackOK,TS val
1940056224 ecr 2251139644,nop,wscale 9], length 0 22:30:46.935706 IP
34.117.59.81.443 > 10.5.0.2.35242: Flags [S.], seq 1495431925, ack
3454559943, win 65535, options [mss 1380,sackOK,TS val 1940056265 ecr
2251139644,nop,wscale 9], length 0 22:30:50.908695 IP 10.5.0.2.35242 >
34.117.59.81.443: Flags [S], seq 3454559942, win 42780, options [mss
1380,sackOK,TS val 2251150831 ecr 0,nop,wscale 9], length 0 22:30:50.967999
IP 34.117.59.81.443 > 10.5.0.2.35242: Flags [S.], seq 1495431925, ack
3454559943, win 65535, options [mss 1380,sackOK,TS val 1940060299 ecr
2251139644,nop,wscale 9], length 0
== rules 0: from all lookup local 100: from 192.168.2.0/24 lookup blue-vpn 32764:
from all lookup wg 32765: from all lookup static 32766: from all lookup main
32767: from all lookup default
Kimi:
🚨 Still only half a handshake
The trace shows the same symptom again:
• Outbound SYN → encrypted → leaves IPFire
• Inbound SYN-ACK → decrypted → arrives at 10.5.0.2
• Local TCP never answers → curl keeps retransmitting
The only missing piece is that the reply packet (generated by the TCP stack
when curl is run with --interface wg3) is not being routed back into wg3; it is
still taking the main-table default (via 212.69.63.25).
✅ Final one-liner – fix the reply path
When you run curl --interface wg3, the source address the kernel chooses
is 10.5.0.2 (because that is the only address on wg3).
Kimi AI 生成
Our policy rule is keyed on source network 192.168.2.0/24, so that rule never
matches and the packet falls back to the main table.
Add a second policy rule for packets whose source address is 10.5.0.2:
ip rule add from 10.5.0.2 lookup blue-vpn prio 99
After this:
Rule (priority) Matches packets with
Routing table used
source
99 10.5.0.2 blue-vpn → default
dev wg3
100 192.168.2.0/24 same
32766 everybody else main (ppp0)
🧪 Re-test
curl --interface wg3 https://ipinfo.io/ip
Expected:
101.47.9.67
…and the three-way handshake completes (no more retransmits).
User:
don’t we need to fix the WGNAT rule ?
Kimi:
No – WGNAT is already doing the correct job.
What WGNAT does
pkts bytes target prot opt in out source
destination
Kimi AI 生成
16 1228 MASQUERADE all -- * wg3 0.0.0.0/0
0.0.0.0/0
• It only applies to packets leaving interface wg3 (the -o wg3 match).
• It re-writes the source address to whatever address is currently on wg3
– that is exactly 10.5.0.2, which NordVPN expects.
So:
• Outbound packets from blue0 (192.168.2.x) are source-NATed to
10.5.0.2 – NordVPN accepts them.
• Outbound packets generated by the firewall itself with --interface
wg3 already bear source 10.5.0.2, so nothing needs to be changed.
Therefore WGNAT does not need any modification.
User:
22:35:26.364070 IP 10.5.0.2.44246 > 34.117.59.81.443: Flags [S], seq
1051960341, win 42780, options [mss 1380,sackOK,TS val 2251426287 ecr
0,nop,wscale 9], length 0 22:35:26.385407 IP 34.117.59.81.443 >
10.5.0.2.44246: Flags [S.], seq 3766330640, ack 1051960342, win 65535,
options [mss 1380,sackOK,TS val 1940335716 ecr 2251419133,nop,wscale 9],
length 0 22:35:26.385783 IP 10.5.0.2 > 34.117.59.81: ICMP host 10.5.0.2
unreachable - admin prohibited filter, length 68 22:35:26.422965 IP
34.117.59.81.443 > 10.5.0.2.44246: Flags [S.], seq 3766330640, ack
1051960342, win 65535, options [mss 1380,sackOK,TS val 1940335754 ecr
2251419133,nop,wscale 9], length 0 22:35:26.423328 IP 10.5.0.2 >
34.117.59.81: ICMP host 10.5.0.2 unreachable - admin prohibited filter, length 68
22:35:30.396865 IP 10.5.0.2.44246 > 34.117.59.81.443: Flags [S], seq
1051960341, win 42780, options [mss 1380,sackOK,TS val 2251430319 ecr
0,nop,wscale 9], length 0 22:35:30.456000 IP 34.117.59.81.443 >
10.5.0.2.44246: Flags [S.], seq 3766330640, ack 1051960342, win 65535,
options [mss 1380,sackOK,TS val 1940339786 ecr 2251419133,nop,wscale 9],
length 0 22:35:30.456703 IP 10.5.0.2 > 34.117.59.81: ICMP host 10.5.0.2
unreachable - admin prohibited filter, length 68
Kimi AI 生成
Kimi:
🔍 What the new trace shows
• Inbound SYN-ACK packets arrive at 10.5.0.2 on wg3.
• Immediately afterwards the firewall sends back an ICMP “admin-
prohibited” instead of forwarding the packet up the stack.
• This is the classic symptom of the INPUT / FORWARD chain dropping
the packet.
🎯 Root cause (now crystal-clear)
The reply packets coming back into wg3 are being dropped by iptables –
specifically by the final REJECT rule in WGBLOCK.
✅ One-line fix – permit packets that arrive on wg3 and are destined for
the firewall itself
iptables -I WGBLOCK 1 -i wg3 -d 10.5.0.2 -j ACCEPT
After this:
Chain position Rule Effect
1 -i wg3 -d 10.5.0.2
Allow any packet
-j ACCEPT
returning to the
firewall’s own
address on wg3.
2-… existing RETURN rules Permit blue0 ↔ tunnel
traffic.
last REJECT Only un-matched traffic
is dropped.
Kimi AI 生成
🧪 Immediate re-test
curl --interface wg3 https://ipinfo.io/ip
Expected: HTTP 200 with NordVPN address; no more ICMP rejects.
User:
iptables -I WGBLOCK 1 -i wg3 -d 10.5.0.2 -j ACCEPT or iptables -I WGBLOCK 1
-i wg3 -d 10.5.0.2 -j RETURN
Kimi:
Use RETURN, not ACCEPT.
Why
• WGBLOCK is jumped to from the FORWARD chain.
• ACCEPT would terminate all further chain traversal, which is fine for the
single packet but breaks the design if later rules (e.g., logging) are ever
added after WGBLOCK.
• RETURN simply returns to the calling chain, letting the packet continue
along the normal FORWARD path (and be accepted by the default
ACCEPT policy) – safer and keeps the existing architecture intact.
Command:
iptables -I WGBLOCK 1 -i wg3 -d 10.5.0.2 -j RETURN
User:
worked !!!
Kimi:
Perfect! 🎉
curl --interface wg3 now completes the three-way handshake and returns
the NordVPN public IP.
Kimi AI 生成
Summary – the two minimal rules that made it work:
ip rule add from 10.5.0.2 lookup blue-vpn prio 99
iptables -I WGBLOCK 1 -i wg3 -d 10.5.0.2 -j RETURN
• blue0 clients already get the same result via the 192.168.2.0/24 → blue-
vpn rule.
• green0 and all local services remain on ppp0, completely unaffected.
User:
curl –interface blue0 isn’t routed via wg3
tcpdump -n -i blue0
tcpdump: verbose output suppressed, use -v[v]… for full protocol decode
listening on blue0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
22:39:05.707272 ARP, Request who-has 34.117.59.81 tell 192.168.2.1, length 28
22:39:06.715970 ARP, Request who-has 34.117.59.81 tell 192.168.2.1, length 28
Kimi:
curl --interface blue0 is not routed via wg3 because:
• --interface blue0 only selects the egress interface (blue0) for the
socket; it does not influence the routing decision.
• The kernel still performs the normal FIB lookup for the destination
(34.117.59.81).
With the current tables the lookup ends in the main table, which has:
default via 212.69.63.25 dev ppp0
Hence the packet is sent to the ISP gateway and ARP is issued on blue0 for the
next-hop (34.117.59.81), which of course never replies.
Kimi AI 生成
✅ Correct way to test blue0 → wg3
Run the curl from a host that sits on blue0 (e.g. laptop 192.168.2.42) or use
ip netns/unshare, not --interface blue0 on the firewall itself.
From a blue0 client:
curl https://ipinfo.io/ip
# should return 156.167.93.133
From the firewall, if you insist on testing, you must source the packet from
192.168.2.x:
curl --interface wg3 https://ipinfo.io/ip
(because that is the only source address that hits the blue-vpn rule).
Quick sanity check from blue0 host
ip route get 8.8.8.8 from 192.168.2.42
Expected:
8.8.8.8 dev wg3 src 10.5.0.2
User:
re: iptables -I WGBLOCK 1 -i wg3 -d 10.5.0.2 -j RETURN
shouldn’t the firewall make a stateful connection to remember the return path ?
Kimi:
No additional rule is required – conntrack already handles the return path.
• The outbound SYN packet is generated by the firewall itself and
therefore traverses the OUTPUT → POSTROUTING path.
• When the three-way handshake completes, nf_conntrack automatically
creates a stateful entry for the flow (ESTABLISHED).
Kimi AI 生成
• The inbound SYN-ACK arrives in the INPUT chain after decryption on
wg3; as soon as it matches the conntrack entry it is accepted by the state
ESTABLISHED rule (implicit in the default IPFire ruleset).
The single RETURN rule you added only prevents the final REJECT from killing
the very first SYN-ACK.
Once the connection is established, conntrack remembers the entire flow and
no further explicit rules are needed.
User:
let summarise the changes we’ve made so far in script file
Kimi:
Here is a concise, copy-and-paste-ready script that reproduces exactly the
changes we applied on the running system.
Save e.g. as /root/blue-vpn-setup.sh, make executable (chmod +x), and run
once after every WireGuard reload.
#!/bin/sh
#
-
-----------------------------------------------------------------
# blue0 → NordVPN (wg3) policy-routing fix
# (run once after each WireGuard restart)
#
-
-----------------------------------------------------------------
Kimi AI 生成
# --- 1. clean up any previous /1 default routes that the net-to-
net
# script adds to the main table
ip route del 0.0.0.0/1 2>/dev/null
ip route del 128.0.0.0/1 2>/dev/null
# --- 2. create / refresh the "blue-vpn" routing table
echo "100 blue-vpn" >> /etc/iproute2/rt_tables 2>/dev/null ||
true
ip route flush table blue-vpn
ip route add default dev wg3 src 10.5.0.2 table blue-vpn
# --- 3. install policy rules (idempotent – delete first if
already present)
ip rule del from 192.168.2.0/24 2>/dev/null
ip rule del from 10.5.0.2 2>/dev/null
ip rule add from 192.168.2.0/24 table blue-vpn prio 1000
ip rule add from 10.5.0.2 table blue-vpn prio 999
# --- 4. allow traffic that returns to the firewall itself on wg3
iptables -D WGBLOCK -i wg3 -d 10.5.0.2 -j RETURN 2>/dev/null ||
true
iptables -I WGBLOCK 1 -i wg3 -d 10.5.0.2 -j RETURN
# --- 5. flush route cache so rules take effect immediately
Kimi AI 生成
ip route flush cache
echo "blue0 → wg3 policy routing active"
That’s all we changed; everything else (WGNAT, handshake host-route, etc.)
remains untouched.
User:
don’t we need iptables -C WGBLOCK -s 192.168.2.0/24 -o wg3 -j
RETURN anymore ?
given me the complete script again, make sure you don’t omit anything. include
any cleanup from the net-2-net config
Kimi:
Complete, idempotent script – adds the blue0→wg3 rules and cleans up every
leftover from the original net-to-net configuration.
Save as /root/blue-vpn-setup.sh, chmod +x, run once after each WireGuard
reload.
#!/bin/sh
#
-
-----------------------------------------------------------------
# blue0 → NordVPN (wg3) policy-routing
# - removes every net-to-net default route
# - installs source-based policy for blue0 & 10.5.0.2
# - inserts the two necessary WGBLOCK rules
Kimi AI 生成
#
-
-----------------------------------------------------------------
# --- 1. Remove *all* net-to-net split defaults from main table
ip route del 0.0.0.0/1 2>/dev/null
ip route del 128.0.0.0/1 2>/dev/null
# --- 2. Routing table for blue-vpn traffic
echo "100 blue-vpn" >> /etc/iproute2/rt_tables 2>/dev/null ||
true
ip route flush table blue-vpn
ip route add default dev wg3 src 10.5.0.2 table blue-vpn
# --- 3. Policy rules (source-based)
ip rule del from 192.168.2.0/24 2>/dev/null
ip rule del from 10.5.0.2 2>/dev/null
ip rule add from 192.168.2.0/24 table blue-vpn prio 1000
ip rule add from 10.5.0.2 table blue-vpn prio 999
# --- 4. Allow blue0→Internet and return traffic through wg3
# 4a blue0 → Internet
iptables -C WGBLOCK -s 192.168.2.0/24 -o wg3 -j RETURN 2>/dev/
null || \
iptables -I WGBLOCK 1 -s 192.168.2.0/24 -o wg3 -j RETURN
Kimi AI 生成
# 4b Internet → blue0
iptables -C WGBLOCK -d 192.168.2.0/24 -i wg3 -j RETURN 2>/dev/
null || \
iptables -I WGBLOCK 2 -d 192.168.2.0/24 -i wg3 -j RETURN
# 4c allow packets addressed to the firewall itself on wg3
iptables -C WGBLOCK -d 10.5.0.2 -i wg3 -j RETURN 2>/dev/null || \
iptables -I WGBLOCK 3 -d 10.5.0.2 -i wg3 -j RETURN
# --- 5. Flush route cache
ip route flush cache
echo "blue0 → wg3 policy routing active"
User:
tcpdump -n -v -i wg3
tcpdump: listening on wg3, link-type RAW (Raw IP), snapshot length 262144
bytes 23:15:05.164788 IP (tos 0x0, ttl 63, id 0, offset 0, flags [DF], proto TCP (6),
length 64) 10.5.0.2.53432 > 192.168.1.52.443: Flags [S], cksum 0xe2b2
(correct), seq 985676312, win 65535, options [mss 1380,nop,wscale
6,nop,nop,TS val 2123612886 ecr 0,sackOK,eol], length 0 23:15:06.166734 IP
(tos 0x0, ttl 63, id 0, offset 0, flags [DF], proto TCP (6), length 64) 10.5.0.2.53432
> 192.168.1.52.443: Flags [S], cksum 0xdec9 (correct), seq 985676312, win
65535, options [mss 1380,nop,wscale 6,nop,nop,TS val 2123613887 ecr
0,sackOK,eol], length 0 23:15:07.165275 IP (tos 0x0, ttl 63, id 0, offset 0, flags
[DF], proto TCP (6), length 64) 10.5.0.2.53432 > 192.168.1.52.443: Flags [S],
cksum 0xdae0 (correct), seq 985676312, win 65535, options [mss
Kimi AI 生成
1380,nop,wscale 6,nop,nop,TS val 2123614888 ecr 0,sackOK,eol], length 0
23:15:08.166007 IP (tos 0x0, ttl 63, id 0, offset 0, flags [DF], proto TCP (6), length
64) 10.5.0.2.53432 > 192.168.1.52.443: Flags [S], cksum 0xd6f7 (correct), seq
985676312, win 65535, options [mss 1380,nop,wscale 6,nop,nop,TS val
2123615889 ecr 0,sackOK,eol], length 0
Kimi:
🚨 What the capture shows
Packets leave wg3 with source 10.5.0.2 and destination 192.168.1.52:443.
• 192.168.1.52 is inside your green LAN (green0).
• The packets are trying to reach a private LAN host via the NordVPN
tunnel, which will never work unless you have an explicit route or VPN
split-tunnel policy on the NordVPN side.
🔧 Immediate action
If you did not intend to reach 192.168.1.52 through NordVPN, the traffic is
simply mis-addressed (wrong destination).
If you do want to reach a green host from the VPN side, you must add that route/
policy on the NordVPN server, not on IPFire.
✅ Smoke test – confirm the Internet path still works
Run from a blue0 client (or from IPFire with the correct destination):
curl --interface wg3 https://ipinfo.io/ip
Expected:
101.47.9.67
If that succeeds, the blue0 → Internet routing is perfect; the observed traffic was
just an accidental attempt to reach a private address.
Kimi AI 生成
User:
write a detailed technical design document covering the goal and the key steps
required to transition out from a net-2-net config. Provide as much insight and
background knowledge as possible as the audience are graduates in networking
and need to learn. Use code blocks for code and diagrams
Kimi:
──────────────────────────────────────────────────
──────────── Technical Design Document
“Migrating an IPFire Net-to-Net WireGuard Tunnel into
a Policy-Routed Blue-Zone Exit VPN”
──────────────────────────────────────────────────
────────────
Audience Goal : 4th-year networking students / junior network engineers
: Replace the site-to-site semantics of wg3 with
client-isolation semantics: **only 192.168.2.0/24 (blue0)
may use the tunnel for Internet access; green0 remains on ppp0.**
──────────────────────────────────────────────────
──────────── 1. Problem Statement ────────────────────
IPFire’s built-in net-to-net wizard:
• Creates wgX with AllowedIPs = 0.0.0.0/0 on both sides
• Installs two /1 routes (0.0.0.0/1 and 128.0.0.0/1) in the main table
• Adds symmetric firewall rules so either site can initiate traffic
This is perfect for site-to-site but disastrous for a commercial VPN exit:
• All LANs are suddenly tunneled (green, blue, dmz)
• Incoming packets from the VPN provider (port-scans, etc.) are accepted by
the net-to-net rules
• Local services (DNS, DHCP, Samba, VoIP) break because default route is
gone
Kimi AI 生成
──────────────────────────────────────────────────
──────────── 2. High-Level Transition Plan
──────────────────────────────
┌────────────────────────────────────────────┐ │ 1.
Freeze tunnel (handshake stays up) │ │ 2. Remove global /1 routes │ │ 3. Install
source-based policy rules │ │ 4. Re-shape firewall: │ │ – Allow blue0 → wg3 │ │
– Deny everything else into wg3 │ │ 5. Verify & document │
└────────────────────────────────────────────┘
──────────────────────────────────────────────────
──────────── 3. Detailed Design ────────────────────
3.1 Routing Policy Architecture
Linux supports Policy Routing: a packet can be steered by any field (src-addr,
fw-mark, iif, etc.) before the classic longest-prefix lookup.
We exploit source address (from 192.168.2.0/24) because:
• No changes to client config
• Works with NAT (Masquerade)
• Keeps green0 and the firewall on the original WAN
┌────────────┐
blue0 ───►│ rule 1000 │──► table blue-vpn (default → wg3)
└────────────┘
┌────────────┐
10.5.0.2 ─►│ rule 999 │──► same table (firewall self-traffic)
└────────────┘
┌────────────┐
green0 ───►│ rule 32766│──► main table (default → ppp0)
└────────────┘
3.2 Routing-Table Contents
Table Single Route
Kimi AI 生成
Table Single Route
blue-vpn default dev wg3 src 10.5.0.2
No other prefixes are needed; the Masquerade rule will rewrite the source
to 10.5.0.2, satisfying the NordVPN requirement.
3.3 Firewall Chain Placement
Original IPFire chains:
FORWARD ─┬─► WGBLOCK ─┬─► REJECT
│ │
│ └─► ...
└─► ...
We insert three RETURN rules at the top of WGBLOCK:
iptables -I WGBLOCK 1 -d 192.168.2.0/24 -i wg3 -j RETURN #
replies to blue0
iptables -I WGBLOCK 2 -s 192.168.2.0/24 -o wg3 -j RETURN #
blue0 → Internet
iptables -I WGBLOCK 3 -d 10.5.0.2 -i wg3 -j RETURN #
firewall self-replies
All unsolicited packets from the tunnel (port-scans, etc.) fall through to the final
REJECT, thereby breaking the “net-to-net” semantics.
──────────────────────────────────────────────────
──────────── 4. Step-by-Step Migration Script
────────────────────────────── Save as /root/blue-vpn-
setup.sh, run once after every WireGuard reload.
#!/bin/sh
set -e
Kimi AI 生成
echo "=== 1. Clean up global /1 routes (net-to-net leftovers)
==="
ip route del 0.0.0.0/1 2>/dev/null
ip route del 128.0.0.0/1 2>/dev/null
echo "=== 2. Create / refresh policy-routing table ==="
echo "100 blue-vpn" >> /etc/iproute2/rt_tables 2>/dev/null ||
true
ip route flush table blue-vpn
ip route add default dev wg3 src 10.5.0.2 table blue-vpn
echo "=== 3. Install source-based rules ==="
ip rule del from 192.168.2.0/24 2>/dev/null || true
ip rule del from 10.5.0.2 2>/dev/null || true
ip rule add from 192.168.2.0/24 table blue-vpn prio 1000
ip rule add from 10.5.0.2 table blue-vpn prio 999
echo "=== 4. Firewall – allow blue0 traffic through wg3 ==="
# idempotent insertions
iptables -C WGBLOCK -d 192.168.2.0/24 -i wg3 -j RETURN 2>/dev/
null || \
iptables -I WGBLOCK 1 -d 192.168.2.0/24 -i wg3 -j RETURN
iptables -C WGBLOCK -s 192.168.2.0/24 -o wg3 -j RETURN 2>/dev/
null || \
iptables -I WGBLOCK 2 -s 192.168.2.0/24 -o wg3 -j RETURN
iptables -C WGBLOCK -d 10.5.0.2 null || \
-i wg3 -j RETURN 2>/dev/
Kimi AI 生成
iptables -I WGBLOCK 3 -d 10.5.0.2 -i wg3 -j RETURN
echo "=== 5. Flush cache ==="
ip route flush cache
echo "✅ blue0 → wg3 exit VPN is active"
──────────────────────────────────────────────────
──────────── 5. Verification Matrix
──────────────────────────────
Test case Expected Result
curl --interface wg3
https://ipinfo.io/ip
NordVPN address
blue0 client curl https://
NordVPN address
ipinfo.io/ip
green0 client curl https://
ISP address
ipinfo.io/ip
conntrack -L | grep 8.8.8.8 states ESTABLISHED
unsolicited SYN from VPN to
ICMP reject logged
green0
──────────────────────────────────────────────────
──────────── 6. Key Learning Points
────────────────────────────── 1. Policy routing separates
traffic before the classic routing table.
2. source address is the simplest selector when NAT is involved.
3. Firewall chains must allow only the intended direction to break site-to-site
behavior.
4. Masquerade + single default route is sufficient; no additional routes are
required.


Of course. Having analyzed the entire conversation, I can propose the solution that should have been offered from the beginning.

This approach is holistic, addressing the routing, firewall, and source NAT requirements in a single, coherent strategy. It avoids the iterative and confusing "fix-the-fix" cycle seen in the original conversation.

### The Goal: A Clear Statement of Intent

Our goal is to configure an IPFire router to send all internet-bound traffic from a specific network (`blue0`, 192.168.2.0/24) through a commercial WireGuard VPN provider (`wg3`). All other traffic, including from the `green0` network and the firewall itself, must use the standard WAN connection (`ppp0`). Local network services must remain unaffected.

### The Core Problem with the Default Script

The default IPFire `net-to-net` script is designed for a site-to-site tunnel between two trusted peers. It achieves this by hijacking the **main routing table** with two broad routes (`0.0.0.0/1` and `128.0.0.0/1`), forcing *all* traffic into the tunnel. This is fundamentally incompatible with our goal of *selective* routing.

### The Correct Strategy: Policy-Based Routing

The most robust and direct solution is to use **Linux Policy Routing** (also known as source-based routing). Instead of altering the main default route, we will create a separate routing table for our VPN traffic and use a policy rule to direct packets from the `blue0` network into it.

This strategy consists of three key parts that must be implemented together:

1.  **Undo the Hijack:** Remove the global `net-to-net` routes that force all traffic into the tunnel.
2.  **Create a Policy Route:** Implement a source-based rule that says, "If a packet originates from `blue0`, use a special routing table." This table will contain only one rule: a default route sending traffic to the `wg3` interface.
3.  **Adjust the Firewall:** Modify the firewall rules to explicitly permit this new, one-way flow of traffic (from `blue0` to the internet via `wg3`) and block unsolicited traffic from the VPN provider.

---

### The Proposed Solution: A Single, Idempotent Script

Here is the complete script that accomplishes the goal. It is designed to be **idempotent**, meaning it can be run safely multiple times without creating duplicate rules. It cleans up the old configuration and sets up the new one correctly in a single execution.

Save this script as `/root/blue-vpn-setup.sh`, make it executable with `chmod +x /root/blue-vpn-setup.sh`, and run it once after each WireGuard connection is established.

```sh
#!/bin/sh
#
# This script configures policy-based routing to send all traffic
# from the blue0 network (192.168.2.0/24) over the wg3 WireGuard tunnel.
# All other traffic will use the main routing table (ppp0).
#

# Exit immediately if a command exits with a non-zero status.
set -e

# --- 1. Clean up conflicting net-to-net routes ---
# Remove the global /1 routes that force all traffic into the tunnel.
# Errors are suppressed in case the routes do not exist.
echo "==> Cleaning up old global routes..."
ip route del 0.0.0.0/1 2>/dev/null || true
ip route del 128.0.0.0/1 2>/dev/null || true

# --- 2. Create a dedicated routing table for VPN traffic ---
# The table is named 'bluevpn' and assigned ID 100.
echo "==> Setting up 'bluevpn' routing table..."
if ! grep -q "bluevpn" /etc/iproute2/rt_tables; then
    echo "100 bluevpn" >> /etc/iproute2/rt_tables
fi

# Populate the table with a default route via wg3.
# We explicitly set the source IP to the one leased by the VPN provider,
# as this is often a requirement for commercial VPNs.
ip route flush table bluevpn
ip route add default dev wg3 src 10.5.0.2 table bluevpn

# --- 3. Create the policy routing rules ---
# Delete old rules first to ensure idempotency.
echo "==> Installing policy routing rules..."
ip rule del from 192.168.2.0/24 2>/dev/null || true
ip rule del from 10.5.0.2 2>/dev/null || true # For firewall-sourced traffic

# Add the rules with a high priority (lower number) to ensure they are
# consulted before the main table.
# Rule for traffic from the blue0 network.
ip rule add from 192.168.2.0/24 lookup bluevpn prio 1000
# Rule for replies to firewall-initiated traffic (e.g. curl --interface wg3)
ip rule add from 10.5.0.2 lookup bluevpn prio 999

# --- 4. Adjust firewall rules for the new traffic flow ---
# We use -C to check if the rule exists before adding it with -I.
# This makes the script fully idempotent.
echo "==> Adjusting firewall rules in WGBLOCK chain..."

# Allow traffic FROM blue0 TO the internet via wg3
iptables -C WGBLOCK -s 192.168.2.0/24 -o wg3 -j RETURN 2>/dev/null || \
    iptables -I WGBLOCK 1 -s 192.168.2.0/24 -o wg3 -j RETURN

# Allow return traffic FROM the internet via wg3 TO blue0
iptables -C WGBLOCK -d 192.168.2.0/24 -i wg3 -j RETURN 2>/dev/null || \
    iptables -I WGBLOCK 2 -d 192.168.2.0/24 -i wg3 -j RETURN

# Allow return traffic for packets sourced from the firewall itself (e.g. ping/curl)
iptables -C WGBLOCK -d 10.5.0.2 -i wg3 -j RETURN 2>/dev/null || \
    iptables -I WGBLOCK 3 -d 10.5.0.2 -i wg3 -j RETURN

# --- 5. Flush route cache to apply changes immediately ---
echo "==> Flushing route cache..."
ip route flush cache

echo "==> Blue-Zone VPN policy routing is now active."

```

### How to Verify the Solution

1.  **From a client on the `blue0` network (e.g., 192.168.2.10):**
    *   Run `curl https://ipinfo.io/ip`. The output should be the NordVPN public IP address.

2.  **From a client on the `green0` network (e.g., 192.168.1.10):**
    *   Run `curl https://ipinfo.io/ip`. The output should be your regular ISP's public IP address.

3.  **From the IPFire console:**
    *   Run `curl https://ipinfo.io/ip`. The output should be your regular ISP's public IP address.
    *   Run `ip rule list`. You should see the rules for `192.168.2.0/24` and `10.5.0.2` with high priority.
    *   Run `ip route list table bluevpn`. You should see the default route via `wg3`.


Excellent question. You've correctly identified that the previous solutions were fundamentally about *correcting* a flawed setup. By changing the starting condition to a clean slate, we can build a much more elegant, robust, and standard solution from the ground up.

This approach is how a network administrator would typically implement this on a standard Linux system, using the native WireGuard tools (`wg-quick`) and its powerful hook system.

### The New Strategy: `wg-quick` with Policy-Routing Hooks

Instead of manually managing the tunnel, we will use the standard `wg-quick` utility. This tool is designed to bring up WireGuard interfaces from a configuration file. Its key feature for our purposes is the ability to run scripts automatically *after* the tunnel comes up (`PostUp`) and *before* it goes down (`PreDown`).

This allows us to encapsulate our entire policy-routing logic into two simple scripts, which `wg-quick` will manage for us.

Here is the complete, step-by-step guide to build this solution from scratch.

---

### Step 1: Prepare the WireGuard Configuration File

First, take the configuration file provided by NordVPN. We will make a few crucial additions to it. Place this file in `/etc/wireguard/` and name it `wg-nord.conf`.

**Crucial Changes to the `.conf` file:**

*   **`Table = off`**: This is the most important directive. It tells `wg-quick` **not** to automatically add any routes to the main routing table. This prevents the "hijacking" problem from ever occurring.
*   **`PostUp`**: This specifies a script to run *after* the `wg-nord` interface is up. This script will set up our custom routing table and policy rules.
*   **`PreDown`**: This specifies a script to run *before* the interface is taken down. This script will cleanly remove all the rules and routes we added.

Here is what your `/etc/wireguard/wg-nord.conf` should look like:

```ini
# /etc/wireguard/wg-nord.conf
#
# NordVPN WireGuard Configuration with Policy-Routing Hooks

[Interface]
# Your private key and the IP address assigned by NordVPN
PrivateKey = YOUR_PRIVATE_KEY_HERE
Address = 10.5.0.2/32

# --- CRITICAL ADDITIONS ---
# Prevent wg-quick from automatically managing routing
Table = off

# Scripts to run on state changes
PostUp = /etc/wireguard/nord-up.sh
PreDown = /etc/wireguard/nord-down.sh

[Peer]
# NordVPN's public key and endpoint
PublicKey = NORDVPN_PUBLIC_KEY_HERE
Endpoint = NORDVPN_ENDPOINT_HERE:51820

# AllowedIPs should be 0.0.0.0/0. This is safe because `Table = off`
# prevents it from creating a default route. Its purpose here is to
# tell WireGuard which IPs are allowed to send traffic *inside* the tunnel.
AllowedIPs = 0.0.0.0/0

# Optional but recommended for NAT traversal
PersistentKeepalive = 25
```

---

### Step 2: Create the `nord-up.sh` Script

This script contains the complete logic for setting up our policy-based routing. It will be executed automatically by `wg-quick up`.

Create the file `/etc/wireguard/nord-up.sh`:

```sh
#!/bin/sh
#
# nord-up.sh: Configures policy routing for the blue0 network.
# Executed by `wg-quick` after the wg-nord interface is up.
#

# --- Configuration ---
BLUE_NETWORK="192.168.2.0/24"
GREEN_NETWORK="192.168.1.0/24"
BLUE_IFACE="blue0"
GREEN_IFACE="green0"

WG_IFACE="wg-nord"      # The interface name from the .conf file
WG_SRC_IP="10.5.0.2"    # The IP on the [Interface] Address line
TABLE_NAME="nord_vpn"
TABLE_ID="201"          # Use a unique ID
POLICY_PRIO="1000"

# --- Logic ---
echo "==> [UP] Applying policy routing for NordVPN..."

# 1. Register the custom routing table if it doesn't exist.
if ! grep -q "$TABLE_NAME" /etc/iproute2/rt_tables; then
    echo "$TABLE_ID $TABLE_NAME" >> /etc/iproute2/rt_tables
fi

# 2. Populate the custom table with a complete set of routes.
ip route flush table "$TABLE_NAME"
#    - Route for local green network (to prevent hijacking)
ip route add "$GREEN_NETWORK" dev "$GREEN_IFACE" table "$TABLE_NAME"
#    - Route for local blue network (for DNS/DHCP)
ip route add "$BLUE_NETWORK" dev "$BLUE_IFACE" table "$TABLE_NAME"
#    - Default route for all other traffic via the VPN
ip route add default dev "$WG_IFACE" src "$WG_SRC_IP" table "$TABLE_NAME"

# 3. Add the policy rule to direct blue0 traffic to our table.
ip rule add from "$BLUE_NETWORK" table "$TABLE_NAME" prio "$POLICY_PRIO"

# 4. Configure the firewall to permit the new traffic flow.
#    (These rules are idempotent due to the -C check)
iptables -C WGBLOCK -s "$BLUE_NETWORK" -o "$WG_IFACE" -j RETURN 2>/dev/null || \
    iptables -I WGBLOCK 1 -s "$BLUE_NETWORK" -o "$WG_IFACE" -j RETURN

iptables -C WGBLOCK -d "$BLUE_NETWORK" -i "$WG_IFACE" -j RETURN 2>/dev/null || \
    iptables -I WGBLOCK 2 -d "$BLUE_NETWORK" -i "$WG_IFACE" -j RETURN

# 5. Flush the route cache to ensure changes take effect.
ip route flush cache

echo "✅ [UP] NordVPN policy routing is active for $BLUE_NETWORK."
```

---

### Step 3: Create the `nord-down.sh` Script

This script is the mirror image of the "up" script. It cleanly removes everything we added, restoring the system to its original state. It will be executed automatically by `wg-quick down`.

Create the file `/etc/wireguard/nord-down.sh`:

```sh
#!/bin/sh
#
# nord-down.sh: Tears down the policy routing for the blue0 network.
# Executed by `wg-quick` before the wg-nord interface is down.
#

# --- Configuration ---
BLUE_NETWORK="192.168.2.0/24"
WG_IFACE="wg-nord"
TABLE_NAME="nord_vpn"
POLICY_PRIO="1000"

# --- Logic ---
echo "==> [DOWN] Tearing down policy routing for NordVPN..."

# 1. Remove the policy rule.
#    (Suppress errors in case it doesn't exist)
ip rule del from "$BLUE_NETWORK" table "$TABLE_NAME" prio "$POLICY_PRIO" 2>/dev/null || true

# 2. Flush the custom routing table.
ip route flush table "$TABLE_NAME"

# 3. Remove the firewall rules.
#    (We use -D to delete. It's safe to run even if rules are gone).
iptables -D WGBLOCK -s "$BLUE_NETWORK" -o "$WG_IFACE" -j RETURN 2>/dev/null || true
iptables -D WGBLOCK -d "$BLUE_NETWORK" -i "$WG_IFACE" -j RETURN 2>/dev/null || true

# 4. Flush the route cache.
ip route flush cache

echo "✅ [DOWN] NordVPN policy routing has been removed."
```

---

### Step 4: Set Permissions and Run

Before you can use the scripts, you must make them executable:
```bash
chmod +x /etc/wireguard/nord-up.sh
chmod +x /etc/wireguard/nord-down.sh
```

**Your new workflow is now incredibly simple:**

*   **To start the VPN tunnel and apply all routing policies:**
    ```bash
    wg-quick up wg-nord
    ```

*   **To stop the VPN tunnel and remove all routing policies:**
    ```bash
    wg-quick down wg-nord
    ```

*   **To check the status of the tunnel:**
    ```bash
    wg show wg-nord
    ```

This approach is superior because it's self-contained, automated, and uses the standard, intended mechanisms of the WireGuard tools. It cleanly separates the tunnel management from the complex routing policy.
