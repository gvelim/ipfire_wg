#!/bin/sh
#
# =================================================================
# Manual Control Script for NordVPN Policy-Routed Tunnel
# =================================================================
# This script manages the full lifecycle of a WireGuard connection
# and applies the necessary policy routing and firewall rules.
# It is designed for systems without `wg-quick`.
#
# Usage: /root/nordvpn.sh {start|stop}
# -----------------------------------------------------------------

# Exit immediately if a command fails
set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# --- Configuration ---
WG_CONF="./your_WireGuard.conf"
WG_LOCAL_IP="X.X.X.X/X" # The IP for our side of the tunnel
WG_IFACE="wg10"

BLUE_NETWORK="192.168.2.0/24"
BLUE_IFACE="blue0"
GREEN_NETWORK="192.168.1.0/24"
GREEN_IFACE="green0"

TABLE_NAME="blue-vpn"
TABLE_ID="202"
POLICY_PRIO="1000"

# --- Logic Functions ---

do_start() {
    if ip link show "${WG_IFACE}" >/dev/null 2>&1; then
        echo "✅ [INFO] Tunnel ${WG_IFACE} already appears to be active. No action taken."
        exit 0
    fi

    echo "### [START] Bringing up VPN tunnel: ${WG_IFACE}..."

   # 1. Create the WireGuard interface if it doesn't exist.
    ip link show "${WG_IFACE}" >/dev/null 2>&1 || ip link add "${WG_IFACE}" type wireguard

    # 2. Assign the local IP address to the interface.
    ip addr add "${WG_LOCAL_IP}" dev "${WG_IFACE}"

    echo "### [START] Activate wireguard VPN profile on ${WG_IFACE}..."

   # 3. Apply the cryptographic configuration from the file.
    #    `wg setconf` is used to apply a static configuration.
    wg setconf "${WG_IFACE}" "${WG_CONF}"

    # 4. Bring the interface UP.
    ip link set "${WG_IFACE}" up

    echo "==> [START] Interface is UP. Applying policy routing and routes..."

    # 5. Register the custom routing table.
    if ! grep -q "$TABLE_NAME" /etc/iproute2/rt_tables; then
        echo "$TABLE_ID $TABLE_NAME" >> /etc/iproute2/rt_tables
    fi

    # 6. Populate the custom routing table with a complete set of routes.
    ip route flush table "$TABLE_NAME"
    ip route add "$GREEN_NETWORK" dev "$GREEN_IFACE" table "$TABLE_NAME"
    ip route add "$BLUE_NETWORK" dev "$BLUE_IFACE" table "$TABLE_NAME"
    ip route add default dev "$WG_IFACE" table "$TABLE_NAME"

    echo "==> [START] Routing in place. Applying NAT & Forwarding firewall rules..."

    # 7. Configure Firewall: Custom NAT and Forwarding rules.
    iptables -t nat -A CUSTOMPOSTROUTING -o "${WG_IFACE}" -j MASQUERADE
    iptables -I WGBLOCK 1 -s "$BLUE_NETWORK" -o "$WG_IFACE" -j RETURN
    iptables -I WGBLOCK 2 -d "$BLUE_NETWORK" -i "$WG_IFACE" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN

    echo "==> [START] NAT & Forwarding rules in place. Activating policy routing ..."

    # 8. Add the policy rule.
    ip rule add from "$BLUE_NETWORK" table "$TABLE_NAME" prio "$POLICY_PRIO"

    # 9. Flush route cache.
    ip route flush cache

    echo "✅ [START] VPN tunnel and policy routing are active."
}

do_stop() {
    echo "==> [STOP] Removing policy routing..."

    # 1. Remove the policy rule.
    ip rule del from "$BLUE_NETWORK" table "$TABLE_NAME" prio "$POLICY_PRIO" 2>/dev/null || true

    echo "==> [STOP] Removing routes..."

    # 2. Flush the custom routing table (for good measure).
    ip route flush table "$TABLE_NAME" 2>/dev/null || true

    # 4. Flush route cache.
    ip route flush cache

    echo "==> [STOP] Removing NAT & Forwarding rules..."

    # 3. Remove Firewall rules.
    iptables -t nat -D CUSTOMPOSTROUTING -o "${WG_IFACE}" -j MASQUERADE 2>/dev/null || true
    iptables -D WGBLOCK -s "$BLUE_NETWORK" -o "$WG_IFACE" -j RETURN 2>/dev/null || true
    iptables -D WGBLOCK -d "$BLUE_NETWORK" -i "$WG_IFACE" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN 2>/dev/null || true

    echo "### [STOP] Tearing down ${WG_IFACE}..."

    # 5. Remove the interface. This is the cleanest way to stop everything.
    #    It automatically removes associated routes and state.
    ip link del "${WG_IFACE}" 2>/dev/null || true

    echo "✅ [STOP] VPN tunnel and all associated rules have been removed."
}

do_show() {
    echo "=== [SHOW] VPN Configuration Status ==="
    echo ""

    echo "### Routing table 'blue-vpn':"
    ip route list table blue-vpn 2>/dev/null || echo "❌ Table 'blue-vpn' not found or empty"
    echo ""

    echo "### Policy routing rules:"
    ip rule show
    echo ""

    echo "### WGBLOCK firewall rules:"
    iptables -L WGBLOCK -n -v 2>/dev/null || echo "❌ WGBLOCK chain not found"
    echo ""

    echo "### CUSTOMPOSTROUTING NAT rules:"
    iptables -t nat -L CUSTOMPOSTROUTING -n -v 2>/dev/null || echo "❌ CUSTOMPOSTROUTING chain not found"
    echo ""

    echo "### WireGuard interface status:"
    if ip link show "${WG_IFACE}" >/dev/null 2>&1; then
        echo "### WireGuard configuration:"
        wg show "${WG_IFACE}" 2>/dev/null || echo "❌ WireGuard config not available"
        echo ""
        echo "### Interface addresses:"
        ip addr show "${WG_IFACE}"
    else
        echo "❌ WireGuard interface ${WG_IFACE} not found"
    fi
    echo ""

    echo "=== [SHOW] Status complete ==="
}


# --- Main Execution ---
case "$1" in
    start)
        do_start
        ;;
    stop)
        do_stop
        ;;
    show)
        do_show
        ;;
    *)
        echo "Usage: $0 {start|stop|show}"
        exit 1
        ;;
esac

exit 0
