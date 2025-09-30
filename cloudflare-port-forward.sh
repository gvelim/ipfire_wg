#!/bin/bash
#
# PURPOSE: Automates creation/removal of iptables rules to forward ports for Cloudflare IP ranges
# TECHNICAL OVERVIEW:
#   - Fetches current IPv4 ranges from Cloudflare's public API
#   - Creates two iptables rules per IP range:
#     1. DNAT rule in NAT_DESTINATION chain to redirect traffic to destination
#     2. ACCEPT rule in CUSTOMFORWARD chain to allow forwarded traffic
#   - Uses ppp0 interface IP as RED_IP (redirection target)
#   - Prevents duplicate rules via is_active() function checks
#
# IPFIRE CHAIN INSIGHTS:
#   - NAT_DESTINATION chain exist in nat table
#   - CUSTOMFORWARD chain exist in filter table
#   - NAT_DESTINATION chain is referenced by PREROUTING
#   - CUSTOMFORWARD chain is referenced by FORWARD
#
# USER GUIDE:
# ==========
# SYNOPSIS:
#   ./cloudflare-port-forward.sh ACTION DEST_IP PORT
# ACTIONS:
#   add  - Create forwarding rules for all Cloudflare IPv4 ranges
#   del  - Remove forwarding rules for all Cloudflare IPv4 ranges
#
# EXAMPLES:
#   # Forward port 443 to internal server 192.168.1.100 for Cloudflare IPs
#   sh ./cloudflare-port-forward.sh add 192.168.1.100 443
#
#   # Remove forwarding rules for port 443 from Cloudflare IPs
#   sh ./cloudflare-port-forward.sh del 192.168.1.100 443
#

# Checks if a port forwarding rule already exists for the given IP range.
# Returns true (0) if both rules exist, false (non-zero) otherwise.
is_active() {
  local ip_range="$1"
  local dest="$2"
  local dport="$3"
  local red_ip="$4"
  iptables -t nat -C CUSTOMPREROUTING -p tcp -s "${ip_range}" -d "${red_ip}" --dport "${dport}" -j DNAT --to-destination "${dest}" &>/dev/null &&
    iptables -C CUSTOMFORWARD -p tcp -s "${ip_range}" -d "${dest}" --dport "${dport}" -j ACCEPT &>/dev/null
}

add_fwd_rule() {
  local ip_range="$1"
  local dest="$2"
  local dport="$3"
  local red_ip="$4"
  if ! is_active "$ip_range" "$dest" "$dport" "$red_ip"; then
    # Rule does not exist, so we add it.
    iptables -t nat -A CUSTOMPREROUTING -p tcp -s "${ip_range}" -d "${red_ip}" --dport "${dport}" -j DNAT --to-destination "${dest}"
    iptables -A CUSTOMFORWARD -p tcp -s "${ip_range}" -d "${dest}" --dport "${dport}" -j ACCEPT
  else
    # Rule already exists, so we report it and do nothing.
    echo "Rule for ${ip_range} already exists. Skipping."
  fi
}

del_fwd_rule() {
  local ip_range="$1"
  local dest="$2"
  local dport="$3"
  local red_ip="$4"
  if is_active "$ip_range" "$dest" "$dport" "$red_ip"; then
    # Rule exists, so we remove it.
    iptables -t nat -D CUSTOMPREROUTING -p tcp -s "${ip_range}" -d "${red_ip}" --dport "${dport}" -j DNAT --to-destination "${dest}"
    iptables -D CUSTOMFORWARD -p tcp -s "${ip_range}" -d "${dest}" --dport "${dport}" -j ACCEPT
  else
    # Rule do not exist, so we report it and do nothing.
    echo "Rule for ${ip_range} does not exist. Skipping."
  fi
}

process_port_fwd_rules() {
  local func="$1"
  local ip_ranges="$2"
  local dest="$3"
  local dport="$4"
  local red_ip="$5"

  echo "Processing IP ranges..."
  # Loop through each IP range
  for ip_range in $ip_ranges; do
    # Skip empty entries from the input
    [[ -z "$ip_range" ]] && {
        echo "Skipping empty entry..."
        continue
    }
    "$func" "$ip_range" "$dest" "$dport" "$red_ip"
  done
}

validate_ip() {
  local ip="$1"
  if [[ $ip =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
    for octet in "${BASH_REMATCH[@]:1}"; do
      if ((octet > 255)); then
        return 1
      fi
    done
    return 0
  else
    return 1
  fi
}

validate_add_del_params() {
  # Check for the correct number of arguments
  if [ "$#" -ne 3 ]; then
    echo "Error: Invalid number of arguments."
    echo "Usage: $0 [add|del] <destination_ip> <destination_port>"
    return 1
  fi

  local dest="$2"
  local dport="$3"

  # Validate the IP format using a regex
  if ! validate_ip "$dest"; then
    echo "Error: Invalid destination IP format for '$dest'."
    return 1
  fi
  # Validate the Port format
  if ! [[ "$dport" =~ ^[0-9]+$ ]] || ((dport < 1 || dport > 65535)); then
      echo "Error: Port must be between 1 and 65535, but got '$dport'."
    return 1
  fi
}
# Main program
# ===============================================================

ACTION=$1
DEST=$2
DPORT=$3

case "$ACTION" in
"add" | "del")
  validate_add_del_params "$@" || exit 1

  RED_IP=$(ifconfig ppp0 | awk '/inet /{print $2}')
  if [ -z "$RED_IP" ]; then
    echo "Error: Could not determine IP for ppp0 interface. Is it up?"
    exit 1
  fi

  echo "Fetching Cloudflare IP ranges..."
  # Fetch IP ranges and handle potential curl errors
  IP_RANGES=$(curl -s https://www.cloudflare.com/ips-v4)
  if [ -z "$IP_RANGES" ]; then
    echo "Error: Failed to fetch IP ranges from Cloudflare. Exiting."
    exit 1
  fi

  if [ "$ACTION" == "add" ]; then
    process_port_fwd_rules "add_fwd_rule" "$IP_RANGES" "$DEST" "$DPORT" "$RED_IP"
    echo "Firewall rules added."
  else
    process_port_fwd_rules "del_fwd_rule" "$IP_RANGES" "$DEST" "$DPORT" "$RED_IP"
    echo "Firewall rules removed."
  fi
  ;;
"show")
  echo "=== CUSTOMFORWARD chain ==="
  iptables -L CUSTOMFORWARD -v -n
  echo "=== NAT_DESTINATION chain ==="
  iptables -t nat -L NAT_DESTINATION -v -n
  ;;
*)
  echo "Usage: $0 [add|del] <destination_ip> <destination_port>"
  echo "       $0 show"
  echo
  echo "Examples:"
  echo "  # Forward port 443 to internal server 192.168.1.100 for Cloudflare IPs"
  echo "  $0 add 192.168.1.100 443"
  echo
  echo "  # Remove forwarding rules for port 443 from Cloudflare IPs"
  echo "  $0 del 192.168.1.100 443"
  echo
  echo "  # Show current rules"
  echo "  $0 show"
  ;;
esac
