#!/bin/bash

# Checks if a port forwarding rule already exists for the given IP range.
# Returns true (0) if the rule exists, false (non-zero) otherwise.
is_active() {
  local ip_range="$1"
  iptables -C CUSTOMFORWARD -p tcp -d "${DEST}" --dport "${DPORT}" -s "${ip_range}" -j ACCEPT &>>/dev/null
  iptables -t nat -C NAT_DESTINATION -p tcp -s "${ip_range}" -d "${RED_IP}" --dport "${DPORT}" -j DNAT --to-destination "${DEST}" &>>/dev/null
}

add_fwd_rule() {
  local IP_RANGE="$1"
  local DEST="$2"
  local DPORT="$3"

  if ! is_active "$IP_RANGE"; then
    # Rule does not exist, so we add it.
    echo "iptables -t nat -A NAT_DESTINATION -p tcp -s ${IP_RANGE} -d ${RED_IP} --dport ${DPORT} -j DNAT --to-destination ${DEST}"
    echo "iptables -A CUSTOMFORWARD -p tcp -s ${IP_RANGE} -d ${DEST} --dport ${DPORT} -j ACCEPT"
  else
    # Rule already exists, so we report it and do nothing.
    echo "Rule for $IP_RANGE already exists. Skipping."
  fi
}

del_fwd_rule() {
  local IP_RANGE="$1"
  local DEST="$2"
  local DPORT="$3"

  if is_active "$IP_RANGE"; then
    # Rule exists, so we remove it.
    echo "iptables -t nat -D NAT_DESTINATION -p tcp -s ${IP_RANGE} -d ${RED_IP} --dport ${DPORT} -j DNAT --to-destination ${DEST}"
    echo "iptables -D CUSTOMFORWARD -p tcp -s ${IP_RANGE} -d ${DEST} --dport ${DPORT} -j ACCEPT"
  else
    # Rule already exists, so we report it and do nothing.
    echo "Rule for $IP_RANGE does not exist. Skipping."
  fi
}

process_port_fwd_rules() {
  local func="$1"
  local IP_RANGES="$2"
  local DEST="$3"
  local DPORT="$4"

  echo "Processing IP ranges..."
  # Loop through each IP range
  for ip_range in $IP_RANGES; do

    if [[ -z "$ip_range" ]]; then
      echo "Skipping empty entry..."
      continue # Go to the next item in the loop
    else
      $func "$ip_range" "$DEST" "$DPORT"
    fi
  done
}

# Main program
# ===============================================================

# Check for the correct number of arguments
[ "$#" -ne 3 ] && {
  echo "Error: Invalid number of arguments."
  echo "Usage: $0 [add|del] <destination_ip> <destination_port>"
  exit 1
}

ACTION=$1
DEST=$2
DPORT=$3

# Validate the action
[[ "$ACTION" != "add" && "$ACTION" != "del" ]] && {
  echo "Error: Invalid action '$ACTION'. Must be 'add' or 'del'."
  exit 1
}
# Validate the IP format
echo "$DEST" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$' || {
  echo "Error: Invalid destination IP format for '$DEST'."
  exit 1
}
# Validate the Port format
echo "$DPORT" | grep -qE '^[0-9]+$' || {
  echo "Error: Port must be a number, but got '$DPORT'."
  exit 1
}

echo "Fetching Cloudflare IP ranges..."
# Fetch IP ranges and handle potential curl errors
IP_RANGES=$(curl -s https://www.cloudflare.com/ips-v4)
if [ -z "$IP_RANGES" ]; then
  echo "Error: Failed to fetch IP ranges from Cloudflare. Exiting."
  exit 1
fi

case "$ACTION" in
"add")
  process_port_fwd_rules "add_fwd_rule" "$IP_RANGES" "$DEST" "$DPORT"
  echo "Firewall rules updated."
  ;;
"del")
  process_port_fwd_rules "del_fwd_rule" "$IP_RANGES" "$DEST" "$DPORT"
  echo "Firewall rules removed."
  ;;
esac
