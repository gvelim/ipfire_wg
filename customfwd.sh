#!/bin/bash

# Checks if a port forwarding rule already exists for the given IP range.
# Returns true (0) if the rule exists, false (non-zero) otherwise.
is_active() {
  local ip_range="$1"
  iptables -C CUSTOMFORWARD -p tcp -d "${DEST}" --dport "${DPORT}" -s "${ip_range}" -j ACCEPT &>>/dev/null
}

add_fwd_rule() {
  local IP_RANGE="$1"
  local DEST="$2"
  local DPORT="$3"

  if ! is_active "$IP_RANGE"; then
    # Rule does not exist, so we add it.
    echo "iptables -A CUSTOMFORWARD -p tcp -d ${DEST} --dport ${DPORT} -s ${IP_RANGE} -j ACCEPT"
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
    echo "iptables -D CUSTOMFORWARD -p tcp -d ${DEST} --dport ${DPORT} -s ${IP_RANGE} -j ACCEPT"
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
DEST=${2:?"destination IP is missing"}
DPORT=${3:?"destination port is missing"}

echo "Fetching Cloudflare IP ranges..."
# Fetch IP ranges and handle potential curl errors
IP_RANGES=$(curl -s https://www.cloudflare.com/ips-v4)
if [ -z "$IP_RANGES" ]; then
  echo "Error: Failed to fetch IP ranges from Cloudflare. Exiting."
  exit 1
fi

case "$1" in
"add")
  process_port_fwd_rules "add_fwd_rule" "$IP_RANGES" "$DEST" "$DPORT"
  echo "Firewall rules updated."
  ;;
"del")
  process_port_fwd_rules "del_fwd_rule" "$IP_RANGES" "$DEST" "$DPORT"
  echo "Firewall rules removed."
  ;;
*)
  echo "use: customfw [add|del] destination port"
  echo ""
  echo "sh ./customfwd add 192.168.1.50 443"
  ;;
esac
