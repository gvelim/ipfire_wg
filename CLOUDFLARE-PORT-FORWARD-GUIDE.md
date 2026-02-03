# Cloudflare Port Forwarding Script - Technical Guide

## Overview

`cloudflare-port-forward.sh` is a Bash script designed for IPFire firewalls that automates the creation and removal of iptables rules to forward ports specifically for Cloudflare IP ranges. This enables secure exposure of services behind Cloudflare's reverse proxy while maintaining firewall protection.

## Purpose

- Automatically fetch Cloudflare's current IPv4 ranges
- Create/remove iptables rules to forward traffic from Cloudflare IPs to internal servers
- Prevent duplicate rule creation
- Provide visibility into existing rules

## firewall.local Integration

To ensure forwarding rules persist across firewall restarts or system reboots, integrate the script into IPFire's `firewall.local` mechanism.

Add a call to the script in `vim /etc/sysconfig/firewall.local`:

```
#!/bin/sh
# Used for private firewall rules

# See how we were called.
case "$1" in
  start)
        ## add your 'start' rules here
        sh /root/cloudflare-port-forward.sh add 192.168.1.52 443
        ;;
  stop)
        ## add your 'stop' rules here
        sh /root/cloudflare-port-forward.sh del 192.168.1.52 443
        ;;
  reload)
        $0 stop
        $0 start
        ## add your 'reload' rules here
        ;;
  *)
        echo "Usage: $0 {start|stop|reload}"
        ;;
esac
```

### Testing Integration

After updating `firewall.local`, test the configuration:

```bash
# Reload the firewall to apply the new rules
/etc/init.d/firewall restart

# Confirm the rules are active
/path/to/cloudflare-port-forward.sh show
```

**Important Notes:**

1. The script must be executable: `chmod +x /path/to/cloudflare-port-forward.sh`
2. Place the script in a persistent location (e.g., `/root/scripts/`)
3. The `firewall.local` file executes after the main firewall rules are loaded
4. Multiple port forwards require multiple script calls in `firewall.local`

## Technical Architecture

### Key Components

1. **IP Range Management**: Fetches real-time Cloudflare IPv4 ranges from `https://www.cloudflare.com/ips-v4`
2. **Rule Creation**: Creates two iptables rules per IP range:
   - DNAT rule in `CUSTOMPREROUTING` chain (nat table) for traffic redirection
   - ACCEPT rule in `CUSTOMFORWARD` chain (filter table) for traffic forwarding
3. **Interface Detection**: Automatically detects the `ppp0` interface IP as the redirection target
4. **Duplicate Prevention**: Checks for existing rules before creation

### IPFire Chain Integration

The script integrates with IPFire's custom firewall chains:

- **CUSTOMPREROUTING**: Custom chain in nat table, referenced by PREROUTING
- **CUSTOMFORWARD**: Custom chain in filter table, referenced by FORWARD

References

- [firewall.local](https://www.ipfire.org/docs/configuration/firewall/firewall-local)

## Usage

### Command Syntax

```bash
./cloudflare-port-forward.sh [add|del|show] <destination_ip> <destination_port>
```

### Actions

- **add**: Create forwarding rules for all Cloudflare IPv4 ranges
- **del**: Remove forwarding rules for all Cloudflare IPv4 ranges
- **show**: Display current rules in CUSTOMFORWARD and CUSTOMPREROUTING chains

### Examples

```bash
# Forward port 443 to internal server 192.168.1.100 for Cloudflare IPs
./cloudflare-port-forward.sh add 192.168.1.100 443

# Remove forwarding rules for port 443
./cloudflare-port-forward.sh del 192.168.1.100 443

# Show current rules
./cloudflare-port-forward.sh show
```

## Functions

### Core Functions

1. **`is_active()`**: Checks if rules already exist for a given IP range
2. **`add_fwd_rule()`**: Adds forwarding rules if they don't exist
3. **`del_fwd_rule()`**: Removes forwarding rules (with error suppression)
4. **`process_port_fwd_rules()`**: Processes all IP ranges with specified function
5. **`validate_ip()`**: Validates IP address format
6. **`validate_add_del_params()`**: Validates command parameters

### Rule Creation Logic

For each Cloudflare IP range, the script creates:

```bash
# NAT rule (redirects traffic)
iptables -t nat -A CUSTOMPREROUTING -p tcp -s <cloudflare_ip> -d <ppp0_ip> --dport <port> -j DNAT --to-destination <internal_ip>

# Forward rule (allows traffic)
iptables -A CUSTOMFORWARD -p tcp -s <cloudflare_ip> -d <internal_ip> --dport <port> -j ACCEPT
```

### IPFire Configuration Prerequisites

Ensure these chains exist in your IPFire configuration:

```bash
# In nat table
iptables -t nat -N CUSTOMPREROUTING
iptables -t nat -A PREROUTING -j CUSTOMPREROUTING

# In filter table
iptables -N CUSTOMFORWARD
iptables -A FORWARD -j CUSTOMFORWARD
```

## Error Handling

- Validates IP address format and port range (1-65535)
- Checks for `ppp0` interface availability
- Handles curl failures when fetching Cloudflare IPs
- Prevents duplicate rule creation
- Provides clear error messages for troubleshooting

### Debug Mode

Add `set -x` at the script beginning to enable debug output:

```bash
#!/bin/bash
set -x
# ... rest of script
```
