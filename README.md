# Policy-Based Routing for WireGuard on IPFire

## 1. Overview

This document describes the design and implementation of a system for routing traffic from a specific internal network (`blue0`) through a commercial WireGuard VPN provider (e.g., NordVPN), while maintaining the standard WAN for other zones.

The solution is provided as a single, standalone control script that manages the VPN connection, routing policies, and firewall rules required for this selective routing scenario.

**Goal:**
- Traffic from the **Blue Zone** (`192.168.2.0/24`) is routed to the internet via the NordVPN tunnel.
- Traffic from the **Green Zone** (`192.168.1.0/24`) and the firewall itself uses the primary WAN connection.
- Local services on the firewall (DNS, DHCP) remain accessible to all internal clients.
- The configuration is designed to prevent traffic leaks if the VPN tunnel fails (a "kill switch").

## 2. IPFire WireGuard Logic: Summary

The default IPFire WireGuard implementation is designed for site-to-site tunnels using predefined IPFire WireGuard profiles. This approach does not provide selective routing or integration with commercial VPNs for specific zones or interfaces.

### Routing Behavior

- **IPFire's Method:** Creating a `net-to-net` tunnel via the IPFire WebUI modifies the main routing table by inserting broad routes (`0.0.0.0/1`, `128.0.0.0/1`) that redirect all outbound traffic through the VPN tunnel.
- **Limitation:** This approach does not allow selective routing and can disrupt local services that expect to use the standard WAN connection.

### Firewall Chains

The main `FORWARD` chain in IPFire consists of a sequence of jumps between chains that enforce the zone-based security model. Packets must traverse several chains (e.g., `CUSTOMFORWARD`, `WGBLOCK`) before being accepted or dropped.

- **`WGBLOCK` Chain:** The `WGBLOCK` chain is configured to filter traffic originating from a WireGuard peer into the network. It does not process outbound traffic from internal zones to the VPN interface.

- **`CUSTOMFORWARD` and `CUSTOMPOSTROUTING`:** IPFire provides official hooks for adding custom firewall and NAT rules. These should be used to ensure rules are applied at the correct stage in packet processing.

## 3. Custom Solution Architecture

The custom solution uses Linux policy-based routing to selectively route traffic from `blue0` through the VPN tunnel without affecting other zones.

### Key Features

1. **Independent Interface Management:** The script manually creates and configures the `wg10` interface, separate from IPFire's default logic.
2. **Policy-Based Routing:** The main routing table remains unchanged. An `ip rule` is used to route all traffic from `blue0` to a dedicated routing table (`blue-vpn`).
3. **Custom Routing Table:** The `blue-vpn` table includes routes for all local networks (for DNS, DHCP, inter-zone traffic) and a default route via the `wg10` interface.
4. **Firewall Integration:**
   - The `MASQUERADE` rule is added to `CUSTOMPOSTROUTING`.
   - `ACCEPT` rules for `blue0` traffic to and from the tunnel are added to `CUSTOMFORWARD`.

### Control Script Functions

- **do_start():** Sets up the interface, routing table, firewall and NAT rules, and activates the policy routing.
- **do_stop():** Reverses the setup, removing rules and restoring the original state.
- **do_show():** Provides a diagnostic overview of the configuration for verification and troubleshooting.

## 4. Usage Instructions

### Prerequisites

- Obtain a valid WireGuard configuration file from your VPN provider (e.g., NordVPN). This file should include the `[Peer]` information, `PublicKey`, and `Endpoint`.

### Step 1: Place the Files

1. Save the control script on your IPFire machine (e.g., `/root/nordvpn.sh`).
2. Save your provider's WireGuard configuration file in the same location.

### Step 2: Configure the Files

1. **Edit the Control Script (`/root/nordvpn.sh`):**
   - Ensure the network variables (`BLUE_NETWORK`, `GREEN_NETWORK`, etc.) match your environment.
   - Update `WG_LOCAL_IP` with the `Address` value from your provider's WireGuard config.
   - Update `WG_CONF` with the location and name of your WireGuard file.
2. **Edit the WireGuard Config File (`/root/your_wireguard.conf`):**
   - Remove the `Address` and `DNS` entries. Only the `PrivateKey` entry should remain in the `[Interface]` section.

### Step 3: Manual Control

You can now manage the VPN tunnel and all associated routing policies from the command line.

- **To START the tunnel and apply all rules:**
  ```bash
  /root/nordvpn.sh start
  ```
- **To STOP the tunnel and remove all rules:**
  ```bash
  /root/nordvpn.sh stop
  ```
- **To SHOW the current status:**
  ```bash
  /root/nordvpn.sh show
  ```
