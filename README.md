# Policy-Based Routing for WireGuard on IPFire

## 1. Overview

This document details the design and implementation of a solution for routing traffic from a specific internal network (`blue0`) through a commercial WireGuard VPN provider (e.g., NordVPN), while ensuring all other traffic uses the standard WAN connection. This solution was developed for the IPFire firewall distribution, specifically on a system where the `wg-quick` utility is unavailable.

The solution is provided as a single, standalone control script that manages the VPN connection, routing policies, and firewall rules required for this selective routing scenario.

**Primary Goals:**
-   Traffic from the **Blue Zone** (`192.168.2.0/24`) must exit to the internet via the VPN tunnel.
-   Traffic from the **Green Zone** (`192.168.1.0/24`) and the firewall itself must use the primary WAN connection.
-   Local services on the firewall (DNS, DHCP) must remain accessible to all internal clients.

## 2. The Problem: IPFire's Net-to-Net Logic vs. Commercial VPNs

IPFire's WebUI provides distinct configurations for "Roadwarrior" (a single client connecting in) and "Net-to-Net" (connecting two networks) setups. Our analysis focuses on the conflict that arises when a commercial VPN profile—which is functionally a roadwarrior profile with a peer `AllowedIPs` of `0.0.0.0/0`—is used within IPFire's `net-to-net` logic. This specific mismatch triggers several problematic behaviors.

### Insight 1: The "Default Route Hijack"
When a `net-to-net` tunnel is created with a commercial VPN profile, IPFire's backend scripts interpret the `0.0.0.0/0` peer as "the entire internet." Consequently, they modify the **main routing table** by inserting broad routes (`0.0.0.0/1`, `128.0.0.0/1`) that force *all* traffic from all zones into the WireGuard tunnel. This all-or-nothing approach prevents selective routing and breaks local services.

### Insight 2: The `FORWARD` Chain Gauntlet
IPFire's main `FORWARD` firewall chain is a complex sequence of jumps to other chains. We discovered that `NEW` packets from our `blue0` zone destined for the `wg9` interface were being dropped by the final `DROP` rule in the `POLICYFWD` chain because there was no explicit `ACCEPT` rule for this non-standard traffic flow.

### Insight 3: Misinterpreting `WGBLOCK`
The `WGBLOCK` chain is designed to filter traffic *coming from* a WireGuard peer (`-i wg+`), not traffic *going out to* one. Attempting to place an outbound `ACCEPT` rule here is ineffective, as the traffic is never sent to this chain.

### Insight 4: The Power of Official "Hooks"
The correct way to integrate custom rules is via IPFire's custom hooks. By using the `CUSTOMFORWARD` and `CUSTOMPOSTROUTING` chains, our rules are processed early and are safe from being overwritten by system updates.

## 3. The Solution: Policy-Based Routing

To overcome these issues, we avoid IPFire's net-to-net logic entirely and use a more precise **Policy-Based Routing** strategy, orchestrated by a manual control script.

This approach leaves the main routing table untouched. Instead, a single `ip rule` identifies traffic from the Blue Zone (`192.168.2.0/24`) and directs it to a custom routing table (`blue-vpn`). This table provides a complete routing environment for VPN clients, containing:
1.  Routes for all local networks (Green, Blue) to ensure local traffic is handled correctly.
2.  A new default route that sends all other traffic through the `wg9` WireGuard interface.

Firewall integration is handled cleanly using the `CUSTOMFORWARD` and `CUSTOMPOSTROUTING` hooks for our `ACCEPT` and `MASQUERADE` rules, respectively.

## 4. Implementation: The `nordvpn.sh` Script

The entire process is managed by a self-contained script that accepts `start`, `stop`, and `show` commands. As `wg-quick` is unavailable on IPFire, the script uses the native `wg` command to configure the tunnel. This approach requires a minor modification to the commercial VPN profile, which is detailed in the configuration steps below.

-   **`do_start()`:** Performs the setup sequence in the correct order:
    1.  Creates the `wg9` virtual interface and assigns its IP address.
    2.  Applies the cryptographic keys from the `.conf` file using `wg setconf`.
    3.  Brings the interface up.
    4.  Builds the `blue-vpn` routing table with both local and default routes.
    5.  Inserts the necessary `MASQUERADE` and `ACCEPT` rules into the `CUSTOMPOSTROUTING` and `CUSTOMFORWARD` chains.
    6.  Activates the policy by adding the `ip rule` *after* all other components are in place.

-   **`do_stop()`**: Tears down the configuration in the reverse order, ensuring the system is returned to its original state. It removes the policy rule, flushes the routes and firewall rules, and finally deletes the WireGuard interface.

-   **`do_show()`**: Provides a comprehensive diagnostic overview of the routing table, policy rules, firewall chains, and WireGuard interface status, making it easy to verify and troubleshoot the configuration.

## 5. How to Use This Solution

### Prerequisites
You must have a valid WireGuard configuration file from your VPN provider. This file should contain your `[Peer]` information, including their `PublicKey` and `Endpoint`.

### Step 1: Place the Files
1.  Save the control script on your IPFire machine as `/root/nordvpn.sh`.
2.  Save your provider's WireGuard configuration file in the same location (e.g., `/root/your_wireguard.conf`).

### Step 2: Configure the Files
1.  **Edit the Control Script (`/root/nordvpn.sh`):**
    -   Verify that the network variables (`BLUE_NETWORK`, `GREEN_NETWORK`, etc.) match your environment.
    -   Update `WG_LOCAL_IP` with the local `Address` from your provider's config.
    -   Update `WG_CONF` to point to your WireGuard configuration file.

2.  **Edit the WireGuard Config File:**
    -   In the `[Interface]` section, remove the `Address` and `DNS` entries, leaving only your `PrivateKey`.

### Step 3: Manual Control
-   **To START the tunnel and apply all rules:**
    ```bash
    /root/nordvpn.sh start
    ```
-   **To STOP the tunnel and cleanly remove all rules:**
    ```bash
    /root/nordvpn.sh stop
    ```
-   **To SHOW the current status of the configuration:**
    ```bash
    /root/nordvpn.sh show
    ```
