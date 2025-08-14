# Selective Policy-Based Routing for WireGuard on IPFire

## 1. Overview

This document details the design and implementation of a robust system for routing traffic from a specific internal network (`blue0`) through a commercial WireGuard VPN provider i.e. NordVPN, while ensuring all other traffic uses the standard WAN connection. This solution was developed for the IPFire firewall distribution, specifically on a system where the `wg-quick` utility is unavailable.

The final product is a single, standalone control script that manages the entire lifecycle of the VPN connection, including the routing policies and firewall rules required for this selective routing to work securely and reliably.

**Goal:**
-   Traffic from the **Blue Zone** (`192.168.2.0/24`) must exit to the internet via the NordVPN tunnel.
-   Traffic from the **Green Zone** (`192.168.1.0/24`) and the firewall itself must use the primary WAN connection.
-   Local services on the firewall (DNS, DHCP) must remain accessible to all internal clients.
-   The connection must be secure, preventing traffic leaks if the VPN tunnel fails (a "kill switch").

## 2. Deconstructing the IPFire WireGuard Logic: Key Insights

We first had to understand how IPFire's default WireGuard implementation works. Our analysis revealed a system designed exclusively for site-to-site tunnels using predefined IPFire WireGuard profiles and such profiles must be used as files for completed the net-2-net peer setup. Use of road-warrior-like WireGuard profiles, can inadvertently expose WLAN/LAN to unsolicited Internet traffic by mismanaging endpoint exposure and route advertisement.

### Insight 1: The "Default Route Hijack"

-   **IPFire's Method:** When a `net-to-net` tunnel is created via the IPFire WebUI, its backend scripts modify the **main routing table**. They insert broad routes (`0.0.0.0/1`, `128.0.0.0/1`) that effectively force *all* traffic from all zones into the WireGuard tunnel.
-   **Problem:** This is an all-or-nothing approach. It does not allow for selective routing and breaks local services that expect to use the standard WAN connection.

### Insight 2: The `FORWARD` Chain is a Gauntlet

The main `FORWARD` chain in IPFire is not a simple list; it's a complex sequence of jumps to other chains that enforce IPFire's zone-based security model. A packet must navigate this entire sequence to be allowed. Our key finding was that our outbound VPN traffic was being dropped deep inside this logic.

-   **The Journey of a Dropped Packet:** A `NEW` packet from our `blue0` zone destined for the `wg10` interface (which is not a recognized zone) would pass through several chains (`CUSTOMFORWARD`, `WIRELESSFORWARD`, etc.) without finding a specific `ACCEPT` rule. It would eventually be passed to the **`POLICYFWD`** chain, which contains a final, catch-all `DROP` rule. This is where our traffic was dying.

### Insight 3: The `WGBLOCK` Chain is a One-Way Street

Our initial assumption was to use the `WGBLOCK` chain, as it seemed designed for WireGuard. However, a closer look at the `FORWARD` chain revealed the truth:

```
# Rule #9 in the FORWARD chain
target     prot opt in     out     source
WGBLOCK    all  --  wg+    *       0.0.0.0/0
```

-   **The Critical Detail:** The rule only matches on the **input interface (`-i wg+`)**. This means `WGBLOCK` is designed *only* to filter traffic **coming from** a WireGuard peer **into** your network. It is never consulted for traffic **going out to** a WireGuard peer.
-   **Conclusion:** Using `WGBLOCK` for our outbound `ACCEPT` rule was incorrect because our packets would never be sent to that chain in the first place.

### Insight 4: The Power of Official "Hooks"

The solution to navigating the complex `FORWARD` chain was not to try and modify it, but to use the official "hooks" provided by the IPFire developers.

-   **`CUSTOMFORWARD`:** This chain is called from **Rule #3** of the `FORWARD` chain, placing it *before* all the complex zone logic and the final `DROP` rule. By placing our `ACCEPT` rules here, we create a "VIP pass" for our VPN traffic, allowing it to be approved and forwarded before it can get lost in the main firewall logic.

-   **`CUSTOMPOSTROUTING`:** Similarly, this chain is the official hook for adding custom NAT rules. It is processed before the system's own NAT chains, ensuring our `MASQUERADE` rule is applied correctly and is safe from being overwritten by system updates. `WGNAT` postrouting chain was also considered.

## 3. Designing the Custom Solution

Armed with these insights, we designed a solution that avoids the "default route hijack" and instead uses a more precise and powerful Linux networking feature: **Policy-Based Routing**.

## 3. The Final Architecture

Our final, working solution is built upon these insights. It respects the IPFire framework and uses policy-based routing to achieve its goal.

1.  **Independent Interface Management:** The script manually creates and configures the `wg10` interface, avoiding any of IPFire's default "net-to-net" logic.

2.  **Policy-Based Routing:** We leave the main routing table untouched. An `ip rule` directs all traffic originating from `blue0` to a separate routing table (`blue-vpn`).

3.  **A Complete Custom Routing Table:** The `blue-vpn` table is a self-contained routing environment for `blue0` clients. It contains:
    -   Specific routes for all **local networks** to ensure local traffic (DNS, DHCP, inter-zone) is handled correctly and never enters the VPN.
    -   A **default route** sending all other traffic to the `wg10` interface.

4.  **IPFire-Native Firewall Integration:** We integrate cleanly and safely with the firewall:
    -   Our `MASQUERADE` rule is placed in the `CUSTOMPOSTROUTING` chain.
    -   Our `ACCEPT` rules for allowing `blue0` traffic to and from the tunnel are placed in the `CUSTOMFORWARD` chain.

### The Implementation: A Manual Control Script

Since `wg-quick` was unavailable, we built a single, self-contained script to orchestrate the low-level tools (`ip`, `wg`, `iptables`). This script acts as a service controller, accepting `start`, `stop`, and `show` commands.

* **do_start():** This function performs the entire setup sequence in the correct order:
    -   Creates the virtual wg10 interface.
    -   Assigns its IP address.
    -   Applies the cryptographic keys from the .conf file using wg setconf.
    -   Brings the interface up.
    -   Builds the custom routing table (blue-vpn) with both local and default routes.
    -   Inserts the necessary MASQUERADE and ACCEPT rules into the IPFire-native `CUSTOMPOSTROUTING` and `CUSTOMFORWARD` chains.
    -   Only after everything else is in place, it activates the policy by adding the ip rule.
* **do_stop()**: This function tears down the configuration in the reverse order, ensuring the system is returned to its original state.
* **do_show()**: A diagnostic function was added to provide a comprehensive overview of all components of our custom solution, making it easy to verify and troubleshoot.


## 4. How to Use This Solution

### Prerequisites

You must have a valid WireGuard configuration file from your VPN provider (e.g., NordVPN). This file should contain your `[Peer]` information, including their `PublicKey` and `Endpoint`.

### Step 1: Place the Files

1.  Save the final control script on your IPFire machine, for example `/root/nordvpn.sh`.
2.  Save your provider's WireGuard configuration file under the same location.

### Step 2: Configure the Files

1.  **Edit the Control Script (`/root/nordvpn.sh`):**
    -   Verify that the network variables (`BLUE_NETWORK`, `GREEN_NETWORK`, etc.) match your environment.
    -   Update `WG_LOCAL_IP` witht the `Address` value found within your provider's wireguard config
    -   Update `WG_CONF` to the location & name of your wireguard file

2.  **Edit the WireGuard Config File (`/root/your_wireguard.conf`):**
    -   Remove the `Address` & `DNS` entries; Leave only the `PrivateKey` entry to the `[Interface]` section.

### Step 3: Manual Control

You can now manage the VPN tunnel and all associated routing policies from the command line.

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
