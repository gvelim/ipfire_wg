# Selective Policy-Based Routing for WireGuard on IPFire

## 1. Overview

This document details the design and implementation of a robust system for routing traffic from a specific internal network (`blue0`) through a commercial WireGuard VPN provider (NordVPN), while ensuring all other traffic uses the standard WAN connection. This solution was developed for the IPFire firewall distribution, specifically on a system where the `wg-quick` utility is unavailable.

The final product is a single, standalone control script that manages the entire lifecycle of the VPN connection, including the complex routing policies and firewall rules required for this selective routing to work securely and reliably.

**Goal:**
-   Traffic from the **Blue Zone** (`192.168.2.0/24`) must exit to the internet via the NordVPN tunnel.
-   Traffic from the **Green Zone** (`192.168.1.0/24`) and the firewall itself must use the primary WAN connection.
-   Local services on the firewall (DNS, DHCP) must remain accessible to all internal clients.
-   The connection must be secure, preventing traffic leaks if the VPN tunnel fails (a "kill switch").

## 2. Deconstructing the IPFire WireGuard Logic: Key Insights

To build a custom solution, we first had to understand how IPFire's default WireGuard implementation works. Our analysis revealed a system designed for site-to-site tunnels, which is fundamentally at odds with our goal.

### Insight 1: The "Default Route Hijack"

-   **IPFire's Method:** When a `net-to-net` tunnel is created via the IPFire WebUI, its backend scripts modify the **main routing table**. They insert broad routes (`0.0.0.0/1`, `128.0.0.0/1`) that effectively force *all* traffic from all zones into the WireGuard tunnel.
-   **Problem:** This is an all-or-nothing approach. It does not allow for selective routing and breaks local services that expect to use the standard WAN connection.

### Insight 2: The `WGBLOCK` Firewall Chain

-   **IPFire's Method:** IPFire automatically creates a dedicated `iptables` chain called `WGBLOCK`. The firewall is configured to automatically pass all traffic coming from or going to any WireGuard interface (`wg+`) into this chain for evaluation.
-   **Key Feature:** This chain has a default-deny posture, ending in a `REJECT` rule. This is a powerful, built-in security feature.
-   **Our Strategy:** This is the designated "sandbox" for WireGuard traffic. We integrate with the system as intended by inserting our `ACCEPT` rules at the top of `WGBLOCK`.

### Insight 3: The `CUSTOMPOSTROUTING` NAT Chain

-   **IPFire's Method:** IPFire provides an official "hook" for custom NAT rules called `CUSTOMPOSTROUTING`.
-   **Our Strategy:** To ensure our NAT rule for the VPN traffic doesn't conflict with system-generated rules, we place our `MASQUERADE` rule here. This is the clean, "IPFire-native" way to handle NAT.

## 3. Designing the Custom Solution

Armed with these insights, we designed a solution that avoids the "default route hijack" and instead uses a more precise and powerful Linux networking feature: **Policy-Based Routing**.

### The Core Concept: Isolate the Routing Logic

The fundamental principle of our solution is to leave the main routing table completely untouched. Instead, we create a parallel routing universe for our `blue0` clients:

1.  **Create a Custom Routing Table:** We define a new routing table named `blue-vpn`.
2.  **Create a Policy Rule:** We use `ip rule add` to create a single, high-priority rule that acts as a traffic cop, instructing the kernel: *"If a packet's source address is within the `blue0` network, use the `blue-vpn` table to make the routing decision."*
3.  **Populate the Custom Table:** This was a critical insight. The `blue-vpn` table is a complete routing environment containing:
    -   Routes for all other **local networks** (`green0`, `blue0`) to prevent local traffic from leaking into the VPN.
    -   A **default route** that sends all other traffic to our `wg10` WireGuard interface.

### The Implementation: A Manual Control Script

Since `wg-quick` was unavailable, we built a single, self-contained script to orchestrate the low-level tools (`ip`, `wg`, `iptables`). This script acts as a service controller, accepting `start`, `stop`, and `show` commands.

* **do_start():** This function performs the entire setup sequence in the correct order:
    -   Creates the virtual wg10 interface.
    -   Assigns its IP address.
    -   Applies the cryptographic keys from the .conf file using wg setconf.
    -   Brings the interface up.
    -   Builds the custom routing table (blue-vpn) with both local and default routes.
    -   Inserts the necessary MASQUERADE and ACCEPT rules into the IPFire-native CUSTOMPOSTROUTING and WGBLOCK chains.
    -   Only after everything else is in place, it activates the policy by adding the ip rule.
* **do_stop()**: This function tears down the configuration in the reverse order, ensuring the system is returned to its original state.
* **do_show()**: A diagnostic function was added to provide a comprehensive overview of all components of our custom solution, making it easy to verify and troubleshoot.


## 4. How to Use This Solution

### Prerequisites

You must have a valid WireGuard configuration file from your VPN provider (e.g., NordVPN). This file should contain your `[Peer]` information, including their `PublicKey` and `Endpoint`.

### Step 1: Place the Files

1.  Save the final control script to `/root/nordvpn.sh` on your IPFire machine.
2.  Save your provider's WireGuard configuration file under the same location.

### Step 2: Configure the Files

1.  **Edit the Control Script (`/root/nordvpn.sh`):**
    -   Verify that the network variables (`BLUE_NETWORK`, `GREEN_NETWORK`, etc.) match your environment.
    -   Update `WG_LOCAL_IP` witht the `Address` value found within your wireguard config
    -   Update `WG_CONF` to the location & name of your wireguard file

2.  **Edit the WireGuard Config File (`/etc/wireguard/nordvpn_gr.conf`):**
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
