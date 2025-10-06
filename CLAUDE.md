# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`ifwatch` is a Rust application using a query/response model over UDP to monitor network interface statistics on remote machines.

- **Server mode**: Runs on monitored machines, responds to queries with current interface stats
- **Query mode**: Polls remote servers for stats, outputs JSON or text format

Example usage:

Server: `ifwatch serve -i eth0,eth2 -p 12120`
Client: `ifwatch query -s 192.168.1.250 -p 12120`

Binary packet format (server responses):
- For each interface: length-prefixed name (1 byte length + name bytes)
- Followed by: rx_bytes (8), tx_bytes (8), rx_rate (8), tx_rate (8) - all big-endian

## Running as a systemd service (NixOS)

Example NixOS configuration to run ifwatch server:

```nix
{ config, pkgs, ... }:
let
  ifwatch = pkgs.rustPlatform.buildRustPackage rec {
    pname = "ifwatch";
    version = "0.1.0";

    src = pkgs.fetchFromGitHub {
      owner = "fjolliton";
      repo = "ifwatch";
      rev = "main";  # or specific commit/tag
      hash = ""; # Run once to get hash, then fill in
    };

    cargoHash = ""; # Run once to get hash, then fill in
  };
in
{
  systemd.services.ifwatch = {
    description = "Network Interface Statistics Server";
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];

    serviceConfig = {
      Type = "simple";
      ExecStart = "${ifwatch}/bin/ifwatch serve -i eth0,wlan0 -p 12120";
      Restart = "always";
      RestartSec = "5";

      # Security hardening
      DynamicUser = true;
      PrivateTmp = true;
      ProtectSystem = "strict";
      ProtectHome = true;
      NoNewPrivileges = true;
      PrivateDevices = false;  # Need access to /sys/class/net
      ReadOnlyPaths = [ "/sys/class/net" ];
    };
  };

  # Open firewall for UDP port
  networking.firewall.allowedUDPPorts = [ 12120 ];
}
```

To get the correct hashes:
1. Leave hash and cargoHash empty (`""`)
2. Run `nixos-rebuild build` - it will fail and show the expected hashes
3. Fill in the correct values and rebuild

## Notes

- Current Rust edition is 2024 (keep this as-is)
