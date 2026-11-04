# Cisco device configs for the range

| File | What it is |
|---|---|
| `seeded_switch.cfg` | Catalyst 9300-style access switch. Fails 24 NDM/L2S STIG rules and carries 9 intrusion seeds (backdoor `netops2` privilege 15, SNMP `private` RW and `public`, `ip http server`, EEM applet copying the config to `tftp://10.10.10.10`, static route to `10.10.10.0/24` via `192.168.250.66`, syslog to `10.10.10.10`, telnet on both vty ranges). This is the simulated demo switch `sim-switch-01`. |
| `clean_switch.cfg` | The same switch after every fix: passes all NDM and L2S rules, no hunt findings. |
| `seeded_router.cfg` | ISR/ASR-style edge router. Fails the five RTR rules plus CISC-ND-000980, and carries a rogue GRE tunnel (`Tunnel99`) and a `permit ip any any` hidden in the boundary ACL `EXTERNAL-IN`. |

Expected findings are in `range/answer_key/cisco_ios.json` (switch under `items`, router under `router.items`).

## Simulated switch (demo)

`cyberthunder demo load` adds `sim-switch-01`. On first use the adapter copies `seeded_switch.cfg` to
`<state_dir>/simulated/sim-switch-01.cfg`; approved fixes edit that copy and rollback writes the saved
pre-change copy back. Resetting the simulated target re-copies the seed.

## A saved config (file transport)

Use this when a config is pulled from a device by hand, or comes in over the constrained link. Add a
target to `<state_dir>/targets.yaml`:

```yaml
targets:
  - id: rtr-01
    name: rtr-01 edge router
    asset_type: cisco_ios
    transport: file
    sudo: false
    options:
      config_path: range/cisco/seeded_router.cfg   # use a copy if you will apply fixes
      known_users: [admin]
      known_syslog: [10.1.1.5, 10.1.2.5]
      external_interfaces: [GigabitEthernet0/0/0]
```

Approved fixes rewrite the file in place; take a copy first if the original must stay seeded.

## A live lab device (ssh transport)

```yaml
  - id: lab-sw-01
    name: lab switch
    asset_type: cisco_ios
    transport: ssh
    address: 192.0.2.10
    username: ctscan
    credential_ref: LABSW            # password read from env CT_CRED_LABSW, never stored here
    sudo: false
    options:
      allow_push: false              # true lets approved fixes be typed into configure terminal
      archive: true                  # run 'archive config' before each change
      archive_path: flash:ct-pre-change.cfg   # running-config copied here before each change; rollback replaces from it
      known_users: [admin]
      known_syslog: [10.1.1.5]
```

The account needs privilege 15 (or a privilege level that can run `show running-config` and, with push
enabled, `configure terminal`). With `allow_push: false` every approved fix is returned as console steps
and nothing on the device changes. Only connect to lab or range equipment, never to a live Navy network.

Organization-defined values used by the fixes (session limit, NTP/syslog/AAA servers, unused and native
VLANs, external interfaces) are documented in `cyberthunder/adapters/cisco/rules.py` (`resolve_options`).
