# vswitch

`vswitch` is a Linux TAP-based L2 virtual switch and lightweight VPN dataplane.

It combines:
- a synchronous high-performance dataplane (`epoll` + nonblocking sockets/TAP),
- an HTTP RPC control-plane (Axum) for authenticated join/token issuance,
- per-session AES-GCM-256 payload protection for client/server frame transport.

---

## Feature Overview

- L2 switching with MAC learning on each switch
- Multiple named switches in one process
- Optional in-process bridge groups across switches
- Host TAP integration per switch (server-side TAP acts as local endpoint)
- Client TAP endpoint with auto rejoin loop
- Join token flow with short-lived one-time JWT
- API key + HMAC request authentication for RPC
- Per-client crypto session key distribution (`AES-GCM-256`)
- Source MAC anti-spoof enforcement (`disable_unknown_mac`, default true)
- Route provisioning:
  - server routes on server TAP (`server_routes`)
  - server-proposed routes for clients (`client_routes`)
  - local client routes (`routes`)
  - client-side selective ignore list for server routes (`ignore_server_routes`)
- CIDR normalization for server-proposed routes and client route application

---

## Architecture (ASCII)

### Control Plane + Data Plane

```text
                    HTTP RPC (Axum)
              +-------------------------+
              |  /switches/list         |
              |  /switches/{name}/join  |
              |  /switches/{name}/peers |
              +-----------+-------------+
                          |
                          | mpsc::Sender<ControlPlaneCmd>
                          v
      +-------------------+----------------------+
      |  Main server loop (epoll thread)         |
      |  - listener fd                            |
      |  - all TAP fds                            |
      |  - eventfd (RPC wake-up)                  |
      +-------------------+----------------------+
                          |
                          | TCP data/control framing
                          v
          +---------------+------------------+
          |          Client session          |
          |   TAP <-> encrypt/decrypt <-> TCP|
          +----------------------------------+
```

### Switch and Bridge Forwarding

```text
Standalone switch:
  [Client A] --\
  [Client B] ----> (Switch MAC table) ---> unicast to known dst
  [Host TAP] --/                        ---> flood bcast/mcast
                                      ---> drop unknown unicast

Bridge group (switch-1 + switch-2):
  switch-1 endpoints <--> bridge MAC table <--> switch-2 endpoints
  unknown unicast: flood across bridge members
```

### RPC wake-up path with eventfd

```text
RPC handler thread (tokio runtime):
  cmd_tx.send(ControlPlaneCmd::X)
  signal_eventfd(event_fd)
              |
              v
Server epoll loop wakes on event_fd readable
  drain_eventfd(event_fd)
  process_control_plane_cmds(...)
  reply via oneshot channels
```

---

## End-to-End Flow

### 1) Server startup

Server reads `vswitch-server.yml` and for each switch:
- creates TAP interface,
- optionally sets TAP MAC/IP,
- installs `server_routes`,
- learns/records TAP MAC as local switch endpoint,
- loads reservations and advertised `client_routes` (normalized CIDR).

If bridges are configured, member switches are linked into bridge state.

### 2) Client join

Client reads `vswitch-client.yml`:
- creates TAP and optional static MAC,
- calls RPC join:
  - `GET /vswitch/switches/{name}/join?switch=<name>&mac=<mac>[&requested_ip=<ip>]`
- gets:
  - one-time token,
  - listener address,
  - assigned `ipv4`,
  - `crypt_method` + `crypt_key`,
  - server-proposed routes.

Then client:
1. connects to listener TCP,
2. sends `CTRL_REGISTER` with token/switch/mac,
3. waits for `CTRL_ACK`,
4. starts bidirectional frame transfer (`CTRL_DATA`).

### 3) Data forwarding

Server learns source MAC on ingress and forwards by destination MAC:
- known unicast -> target endpoint,
- broadcast/multicast -> flood,
- unknown unicast:
  - standalone switch -> drop,
  - bridged switch -> flood to bridge targets.

Client and server only exchange encrypted frame payloads once registered.

---

## Security Model

### Control-plane auth and join

- API calls signed using HMAC-SHA256 with shared API secret.
- Required headers:
  - `x-api-key`
  - `x-client-nounce` (32-byte hex nonce; name intentionally spelled as implemented)
  - `x-client-ts` (epoch ms)
  - `x-signature` (HMAC over `query_string + nonce + ts`)
- Nonce replay cache window: 5 minutes.
- Max allowed request age skew: 2 minutes.

### Join token

- JWT signed by `rpc_hmac_secret`
- short expiry (~60s)
- one-time use (consumed/invalidated on successful register)
- token binds switch + MAC + assigned IP + crypto material

### Data-plane protection

- `AES-GCM-256` payload encryption/integrity
- per-session key from join response
- separate directional nonce/counter domain

### Anti-spoofing

Per switch:
- `disable_unknown_mac: true` (default) drops client frames if source MAC is not exactly registered MAC.

---

## Routing Behavior

Route format:

```yaml
- to: "10.99.0.0/16"
  via: "10.200.1.5"   # optional
```

- with `via`: `ip route replace <to> via <via> dev <tap>`
- without `via`: `ip route replace <to> dev <tap>`

### Route sources

- `server_routes` (server switch TAP)
- `client_routes` from server join response (client side, optional via `use_server_routes`)
- local client `routes` (always applied if configured)

### New: ignore selected server-proposed routes

Client config supports:

```yaml
ignore_server_routes:
  - "192.168.44.0/16"
```

When `use_server_routes: true`, server routes that overlap any ignored CIDR are skipped.

### Normalization

- Server `client_routes` are normalized before exposure via RPC/join.
- Client normalizes server-proposed routes before filtering/applying.
- This prevents mismatch from non-canonical CIDR inputs.

---

## Configuration

### Server (`vswitch-server.yml`)

```yaml
listener: "0.0.0.0:4456"
advertised_listener: "example.com:4456"
rpc: "0.0.0.0:4455"
principals:
  - name: "demo-client"
    api_credentials:
      - api_key: "demo-api-key"
        api_secret: "demo-api-secret"
    groups:
      - "trusted"
groups:
  - name: "trusted"
acl:
  - switch: "switch-1"
    groups:
      - "trusted"
rpc_hmac_secret: "change-this-secret"
crypto_method: "AES-GCM-256"

switches:
  - name: "switch-1"
    tap: "tap-server1"
    disable_unknown_mac: true
    mac: "02:11:22:33:44:01"
    ipv4: "10.200.1.1/24"
    address_reservation:
      - mac: "02:aa:bb:cc:dd:01"
        ipv4: "10.220.22.33/24"
    server_routes:
      - to: "10.99.0.0/16"
        via: "10.200.1.5"
    client_routes:
      - to: "172.19.0.0/16"
        via: "10.200.1.1"

  - name: "switch-2"
    tap: "tap-server2"
    mac: "02:11:22:33:44:02"
    ipv4: "10.200.2.1/24"

bridges:
  - name: "bridge-12"
    members:
      - "switch-1"
      - "switch-2"
```

### Client (`vswitch-client.yml`)

```yaml
rpc: "http://example.com:4455"
api_key: "demo-api-key"
api_secret: "demo-api-secret"
switch: "switch-1"
tap: "tap-client1"
mac: "02:aa:bb:cc:dd:01"
use_server_routes: true
ignore_server_routes:
  - "192.168.44.0/16"
# optional static client IP; otherwise RPC-assigned value is used
# ipv4: "10.200.1.197/24"

routes:
  - to: "172.177.1.72/18"
    via: "10.200.1.1"
```

---

## Running

```bash
# Server
vswitch server -c vswitch-server.yml

# Client
vswitch client -c vswitch-client.yml
```

If `-c/--config` is omitted, auto-load order:
- server: `vswitch-server.yml`, `server.yml`, `vswitch.yml`
- client: `vswitch-client.yml`, `client.yml`, `vswitch.yml`

---

## RPC Endpoints

- `GET /vswitch/switches/list`
- `GET /vswitch/switches/{name}/join`
- `GET /vswitch/switches/{name}/peers`

---

## Operational Notes

- Keep `rpc_hmac_secret` and principal `api_secret` values strong and private.
- Prefer private RPC exposure and/or TLS termination in production.
- Data plane transport is TCP; payload is encrypted but transport metadata is still visible.
- Use explicit `via` where appropriate in routed designs.
- If client host network already owns a subnet, use `ignore_server_routes` to prevent route hijack through TAP.

