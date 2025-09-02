# Deployment Guide: WordPress on GCP + OpenVPN + Split‑DNS/NAT

This README provides a clean, three‑part flow for your setup:
1. **Getting WordPress live on a GCP VM with HTTPS**
2. **OpenVPN setup (server + client provisioning)**
3. **Server/client config + Split‑DNS & NAT to reach WordPress on a private IP**

> In the examples below, the WordPress VM’s private IP is `10.128.0.3`, the VPN subnet is `10.8.0.0/24`, and the VPN server address is `10.8.0.1`.

---

## Part 1 — Getting WordPress Live on a GCP VM with HTTPS

### 1. Cloud Infrastructure & Networking (GCP)
- **VM provisioning (Ubuntu/Debian):** Create a Compute Engine VM for Nginx, PHP‑FPM, and WordPress.
- **VPC firewall:** Allow ingress TCP **80** (HTTP) and **443** (HTTPS) to the VM via a tag (e.g., `web-server`).
- **(Initial) local hosts override:**
  ```text
  <your_instance_external_ip> example.com
  ```

### 2. LEMP + WordPress
- **Install:** Nginx, MySQL, PHP‑FPM.
- **Create DB + user (localhost‑only):**
  ```sql
  CREATE DATABASE wordpress_db;
  CREATE USER 'wp_user'@'localhost' IDENTIFIED BY 'your_strong_password';
  GRANT ALL PRIVILEGES ON wordpress_db.* TO 'wp_user'@'localhost';
  FLUSH PRIVILEGES;
  ```
### 3. Self-signed Certificate
- **Create a Self-Signed Certificate:**
```
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/example.com.key \
    -out /etc/nginx/ssl/example.com.crt \
    -config /etc/ssl/openssl-san.cnf \
    -extensions v3_req
```
- **Edit the Niginx configuration file:**
```
sudo nano /etc/nginx/sites-available/example.com
```
- **Copy the content below and paste it in the file:**
  ```
  server {
      listen 80;
      listen [::]:80;
      server_name example.com www.example.com;
      return 301 https://$server_name$request_uri;
  }

  server {
      listen 443 ssl;
      listen [::]:443 ssl;
      server_name example.com www.example.com;

      ssl_certificate     /etc/nginx/ssl/example.com.crt;
      ssl_certificate_key /etc/nginx/ssl/example.com.key;

      root /var/www/html;
      index index.php index.html;

      location / {
          try_files $uri $uri/ /index.php?$args;
      }

      location ~ \.php$ {
          include snippets/fastcgi-php.conf;
          fastcgi_pass unix:/run/php/php8.4-fpm.sock;  # adjust to your PHP-FPM version/socket
      }
  }
  ```
  Enable + reload:
  ```bash
  sudo ln -s /etc/nginx/sites-available/example.com /etc/nginx/sites-enabled/ 2>/dev/null || true
  sudo nginx -t && sudo systemctl reload nginx
  ```

### 4. HTTPS Certificate (initial testing with self‑signed)
- **Make the self-signed certificates trusted locally by adding them into the macOS Keychain and change the settings to *Always Trust***

### 5. Quick smoke test (public path)
```bash
curl -I https://example.com       # Expect 200 or 301→200
```

---

## Part 2 — OpenVPN Setup (Server + Client)

### 1. Install OpenVPN (Debian server)
```bash
sudo apt update
sudo apt install -y openvpn easy-rsa
```

Ensure TUN is present:
```bash
ls /dev/net/tun || sudo modprobe tun
```

### 2. PKI (Easy‑RSA) — create CA, server, and client certs
```bash
sudo make-cadir /etc/openvpn/easy-rsa
sudo -i
cd /etc/openvpn/easy-rsa

./easyrsa init-pki
./easyrsa build-ca

# Server cert
./easyrsa gen-req openvpn-sate.am nopass
./easyrsa sign-req server openvpn-sate.am
./easyrsa gen-dh

# Client cert (repeat per client)
./easyrsa gen-req macbook-client nopass
./easyrsa sign-req client macbook-client
```
Copy artifacts (adjust names/paths as needed):
```bash
cp pki/ca.crt pki/dh.pem    pki/issued/openvpn-sate.am.crt    pki/private/openvpn-sate.am.key /etc/openvpn/
```

### 3. HMAC key (tls‑auth)
```bash
sudo openvpn --genkey secret /etc/openvpn/ta.key
```

### 4. Server config (tls‑auth; OpenVPN 2.4+ compatible)
**File:** `/etc/openvpn/openvpn-sate.am.conf` (used by unit `openvpn@openvpn-sate.am`)
```conf
port 1194
proto udp
dev tun

server 10.8.0.0 255.255.255.0

# PKI
ca   /etc/openvpn/ca.crt
cert /etc/openvpn/openvpn-sate.am.crt
key  /etc/openvpn/openvpn-sate.am.key
dh   /etc/openvpn/dh.pem

# HMAC (server uses 0)
tls-auth /etc/openvpn/ta.key 0

# DNS (used in Part 3)
push "dhcp-option DNS 10.8.0.1"

keepalive 10 120
persist-key
persist-tun
verb 3
explicit-exit-notify 1
```

**Start/enable the service:**
```bash
sudo systemctl enable --now openvpn@openvpn-sate.am
sudo systemctl status openvpn@openvpn-sate.am --no-pager -l
# Expect: "Initialization Sequence Completed"
```

> **Unit/file mapping:**  
> `openvpn@NAME` → `/etc/openvpn/NAME.conf`  
> `openvpn-server@NAME` → `/etc/openvpn/server/NAME.conf`

### 5. Client profile (`.ovpn`) for macOS (OpenVPN Connect)
Create `macbook-client.ovpn`:
```conf
client
dev tun #Use IP level vpn tunneling
proto udp
remote <your_vpn_server_public_ip_or_name> 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
tls-auth ta.key 1
key-direction 1
cipher AES-256-CBC
verb 3

<ca>
# paste ca.crt
</ca>
<cert>
# paste macbook-client.crt
</cert>
<key>
# paste macbook-client.key
</key>
<tls-auth>
# paste ta.key
</tls-auth>
```
Import into **OpenVPN Connect** on macOS and connect.

### 6. Quick VPN health checks
```bash
# On the server
journalctl -u openvpn@openvpn-sate.am -e
sudo ss -lunp | grep 1194         # UDP/1194 listening
ip addr show dev tun0             # tun0 with 10.8.0.1
```

---

## Part 3 — Server/Client Config + Split‑DNS & NAT (Private WordPress)

### 1. Split‑DNS on VPN server (dnsmasq)
Install & configure:
```bash
sudo apt update
sudo apt install -y dnsmasq dnsutils

sudo tee /etc/dnsmasq.d/split.conf >/dev/null <<'EOF'
interface=tun0
bind-interfaces
listen-address=10.8.0.1

# Upstream for everything else
server=1.1.1.1
server=8.8.8.8

# Map example.com to the private WP IP when on VPN
address=/example.com/10.128.0.3
EOF

sudo systemctl enable dnsmasq
sudo systemctl restart dnsmasq
sudo ss -lunp | grep ':53'    # should show 10.8.0.1:53 (dnsmasq)
```
Server‑side DNS tests:
```bash
dig @10.8.0.1 example.com +short   # -> 10.128.0.3
dig @10.8.0.1 google.com +short    # -> public IPs
```

### 2. Push VPN DNS to clients (OpenVPN server)
In `/etc/openvpn/openvpn-sate.am.conf` (already present from Part 2):
```conf
push "dhcp-option DNS 10.8.0.1"
```
Restart OpenVPN if edited:
```bash
sudo systemctl restart openvpn@openvpn-sate.am
```

### 3. Routing & NAT on VPN server
Enable IPv4 forwarding and open the path to the WP VM:
```bash
echo 'net.ipv4.ip_forward = 1' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -d 10.128.0.3/32 -j MASQUERADE
sudo iptables -A FORWARD -s 10.8.0.0/24 -d 10.128.0.3 -p tcp -m multiport --dports 80,443 -j ACCEPT

# Persist rules
sudo apt install -y iptables-persistent
sudo netfilter-persistent save
```
> With MASQUERADE, the WP VM sees requests as coming **from the VPN server’s private IP**. Allow it in the WP VM’s firewall if restrictive.

### 4. WordPress VM (Nginx) hostname sanity
Ensure the HTTPS vhost uses the hostname:
```nginx
server_name example.com www.example.com;
```
Reload:
```bash
sudo nginx -t && sudo systemctl reload nginx
```

### 5. Client validation (macOS; VPN ON)
```bash
dig example.com +short         # -> 10.128.0.3
curl -I https://example.com    # -> 200 OK (or 301 then 200)
```
> `https://10.128.0.3` won’t validate TLS CN and may hit a default vhost; use the hostname.


### 7. Final expectations
- **On VPN:** `example.com` → `10.128.0.3` (private), HTTPS works with the normal `example.com` cert.
- **Off VPN:** `example.com` resolves/behaves per your public DNS policy.

