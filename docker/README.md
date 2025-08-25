
# 🚀 Bitcoin Knots Docker Image (Headless Node)

This Dockerfile builds and runs a **Bitcoin Knots** full node (no wallet, no ZMQ) from source.

## 🧱 Features

* Built from a specific Bitcoin Knots tag
* `--disable-wallet` and `--disable-zmq`
* Data directory persisted via volume
* Easy to update by just changing the tag
* RPC support enabled by default

---

## 📦 Build the Docker Image

```bash
docker build -t bitcoin-knots:v28.1.knots20250305 .
```

> Replace `v28.1.knots20250305` with your desired tag.

---

## ▶️ Run the Node

```bash
docker run -d \
  --name bitcoinknots \
  -v $HOME/bitcoin-knots-data:/bitcoin/.bitcoin \
  -p 8333:8333 \
  -p 8332:8332 \
  bitcoin-knots:v28.1.knots20250305
```

This will:

* Start the node in the background
* Save the blockchain and config in `~/bitcoin-knots-data`
* Expose peer and RPC ports

---

## 📊 Check Node Status

You can monitor the sync status using:

```bash
docker exec -it bitcoinknots bitcoin-cli -datadir=/bitcoin/.bitcoin getblockchaininfo
```

---

## 📁 Bitcoin Config File

The config is stored at:

```
$HOME/bitcoin-knots-data/bitcoin.conf
```

Create it manually if needed:

```ini
server=1
rpcuser=yourusername
rpcpassword=yoursecurepassword
```

---

## 🛑 Stop the Node

```bash
docker stop bitcoinknots
```

---

## ❗ Notes

* You must manually create `bitcoin.conf` to use RPC securely.
* Port 8333 is for P2P, 8332 is for RPC.
* You can change the tag to build newer releases.

---

## 📌 Update to New Release

Just change the `ARG BITCOIN_KNOTS_TAG` in the `Dockerfile` and rebuild:

```dockerfile
ARG BITCOIN_KNOTS_TAG=v29.0.knots20251001
```

Then:

```bash
docker build -t bitcoin-knots:v29.0.knots20251001 .
```

---

