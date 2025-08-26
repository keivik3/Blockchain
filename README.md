# ⛓️ Blockchain with GOST Hashing, Schnorr Signatures & Proof-of-Work  

A **blockchain implementation** featuring secure cryptographic primitives:  

- 🔐 **Schnorr Signatures** (key-prefixed)  
- 🌀 **GOST 34.11-2018 Hashing** (256-bit)  
- 🌳 **Merkle Tree** for transaction integrity  
- ⛏️ **Proof-of-Work mining** (configurable difficulty)  
- 🎲 **PRNG** based on iterative GOST hashing  

---

## ✨ Features  

- 🌳 **Merkle root calculation** (duplicates last hash on odd levels).  
- 📦 **Block header serialization** with strict format:  
  - `size` (4 bytes, big-endian)  
  - `prev_hash` (32 bytes)  
  - `merkle_root` (32 bytes)  
  - `timestamp` (4 bytes: hour, day, month, year)  
  - `nonce` (4 bytes, big-endian)  
- ⛏️ **Proof-of-Work**: find nonce such that the first **N bits** of block hash are zero.  
- 🎲 **Deterministic PRNG** for seeding & nonce generation.  
- 🔐 **Schnorr signature scheme** in multiplicative group of finite field.  

---

## 📂 Repository Structure  

```
├── blockchain.py # Block, BlockHeader, Merkle tree, PoW mining, chain logic
├── gost_hash256.py # Implementation of GOST 34.11-2018 (256-bit)
├── prng.py # PRNG using iterative GOST hashing
├── signature.py # Schnorr signature (key-prefixed)
├── tests/
│ └── smoke_demo.py # Minimal integration test
└── README.md
```

---

## ⚙️ Installation  

```
git clone https://github.com/keivik3/Blockchain.git
```

## ▶️ Usage

Run Blockchain Demo
```
python blockchain.py
```
Example output:
```
Block mined: nonce=26, hash=04b739b1dd02d0c3...
Block mined: nonce=110, hash=01715dec01c126b4...
Blockchain length: 2
```

---

## ⛏️ Proof-of-Work
Mining target is configurable:
```
block.mine(target_bits=5)
```
Ensures the first 5 bits of the block header hash are zero.

---

## 💸 Transactions

* Each transaction = 200 bytes
* Signed using Schnorr key-prefixed scheme
* Transaction hash =
```
H(payload || signature) 
```

with GOST 34.11-2018

## 📜 License

📖 MIT License — see LICENSE for details.
