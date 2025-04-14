# Cryptography
C++ implementations of classic cryptographic algorithms including DES, RSA, and a simplified hash chain system using SHA256.

# Cryptography in C++

This repository contains my implementations of classical cryptographic algorithms written in C++. The focus was to deepen my understanding of low-level cryptographic logic by implementing each algorithm from scratch or minimal library support.

## 🔐 Implemented Algorithms

- **DES (Data Encryption Standard)**
  - Full bitwise implementation including: Initial/Final Permutation, Key Scheduling, Expansion, S-box substitution, and 16 rounds of Feistel network
  - Developed without external libraries

- **RSA (Rivest–Shamir–Adleman)**
  - Utilized Crypto++ for large prime number generation and modular exponentiation
  - Implemented key generation, encryption, and decryption
  - Extended Euclidean Algorithm for computing private key exponent

- **Hash Chain**
  - Custom implementation of a simplified "proof-of-work"-style chain
  - Based on repeated SHA256 hashes and nonce searching
  - Inspired by blockchain concepts

## 🧪 Learning Outcomes
- Bit-level manipulation in DES helped me understand how symmetric encryption operates internally
- RSA strengthened my grasp on number theory, especially modular arithmetic
- Hash Chain showed how hash functions can be used for integrity and linking data

## 🔧 Environment
- Language: C++
- Library: Crypto++ (only for RSA)
- Hash: SHA256 via built-in utilities or wrappers

## 📌 Notes
These algorithms were implemented as assignments and study projects during a university-level cryptography course.

