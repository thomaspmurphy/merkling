# Merkle Tree Implementation in Rust

This repository contains a Rust implementation of a Merkle Tree, a fundamental data structure used in various cryptographic applications, including blockchain technology.

## Overview

A Merkle Tree is a binary tree of hashes, where each leaf node contains the hash of a data block, and each non-leaf node contains the hash of its two child nodes. This implementation uses SHA-256 for hashing.

## Features

- Creation of a Merkle Tree from a list of data blocks
- Generation of Merkle proofs
- Verification of Merkle proofs
- Root hash calculation

## Dependencies

This project uses the following external crate:
- `sha2` (for SHA-256 hashing)