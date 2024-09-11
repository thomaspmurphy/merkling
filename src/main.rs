use sha2::{Digest, Sha256};
use std::fmt::Debug;
use thiserror::Error;

#[derive(Clone, Debug)]
enum Node {
    Leaf {
        hash: Vec<u8>,
    },
    Internal {
        hash: Vec<u8>,
        left: Box<Node>,
        right: Box<Node>,
    },
}

impl Default for Node {
    fn default() -> Self {
        Node::Leaf { hash: vec![0; 32] }
    }
}

impl Node {
    fn hash_data(data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    fn new_leaf(data: &[u8]) -> Node {
        let hash = Self::hash_data(data);
        Node::Leaf { hash }
    }

    fn new_internal(left: Box<Node>, right: Box<Node>) -> Node {
        let mut combined_hash = Vec::with_capacity(64);
        combined_hash.extend_from_slice(&left.get_hash());
        combined_hash.extend_from_slice(&right.get_hash());
        let hash = Self::hash_data(&combined_hash);
        Node::Internal { hash, left, right }
    }

    fn get_hash(&self) -> &Vec<u8> {
        match self {
            Node::Leaf { hash } => hash,
            Node::Internal { hash, .. } => hash,
        }
    }
}

#[derive(Debug)]
struct MerkleTree {
    root: Node,
}

#[derive(Error, Debug)]
pub enum MerkleTreeError {
    #[error("Failed to generate proof")]
    ProofGenerationFailed,
}

impl From<Vec<&[u8]>> for MerkleTree {
    fn from(data_blocks: Vec<&[u8]>) -> Self {
        let mut nodes: Vec<Box<Node>> = data_blocks
            .into_iter()
            .map(|data| Box::new(Node::new_leaf(data)))
            .collect();
        let root = MerkleTree::build_tree(&mut nodes);
        MerkleTree { root: *root }
    }
}

impl MerkleTree {
    fn build_tree(nodes: &mut Vec<Box<Node>>) -> Box<Node> {
        while nodes.len() > 1 {
            let mut new_level = Vec::with_capacity((nodes.len() + 1) / 2);

            for chunk in nodes.chunks(2) {
                let left = chunk[0].clone();
                let right = chunk.get(1).cloned().unwrap_or_else(|| Box::new(Node::default()));
                new_level.push(Box::new(Node::new_internal(left, right)));
            }

            *nodes = new_level;
        }

        nodes.pop().expect("Tree must have at least one node")
    }

    fn root_hash(&self) -> &Vec<u8> {
        self.root.get_hash()
    }

    fn generate_proof(&self, data: &[u8]) -> Result<Vec<(Vec<u8>, bool)>, MerkleTreeError> {
        let mut proof = Vec::new();
        let data_hash = Node::hash_data(data);

        if !self.generate_proof_recursive(&self.root, &data_hash, &mut proof) {
            return Err(MerkleTreeError::ProofGenerationFailed);
        }

        Ok(proof)
    }

    fn generate_proof_recursive(&self, node: &Node, target_hash: &Vec<u8>, proof: &mut Vec<(Vec<u8>, bool)>) -> bool {
        match node {
            Node::Leaf { hash } => hash == target_hash,
            Node::Internal { left, right, .. } => {
                if self.generate_proof_recursive(left, target_hash, proof) {
                    proof.push((right.get_hash().clone(), false));
                    true
                } else if self.generate_proof_recursive(right, target_hash, proof) {
                    proof.push((left.get_hash().clone(), true));
                    true
                } else {
                    false
                }
            }
        }
    }

    fn verify(&self, data: &[u8], proof: &[(Vec<u8>, bool)]) -> bool {
        Self::verify_proof(data, proof, self.root_hash())
    }

    fn verify_proof(data: &[u8], proof: &[(Vec<u8>, bool)], root_hash: &[u8]) -> bool {
        let mut current_hash = Node::hash_data(data);

        for (sibling_hash, is_left) in proof {
            let mut combined = Vec::with_capacity(current_hash.len() + sibling_hash.len());
            if *is_left {
                combined.extend_from_slice(sibling_hash);
                combined.extend_from_slice(&current_hash);
            } else {
                combined.extend_from_slice(&current_hash);
                combined.extend_from_slice(sibling_hash);
            }
            current_hash = Node::hash_data(&combined);
        }

        &current_hash[..] == root_hash
    }
}

fn main() {
    let transactions = vec![
        b"tx: Alice -> Bob, amount: 10".as_ref(),
        b"tx: Eve -> Frank, amount: 30".as_ref(),
        b"tx: Grace -> Heidi, amount: 40".as_ref(),
    ];

    let merkle_tree = MerkleTree::from(transactions);
    let root_hash = merkle_tree.root_hash();
    println!("Merkle Tree Root Hash: {:x?}", root_hash);

    // Example usage of proof generation and verification
    if let Ok(proof) = merkle_tree.generate_proof(b"tx: Alice -> Bob, amount: 10") {
        let is_valid = merkle_tree.verify(b"tx: Alice -> Bob, amount: 10", &proof);
        println!("Proof is valid: {}", is_valid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_construction() {
        let transactions = vec![
            b"tx: Alice -> Bob, amount: 10".as_ref(),
            b"tx: Grace -> Heidi, amount: 40".as_ref(),
        ];

        let merkle_tree = MerkleTree::from(transactions.clone());

        let root_hash = merkle_tree.root_hash();
        assert!(!root_hash.is_empty());

        let expected_root_hash = merkle_tree.root_hash();
        assert_eq!(root_hash, expected_root_hash);
    }

    #[test]
    fn test_merkle_tree_root_hash_changes_with_data() {
        let transactions_1 = vec![
            b"tx: Alice -> Bob, amount: 10".as_ref(),
            b"tx: Charlie -> Dave, amount: 20".as_ref(),
            b"tx: Eve -> Frank, amount: 30".as_ref(),
            b"tx: Grace -> Heidi, amount: 40".as_ref(),
        ];

        let transactions_2 = vec![
            b"tx: Alice -> Bob, amount: 15".as_ref(), // Only this transaction is different
            b"tx: Charlie -> Dave, amount: 20".as_ref(),
            b"tx: Eve -> Frank, amount: 30".as_ref(),
            b"tx: Grace -> Heidi, amount: 40".as_ref(),
        ];

        let merkle_tree_1 = MerkleTree::from(transactions_1);
        let merkle_tree_2 = MerkleTree::from(transactions_2);

        assert_ne!(merkle_tree_1.root_hash(), merkle_tree_2.root_hash());
    }

    #[test]
    fn test_generate_and_verify_proof() {
        let transactions = vec![
            b"tx: Alice -> Bob, amount: 10".as_ref(),
            b"tx: Eve -> Frank, amount: 30".as_ref(),
            b"tx: Grace -> Heidi, amount: 40".as_ref(),
        ];

        let merkle_tree = MerkleTree::from(transactions);
        let root_hash = merkle_tree.root_hash();

        let data = b"tx: Alice -> Bob, amount: 10";
        if let Ok(proof) = merkle_tree.generate_proof(data) {
            let is_valid = MerkleTree::verify_proof(data, &proof, root_hash);
            assert!(is_valid, "Proof should be valid");

            // Test with incorrect data
            let incorrect_data = b"tx: Alice -> Bob, amount: 20";
            let is_invalid = MerkleTree::verify_proof(incorrect_data, &proof, root_hash);
            assert!(!is_invalid, "Proof should be invalid for incorrect data");
        } else {
            panic!("Proof generation failed");
        }
    }
}
