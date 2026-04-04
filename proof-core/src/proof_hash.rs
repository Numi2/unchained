use winter_crypto::{hashers::Rp64_256, Digest, ElementHasher};
use winter_math::fields::f64::BaseElement;

const PROOF_HASH_TAG_DOMAIN: &str = "unchained-proof-hash-parts-v1";
const MERKLE_NODE_DOMAIN: &str = "unchained-shielded-merkle-node-v1";
const NULLIFIER_MEMBERSHIP_WITNESS_DOMAIN: &str = "unchained-shielded-membership-witness-v1";

pub fn proof_hash_bytes(domain: &str, bytes: &[u8]) -> [u8; 32] {
    proof_hash_domain_parts(domain, &[bytes])
}

pub fn proof_hash_domain_parts(domain: &str, parts: &[&[u8]]) -> [u8; 32] {
    let capacity = PROOF_HASH_TAG_DOMAIN.len()
        + domain.len()
        + parts.iter().map(|part| part.len()).sum::<usize>()
        + 12
        + parts.len() * 4;
    let mut encoded = Vec::with_capacity(capacity);
    encoded.extend_from_slice(&(PROOF_HASH_TAG_DOMAIN.len() as u32).to_le_bytes());
    encoded.extend_from_slice(PROOF_HASH_TAG_DOMAIN.as_bytes());
    encoded.extend_from_slice(&(domain.len() as u32).to_le_bytes());
    encoded.extend_from_slice(domain.as_bytes());
    encoded.extend_from_slice(&(parts.len() as u32).to_le_bytes());
    for part in parts {
        encoded.extend_from_slice(&(part.len() as u32).to_le_bytes());
        encoded.extend_from_slice(part);
    }
    let elements = rescue_elements_from_bytes(&encoded);
    Rp64_256::hash_elements(&elements).as_bytes()
}

pub fn merkle_parent_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    proof_hash_domain_parts(MERKLE_NODE_DOMAIN, &[left.as_slice(), right.as_slice()])
}

pub fn nullifier_membership_witness_digest(
    nullifier: &[u8; 32],
    root: &[u8; 32],
    proof: &[([u8; 32], bool)],
) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(68 + proof.len() * 33);
    encoded.extend_from_slice(nullifier);
    encoded.extend_from_slice(root);
    encoded.extend_from_slice(&(proof.len() as u32).to_le_bytes());
    for (hash, sibling_is_left) in proof {
        encoded.extend_from_slice(hash);
        encoded.push(u8::from(*sibling_is_left));
    }
    proof_hash_bytes(NULLIFIER_MEMBERSHIP_WITNESS_DOMAIN, &encoded)
}

fn rescue_elements_from_bytes(bytes: &[u8]) -> Vec<BaseElement> {
    if bytes.is_empty() {
        return Vec::new();
    }
    let num_chunks = bytes.len().div_ceil(7);
    let mut elements = Vec::with_capacity(num_chunks);
    for (index, chunk) in bytes.chunks(7).enumerate() {
        let mut buf = [0u8; 8];
        if index + 1 == num_chunks {
            buf[..chunk.len()].copy_from_slice(chunk);
            buf[chunk.len()] = 1;
        } else {
            buf[..7].copy_from_slice(chunk);
        }
        elements.push(BaseElement::new(u64::from_le_bytes(buf)));
    }
    elements
}
