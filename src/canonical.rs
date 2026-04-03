use anyhow::{anyhow, bail, Result};

use crate::{
    coin::{Coin, CoinCandidate},
    crypto::{
        Address, KemAlgorithm, SignatureAlgorithm, TaggedKemPublicKey, TaggedSigningPublicKey,
        ML_DSA_65_PK_BYTES, ML_KEM_768_PK_BYTES,
    },
    epoch::Anchor,
    network::{
        CompactEpoch, EpochByHash, EpochCandidatesResponse, EpochGetTxn, EpochHeadersBatch,
        EpochHeadersRange, EpochLeavesBundle, EpochTxn, SelectedIdsBundle,
    },
    node_identity::{
        NodeRecordV2, SignedEnvelope, TrustApprovalV1, TrustUpdateAction, TrustUpdateV1,
    },
    shielded::{
        ArchiveCustodyCommitment, ArchiveOperatorScorecard, ArchiveProviderManifest,
        ArchiveReplicaAttestation, ArchiveRetrievalKind, ArchiveRetrievalReceipt,
        ArchiveServiceLedger, ArchiveShard, ArchiveShardBundle, ArchivedNullifierEpoch,
        CheckpointBatchRequest, CheckpointBatchResponse, CheckpointExtensionRequest,
        CheckpointPresentation, EvolvingNullifierQuery, HistoricalAbsenceRecord,
        HistoricalUnspentCheckpoint, HistoricalUnspentExtension, HistoricalUnspentPacket,
        HistoricalUnspentSegment, HistoricalUnspentServiceResponse, HistoricalUnspentStratum,
        NoteCommitmentTree, NoteMembershipProof, NullifierMembershipWitness,
        NullifierNonMembershipProof, NullifierRootLedger, ShieldedNote, ShieldedSpendContext,
    },
    transaction::{ShieldedOutput, ShieldedOutputPlaintext, Tx},
    wallet::RecipientHandle,
};

pub struct CanonicalWriter {
    buf: Vec<u8>,
}

impl CanonicalWriter {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }

    pub fn write_u8(&mut self, value: u8) {
        self.buf.push(value);
    }

    pub fn write_bool(&mut self, value: bool) {
        self.write_u8(if value { 1 } else { 0 });
    }

    pub fn write_u32(&mut self, value: u32) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    pub fn write_u64(&mut self, value: u64) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    pub fn write_u128(&mut self, value: u128) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    pub fn write_fixed<const N: usize>(&mut self, value: &[u8; N]) {
        self.buf.extend_from_slice(value);
    }

    pub fn write_bytes(&mut self, value: &[u8]) -> Result<()> {
        let len = u32::try_from(value.len()).map_err(|_| anyhow!("byte slice too large"))?;
        self.write_u32(len);
        self.buf.extend_from_slice(value);
        Ok(())
    }

    pub fn write_string(&mut self, value: &str) -> Result<()> {
        self.write_bytes(value.as_bytes())
    }

    pub fn write_vec<T>(
        &mut self,
        values: &[T],
        mut write_item: impl FnMut(&mut Self, &T) -> Result<()>,
    ) -> Result<()> {
        let len = u32::try_from(values.len()).map_err(|_| anyhow!("vector too large"))?;
        self.write_u32(len);
        for value in values {
            write_item(self, value)?;
        }
        Ok(())
    }
}

pub struct CanonicalReader<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> CanonicalReader<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| anyhow!("canonical decode overflow"))?;
        if end > self.input.len() {
            bail!("truncated canonical input");
        }
        let slice = &self.input[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    pub fn finish(self) -> Result<()> {
        if self.pos != self.input.len() {
            bail!("trailing bytes in canonical input");
        }
        Ok(())
    }

    pub fn read_u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn read_bool(&mut self) -> Result<bool> {
        match self.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            other => bail!("invalid canonical bool {}", other),
        }
    }

    pub fn read_u32(&mut self) -> Result<u32> {
        let mut out = [0u8; 4];
        out.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(out))
    }

    pub fn read_u64(&mut self) -> Result<u64> {
        let mut out = [0u8; 8];
        out.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(out))
    }

    pub fn read_u128(&mut self) -> Result<u128> {
        let mut out = [0u8; 16];
        out.copy_from_slice(self.take(16)?);
        Ok(u128::from_le_bytes(out))
    }

    pub fn read_fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    pub fn read_bytes(&mut self) -> Result<Vec<u8>> {
        let len = self.read_u32()? as usize;
        Ok(self.take(len)?.to_vec())
    }

    pub fn read_string(&mut self) -> Result<String> {
        let bytes = self.read_bytes()?;
        String::from_utf8(bytes).map_err(|_| anyhow!("invalid UTF-8 string"))
    }

    pub fn read_vec<T>(
        &mut self,
        mut read_item: impl FnMut(&mut Self) -> Result<T>,
    ) -> Result<Vec<T>> {
        let len = self.read_u32()? as usize;
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            out.push(read_item(self)?);
        }
        Ok(out)
    }
}

fn write_address(writer: &mut CanonicalWriter, address: &Address) {
    writer.write_fixed(address);
}

fn read_address(reader: &mut CanonicalReader<'_>) -> Result<Address> {
    reader.read_fixed()
}

fn write_signature_algorithm(writer: &mut CanonicalWriter, algorithm: SignatureAlgorithm) {
    let id = match algorithm {
        SignatureAlgorithm::MlDsa65 => 1,
    };
    writer.write_u8(id);
}

fn read_signature_algorithm(reader: &mut CanonicalReader<'_>) -> Result<SignatureAlgorithm> {
    match reader.read_u8()? {
        1 => Ok(SignatureAlgorithm::MlDsa65),
        other => bail!("unsupported signature algorithm {}", other),
    }
}

fn write_kem_algorithm(writer: &mut CanonicalWriter, algorithm: KemAlgorithm) {
    let id = match algorithm {
        KemAlgorithm::MlKem768 => 1,
    };
    writer.write_u8(id);
}

fn read_kem_algorithm(reader: &mut CanonicalReader<'_>) -> Result<KemAlgorithm> {
    match reader.read_u8()? {
        1 => Ok(KemAlgorithm::MlKem768),
        other => bail!("unsupported KEM algorithm {}", other),
    }
}

pub fn write_tagged_signing_public_key(writer: &mut CanonicalWriter, key: &TaggedSigningPublicKey) {
    write_signature_algorithm(writer, key.algorithm);
    writer.write_fixed(&key.bytes);
}

pub fn read_tagged_signing_public_key(
    reader: &mut CanonicalReader<'_>,
) -> Result<TaggedSigningPublicKey> {
    let algorithm = read_signature_algorithm(reader)?;
    let bytes = reader.read_fixed::<ML_DSA_65_PK_BYTES>()?;
    Ok(TaggedSigningPublicKey { algorithm, bytes })
}

pub fn write_tagged_kem_public_key(writer: &mut CanonicalWriter, key: &TaggedKemPublicKey) {
    write_kem_algorithm(writer, key.algorithm);
    writer.write_fixed(&key.bytes);
}

pub fn read_tagged_kem_public_key(reader: &mut CanonicalReader<'_>) -> Result<TaggedKemPublicKey> {
    let algorithm = read_kem_algorithm(reader)?;
    let bytes = reader.read_fixed::<ML_KEM_768_PK_BYTES>()?;
    Ok(TaggedKemPublicKey { algorithm, bytes })
}

fn write_option_fixed32(writer: &mut CanonicalWriter, value: &Option<[u8; 32]>) {
    writer.write_bool(value.is_some());
    if let Some(value) = value {
        writer.write_fixed(value);
    }
}

fn read_option_fixed32(reader: &mut CanonicalReader<'_>) -> Result<Option<[u8; 32]>> {
    if reader.read_bool()? {
        Ok(Some(reader.read_fixed()?))
    } else {
        Ok(None)
    }
}

fn write_option_bytes(writer: &mut CanonicalWriter, value: &Option<Vec<u8>>) -> Result<()> {
    writer.write_bool(value.is_some());
    if let Some(value) = value {
        writer.write_bytes(value)?;
    }
    Ok(())
}

fn read_option_bytes(reader: &mut CanonicalReader<'_>) -> Result<Option<Vec<u8>>> {
    if reader.read_bool()? {
        Ok(Some(reader.read_bytes()?))
    } else {
        Ok(None)
    }
}

fn write_merkle_proof(writer: &mut CanonicalWriter, proof: &[([u8; 32], bool)]) -> Result<()> {
    writer.write_vec(proof, |writer, (hash, is_left)| {
        writer.write_fixed(hash);
        writer.write_bool(*is_left);
        Ok(())
    })
}

fn read_merkle_proof(reader: &mut CanonicalReader<'_>) -> Result<Vec<([u8; 32], bool)>> {
    reader.read_vec(|reader| {
        let hash = reader.read_fixed()?;
        let is_left = reader.read_bool()?;
        Ok((hash, is_left))
    })
}

pub fn write_anchor(writer: &mut CanonicalWriter, anchor: &Anchor) -> Result<()> {
    writer.write_u64(anchor.num);
    writer.write_fixed(&anchor.hash);
    writer.write_fixed(&anchor.merkle_root);
    let difficulty =
        u32::try_from(anchor.difficulty).map_err(|_| anyhow!("difficulty too large"))?;
    writer.write_u32(difficulty);
    writer.write_u32(anchor.coin_count);
    writer.write_u128(anchor.cumulative_work);
    writer.write_u32(anchor.mem_kib);
    Ok(())
}

pub fn read_anchor(reader: &mut CanonicalReader<'_>) -> Result<Anchor> {
    Ok(Anchor {
        num: reader.read_u64()?,
        hash: reader.read_fixed()?,
        merkle_root: reader.read_fixed()?,
        difficulty: reader.read_u32()? as usize,
        coin_count: reader.read_u32()?,
        cumulative_work: reader.read_u128()?,
        mem_kib: reader.read_u32()?,
    })
}

pub fn encode_anchor(anchor: &Anchor) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    write_anchor(&mut writer, anchor)?;
    Ok(writer.into_vec())
}

pub fn decode_anchor(bytes: &[u8]) -> Result<Anchor> {
    let mut reader = CanonicalReader::new(bytes);
    let anchor = read_anchor(&mut reader)?;
    reader.finish()?;
    Ok(anchor)
}

pub fn write_coin(writer: &mut CanonicalWriter, coin: &Coin) -> Result<()> {
    writer.write_fixed(&coin.id);
    writer.write_u64(coin.value);
    writer.write_fixed(&coin.epoch_hash);
    writer.write_u64(coin.nonce);
    write_address(writer, &coin.creator_address);
    write_tagged_signing_public_key(writer, &coin.creator_pk);
    writer.write_fixed(&coin.lock_hash);
    Ok(())
}

pub fn read_coin(reader: &mut CanonicalReader<'_>) -> Result<Coin> {
    Ok(Coin {
        id: reader.read_fixed()?,
        value: reader.read_u64()?,
        epoch_hash: reader.read_fixed()?,
        nonce: reader.read_u64()?,
        creator_address: read_address(reader)?,
        creator_pk: read_tagged_signing_public_key(reader)?,
        lock_hash: reader.read_fixed()?,
    })
}

pub fn encode_coin(coin: &Coin) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    write_coin(&mut writer, coin)?;
    Ok(writer.into_vec())
}

pub fn decode_coin(bytes: &[u8]) -> Result<Coin> {
    let mut reader = CanonicalReader::new(bytes);
    let coin = read_coin(&mut reader)?;
    reader.finish()?;
    Ok(coin)
}

pub fn write_coin_candidate(writer: &mut CanonicalWriter, coin: &CoinCandidate) -> Result<()> {
    writer.write_fixed(&coin.id);
    writer.write_u64(coin.value);
    writer.write_fixed(&coin.epoch_hash);
    writer.write_u64(coin.nonce);
    write_address(writer, &coin.creator_address);
    write_tagged_signing_public_key(writer, &coin.creator_pk);
    writer.write_fixed(&coin.lock_hash);
    writer.write_fixed(&coin.pow_hash);
    Ok(())
}

pub fn read_coin_candidate(reader: &mut CanonicalReader<'_>) -> Result<CoinCandidate> {
    Ok(CoinCandidate {
        id: reader.read_fixed()?,
        value: reader.read_u64()?,
        epoch_hash: reader.read_fixed()?,
        nonce: reader.read_u64()?,
        creator_address: read_address(reader)?,
        creator_pk: read_tagged_signing_public_key(reader)?,
        lock_hash: reader.read_fixed()?,
        pow_hash: reader.read_fixed()?,
    })
}

pub fn encode_coin_candidate(coin: &CoinCandidate) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    write_coin_candidate(&mut writer, coin)?;
    Ok(writer.into_vec())
}

pub fn decode_coin_candidate(bytes: &[u8]) -> Result<CoinCandidate> {
    let mut reader = CanonicalReader::new(bytes);
    let coin = read_coin_candidate(&mut reader)?;
    reader.finish()?;
    Ok(coin)
}

pub fn encode_shielded_output(output: &ShieldedOutput) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_fixed(&output.note_commitment);
    writer.write_fixed(&output.kem_ct);
    writer.write_fixed(&output.nonce);
    writer.write_u8(output.view_tag);
    writer.write_bytes(&output.ciphertext)?;
    Ok(writer.into_vec())
}

pub fn decode_shielded_output(bytes: &[u8]) -> Result<ShieldedOutput> {
    let mut reader = CanonicalReader::new(bytes);
    let output = ShieldedOutput {
        note_commitment: reader.read_fixed()?,
        kem_ct: reader.read_fixed()?,
        nonce: reader.read_fixed()?,
        view_tag: reader.read_u8()?,
        ciphertext: reader.read_bytes()?,
    };
    reader.finish()?;
    Ok(output)
}

pub fn encode_shielded_output_plaintext(plaintext: &ShieldedOutputPlaintext) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_bytes(&encode_shielded_note(&plaintext.note)?)?;
    writer.write_fixed(&plaintext.note_key);
    writer.write_bytes(&encode_historical_unspent_checkpoint(
        &plaintext.checkpoint,
    )?)?;
    Ok(writer.into_vec())
}

pub fn decode_shielded_output_plaintext(bytes: &[u8]) -> Result<ShieldedOutputPlaintext> {
    let mut reader = CanonicalReader::new(bytes);
    let plaintext = ShieldedOutputPlaintext {
        note: decode_shielded_note(&reader.read_bytes()?)?,
        note_key: reader.read_fixed()?,
        checkpoint: decode_historical_unspent_checkpoint(&reader.read_bytes()?)?,
    };
    reader.finish()?;
    Ok(plaintext)
}

pub fn encode_tx(tx: &Tx) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_bytes(b"unchained.shielded_tx.v2")?;
    writer.write_vec(&tx.nullifiers, |writer, nullifier| {
        writer.write_fixed(nullifier);
        Ok(())
    })?;
    writer.write_vec(&tx.outputs, |writer, output| {
        writer.write_bytes(&encode_shielded_output(output)?)?;
        Ok(())
    })?;
    writer.write_bytes(&tx.proof)?;
    Ok(writer.into_vec())
}

pub fn decode_tx(bytes: &[u8]) -> Result<Tx> {
    let mut reader = CanonicalReader::new(bytes);
    let domain = reader.read_bytes()?;
    if domain.as_slice() != b"unchained.shielded_tx.v2" {
        bail!("unsupported transaction encoding");
    }
    let nullifiers = reader.read_vec(|reader| reader.read_fixed())?;
    let outputs = reader.read_vec(|reader| decode_shielded_output(&reader.read_bytes()?))?;
    let proof = reader.read_bytes()?;
    reader.finish()?;
    Ok(Tx {
        nullifiers,
        outputs,
        proof,
    })
}

pub fn encode_recipient_handle_signable(
    chain_id: &[u8; 32],
    signing_pk: &TaggedSigningPublicKey,
    receive_key_id: &[u8; 32],
    kem_pk: &TaggedKemPublicKey,
    issued_unix_ms: u64,
    expires_unix_ms: u64,
) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_fixed(chain_id);
    write_tagged_signing_public_key(&mut writer, signing_pk);
    writer.write_fixed(receive_key_id);
    write_tagged_kem_public_key(&mut writer, kem_pk);
    writer.write_u64(issued_unix_ms);
    writer.write_u64(expires_unix_ms);
    Ok(writer.into_vec())
}

pub fn encode_recipient_handle(doc: &RecipientHandle) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_fixed(&doc.chain_id);
    write_tagged_signing_public_key(&mut writer, &doc.signing_pk);
    writer.write_fixed(&doc.receive_key_id);
    write_tagged_kem_public_key(&mut writer, &doc.kem_pk);
    writer.write_u64(doc.issued_unix_ms);
    writer.write_u64(doc.expires_unix_ms);
    writer.write_bytes(&doc.sig)?;
    Ok(writer.into_vec())
}

pub fn decode_recipient_handle(bytes: &[u8]) -> Result<RecipientHandle> {
    let mut reader = CanonicalReader::new(bytes);
    let doc = RecipientHandle {
        chain_id: reader.read_fixed()?,
        signing_pk: read_tagged_signing_public_key(&mut reader)?,
        receive_key_id: reader.read_fixed()?,
        kem_pk: read_tagged_kem_public_key(&mut reader)?,
        issued_unix_ms: reader.read_u64()?,
        expires_unix_ms: reader.read_u64()?,
        sig: reader.read_bytes()?,
    };
    reader.finish()?;
    Ok(doc)
}

pub fn encode_epoch_leaves_bundle(bundle: &EpochLeavesBundle) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_u64(bundle.epoch_num);
    writer.write_fixed(&bundle.merkle_root);
    writer.write_vec(&bundle.leaves, |writer, leaf| {
        writer.write_fixed(leaf);
        Ok(())
    })?;
    Ok(writer.into_vec())
}

pub fn decode_epoch_leaves_bundle(bytes: &[u8]) -> Result<EpochLeavesBundle> {
    let mut reader = CanonicalReader::new(bytes);
    let bundle = EpochLeavesBundle {
        epoch_num: reader.read_u64()?,
        merkle_root: reader.read_fixed()?,
        leaves: reader.read_vec(|reader| reader.read_fixed())?,
    };
    reader.finish()?;
    Ok(bundle)
}

pub fn encode_selected_ids_bundle(bundle: &SelectedIdsBundle) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_u64(bundle.epoch_num);
    writer.write_fixed(&bundle.merkle_root);
    writer.write_vec(&bundle.coin_ids, |writer, id| {
        writer.write_fixed(id);
        Ok(())
    })?;
    Ok(writer.into_vec())
}

pub fn decode_selected_ids_bundle(bytes: &[u8]) -> Result<SelectedIdsBundle> {
    let mut reader = CanonicalReader::new(bytes);
    let bundle = SelectedIdsBundle {
        epoch_num: reader.read_u64()?,
        merkle_root: reader.read_fixed()?,
        coin_ids: reader.read_vec(|reader| reader.read_fixed())?,
    };
    reader.finish()?;
    Ok(bundle)
}

pub fn encode_epoch_candidates_response(response: &EpochCandidatesResponse) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_fixed(&response.epoch_hash);
    writer.write_vec(&response.candidates, |writer, coin| {
        write_coin_candidate(writer, coin)
    })?;
    Ok(writer.into_vec())
}

pub fn decode_epoch_candidates_response(bytes: &[u8]) -> Result<EpochCandidatesResponse> {
    let mut reader = CanonicalReader::new(bytes);
    let response = EpochCandidatesResponse {
        epoch_hash: reader.read_fixed()?,
        candidates: reader.read_vec(read_coin_candidate)?,
    };
    reader.finish()?;
    Ok(response)
}

pub fn encode_epoch_headers_range(range: &EpochHeadersRange) -> Vec<u8> {
    let mut writer = CanonicalWriter::new();
    writer.write_u64(range.start_height);
    writer.write_u32(range.count);
    writer.into_vec()
}

pub fn decode_epoch_headers_range(bytes: &[u8]) -> Result<EpochHeadersRange> {
    let mut reader = CanonicalReader::new(bytes);
    let range = EpochHeadersRange {
        start_height: reader.read_u64()?,
        count: reader.read_u32()?,
    };
    reader.finish()?;
    Ok(range)
}

pub fn encode_compact_epoch(compact: &CompactEpoch) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    write_anchor(&mut writer, &compact.anchor)?;
    writer.write_vec(&compact.short_ids, |writer, short_id| {
        writer.write_fixed(short_id);
        Ok(())
    })?;
    writer.write_vec(&compact.prefilled, |writer, (index, coin)| {
        writer.write_u32(*index);
        write_coin(writer, coin)
    })?;
    Ok(writer.into_vec())
}

pub fn decode_compact_epoch(bytes: &[u8]) -> Result<CompactEpoch> {
    let mut reader = CanonicalReader::new(bytes);
    let compact = CompactEpoch {
        anchor: read_anchor(&mut reader)?,
        short_ids: reader.read_vec(|reader| reader.read_fixed())?,
        prefilled: reader.read_vec(|reader| {
            let index = reader.read_u32()?;
            let coin = read_coin(reader)?;
            Ok((index, coin))
        })?,
    };
    reader.finish()?;
    Ok(compact)
}

pub fn encode_epoch_get_txn(request: &EpochGetTxn) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_fixed(&request.epoch_hash);
    writer.write_vec(&request.indexes, |writer, index| {
        writer.write_u32(*index);
        Ok(())
    })?;
    Ok(writer.into_vec())
}

pub fn decode_epoch_get_txn(bytes: &[u8]) -> Result<EpochGetTxn> {
    let mut reader = CanonicalReader::new(bytes);
    let request = EpochGetTxn {
        epoch_hash: reader.read_fixed()?,
        indexes: reader.read_vec(|reader| reader.read_u32())?,
    };
    reader.finish()?;
    Ok(request)
}

pub fn encode_epoch_txn(response: &EpochTxn) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_fixed(&response.epoch_hash);
    writer.write_vec(&response.indexes, |writer, index| {
        writer.write_u32(*index);
        Ok(())
    })?;
    writer.write_vec(&response.coins, |writer, coin| write_coin(writer, coin))?;
    Ok(writer.into_vec())
}

pub fn decode_epoch_txn(bytes: &[u8]) -> Result<EpochTxn> {
    let mut reader = CanonicalReader::new(bytes);
    let response = EpochTxn {
        epoch_hash: reader.read_fixed()?,
        indexes: reader.read_vec(|reader| reader.read_u32())?,
        coins: reader.read_vec(read_coin)?,
    };
    reader.finish()?;
    Ok(response)
}

pub fn encode_epoch_headers_batch(batch: &EpochHeadersBatch) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_u64(batch.start_height);
    writer.write_vec(&batch.headers, |writer, anchor| {
        write_anchor(writer, anchor)
    })?;
    Ok(writer.into_vec())
}

pub fn decode_epoch_headers_batch(bytes: &[u8]) -> Result<EpochHeadersBatch> {
    let mut reader = CanonicalReader::new(bytes);
    let batch = EpochHeadersBatch {
        start_height: reader.read_u64()?,
        headers: reader.read_vec(read_anchor)?,
    };
    reader.finish()?;
    Ok(batch)
}

pub fn encode_epoch_by_hash(request: &EpochByHash) -> Vec<u8> {
    let mut writer = CanonicalWriter::new();
    writer.write_fixed(&request.hash);
    writer.into_vec()
}

pub fn decode_epoch_by_hash(bytes: &[u8]) -> Result<EpochByHash> {
    let mut reader = CanonicalReader::new(bytes);
    let request = EpochByHash {
        hash: reader.read_fixed()?,
    };
    reader.finish()?;
    Ok(request)
}

pub fn encode_node_record(record: &NodeRecordV2) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_u8(record.version);
    writer.write_u32(record.protocol_version);
    writer.write_fixed(&record.node_id);
    write_option_fixed32(&mut writer, &record.chain_id);
    writer.write_bytes(&record.root_spki)?;
    writer.write_bytes(&record.auth_spki)?;
    writer.write_vec(&record.addresses, |writer, address| {
        writer.write_string(address)
    })?;
    writer.write_u64(record.issued_unix_ms);
    writer.write_u64(record.expires_unix_ms);
    writer.write_bytes(&record.sig)?;
    Ok(writer.into_vec())
}

pub fn decode_node_record(bytes: &[u8]) -> Result<NodeRecordV2> {
    let mut reader = CanonicalReader::new(bytes);
    let record = NodeRecordV2 {
        version: reader.read_u8()?,
        protocol_version: reader.read_u32()?,
        node_id: reader.read_fixed()?,
        chain_id: read_option_fixed32(&mut reader)?,
        root_spki: reader.read_bytes()?,
        auth_spki: reader.read_bytes()?,
        addresses: reader.read_vec(|reader| reader.read_string())?,
        issued_unix_ms: reader.read_u64()?,
        expires_unix_ms: reader.read_u64()?,
        sig: reader.read_bytes()?,
    };
    reader.finish()?;
    Ok(record)
}

fn write_trust_update_action(writer: &mut CanonicalWriter, action: &TrustUpdateAction) {
    let id = match action {
        TrustUpdateAction::Revoke => 1,
        TrustUpdateAction::Replace => 2,
    };
    writer.write_u8(id);
}

fn read_trust_update_action(reader: &mut CanonicalReader<'_>) -> Result<TrustUpdateAction> {
    match reader.read_u8()? {
        1 => Ok(TrustUpdateAction::Revoke),
        2 => Ok(TrustUpdateAction::Replace),
        other => bail!("unsupported trust update action {}", other),
    }
}

pub fn encode_trust_update(update: &TrustUpdateV1) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_u8(update.version);
    write_trust_update_action(&mut writer, &update.action);
    writer.write_fixed(&update.subject_node_id);
    write_option_fixed32(&mut writer, &update.replacement_node_id);
    write_option_bytes(&mut writer, &update.replacement_root_spki)?;
    writer.write_u64(update.issued_unix_ms);
    writer.write_vec(&update.approvals, |writer, approval| {
        writer.write_fixed(&approval.signer_node_id);
        writer.write_bytes(&approval.signer_root_spki)?;
        writer.write_bytes(&approval.sig)?;
        Ok(())
    })?;
    Ok(writer.into_vec())
}

pub fn decode_trust_update(bytes: &[u8]) -> Result<TrustUpdateV1> {
    let mut reader = CanonicalReader::new(bytes);
    let update = TrustUpdateV1 {
        version: reader.read_u8()?,
        action: read_trust_update_action(&mut reader)?,
        subject_node_id: reader.read_fixed()?,
        replacement_node_id: read_option_fixed32(&mut reader)?,
        replacement_root_spki: read_option_bytes(&mut reader)?,
        issued_unix_ms: reader.read_u64()?,
        approvals: reader.read_vec(|reader| {
            Ok(TrustApprovalV1 {
                signer_node_id: reader.read_fixed()?,
                signer_root_spki: reader.read_bytes()?,
                sig: reader.read_bytes()?,
            })
        })?,
    };
    reader.finish()?;
    Ok(update)
}

pub fn encode_signed_envelope(envelope: &SignedEnvelope) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_u8(envelope.version);
    writer.write_u32(envelope.protocol_version);
    writer.write_fixed(&envelope.node_id);
    write_option_fixed32(&mut writer, &envelope.chain_id);
    writer.write_u64(envelope.issued_unix_ms);
    writer.write_u64(envelope.expires_unix_ms);
    write_option_fixed32(&mut writer, &envelope.response_to_message_id);
    writer.write_fixed(&envelope.nonce);
    writer.write_fixed(&envelope.message_id);
    writer.write_bytes(&envelope.payload)?;
    writer.write_bytes(&envelope.sig)?;
    Ok(writer.into_vec())
}

pub fn decode_signed_envelope(bytes: &[u8]) -> Result<SignedEnvelope> {
    let mut reader = CanonicalReader::new(bytes);
    let envelope = SignedEnvelope {
        version: reader.read_u8()?,
        protocol_version: reader.read_u32()?,
        node_id: reader.read_fixed()?,
        chain_id: read_option_fixed32(&mut reader)?,
        issued_unix_ms: reader.read_u64()?,
        expires_unix_ms: reader.read_u64()?,
        response_to_message_id: read_option_fixed32(&mut reader)?,
        nonce: reader.read_fixed()?,
        message_id: reader.read_fixed()?,
        payload: reader.read_bytes()?,
        sig: reader.read_bytes()?,
    };
    reader.finish()?;
    Ok(envelope)
}

pub fn encode_shielded_note(note: &ShieldedNote) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_u8(note.version);
    writer.write_u64(note.value);
    writer.write_u64(note.birth_epoch);
    write_address(&mut writer, &note.owner_address);
    write_tagged_signing_public_key(&mut writer, &note.owner_signing_pk);
    write_tagged_kem_public_key(&mut writer, &note.owner_kem_pk);
    writer.write_fixed(&note.rho);
    writer.write_fixed(&note.note_randomizer);
    writer.write_fixed(&note.note_key_commitment);
    writer.write_fixed(&note.commitment);
    Ok(writer.into_vec())
}

pub fn decode_shielded_note(bytes: &[u8]) -> Result<ShieldedNote> {
    let mut reader = CanonicalReader::new(bytes);
    let note = ShieldedNote {
        version: reader.read_u8()?,
        value: reader.read_u64()?,
        birth_epoch: reader.read_u64()?,
        owner_address: read_address(&mut reader)?,
        owner_signing_pk: read_tagged_signing_public_key(&mut reader)?,
        owner_kem_pk: read_tagged_kem_public_key(&mut reader)?,
        rho: reader.read_fixed()?,
        note_randomizer: reader.read_fixed()?,
        note_key_commitment: reader.read_fixed()?,
        commitment: reader.read_fixed()?,
    };
    reader.finish()?;
    Ok(note)
}

pub fn encode_note_commitment_tree(tree: &NoteCommitmentTree) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_vec(&tree.commitments, |writer, commitment| {
        writer.write_fixed(commitment);
        Ok(())
    })?;
    writer.write_vec(&tree.levels, |writer, level| {
        writer.write_vec(level, |writer, node| {
            writer.write_fixed(node);
            Ok(())
        })
    })?;
    Ok(writer.into_vec())
}

pub fn decode_note_commitment_tree(bytes: &[u8]) -> Result<NoteCommitmentTree> {
    let mut reader = CanonicalReader::new(bytes);
    let commitments = reader.read_vec(|reader| reader.read_fixed())?;
    let levels = reader.read_vec(|reader| reader.read_vec(|reader| reader.read_fixed()))?;
    reader.finish()?;
    NoteCommitmentTree::from_parts(commitments, levels)
}

pub fn encode_note_membership_proof(proof: &NoteMembershipProof) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_fixed(&proof.note_commitment);
    writer.write_fixed(&proof.root);
    write_merkle_proof(&mut writer, &proof.proof)?;
    Ok(writer.into_vec())
}

pub fn decode_note_membership_proof(bytes: &[u8]) -> Result<NoteMembershipProof> {
    let mut reader = CanonicalReader::new(bytes);
    let proof = NoteMembershipProof {
        note_commitment: reader.read_fixed()?,
        root: reader.read_fixed()?,
        proof: read_merkle_proof(&mut reader)?,
    };
    reader.finish()?;
    Ok(proof)
}

fn write_nullifier_membership_witness(
    writer: &mut CanonicalWriter,
    witness: &NullifierMembershipWitness,
) -> Result<()> {
    writer.write_fixed(&witness.nullifier);
    writer.write_fixed(&witness.root);
    write_merkle_proof(writer, &witness.proof)?;
    Ok(())
}

fn read_nullifier_membership_witness(
    reader: &mut CanonicalReader<'_>,
) -> Result<NullifierMembershipWitness> {
    Ok(NullifierMembershipWitness {
        nullifier: reader.read_fixed()?,
        root: reader.read_fixed()?,
        proof: read_merkle_proof(reader)?,
    })
}

fn write_optional_nullifier_membership_witness(
    writer: &mut CanonicalWriter,
    witness: &Option<NullifierMembershipWitness>,
) -> Result<()> {
    writer.write_bool(witness.is_some());
    if let Some(witness) = witness {
        write_nullifier_membership_witness(writer, witness)?;
    }
    Ok(())
}

fn read_optional_nullifier_membership_witness(
    reader: &mut CanonicalReader<'_>,
) -> Result<Option<NullifierMembershipWitness>> {
    if reader.read_bool()? {
        Ok(Some(read_nullifier_membership_witness(reader)?))
    } else {
        Ok(None)
    }
}

pub fn encode_nullifier_non_membership_proof(
    proof: &NullifierNonMembershipProof,
) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_u64(proof.epoch);
    writer.write_fixed(&proof.queried_nullifier);
    writer.write_fixed(&proof.root);
    writer.write_u32(proof.set_size);
    write_optional_nullifier_membership_witness(&mut writer, &proof.predecessor)?;
    write_optional_nullifier_membership_witness(&mut writer, &proof.successor)?;
    Ok(writer.into_vec())
}

pub fn decode_nullifier_non_membership_proof(bytes: &[u8]) -> Result<NullifierNonMembershipProof> {
    let mut reader = CanonicalReader::new(bytes);
    let proof = NullifierNonMembershipProof {
        epoch: reader.read_u64()?,
        queried_nullifier: reader.read_fixed()?,
        root: reader.read_fixed()?,
        set_size: reader.read_u32()?,
        predecessor: read_optional_nullifier_membership_witness(&mut reader)?,
        successor: read_optional_nullifier_membership_witness(&mut reader)?,
    };
    reader.finish()?;
    Ok(proof)
}

pub fn encode_archived_nullifier_epoch(epoch: &ArchivedNullifierEpoch) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_u64(epoch.epoch);
    writer.write_vec(&epoch.nullifiers, |writer, nullifier| {
        writer.write_fixed(nullifier);
        Ok(())
    })?;
    writer.write_vec(&epoch.levels, |writer, level| {
        writer.write_vec(level, |writer, node| {
            writer.write_fixed(node);
            Ok(())
        })
    })?;
    writer.write_fixed(&epoch.root);
    Ok(writer.into_vec())
}

pub fn decode_archived_nullifier_epoch(bytes: &[u8]) -> Result<ArchivedNullifierEpoch> {
    let mut reader = CanonicalReader::new(bytes);
    let epoch_num = reader.read_u64()?;
    let nullifiers = reader.read_vec(|reader| reader.read_fixed())?;
    let levels = reader.read_vec(|reader| reader.read_vec(|reader| reader.read_fixed()))?;
    let root = reader.read_fixed()?;
    reader.finish()?;
    ArchivedNullifierEpoch::from_parts(epoch_num, nullifiers, levels, root)
}

pub fn encode_archive_shard(shard: &ArchiveShard) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_u64(shard.shard_id);
    writer.write_u64(shard.first_epoch);
    writer.write_u64(shard.last_epoch);
    writer.write_fixed(&shard.root_digest);
    writer.write_vec(&shard.epoch_roots, |writer, (epoch, root)| {
        writer.write_u64(*epoch);
        writer.write_fixed(root);
        Ok(())
    })?;
    Ok(writer.into_vec())
}

pub fn decode_archive_shard(bytes: &[u8]) -> Result<ArchiveShard> {
    let mut reader = CanonicalReader::new(bytes);
    let shard_id = reader.read_u64()?;
    let first_epoch = reader.read_u64()?;
    let last_epoch = reader.read_u64()?;
    let root_digest = reader.read_fixed()?;
    let epoch_roots = reader.read_vec(|reader| {
        let epoch = reader.read_u64()?;
        let root = reader.read_fixed()?;
        Ok((epoch, root))
    })?;
    reader.finish()?;
    let shard = ArchiveShard::new(shard_id, epoch_roots)?;
    if shard.first_epoch != first_epoch
        || shard.last_epoch != last_epoch
        || shard.root_digest != root_digest
    {
        bail!("archive shard canonical fields mismatch");
    }
    Ok(shard)
}

pub fn encode_archive_provider_manifest(manifest: &ArchiveProviderManifest) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_fixed(&manifest.provider_id);
    writer.write_fixed(&manifest.schedule_seed);
    writer.write_u64(manifest.coverage_first_epoch);
    writer.write_u64(manifest.coverage_last_epoch);
    writer.write_vec(&manifest.shard_ids, |writer, shard_id| {
        writer.write_u64(*shard_id);
        Ok(())
    })?;
    writer.write_vec(&manifest.shard_digests, |writer, digest| {
        writer.write_fixed(digest);
        Ok(())
    })?;
    writer.write_fixed(&manifest.manifest_digest);
    Ok(writer.into_vec())
}

pub fn decode_archive_provider_manifest(bytes: &[u8]) -> Result<ArchiveProviderManifest> {
    let mut reader = CanonicalReader::new(bytes);
    let manifest = ArchiveProviderManifest {
        provider_id: reader.read_fixed()?,
        schedule_seed: reader.read_fixed()?,
        coverage_first_epoch: reader.read_u64()?,
        coverage_last_epoch: reader.read_u64()?,
        shard_ids: reader.read_vec(|reader| reader.read_u64())?,
        shard_digests: reader.read_vec(|reader| reader.read_fixed())?,
        manifest_digest: reader.read_fixed()?,
    };
    reader.finish()?;
    Ok(manifest)
}

pub fn encode_archive_replica_attestation(
    attestation: &ArchiveReplicaAttestation,
) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_fixed(&attestation.provider_id);
    writer.write_u64(attestation.shard_id);
    writer.write_fixed(&attestation.shard_digest);
    writer.write_u64(attestation.first_epoch);
    writer.write_u64(attestation.last_epoch);
    writer.write_u64(attestation.retention_through_epoch);
    writer.write_fixed(&attestation.attestation_digest);
    Ok(writer.into_vec())
}

pub fn decode_archive_replica_attestation(bytes: &[u8]) -> Result<ArchiveReplicaAttestation> {
    let mut reader = CanonicalReader::new(bytes);
    let attestation = ArchiveReplicaAttestation {
        provider_id: reader.read_fixed()?,
        shard_id: reader.read_u64()?,
        shard_digest: reader.read_fixed()?,
        first_epoch: reader.read_u64()?,
        last_epoch: reader.read_u64()?,
        retention_through_epoch: reader.read_u64()?,
        attestation_digest: reader.read_fixed()?,
    };
    reader.finish()?;
    Ok(attestation)
}

pub fn encode_archive_custody_commitment(commitment: &ArchiveCustodyCommitment) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_fixed(&commitment.provider_id);
    writer.write_fixed(&commitment.provider_manifest_digest);
    writer.write_u64(commitment.shard_id);
    writer.write_fixed(&commitment.shard_digest);
    writer.write_u64(commitment.retention_through_epoch);
    writer.write_fixed(&commitment.commitment_digest);
    Ok(writer.into_vec())
}

pub fn decode_archive_custody_commitment(bytes: &[u8]) -> Result<ArchiveCustodyCommitment> {
    let mut reader = CanonicalReader::new(bytes);
    let commitment = ArchiveCustodyCommitment {
        provider_id: reader.read_fixed()?,
        provider_manifest_digest: reader.read_fixed()?,
        shard_id: reader.read_u64()?,
        shard_digest: reader.read_fixed()?,
        retention_through_epoch: reader.read_u64()?,
        commitment_digest: reader.read_fixed()?,
    };
    reader.finish()?;
    Ok(commitment)
}

pub fn encode_archive_operator_scorecard(scorecard: &ArchiveOperatorScorecard) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_fixed(&scorecard.provider_id);
    writer.write_fixed(&scorecard.provider_manifest_digest);
    writer.write_u32(scorecard.advertised_shard_count);
    writer.write_u32(scorecard.assigned_shard_count);
    writer.write_u32(scorecard.fulfilled_custody_count);
    writer.write_u32(scorecard.committed_custody_count);
    writer.write_u32(scorecard.missing_custody_commitment_count);
    writer.write_u64(scorecard.retention_surplus_epochs);
    writer.write_u32(scorecard.availability_bps as u32);
    writer.write_u32(scorecard.service_success_bps as u32);
    writer.write_u64(scorecard.successful_retrieval_receipts);
    writer.write_u64(scorecard.failed_retrieval_receipts);
    writer.write_u64(scorecard.served_checkpoint_batches);
    writer.write_u64(scorecard.served_checkpoint_segments);
    writer.write_u64(scorecard.served_archive_shards);
    writer.write_u32(scorecard.mean_checkpoint_latency_ms);
    writer.write_u64(scorecard.reward_weight);
    Ok(writer.into_vec())
}

pub fn decode_archive_operator_scorecard(bytes: &[u8]) -> Result<ArchiveOperatorScorecard> {
    let mut reader = CanonicalReader::new(bytes);
    let provider_id = reader.read_fixed()?;
    let provider_manifest_digest = reader.read_fixed()?;
    let advertised_shard_count = reader.read_u32()?;
    let assigned_shard_count = reader.read_u32()?;
    let fulfilled_custody_count = reader.read_u32()?;
    let committed_custody_count = reader.read_u32()?;
    let missing_custody_commitment_count = reader.read_u32()?;
    let retention_surplus_epochs = reader.read_u64()?;
    let availability_bps = reader.read_u32()?;
    let service_success_bps = reader.read_u32()?;
    let successful_retrieval_receipts = reader.read_u64()?;
    let failed_retrieval_receipts = reader.read_u64()?;
    let served_checkpoint_batches = reader.read_u64()?;
    let served_checkpoint_segments = reader.read_u64()?;
    let served_archive_shards = reader.read_u64()?;
    let mean_checkpoint_latency_ms = reader.read_u32()?;
    let reward_weight = reader.read_u64()?;
    let scorecard = ArchiveOperatorScorecard {
        provider_id,
        provider_manifest_digest,
        advertised_shard_count,
        assigned_shard_count,
        fulfilled_custody_count,
        committed_custody_count,
        missing_custody_commitment_count,
        retention_surplus_epochs,
        availability_bps: u16::try_from(availability_bps)
            .map_err(|_| anyhow!("archive operator availability does not fit in u16"))?,
        service_success_bps: u16::try_from(service_success_bps)
            .map_err(|_| anyhow!("archive operator service availability does not fit in u16"))?,
        successful_retrieval_receipts,
        failed_retrieval_receipts,
        served_checkpoint_batches,
        served_checkpoint_segments,
        served_archive_shards,
        mean_checkpoint_latency_ms,
        reward_weight,
    };
    reader.finish()?;
    Ok(scorecard)
}

pub fn encode_archive_service_ledger(ledger: &ArchiveServiceLedger) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_fixed(&ledger.provider_id);
    writer.write_fixed(&ledger.provider_manifest_digest);
    writer.write_u64(ledger.served_checkpoint_batches);
    writer.write_u64(ledger.served_checkpoint_segments);
    writer.write_u64(ledger.served_archive_shards);
    writer.write_u64(ledger.failed_checkpoint_batches);
    writer.write_u64(ledger.failed_archive_shards);
    writer.write_u64(ledger.total_checkpoint_latency_ms);
    writer.write_u64(ledger.last_success_unix_ms);
    writer.write_fixed(&ledger.ledger_digest);
    Ok(writer.into_vec())
}

pub fn decode_archive_service_ledger(bytes: &[u8]) -> Result<ArchiveServiceLedger> {
    let mut reader = CanonicalReader::new(bytes);
    let ledger = ArchiveServiceLedger {
        provider_id: reader.read_fixed()?,
        provider_manifest_digest: reader.read_fixed()?,
        served_checkpoint_batches: reader.read_u64()?,
        served_checkpoint_segments: reader.read_u64()?,
        served_archive_shards: reader.read_u64()?,
        failed_checkpoint_batches: reader.read_u64()?,
        failed_archive_shards: reader.read_u64()?,
        total_checkpoint_latency_ms: reader.read_u64()?,
        last_success_unix_ms: reader.read_u64()?,
        ledger_digest: reader.read_fixed()?,
    };
    reader.finish()?;
    Ok(ledger)
}

pub fn encode_archive_retrieval_receipt(receipt: &ArchiveRetrievalReceipt) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_fixed(&receipt.requester_id);
    writer.write_fixed(&receipt.provider_id);
    writer.write_fixed(&receipt.provider_manifest_digest);
    writer.write_u8(match receipt.retrieval_kind {
        ArchiveRetrievalKind::CheckpointBatch => 1,
        ArchiveRetrievalKind::ArchiveShard => 2,
    });
    writer.write_fixed(&receipt.request_message_id);
    write_option_fixed32(&mut writer, &receipt.response_message_id);
    writer.write_u64(receipt.from_epoch);
    writer.write_u64(receipt.through_epoch);
    writer.write_bool(receipt.shard_id.is_some());
    if let Some(shard_id) = receipt.shard_id {
        writer.write_u64(shard_id);
    }
    writer.write_u32(receipt.served_units);
    writer.write_bool(receipt.success);
    writer.write_u64(receipt.latency_ms);
    writer.write_u64(receipt.observed_unix_ms);
    writer.write_fixed(&receipt.receipt_digest);
    Ok(writer.into_vec())
}

pub fn decode_archive_retrieval_receipt(bytes: &[u8]) -> Result<ArchiveRetrievalReceipt> {
    let mut reader = CanonicalReader::new(bytes);
    let requester_id = reader.read_fixed()?;
    let provider_id = reader.read_fixed()?;
    let provider_manifest_digest = reader.read_fixed()?;
    let retrieval_kind = match reader.read_u8()? {
        1 => ArchiveRetrievalKind::CheckpointBatch,
        2 => ArchiveRetrievalKind::ArchiveShard,
        other => bail!("unsupported archive retrieval kind {}", other),
    };
    let request_message_id = reader.read_fixed()?;
    let response_message_id = read_option_fixed32(&mut reader)?;
    let from_epoch = reader.read_u64()?;
    let through_epoch = reader.read_u64()?;
    let shard_id = if reader.read_bool()? {
        Some(reader.read_u64()?)
    } else {
        None
    };
    let served_units = reader.read_u32()?;
    let success = reader.read_bool()?;
    let latency_ms = reader.read_u64()?;
    let observed_unix_ms = reader.read_u64()?;
    let receipt_digest = reader.read_fixed()?;
    let receipt = ArchiveRetrievalReceipt {
        requester_id,
        provider_id,
        provider_manifest_digest,
        retrieval_kind,
        request_message_id,
        response_message_id,
        from_epoch,
        through_epoch,
        shard_id,
        served_units,
        success,
        latency_ms,
        observed_unix_ms,
        receipt_digest,
    };
    reader.finish()?;
    Ok(receipt)
}

pub fn encode_archive_shard_bundle(bundle: &ArchiveShardBundle) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_fixed(&bundle.provider_id);
    writer.write_fixed(&bundle.provider_manifest_digest);
    writer.write_bytes(&encode_archive_shard(&bundle.shard)?)?;
    writer.write_vec(&bundle.epochs, |writer, epoch| {
        writer.write_bytes(&encode_archived_nullifier_epoch(epoch)?)?;
        Ok(())
    })?;
    Ok(writer.into_vec())
}

pub fn decode_archive_shard_bundle(bytes: &[u8]) -> Result<ArchiveShardBundle> {
    let mut reader = CanonicalReader::new(bytes);
    let bundle = ArchiveShardBundle {
        provider_id: reader.read_fixed()?,
        provider_manifest_digest: reader.read_fixed()?,
        shard: decode_archive_shard(&reader.read_bytes()?)?,
        epochs: reader.read_vec(|reader| decode_archived_nullifier_epoch(&reader.read_bytes()?))?,
    };
    reader.finish()?;
    Ok(bundle)
}

pub fn encode_nullifier_root_ledger(ledger: &NullifierRootLedger) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    let entries = ledger.roots.iter().collect::<Vec<_>>();
    writer.write_vec(&entries, |writer, (epoch, root)| {
        writer.write_u64(**epoch);
        writer.write_fixed(root);
        Ok(())
    })?;
    Ok(writer.into_vec())
}

pub fn decode_nullifier_root_ledger(bytes: &[u8]) -> Result<NullifierRootLedger> {
    let mut reader = CanonicalReader::new(bytes);
    let entries = reader.read_vec(|reader| {
        let epoch = reader.read_u64()?;
        let root = reader.read_fixed()?;
        Ok((epoch, root))
    })?;
    reader.finish()?;
    Ok(NullifierRootLedger {
        roots: entries.into_iter().collect(),
    })
}

pub fn encode_historical_unspent_checkpoint(
    checkpoint: &HistoricalUnspentCheckpoint,
) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_u8(checkpoint.version);
    writer.write_fixed(&checkpoint.note_commitment);
    writer.write_u64(checkpoint.birth_epoch);
    writer.write_u64(checkpoint.covered_through_epoch);
    writer.write_fixed(&checkpoint.transcript_root);
    writer.write_u32(checkpoint.verified_epoch_count);
    Ok(writer.into_vec())
}

pub fn decode_historical_unspent_checkpoint(bytes: &[u8]) -> Result<HistoricalUnspentCheckpoint> {
    let mut reader = CanonicalReader::new(bytes);
    let checkpoint = HistoricalUnspentCheckpoint {
        version: reader.read_u8()?,
        note_commitment: reader.read_fixed()?,
        birth_epoch: reader.read_u64()?,
        covered_through_epoch: reader.read_u64()?,
        transcript_root: reader.read_fixed()?,
        verified_epoch_count: reader.read_u32()?,
    };
    reader.finish()?;
    Ok(checkpoint)
}

fn write_evolving_nullifier_query(writer: &mut CanonicalWriter, query: &EvolvingNullifierQuery) {
    writer.write_u64(query.epoch);
    writer.write_fixed(&query.nullifier);
}

fn read_evolving_nullifier_query(
    reader: &mut CanonicalReader<'_>,
) -> Result<EvolvingNullifierQuery> {
    Ok(EvolvingNullifierQuery {
        epoch: reader.read_u64()?,
        nullifier: reader.read_fixed()?,
    })
}

pub fn encode_checkpoint_extension_request(
    request: &CheckpointExtensionRequest,
) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_bytes(&encode_checkpoint_presentation(&request.presentation)?)?;
    writer.write_vec(&request.queries, |writer, query| {
        write_evolving_nullifier_query(writer, query);
        Ok(())
    })?;
    Ok(writer.into_vec())
}

pub fn decode_checkpoint_extension_request(bytes: &[u8]) -> Result<CheckpointExtensionRequest> {
    let mut reader = CanonicalReader::new(bytes);
    let request = CheckpointExtensionRequest {
        checkpoint: None,
        presentation: decode_checkpoint_presentation(&reader.read_bytes()?)?,
        queries: reader.read_vec(read_evolving_nullifier_query)?,
    };
    reader.finish()?;
    Ok(request)
}

fn write_historical_absence_record(
    writer: &mut CanonicalWriter,
    record: &HistoricalAbsenceRecord,
) -> Result<()> {
    writer.write_u64(record.epoch);
    writer.write_fixed(&record.nullifier);
    writer.write_bytes(&encode_nullifier_non_membership_proof(&record.proof)?)?;
    Ok(())
}

fn read_historical_absence_record(
    reader: &mut CanonicalReader<'_>,
) -> Result<HistoricalAbsenceRecord> {
    Ok(HistoricalAbsenceRecord {
        epoch: reader.read_u64()?,
        nullifier: reader.read_fixed()?,
        proof: decode_nullifier_non_membership_proof(&reader.read_bytes()?)?,
    })
}

fn write_historical_unspent_packet(
    writer: &mut CanonicalWriter,
    packet: &HistoricalUnspentPacket,
) -> Result<()> {
    writer.write_u64(packet.from_epoch);
    writer.write_u64(packet.through_epoch);
    writer.write_fixed(&packet.packet_historical_root_digest);
    writer.write_fixed(&packet.segment_commitment_root);
    writer.write_fixed(&packet.packet_rerandomization_blinding);
    writer.write_fixed(&packet.packet_transcript_root);
    writer.write_vec(&packet.segments, |writer, segment| {
        writer.write_fixed(&segment.provider_id);
        writer.write_fixed(&segment.provider_manifest_digest);
        writer.write_fixed(&segment.request_binding);
        writer.write_u64(segment.from_epoch);
        writer.write_u64(segment.through_epoch);
        writer.write_fixed(&segment.segment_service_root);
        writer.write_fixed(&segment.segment_historical_root_digest);
        writer.write_fixed(&segment.rerandomization_blinding);
        writer.write_fixed(&segment.segment_transcript_root);
        writer.write_vec(&segment.records, |writer, record| {
            write_historical_absence_record(writer, record)
        })
    })?;
    Ok(())
}

fn read_historical_unspent_packet(
    reader: &mut CanonicalReader<'_>,
) -> Result<HistoricalUnspentPacket> {
    Ok(HistoricalUnspentPacket {
        from_epoch: reader.read_u64()?,
        through_epoch: reader.read_u64()?,
        packet_historical_root_digest: reader.read_fixed()?,
        segment_commitment_root: reader.read_fixed()?,
        packet_rerandomization_blinding: reader.read_fixed()?,
        packet_transcript_root: reader.read_fixed()?,
        segments: reader.read_vec(|reader| {
            Ok(HistoricalUnspentSegment {
                provider_id: reader.read_fixed()?,
                provider_manifest_digest: reader.read_fixed()?,
                request_binding: reader.read_fixed()?,
                from_epoch: reader.read_u64()?,
                through_epoch: reader.read_u64()?,
                segment_service_root: reader.read_fixed()?,
                segment_historical_root_digest: reader.read_fixed()?,
                rerandomization_blinding: reader.read_fixed()?,
                segment_transcript_root: reader.read_fixed()?,
                records: reader.read_vec(read_historical_absence_record)?,
            })
        })?,
    })
}

fn write_historical_unspent_stratum(
    writer: &mut CanonicalWriter,
    stratum: &HistoricalUnspentStratum,
) -> Result<()> {
    writer.write_u64(stratum.from_epoch);
    writer.write_u64(stratum.through_epoch);
    writer.write_fixed(&stratum.stratum_historical_root_digest);
    writer.write_fixed(&stratum.packet_commitment_root);
    writer.write_fixed(&stratum.stratum_rerandomization_blinding);
    writer.write_fixed(&stratum.stratum_transcript_root);
    writer.write_vec(&stratum.packets, write_historical_unspent_packet)?;
    Ok(())
}

fn read_historical_unspent_stratum(
    reader: &mut CanonicalReader<'_>,
) -> Result<HistoricalUnspentStratum> {
    Ok(HistoricalUnspentStratum {
        from_epoch: reader.read_u64()?,
        through_epoch: reader.read_u64()?,
        stratum_historical_root_digest: reader.read_fixed()?,
        packet_commitment_root: reader.read_fixed()?,
        stratum_rerandomization_blinding: reader.read_fixed()?,
        stratum_transcript_root: reader.read_fixed()?,
        packets: reader.read_vec(read_historical_unspent_packet)?,
    })
}

pub fn encode_historical_unspent_extension(
    extension: &HistoricalUnspentExtension,
) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_u8(extension.version);
    writer.write_fixed(&extension.note_commitment);
    writer.write_u64(extension.from_epoch);
    writer.write_u64(extension.through_epoch);
    writer.write_fixed(&extension.prior_transcript_root);
    writer.write_fixed(&extension.historical_root_digest);
    writer.write_fixed(&extension.stratum_commitment_root);
    writer.write_fixed(&extension.aggregate_rerandomization_blinding);
    writer.write_fixed(&extension.new_transcript_root);
    writer.write_vec(&extension.strata, write_historical_unspent_stratum)?;
    Ok(writer.into_vec())
}

pub fn decode_historical_unspent_extension(bytes: &[u8]) -> Result<HistoricalUnspentExtension> {
    let mut reader = CanonicalReader::new(bytes);
    let extension = HistoricalUnspentExtension {
        version: reader.read_u8()?,
        note_commitment: reader.read_fixed()?,
        from_epoch: reader.read_u64()?,
        through_epoch: reader.read_u64()?,
        prior_transcript_root: reader.read_fixed()?,
        historical_root_digest: reader.read_fixed()?,
        stratum_commitment_root: reader.read_fixed()?,
        aggregate_rerandomization_blinding: reader.read_fixed()?,
        new_transcript_root: reader.read_fixed()?,
        strata: reader.read_vec(read_historical_unspent_stratum)?,
    };
    reader.finish()?;
    Ok(extension)
}

pub fn encode_historical_unspent_service_response(
    response: &HistoricalUnspentServiceResponse,
) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_u8(response.version);
    writer.write_fixed(&response.provider_id);
    writer.write_fixed(&response.provider_manifest_digest);
    writer.write_fixed(&response.request_binding);
    writer.write_u64(response.from_epoch);
    writer.write_u64(response.through_epoch);
    writer.write_fixed(&response.segment_service_root);
    writer.write_fixed(&response.segment_historical_root_digest);
    writer.write_vec(&response.records, |writer, record| {
        write_historical_absence_record(writer, record)
    })?;
    Ok(writer.into_vec())
}

pub fn decode_historical_unspent_service_response(
    bytes: &[u8],
) -> Result<HistoricalUnspentServiceResponse> {
    let mut reader = CanonicalReader::new(bytes);
    let response = HistoricalUnspentServiceResponse {
        version: reader.read_u8()?,
        provider_id: reader.read_fixed()?,
        provider_manifest_digest: reader.read_fixed()?,
        request_binding: reader.read_fixed()?,
        from_epoch: reader.read_u64()?,
        through_epoch: reader.read_u64()?,
        segment_service_root: reader.read_fixed()?,
        segment_historical_root_digest: reader.read_fixed()?,
        records: reader.read_vec(read_historical_absence_record)?,
    };
    reader.finish()?;
    Ok(response)
}

pub fn encode_checkpoint_batch_request(request: &CheckpointBatchRequest) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_fixed(&request.provider_id);
    writer.write_fixed(&request.provider_manifest_digest);
    writer.write_vec(&request.requests, |writer, request| {
        writer.write_bytes(&encode_checkpoint_extension_request(request)?)?;
        Ok(())
    })?;
    Ok(writer.into_vec())
}

pub fn decode_checkpoint_batch_request(bytes: &[u8]) -> Result<CheckpointBatchRequest> {
    let mut reader = CanonicalReader::new(bytes);
    let request = CheckpointBatchRequest {
        provider_id: reader.read_fixed()?,
        provider_manifest_digest: reader.read_fixed()?,
        requests: reader
            .read_vec(|reader| decode_checkpoint_extension_request(&reader.read_bytes()?))?,
    };
    reader.finish()?;
    Ok(request)
}

pub fn encode_checkpoint_batch_response(response: &CheckpointBatchResponse) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_fixed(&response.provider_id);
    writer.write_fixed(&response.provider_manifest_digest);
    writer.write_vec(&response.responses, |writer, response| {
        writer.write_bytes(&encode_historical_unspent_service_response(response)?)?;
        Ok(())
    })?;
    Ok(writer.into_vec())
}

pub fn decode_checkpoint_batch_response(bytes: &[u8]) -> Result<CheckpointBatchResponse> {
    let mut reader = CanonicalReader::new(bytes);
    let response = CheckpointBatchResponse {
        provider_id: reader.read_fixed()?,
        provider_manifest_digest: reader.read_fixed()?,
        responses: reader
            .read_vec(|reader| decode_historical_unspent_service_response(&reader.read_bytes()?))?,
    };
    reader.finish()?;
    Ok(response)
}

pub fn encode_checkpoint_presentation(presentation: &CheckpointPresentation) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_u64(presentation.covered_through_epoch);
    writer.write_fixed(&presentation.blinding);
    writer.write_fixed(&presentation.presentation_digest);
    Ok(writer.into_vec())
}

pub fn decode_checkpoint_presentation(bytes: &[u8]) -> Result<CheckpointPresentation> {
    let mut reader = CanonicalReader::new(bytes);
    let presentation = CheckpointPresentation {
        covered_through_epoch: reader.read_u64()?,
        blinding: reader.read_fixed()?,
        presentation_digest: reader.read_fixed()?,
    };
    reader.finish()?;
    Ok(presentation)
}

pub fn encode_shielded_spend_context(context: &ShieldedSpendContext) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_fixed(&context.note_commitment);
    writer.write_u64(context.current_epoch);
    writer.write_fixed(&context.current_nullifier);
    writer.write_fixed(&context.historical_checkpoint_root);
    Ok(writer.into_vec())
}

pub fn decode_shielded_spend_context(bytes: &[u8]) -> Result<ShieldedSpendContext> {
    let mut reader = CanonicalReader::new(bytes);
    let context = ShieldedSpendContext {
        note_commitment: reader.read_fixed()?,
        current_epoch: reader.read_u64()?,
        current_nullifier: reader.read_fixed()?,
        historical_checkpoint_root: reader.read_fixed()?,
    };
    reader.finish()?;
    Ok(context)
}
