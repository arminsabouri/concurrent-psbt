use psbt_v2::bitcoin::Transaction;
use psbt_v2::bitcoin::consensus::encode::{
    Decodable, MAX_VEC_SIZE, VarInt, deserialize, serialize,
};
use psbt_v2::raw::{Key, Pair};

/// PSBT magic bytes: "psbt\xff"
const MAGIC: [u8; 5] = [0x70, 0x73, 0x62, 0x74, 0xff];

/// Global map key types retained when scrubbing (non-sensitive).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GlobalInsensitive {
    UnsignedTx = 0x00,
    TxVersion = 0x02,
    FallbackLocktime = 0x03,
    InputCount = 0x04,
    OutputCount = 0x05,
    TxModifiable = 0x06,
    Version = 0xFB,
}

impl GlobalInsensitive {
    fn contains(v: u8) -> bool {
        matches!(
            v,
            x if x == Self::UnsignedTx as u8
                || x == Self::TxVersion as u8
                || x == Self::FallbackLocktime as u8
                || x == Self::InputCount as u8
                || x == Self::OutputCount as u8
                || x == Self::TxModifiable as u8
                || x == Self::Version as u8
        )
    }
}

/// Input map key types retained when scrubbing (non-sensitive).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InputInsensitive {
    NonWitnessUtxo = 0x00,
    WitnessUtxo = 0x01,
    SighashType = 0x03,
    RedeemScript = 0x04,
    WitnessScript = 0x05,
    FinalScriptsig = 0x07,
    FinalScriptwitness = 0x08,
    PreviousTxid = 0x0e,
    OutputIndex = 0x0f,
    Sequence = 0x10,
    RequiredTimeLocktime = 0x11,
    RequiredHeightLocktime = 0x12,
    TapKeySig = 0x13,
    TapScriptSig = 0x14,
    TapLeafScript = 0x15,
}

impl InputInsensitive {
    fn contains(v: u8) -> bool {
        matches!(
            v,
            x if x == Self::NonWitnessUtxo as u8
                || x == Self::WitnessUtxo as u8
                || x == Self::SighashType as u8
                || x == Self::RedeemScript as u8
                || x == Self::WitnessScript as u8
                || x == Self::FinalScriptsig as u8
                || x == Self::FinalScriptwitness as u8
                || x == Self::PreviousTxid as u8
                || x == Self::OutputIndex as u8
                || x == Self::Sequence as u8
                || x == Self::RequiredTimeLocktime as u8
                || x == Self::RequiredHeightLocktime as u8
                || x == Self::TapKeySig as u8
                || x == Self::TapScriptSig as u8
                || x == Self::TapLeafScript as u8
        )
    }
}

/// Output map key types retained when scrubbing (non-sensitive).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutputInsensitive {
    Amount = 0x03,
    Script = 0x04,
}

impl OutputInsensitive {
    fn contains(v: u8) -> bool {
        matches!(
            v,
            x if x == Self::Amount as u8 || x == Self::Script as u8
        )
    }
}

/// Errors that can occur while scrubbing a PSBT.
#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidMagic,
    UnexpectedEof,
    InvalidGlobal,
}

impl std::fmt::Display for Error {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidMagic => write!(f, "invalid PSBT magic bytes"),
            Error::UnexpectedEof => write!(f, "unexpected end of input"),
            Error::InvalidGlobal => write!(f, "invalid or missing global map fields"),
        }
    }
}

impl std::error::Error for Error {}

fn get_number_of_inputs_and_outputs(global: &[Pair]) -> Result<(u64, u64), Error> {
    let is_v2 = global
        .iter()
        .find(|p| p.key.type_value == 0xFB && p.key.key.is_empty())
        .and_then(|p| p.value.first().copied())
        .map(|v| v == 2)
        .unwrap_or(false);

    if is_v2 {
        let n_in = global
            .iter()
            .find(|p| p.key.type_value == 0x04 && p.key.key.is_empty())
            .and_then(|p| deserialize(&p.value).ok())
            .map(|VarInt(n)| n)
            .ok_or(Error::InvalidGlobal)?;
        let n_out = global
            .iter()
            .find(|p| p.key.type_value == 0x05 && p.key.key.is_empty())
            .and_then(|p| deserialize(&p.value).ok())
            .map(|VarInt(n)| n)
            .ok_or(Error::InvalidGlobal)?;
        return Ok((n_in, n_out));
    }
    let tx_bytes = global
        .iter()
        .find(|p| p.key.type_value == 0x00 && p.key.key.is_empty())
        .map(|p| p.value.as_slice())
        .ok_or(Error::InvalidGlobal)?;
    let tx: Transaction = deserialize(tx_bytes).map_err(|_| Error::InvalidGlobal)?;
    Ok((tx.input.len() as u64, tx.output.len() as u64))
}

/// Scrub a PSBT, retaining only non-sensitive fields safe to share with untrusted peers.
///
/// Buffers the global map to detect version and input/output counts, then streams
/// the remaining maps applying per-map-type filters. Both PSBT v0 and v2 are supported.
pub fn scrub(psbt: &[u8]) -> Result<Vec<u8>, Error> {
    if psbt.get(..5) != Some(&MAGIC) {
        return Err(Error::InvalidMagic);
    }
    let mut r = &psbt[5..];
    let mut out = vec![0u8; psbt.len()];
    let mut w: &mut [u8] = &mut out;
    write_bytes(&mut w, &MAGIC);

    // Buffer the global map to detect version and input/output counts before streaming the rest.
    let mut global: Vec<Pair> = Vec::new();
    while let Some(pair) = Pair::decode(&mut r)? {
        global.push(pair);
    }

    let (n_inputs, n_outputs) = get_number_of_inputs_and_outputs(&global)?;
    for pair in &global {
        if GlobalInsensitive::contains(pair.key.type_value) {
            encode_pair(&mut w, pair);
        }
    }
    write_byte(&mut w, 0x00);

    for _ in 0..n_inputs {
        while let Some(pair) = Pair::decode(&mut r)? {
            if InputInsensitive::contains(pair.key.type_value) {
                encode_pair(&mut w, &pair);
            }
        }
        write_byte(&mut w, 0x00);
    }

    for _ in 0..n_outputs {
        while let Some(pair) = Pair::decode(&mut r)? {
            if OutputInsensitive::contains(pair.key.type_value) {
                encode_pair(&mut w, &pair);
            }
        }
        write_byte(&mut w, 0x00);
    }

    let written = psbt.len() - w.len();
    out.truncate(written);
    Ok(out)
}

// Workaround: Pair::decode and Key::decode are pub(crate) in psbt-v2 0.3.0.
// This replicates the upstream logic exactly using the same bitcoin primitives.
// This can be removed once / if the visibility becomes more permissible upstream
trait PairDecode: Sized {
    fn decode(input: &mut &[u8]) -> Result<Option<Self>, Error>;
}

impl PairDecode for Pair {
    fn decode(input: &mut &[u8]) -> Result<Option<Self>, Error> {
        let VarInt(byte_size) =
            Decodable::consensus_decode(input).map_err(|_| Error::UnexpectedEof)?;
        if byte_size == 0 {
            return Ok(None);
        }
        let key_byte_size = byte_size - 1;
        if key_byte_size > MAX_VEC_SIZE as u64 {
            return Err(Error::UnexpectedEof);
        }
        let type_value: u8 =
            Decodable::consensus_decode(input).map_err(|_| Error::UnexpectedEof)?;
        let mut key = Vec::with_capacity(key_byte_size as usize);
        for _ in 0..key_byte_size {
            key.push(Decodable::consensus_decode(input).map_err(|_| Error::UnexpectedEof)?);
        }
        let value: Vec<u8> =
            Decodable::consensus_decode(input).map_err(|_| Error::UnexpectedEof)?;
        Ok(Some(Pair {
            key: Key { type_value, key },
            value,
        }))
    }
}

fn write_bytes(out: &mut &mut [u8], bytes: &[u8]) {
    let buf = std::mem::take(out);
    let (head, tail) = buf.split_at_mut(bytes.len());
    head.copy_from_slice(bytes);
    *out = tail;
}

fn write_byte(out: &mut &mut [u8], byte: u8) {
    write_bytes(out, std::slice::from_ref(&byte));
}

fn encode_pair(out: &mut &mut [u8], pair: &Pair) {
    write_bytes(out, &serialize(&VarInt::from(pair.key.key.len() + 1)));
    write_bytes(out, &serialize(&pair.key.type_value));
    write_bytes(out, &pair.key.key);
    write_bytes(out, &serialize(&VarInt::from(pair.value.len() as u64)));
    write_bytes(out, &pair.value);
}

#[cfg(any(test, feature = "unit-tests"))]
mod tests {
    #![allow(dead_code)]
    use super::*;

    fn kv(type_value: u8, key_suffix: &[u8], val: &[u8]) -> Vec<u8> {
        let pair = Pair {
            key: Key {
                type_value,
                key: key_suffix.to_vec(),
            },
            value: val.to_vec(),
        };
        let cap = key_suffix.len() + val.len() + 32;
        let mut buf = vec![0u8; cap];
        let mut w: &mut [u8] = &mut buf;
        encode_pair(&mut w, &pair);
        let written = cap - w.len();
        buf.truncate(written);
        buf
    }

    fn kv_global(key: GlobalInsensitive, val: &[u8]) -> Vec<u8> {
        kv(key as u8, &[], val)
    }

    fn kv_input(key: InputInsensitive, key_suffix: &[u8], val: &[u8]) -> Vec<u8> {
        kv(key as u8, key_suffix, val)
    }

    fn kv_output(key: OutputInsensitive, val: &[u8]) -> Vec<u8> {
        kv(key as u8, &[], val)
    }

    fn v2_global(input_count: u8, output_count: u8, extra: &[Vec<u8>]) -> Vec<u8> {
        let mut map = Vec::new();
        map.extend(kv_global(GlobalInsensitive::Version, &[2, 0, 0, 0]));
        map.extend(kv_global(GlobalInsensitive::TxVersion, &[2, 0, 0, 0]));
        map.extend(kv_global(GlobalInsensitive::InputCount, &[input_count]));
        map.extend(kv_global(GlobalInsensitive::OutputCount, &[output_count]));
        for e in extra {
            map.extend(e);
        }
        map.push(0x00);
        map
    }

    fn v2_psbt(
        input_count: u8,
        output_count: u8,
        global_extra: &[Vec<u8>],
        maps: &[Vec<u8>],
    ) -> Vec<u8> {
        let mut buf = MAGIC.to_vec();
        buf.extend(v2_global(input_count, output_count, global_extra));
        for m in maps {
            buf.extend(m);
        }
        buf
    }

    fn dummy_tx(input_count: u8, output_count: u8) -> Vec<u8> {
        let mut tx = Vec::new();
        tx.extend_from_slice(&1u32.to_le_bytes());
        tx.push(input_count);
        for _ in 0..input_count {
            tx.extend_from_slice(&[0u8; 32]);
            tx.extend_from_slice(&0u32.to_le_bytes());
            tx.push(0x00);
            tx.extend_from_slice(&u32::MAX.to_le_bytes());
        }
        tx.push(output_count);
        for _ in 0..output_count {
            tx.extend_from_slice(&1000u64.to_le_bytes());
            tx.push(0x00);
        }
        tx.extend_from_slice(&0u32.to_le_bytes());
        tx
    }

    #[test]
    fn scrub_empty_v2_roundtrip() {
        let psbt = v2_psbt(0, 0, &[], &[]);
        assert_eq!(scrub(&psbt).unwrap(), psbt);
    }

    #[test]
    fn invalid_global_v0_invalid_tx() {
        // v0 PSBT with invalid transaction data
        let mut psbt = MAGIC.to_vec();
        psbt.extend(kv_global(GlobalInsensitive::UnsignedTx, &[0xFF, 0xFF]));
        psbt.push(0x00);
        assert_eq!(scrub(&psbt), Err(Error::InvalidGlobal));
    }

    #[test]
    fn invalid_pair_key_too_large() {
        // Pair key exceeds MAX_VEC_SIZE — this tests the boundary check
        let mut psbt = MAGIC.to_vec();
        psbt.push(0xFF); // VarInt indicating huge size
        psbt.push(0xFF);
        psbt.push(0xFF);
        psbt.push(0xFF);
        psbt.push(0xFF); // This creates a byte_size that would overflow MAX_VEC_SIZE
        assert_eq!(scrub(&psbt), Err(Error::UnexpectedEof));
    }

    #[test]
    fn invalid_pair_value_truncated() {
        // Pair with VarInt-encoded value size but missing value data
        let mut psbt = MAGIC.to_vec();
        psbt.extend(v2_global(1, 1, &[]));
        psbt.push(0x00); // End global
        psbt.push(0x05); // VarInt key size
        psbt.push(InputInsensitive::WitnessUtxo as u8);
        // Missing key data and value should trigger UnexpectedEof
        assert_eq!(scrub(&psbt), Err(Error::UnexpectedEof));
    }

    #[test]
    fn scrub_input_with_multiple_maps() {
        let witness_utxo = kv_input(InputInsensitive::WitnessUtxo, &[], &[0xAA]);
        let amount = kv_output(
            OutputInsensitive::Amount,
            &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        );

        let mut input = Vec::new();
        for _ in 0..2 {
            input.extend(&witness_utxo);
            // BIP32_DERIVATION (sensitive)
            input.extend(&kv(0x06, &[0x02, 0x03], &[0xFF]));
            input.push(0x00);
        }

        let mut output = Vec::new();
        for _ in 0..2 {
            output.extend(&amount);
            // PROPRIETARY (sensitive)
            output.extend(&kv(0xFC, &[0x01], &[0xFF]));
            output.push(0x00);
        }

        let psbt = v2_psbt(2, 2, &[], &[input, output.clone()]);
        let result = scrub(&psbt).unwrap();

        let mut expected_input = Vec::new();
        for _ in 0..2 {
            expected_input.extend(&witness_utxo);
            expected_input.push(0x00);
        }

        let mut expected_output = Vec::new();
        for _ in 0..2 {
            expected_output.extend(&amount);
            expected_output.push(0x00);
        }

        let expected = v2_psbt(2, 2, &[], &[expected_input, expected_output]);
        assert_eq!(result, expected);
    }

    #[test]
    fn scrub_v2_tx_not_modifiable_strips_sensitive_fields() {
        // PSBT_GLOBAL_TX_MODIFIABLE = 0x06 set to 0. tx not modifiable, scrubbing still applies.
        let tx_not_modifiable = kv_global(GlobalInsensitive::TxModifiable, &[0x00]);
        let witness_utxo = kv_input(InputInsensitive::WitnessUtxo, &[], &[0xAA]);
        let amount = kv_output(
            OutputInsensitive::Amount,
            &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        );

        // POR_COMMITMENT (sensitive global)
        let sensitive_global = kv(0x09, &[], &[0xDE, 0xAD]);

        let mut input_map = Vec::new();
        input_map.extend(&witness_utxo);
        // BIP32_DERIVATION (sensitive input)
        input_map.extend(&kv(0x06, &[0x02, 0x03], &[0xFF]));
        input_map.push(0x00);

        let mut output_map = Vec::new();
        output_map.extend(&amount);
        // PROPRIETARY (sensitive output)
        output_map.extend(&kv(0xFC, &[0x01], &[0xFF]));
        output_map.push(0x00);

        let psbt = v2_psbt(
            1,
            1,
            &[sensitive_global, tx_not_modifiable.clone()],
            &[input_map, output_map],
        );
        let result = scrub(&psbt).unwrap();

        let mut expected_input = Vec::new();
        expected_input.extend(&witness_utxo);
        expected_input.push(0x00);

        let mut expected_output = Vec::new();
        expected_output.extend(&amount);
        expected_output.push(0x00);

        let expected = v2_psbt(
            1,
            1,
            &[tx_not_modifiable],
            &[expected_input, expected_output],
        );
        assert_eq!(result, expected);
    }

    #[test]
    fn scrub_v0() {
        let tx = dummy_tx(1, 1);
        let unsigned_tx = kv_global(GlobalInsensitive::UnsignedTx, &tx);
        // POR_COMMITMENT (sensitive)
        let sensitive_global = kv(0x09, &[], &[0xDE, 0xAD]);

        let mut global = Vec::new();
        global.extend(&unsigned_tx);
        global.extend(&sensitive_global);
        global.push(0x00);

        let witness_utxo = kv_input(InputInsensitive::WitnessUtxo, &[], &[0xAA]);
        // TAP_BIP32_DERIVATION (sensitive)
        let tap_bip32_input = kv(0x06, &[0x02, 0x03], &[0xFF]);

        let mut input_map = Vec::new();
        input_map.extend(&witness_utxo);
        input_map.extend(&tap_bip32_input);
        input_map.push(0x00);

        // unknown output key type (sensitive)
        let mut output_map = kv(0x17, &[], &[0xCC]);

        output_map.push(0x00);

        let mut psbt = MAGIC.to_vec();
        psbt.extend(&global);
        psbt.extend(&input_map);
        psbt.extend(&output_map);

        let result = scrub(&psbt).unwrap();

        let mut expected_global = Vec::new();
        expected_global.extend(&unsigned_tx);
        expected_global.push(0x00);
        let mut expected_input = Vec::new();
        expected_input.extend(&witness_utxo);
        expected_input.push(0x00);

        let mut expected = MAGIC.to_vec();
        expected.extend(&expected_global);
        expected.extend(&expected_input);
        expected.extend(vec![0x00]);

        assert_eq!(result, expected);
    }

    #[test]
    fn invalid_magic() {
        assert_eq!(scrub(b"not a psbt"), Err(Error::InvalidMagic));
    }

    #[test]
    fn unexpected_eof_truncated_after_magic() {
        assert_eq!(scrub(&MAGIC), Err(Error::UnexpectedEof));
    }

    #[test]
    fn unexpected_eof_truncated_mid_map() {
        let mut psbt = MAGIC.to_vec();
        psbt.push(0x05); // key length = 5 but no data follows
        assert_eq!(scrub(&psbt), Err(Error::UnexpectedEof));
    }

    #[test]
    fn invalid_global_v2_missing_counts() {
        // VERSION present and v2, but INPUT_COUNT and OUTPUT_COUNT absent.
        let mut psbt = MAGIC.to_vec();
        psbt.extend(kv_global(GlobalInsensitive::Version, &[2, 0, 0, 0]));
        psbt.push(0x00);
        assert_eq!(scrub(&psbt), Err(Error::InvalidGlobal));
    }

    #[test]
    fn invalid_global_v0_missing_unsigned_tx() {
        // v0 PSBT with no UNSIGNED_TX field.
        let mut psbt = MAGIC.to_vec();
        // POR_COMMITMENT (sensitive), not UNSIGNED_TX
        psbt.extend(kv(0x09, &[], &[0xDE, 0xAD]));
        psbt.push(0x00);
        assert_eq!(scrub(&psbt), Err(Error::InvalidGlobal));
    }
}

#[cfg(all(test, feature = "prop-tests"))]
mod prop {
    use super::*;
    use proptest::prelude::*;

    fn arb_value() -> impl Strategy<Value = Vec<u8>> {
        proptest::collection::vec(any::<u8>(), 0..=64)
    }

    fn encoded_pair(type_value: u8, key: Vec<u8>, value: Vec<u8>) -> Vec<u8> {
        let pair = Pair {
            key: Key { type_value, key },
            value,
        };
        let cap = pair.key.key.len() + pair.value.len() + 32;
        let mut buf = vec![0u8; cap];
        let mut w: &mut [u8] = &mut buf;
        encode_pair(&mut w, &pair);
        let written = cap - w.len();
        buf.truncate(written);
        buf
    }

    fn encoded_global(key: GlobalInsensitive, value: Vec<u8>) -> Vec<u8> {
        encoded_pair(key as u8, vec![], value)
    }

    fn encoded_input(key: InputInsensitive, key_suffix: Vec<u8>, value: Vec<u8>) -> Vec<u8> {
        encoded_pair(key as u8, key_suffix, value)
    }

    fn encoded_output(key: OutputInsensitive, key_suffix: Vec<u8>, value: Vec<u8>) -> Vec<u8> {
        encoded_pair(key as u8, key_suffix, value)
    }

    #[derive(Clone, Copy, Debug)]
    enum InsensitiveField {
        Global(GlobalInsensitive),
        Input(InputInsensitive),
        Output(OutputInsensitive),
    }

    fn arb_global_insensitive() -> impl Strategy<Value = GlobalInsensitive> {
        use GlobalInsensitive::*;
        proptest::sample::select(
            [
                UnsignedTx,
                TxVersion,
                FallbackLocktime,
                InputCount,
                OutputCount,
                TxModifiable,
                Version,
            ]
            .to_vec(),
        )
    }

    fn arb_input_insensitive() -> impl Strategy<Value = InputInsensitive> {
        use InputInsensitive::*;
        proptest::sample::select(
            [
                NonWitnessUtxo,
                WitnessUtxo,
                SighashType,
                RedeemScript,
                WitnessScript,
                FinalScriptsig,
                FinalScriptwitness,
                PreviousTxid,
                OutputIndex,
                Sequence,
                RequiredTimeLocktime,
                RequiredHeightLocktime,
                TapKeySig,
                TapScriptSig,
                TapLeafScript,
            ]
            .to_vec(),
        )
    }

    fn arb_output_insensitive() -> impl Strategy<Value = OutputInsensitive> {
        use OutputInsensitive::*;
        proptest::sample::select([Amount, Script].to_vec())
    }

    fn arb_insensitive_field() -> impl Strategy<Value = InsensitiveField> {
        prop_oneof![
            arb_global_insensitive().prop_map(InsensitiveField::Global),
            arb_input_insensitive().prop_map(InsensitiveField::Input),
            arb_output_insensitive().prop_map(InsensitiveField::Output),
        ]
    }

    fn encode_insensitive(field: InsensitiveField, value: Vec<u8>) -> Vec<u8> {
        match field {
            InsensitiveField::Global(key) => encoded_global(key, value),
            InsensitiveField::Input(key) => encoded_input(key, vec![], value),
            InsensitiveField::Output(key) => encoded_output(key, vec![], value),
        }
    }

    fn build_psbt_with_insensitive(field: InsensitiveField, pair: &[u8]) -> Vec<u8> {
        let mut test_psbt = MAGIC.to_vec();
        let (n_inputs, n_outputs) = match field {
            InsensitiveField::Global(_) => (0, 0),
            InsensitiveField::Input(_) => (1, 0),
            InsensitiveField::Output(_) => (0, 1),
        };
        let extra_global = match field {
            InsensitiveField::Global(_) => &[pair][..],
            _ => &[],
        };
        append_v2_global_fields(&mut test_psbt, n_inputs, n_outputs, extra_global);
        if !matches!(field, InsensitiveField::Global(_)) {
            test_psbt.extend_from_slice(pair);
            test_psbt.push(0x00);
        }
        test_psbt
    }

    fn arb_pair() -> impl Strategy<Value = Vec<u8>> {
        (any::<u8>(), arb_value()).prop_map(|(t, v)| encoded_pair(t, vec![], v))
    }

    fn arb_map() -> impl Strategy<Value = Vec<u8>> {
        proptest::collection::vec(arb_pair(), 0..=4).prop_map(|pairs| {
            let mut map: Vec<u8> = pairs.into_iter().flatten().collect();
            map.push(0x00);
            map
        })
    }

    fn append_v2_global_fields(psbt: &mut Vec<u8>, n_inputs: u8, n_outputs: u8, extra: &[&[u8]]) {
        psbt.extend(encoded_global(GlobalInsensitive::Version, vec![2, 0, 0, 0]));
        psbt.extend(encoded_global(
            GlobalInsensitive::TxVersion,
            vec![2, 0, 0, 0],
        ));
        psbt.extend(encoded_global(
            GlobalInsensitive::InputCount,
            vec![n_inputs],
        ));
        psbt.extend(encoded_global(
            GlobalInsensitive::OutputCount,
            vec![n_outputs],
        ));
        for field in extra {
            psbt.extend_from_slice(field);
        }
        psbt.push(0x00);
    }

    prop_compose! {
        fn arb_v2_psbt()(
            n_inputs in 0u8..=3,
            n_outputs in 0u8..=3,
        )(
            extra_global in arb_map().prop_map(|m| m[..m.len()-1].to_vec()),
            input_maps in proptest::collection::vec(arb_map(), n_inputs as usize),
            output_maps in proptest::collection::vec(arb_map(), n_outputs as usize),
            n_inputs in Just(n_inputs),
            n_outputs in Just(n_outputs),
        ) -> Vec<u8> {
            let mut psbt = MAGIC.to_vec();
            append_v2_global_fields(
                &mut psbt,
                n_inputs,
                n_outputs,
                &[&extra_global],
            );
            for map in input_maps { psbt.extend(map); }
            for map in output_maps { psbt.extend(map); }
            psbt
        }
    }

    proptest! {
        #[test]
        fn idempotent(psbt in arb_v2_psbt()) {
            if let Ok(once) = scrub(&psbt) {
                let twice = scrub(&once).expect("scrub of scrubbed output must succeed");
                prop_assert_eq!(once, twice);
            }
        }

        #[test]
        fn output_is_valid_psbt(psbt in arb_v2_psbt()) {
            if let Ok(scrubbed) = scrub(&psbt) {
                prop_assert!(scrub(&scrubbed).is_ok());
            }
        }

        #[test]
        fn sensitive_fields_absent_from_output(
            sensitive_type in proptest::sample::select(vec![
                0x02u8, // PARTIAL_SIG
                0x06,   // BIP32_DERIVATION
                0x16,   // TAP_BIP32_DERIVATION
                0x17,   // TAP_INTERNAL_KEY
                0xFC,   // PROPRIETARY
            ])
        ) {
            let sensitive_pair = encoded_pair(sensitive_type, vec![0xAA], vec![0xBB]);

            let mut test_psbt = MAGIC.to_vec();
            append_v2_global_fields(&mut test_psbt, 1, 0, &[]);
            test_psbt.extend(&sensitive_pair);
            test_psbt.push(0x00);

            let result = scrub(&test_psbt).unwrap();
            prop_assert!(!result.windows(sensitive_pair.len()).any(|w| w == sensitive_pair));
        }

        #[test]
        fn insensitive_fields_preserved(
            value in arb_value(),
            field in arb_insensitive_field(),
        ) {
            let pair = encode_insensitive(field, value);
            let test_psbt = build_psbt_with_insensitive(field, &pair);

            let result = scrub(&test_psbt).unwrap();
            prop_assert!(result.windows(pair.len()).any(|w| w == pair));
        }
    }
}
