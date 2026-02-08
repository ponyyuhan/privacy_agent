use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hmac::{Hmac, Mac};
use rayon::prelude::*;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha512};
use std::collections::{BTreeMap, HashMap};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

type HmacSha256 = Hmac<Sha256>;

const SEED_BYTES: usize = 16;

#[derive(Clone)]
struct AppState {
    server_id: u8,
    data_dir: PathBuf,
    mac_keys: HashMap<String, Vec<u8>>, // kid -> key bytes
    active_kid: String,
    bitsets: Arc<HashMap<String, Arc<Vec<u8>>>>,
    blocks: Arc<HashMap<String, (Arc<Vec<u8>>, usize)>>,
    mpc_sessions: Arc<Mutex<HashMap<String, MpcSession>>>,
}

#[derive(Debug, Clone, Deserialize)]
struct MpcGate {
    op: String,
    out: usize,
    a: Option<usize>,
    b: Option<usize>,
    value: Option<u8>,
}

#[derive(Debug)]
struct MpcSession {
    program_id: String,
    request_sha256: String,
    created_at: u64,
    ttl_seconds: u64,
    gates: Vec<MpcGate>,
    wires: Vec<Option<u8>>,
    outputs: HashMap<String, usize>,
    pc: usize,
    pending: HashMap<usize, (u8, u8, u8)>, // gate_index -> (a,b,c) shares
}

impl MpcSession {
    fn expired(&self, now: u64) -> bool {
        now.saturating_sub(self.created_at) > self.ttl_seconds
    }

    fn wire(&self, idx: usize) -> Result<u8, String> {
        self.wires
            .get(idx)
            .and_then(|v| *v)
            .map(|v| v & 1)
            .ok_or_else(|| "wire_not_ready".to_string())
    }

    fn set_wire(&mut self, idx: usize, v: u8) -> Result<(), String> {
        if idx >= self.wires.len() {
            return Err("wire_oob".to_string());
        }
        self.wires[idx] = Some(v & 1);
        Ok(())
    }

    fn eval_gate(&mut self, party: u8, gi: usize) -> Result<(), String> {
        let g = self.gates.get(gi).ok_or_else(|| "gate_oob".to_string())?;
        let op = g.op.to_ascii_uppercase();
        if op == "XOR" {
            let a = g.a.ok_or_else(|| "bad_gate".to_string())?;
            let b = g.b.ok_or_else(|| "bad_gate".to_string())?;
            let v = self.wire(a)? ^ self.wire(b)?;
            self.set_wire(g.out, v)?;
            return Ok(());
        }
        if op == "NOT" {
            let a = g.a.ok_or_else(|| "bad_gate".to_string())?;
            let v = self.wire(a)? ^ if party == 0 { 1 } else { 0 };
            self.set_wire(g.out, v)?;
            return Ok(());
        }
        if op == "CONST" {
            let v = g.value.unwrap_or(0) & 1;
            self.set_wire(g.out, if party == 0 { v } else { 0 })?;
            return Ok(());
        }
        if op == "AND" {
            return Err("and_requires_interaction".to_string());
        }
        Err("unknown_gate".to_string())
    }

    fn eval_until(&mut self, party: u8, gate_index: usize) -> Result<(), String> {
        if gate_index > self.gates.len() {
            return Err("gate_oob".to_string());
        }
        while self.pc < gate_index {
            let op = self.gates[self.pc].op.to_ascii_uppercase();
            if op == "AND" {
                return Err("hit_and_early".to_string());
            }
            self.eval_gate(party, self.pc)?;
            self.pc += 1;
        }
        Ok(())
    }

    fn and_mask(&mut self, party: u8, gate_index: usize, a_share: u8, b_share: u8, c_share: u8) -> Result<(u8, u8), String> {
        if gate_index >= self.gates.len() {
            return Err("gate_oob".to_string());
        }
        self.eval_until(party, gate_index)?;
        if self.pc != gate_index {
            return Err("bad_pc".to_string());
        }
        let g = &self.gates[gate_index];
        if g.op.to_ascii_uppercase() != "AND" {
            return Err("not_and_gate".to_string());
        }
        let a = g.a.ok_or_else(|| "bad_gate".to_string())?;
        let b = g.b.ok_or_else(|| "bad_gate".to_string())?;
        self.pending.insert(gate_index, (a_share & 1, b_share & 1, c_share & 1));
        let d_share = self.wire(a)? ^ (a_share & 1);
        let e_share = self.wire(b)? ^ (b_share & 1);
        Ok((d_share & 1, e_share & 1))
    }

    fn and_finish(&mut self, party: u8, gate_index: usize, d: u8, e: u8) -> Result<u8, String> {
        if self.pc != gate_index {
            return Err("bad_pc".to_string());
        }
        let g = &self.gates[gate_index];
        if g.op.to_ascii_uppercase() != "AND" {
            return Err("not_and_gate".to_string());
        }
        let (a_share, b_share, c_share) = self.pending.remove(&gate_index).ok_or_else(|| "missing_triple".to_string())?;
        let dd = d & 1;
        let ee = e & 1;
        let mut z = (c_share ^ (dd & b_share) ^ (ee & a_share)) & 1;
        if party == 0 {
            z ^= (dd & ee) & 1;
        }
        self.set_wire(g.out, z)?;
        self.pc += 1;
        Ok(z & 1)
    }

    fn finalize(&mut self, party: u8) -> Result<HashMap<String, u8>, String> {
        while self.pc < self.gates.len() {
            let op = self.gates[self.pc].op.to_ascii_uppercase();
            if op == "AND" {
                return Err("unfinished_and".to_string());
            }
            self.eval_gate(party, self.pc)?;
            self.pc += 1;
        }
        let mut out = HashMap::new();
        for (k, wi) in self.outputs.iter() {
            out.insert(k.clone(), self.wire(*wi)? & 1);
        }
        Ok(out)
    }
}

#[derive(Deserialize)]
struct MpcInitReq {
    action_id: String,
    program_id: String,
    request_sha256: String,
    n_wires: usize,
    gates: Vec<MpcGate>,
    input_shares: HashMap<String, u8>,
    outputs: HashMap<String, usize>,
    ttl_seconds: Option<u64>,
}

#[derive(Deserialize)]
struct MpcAndMaskReq {
    action_id: String,
    gate_index: usize,
    a_share: u8,
    b_share: u8,
    c_share: u8,
}

#[derive(Deserialize)]
struct MpcAndFinishReq {
    action_id: String,
    gate_index: usize,
    d: u8,
    e: u8,
}

#[derive(Deserialize)]
struct MpcFinalizeReq {
    action_id: String,
}

#[derive(Debug)]
struct DpfKey {
    version: u8,
    domain_bits: u8,
    seed0: [u8; SEED_BYTES],
    cw_last: u8,
    cws: Vec<CorrectionWord>,
}

#[derive(Debug, Clone)]
struct CorrectionWord {
    s_cw: [u8; SEED_BYTES],
    t_l: u8,
    t_r: u8,
}

fn decode_dpf_key(data: &[u8]) -> Result<DpfKey, String> {
    if data.len() < 1 + 1 + SEED_BYTES + 1 {
        return Err("truncated key".to_string());
    }
    let version = data[0];
    if version != 1 && version != 2 {
        return Err("unsupported key version".to_string());
    }
    let domain_bits = data[1];
    if domain_bits == 0 || domain_bits > 30 {
        return Err("domain_bits out of supported range".to_string());
    }
    let mut seed0 = [0u8; SEED_BYTES];
    seed0.copy_from_slice(&data[2..2 + SEED_BYTES]);
    let cw_last = data[2 + SEED_BYTES] & 1;
    let rest = &data[2 + SEED_BYTES + 1..];
    let expected = (domain_bits as usize) * (SEED_BYTES + 2);
    if rest.len() != expected {
        return Err("bad key length".to_string());
    }
    let mut cws = Vec::with_capacity(domain_bits as usize);
    let mut off = 0usize;
    for _ in 0..domain_bits {
        let mut s_cw = [0u8; SEED_BYTES];
        s_cw.copy_from_slice(&rest[off..off + SEED_BYTES]);
        let t_l = rest[off + SEED_BYTES] & 1;
        let t_r = rest[off + SEED_BYTES + 1] & 1;
        cws.push(CorrectionWord { s_cw, t_l, t_r });
        off += SEED_BYTES + 2;
    }
    Ok(DpfKey {
        version,
        domain_bits,
        seed0,
        cw_last,
        cws,
    })
}

#[inline]
fn xor16(a: &[u8; SEED_BYTES], b: &[u8; SEED_BYTES]) -> [u8; SEED_BYTES] {
    let mut out = [0u8; SEED_BYTES];
    for i in 0..SEED_BYTES {
        out[i] = a[i] ^ b[i];
    }
    out
}

#[inline]
fn prg_v2(seed: &[u8; SEED_BYTES]) -> ([u8; SEED_BYTES], u8, [u8; SEED_BYTES], u8) {
    let mut h = Sha512::new();
    h.update(seed);
    h.update(b"prg");
    let d = h.finalize();
    let mut s_l = [0u8; SEED_BYTES];
    s_l.copy_from_slice(&d[0..SEED_BYTES]);
    let t_l = d[SEED_BYTES] & 1;
    let mut s_r = [0u8; SEED_BYTES];
    s_r.copy_from_slice(&d[SEED_BYTES + 1..SEED_BYTES + 1 + SEED_BYTES]);
    let t_r = d[2 * SEED_BYTES + 1] & 1;
    (s_l, t_l, s_r, t_r)
}

#[inline]
fn prg_v1(seed: &[u8; SEED_BYTES]) -> ([u8; SEED_BYTES], u8, [u8; SEED_BYTES], u8) {
    let mut h0 = Sha256::new();
    h0.update(seed);
    h0.update([0u8]);
    let d0 = h0.finalize();
    let mut h1 = Sha256::new();
    h1.update(seed);
    h1.update([1u8]);
    let d1 = h1.finalize();
    let mut s_l = [0u8; SEED_BYTES];
    s_l.copy_from_slice(&d0[0..SEED_BYTES]);
    let t_l = d0[d0.len() - 1] & 1;
    let mut s_r = [0u8; SEED_BYTES];
    s_r.copy_from_slice(&d1[0..SEED_BYTES]);
    let t_r = d1[d1.len() - 1] & 1;
    (s_l, t_l, s_r, t_r)
}

#[inline]
fn convert_bit_v2(seed: &[u8; SEED_BYTES]) -> u8 {
    seed[0] & 1
}

#[inline]
fn convert_bit_v1(seed: &[u8; SEED_BYTES]) -> u8 {
    let mut h = Sha256::new();
    h.update(seed);
    h.update(b"convert");
    let d = h.finalize();
    d[0] & 1
}

fn eval_parity_share(key_bytes: &[u8], db: &[u8], party: u8) -> Result<u8, String> {
    let key = decode_dpf_key(key_bytes)?;
    let domain_size = 1usize << (key.domain_bits as usize);
    let nbytes = (domain_size + 7) / 8;
    if db.len() != nbytes {
        return Err("db length mismatch".to_string());
    }
    if party > 1 {
        return Err("party must be 0/1".to_string());
    }

    let mut ans: u8 = 0;
    let mut stack: Vec<(u8, [u8; SEED_BYTES], u8, u32)> = Vec::with_capacity(domain_size / 2);
    stack.push((0, key.seed0, party, 0));

    while let Some((level, seed, t, node_idx)) = stack.pop() {
        if level == key.domain_bits {
            let out = if key.version == 1 {
                convert_bit_v1(&seed)
            } else {
                convert_bit_v2(&seed)
            };
            let out_bit = (out ^ (t & key.cw_last)) & 1;
            if out_bit == 1 {
                let leaf = node_idx as usize;
                let b = (db[leaf / 8] >> (leaf % 8)) & 1;
                ans ^= b;
            }
            continue;
        }

        let cw = &key.cws[level as usize];
        let (mut s_l, mut t_l, mut s_r, mut t_r) = if key.version == 1 {
            prg_v1(&seed)
        } else {
            prg_v2(&seed)
        };
        if t == 1 {
            s_l = xor16(&s_l, &cw.s_cw);
            t_l ^= cw.t_l;
            s_r = xor16(&s_r, &cw.s_cw);
            t_r ^= cw.t_r;
        }

        // Right then left (deterministic, like the Python stack DFS).
        stack.push((level + 1, s_r, t_r & 1, (node_idx << 1) | 1));
        stack.push((level + 1, s_l, t_l & 1, (node_idx << 1) | 0));
    }
    Ok(ans & 1)
}

fn eval_block_share(key_bytes: &[u8], db: &[u8], block_size: usize, party: u8) -> Result<Vec<u8>, String> {
    if block_size == 0 || block_size > 4096 {
        return Err("bad block_size".to_string());
    }
    let key = decode_dpf_key(key_bytes)?;
    let domain_size = 1usize << (key.domain_bits as usize);
    if db.len() != domain_size * block_size {
        return Err("db length mismatch".to_string());
    }
    if party > 1 {
        return Err("party must be 0/1".to_string());
    }

    let mut acc = vec![0u8; block_size];
    let mut stack: Vec<(u8, [u8; SEED_BYTES], u8, u32)> = Vec::with_capacity(domain_size / 2);
    stack.push((0, key.seed0, party, 0));

    while let Some((level, seed, t, node_idx)) = stack.pop() {
        if level == key.domain_bits {
            let out = if key.version == 1 {
                convert_bit_v1(&seed)
            } else {
                convert_bit_v2(&seed)
            };
            let out_bit = (out ^ (t & key.cw_last)) & 1;
            if out_bit == 1 {
                let leaf = node_idx as usize;
                let off = leaf * block_size;
                let blk = &db[off..off + block_size];
                for i in 0..block_size {
                    acc[i] ^= blk[i];
                }
            }
            continue;
        }

        let cw = &key.cws[level as usize];
        let (mut s_l, mut t_l, mut s_r, mut t_r) = if key.version == 1 {
            prg_v1(&seed)
        } else {
            prg_v2(&seed)
        };
        if t == 1 {
            s_l = xor16(&s_l, &cw.s_cw);
            t_l ^= cw.t_l;
            s_r = xor16(&s_r, &cw.s_cw);
            t_r ^= cw.t_r;
        }

        stack.push((level + 1, s_r, t_r & 1, (node_idx << 1) | 1));
        stack.push((level + 1, s_l, t_l & 1, (node_idx << 1) | 0));
    }
    Ok(acc)
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

fn parse_mac_keys(s: &str) -> HashMap<String, Vec<u8>> {
    let mut out = HashMap::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (kid, hexkey) = if let Some((a, b)) = part.split_once(':') {
            (a.trim(), b.trim())
        } else {
            ("0", part)
        };
        if hexkey.is_empty() {
            continue;
        }
        if let Ok(bytes) = hex::decode(hexkey) {
            out.insert(kid.to_string(), bytes);
        }
    }
    out
}

fn canonical_json_bytes(payload: &BTreeMap<&str, Value>) -> Vec<u8> {
    // BTreeMap keeps keys sorted, matching Python json.dumps(sort_keys=True,separators=(",",":")) for ASCII payloads.
    serde_json::to_vec(payload).unwrap_or_else(|_| b"{}".to_vec())
}

fn sign_payload(mac_key: &[u8], payload: &BTreeMap<&str, Value>) -> String {
    let msg = canonical_json_bytes(payload);
    let mut mac = HmacSha256::new_from_slice(mac_key).expect("hmac key");
    mac.update(&msg);
    let out = mac.finalize().into_bytes();
    B64.encode(out)
}

#[derive(Deserialize)]
struct PirQueryBatch {
    db: String,
    dpf_keys_b64: Vec<String>,
}

#[derive(Deserialize)]
struct PirQueryBatchSigned {
    db: String,
    dpf_keys_b64: Vec<String>,
    action_id: String,
}

#[derive(Serialize)]
struct PirAnsBatch {
    ans_shares: Vec<u8>,
}

#[derive(Serialize)]
struct PirAnsBatchSigned {
    ans_shares: Vec<u8>,
    proof: Value,
}

#[derive(Serialize)]
struct PirBlockBatch {
    block_shares_b64: Vec<String>,
}

#[derive(Serialize)]
struct PirBlockBatchSigned {
    block_shares_b64: Vec<String>,
    proof: Value,
}

async fn health(State(st): State<AppState>) -> Json<Value> {
    Json(json!({"ok": true, "server_id": st.server_id}))
}

async fn meta(State(st): State<AppState>) -> Json<Value> {
    let mut out = serde_json::Map::new();
    let p = st.data_dir.join("meta.json");
    if let Ok(s) = fs::read_to_string(&p) {
        if let Ok(v) = serde_json::from_str::<Value>(&s) {
            if let Some(obj) = v.as_object() {
                for (k, v) in obj.iter() {
                    out.insert(k.clone(), v.clone());
                }
            }
        } else {
            out.insert("meta_error".to_string(), Value::from("failed_to_parse_meta_json"));
        }
    }
    let a = st.data_dir.join("dfa_alphabet.json");
    if let Ok(s) = fs::read_to_string(&a) {
        if let Ok(v) = serde_json::from_str::<Value>(&s) {
            out.insert("dfa_alphabet".to_string(), v);
        } else {
            out.insert(
                "dfa_alphabet_error".to_string(),
                Value::from("failed_to_parse_dfa_alphabet_json"),
            );
        }
    }
    Json(Value::Object(out))
}

fn get_bitset<'a>(st: &'a AppState, name: &str) -> Result<Arc<Vec<u8>>, String> {
    st.bitsets
        .get(name)
        .cloned()
        .ok_or_else(|| format!("unknown bitset db: {name}"))
}

fn get_block_db<'a>(st: &'a AppState, name: &str) -> Result<(Arc<Vec<u8>>, usize), String> {
    st.blocks
        .get(name)
        .cloned()
        .ok_or_else(|| format!("unknown block db: {name}"))
}

async fn pir_query_batch(State(st): State<AppState>, Json(q): Json<PirQueryBatch>) -> Result<Json<PirAnsBatch>, (StatusCode, String)> {
    let db = get_bitset(&st, &q.db).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let party = st.server_id;
    let ans: Result<Vec<u8>, String> = q
        .dpf_keys_b64
        .par_iter()
        .map(|k| {
            let kb = B64
                .decode(k.as_bytes())
                .map_err(|_| "bad base64 key".to_string())?;
            eval_parity_share(&kb, &db, party)
        })
        .collect();
    let ans = ans.map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    Ok(Json(PirAnsBatch { ans_shares: ans }))
}

async fn pir_query_block_batch(
    State(st): State<AppState>,
    Json(q): Json<PirQueryBatch>,
) -> Result<Json<PirBlockBatch>, (StatusCode, String)> {
    let (db, block_size) = get_block_db(&st, &q.db).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let party = st.server_id;
    let out: Result<Vec<String>, String> = q
        .dpf_keys_b64
        .par_iter()
        .map(|k| {
            let kb = B64
                .decode(k.as_bytes())
                .map_err(|_| "bad base64 key".to_string())?;
            let share = eval_block_share(&kb, &db, block_size, party)?;
            Ok(B64.encode(share))
        })
        .collect();
    let out = out.map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    Ok(Json(PirBlockBatch {
        block_shares_b64: out,
    }))
}

async fn pir_query_batch_signed(
    State(st): State<AppState>,
    Json(q): Json<PirQueryBatchSigned>,
) -> Result<Json<PirAnsBatchSigned>, (StatusCode, String)> {
    let db = get_bitset(&st, &q.db).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let party = st.server_id;

    let decoded_keys: Result<Vec<Vec<u8>>, String> = q
        .dpf_keys_b64
        .iter()
        .map(|k| B64.decode(k.as_bytes()).map_err(|_| "bad base64 key".to_string()))
        .collect();
    let decoded_keys = decoded_keys.map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    let ans: Result<Vec<u8>, String> = decoded_keys
        .par_iter()
        .map(|kb| eval_parity_share(kb, &db, party))
        .collect();
    let ans = ans.map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    let mut keys_concat = Vec::new();
    for kb in decoded_keys.iter() {
        keys_concat.extend_from_slice(kb);
    }
    let keys_sha256 = sha256_hex(&keys_concat);
    let resp_sha256 = sha256_hex(&ans.iter().map(|x| x & 1).collect::<Vec<u8>>());

    let ts = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()) as i64;

    let kid = st.active_kid.clone();
    let key = st
        .mac_keys
        .get(&kid)
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "missing mac key".to_string()))?;

    let mut payload: BTreeMap<&str, Value> = BTreeMap::new();
    payload.insert("v", Value::from(1));
    payload.insert("kind", Value::from("bit"));
    payload.insert("server_id", Value::from(st.server_id as i64));
    payload.insert("kid", Value::from(kid.clone()));
    payload.insert("ts", Value::from(ts));
    payload.insert("action_id", Value::from(q.action_id.clone()));
    payload.insert("db", Value::from(q.db.clone()));
    payload.insert("keys_sha256", Value::from(keys_sha256));
    payload.insert("resp_sha256", Value::from(resp_sha256));

    let mac_b64 = sign_payload(key, &payload);
    let mut proof_obj = serde_json::Map::new();
    for (k, v) in payload.into_iter() {
        proof_obj.insert(k.to_string(), v);
    }
    proof_obj.insert("mac_b64".to_string(), Value::from(mac_b64));
    Ok(Json(PirAnsBatchSigned {
        ans_shares: ans,
        proof: Value::Object(proof_obj),
    }))
}

async fn pir_query_block_batch_signed(
    State(st): State<AppState>,
    Json(q): Json<PirQueryBatchSigned>,
) -> Result<Json<PirBlockBatchSigned>, (StatusCode, String)> {
    let (db, block_size) = get_block_db(&st, &q.db).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let party = st.server_id;

    let decoded_keys: Result<Vec<Vec<u8>>, String> = q
        .dpf_keys_b64
        .iter()
        .map(|k| B64.decode(k.as_bytes()).map_err(|_| "bad base64 key".to_string()))
        .collect();
    let decoded_keys = decoded_keys.map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    let shares: Result<Vec<Vec<u8>>, String> = decoded_keys
        .par_iter()
        .map(|kb| eval_block_share(kb, &db, block_size, party))
        .collect();
    let shares = shares.map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let block_shares_b64: Vec<String> = shares.iter().map(|b| B64.encode(b)).collect();

    let mut keys_concat = Vec::new();
    for kb in decoded_keys.iter() {
        keys_concat.extend_from_slice(kb);
    }
    let keys_sha256 = sha256_hex(&keys_concat);
    let mut resp_concat = Vec::new();
    for b in shares.iter() {
        resp_concat.extend_from_slice(b);
    }
    let resp_sha256 = sha256_hex(&resp_concat);

    let ts = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()) as i64;

    let kid = st.active_kid.clone();
    let key = st
        .mac_keys
        .get(&kid)
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "missing mac key".to_string()))?;

    let mut payload: BTreeMap<&str, Value> = BTreeMap::new();
    payload.insert("v", Value::from(1));
    payload.insert("kind", Value::from("block"));
    payload.insert("server_id", Value::from(st.server_id as i64));
    payload.insert("kid", Value::from(kid.clone()));
    payload.insert("ts", Value::from(ts));
    payload.insert("action_id", Value::from(q.action_id.clone()));
    payload.insert("db", Value::from(q.db.clone()));
    payload.insert("keys_sha256", Value::from(keys_sha256));
    payload.insert("resp_sha256", Value::from(resp_sha256));

    let mac_b64 = sign_payload(key, &payload);
    let mut proof_obj = serde_json::Map::new();
    for (k, v) in payload.into_iter() {
        proof_obj.insert(k.to_string(), v);
    }
    proof_obj.insert("mac_b64".to_string(), Value::from(mac_b64));

    Ok(Json(PirBlockBatchSigned {
        block_shares_b64,
        proof: Value::Object(proof_obj),
    }))
}

fn now_s() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn cleanup_mpc_sessions(map: &mut HashMap<String, MpcSession>) {
    let now = now_s();
    map.retain(|_, s| !s.expired(now));
}

async fn mpc_init(State(st): State<AppState>, Json(req): Json<MpcInitReq>) -> Result<Json<Value>, (StatusCode, String)> {
    let mut wires: Vec<Option<u8>> = vec![None; req.n_wires];
    for (k, v) in req.input_shares.iter() {
        let idx: usize = k.parse::<usize>().map_err(|_| (StatusCode::BAD_REQUEST, "bad_wire_index".to_string()))?;
        if idx >= wires.len() {
            return Err((StatusCode::BAD_REQUEST, "wire_oob".to_string()));
        }
        wires[idx] = Some(v & 1);
    }
    let ttl = req.ttl_seconds.unwrap_or(30);
    let sess = MpcSession {
        program_id: req.program_id.clone(),
        request_sha256: req.request_sha256.clone(),
        created_at: now_s(),
        ttl_seconds: ttl,
        gates: req.gates.clone(),
        wires,
        outputs: req.outputs.clone(),
        pc: 0,
        pending: HashMap::new(),
    };

    let mut map = st.mpc_sessions.lock().unwrap();
    cleanup_mpc_sessions(&mut map);
    map.insert(req.action_id.clone(), sess);
    Ok(Json(json!({"ok": true, "party": st.server_id, "gates": req.gates.len()})))
}

async fn mpc_and_mask(State(st): State<AppState>, Json(req): Json<MpcAndMaskReq>) -> Result<Json<Value>, (StatusCode, String)> {
    let mut map = st.mpc_sessions.lock().unwrap();
    cleanup_mpc_sessions(&mut map);
    let sess = map.get_mut(&req.action_id).ok_or_else(|| (StatusCode::BAD_REQUEST, "missing_session".to_string()))?;
    let (d, e) = sess
        .and_mask(st.server_id, req.gate_index, req.a_share, req.b_share, req.c_share)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    Ok(Json(json!({"d_share": d & 1, "e_share": e & 1})))
}

async fn mpc_and_finish(State(st): State<AppState>, Json(req): Json<MpcAndFinishReq>) -> Result<Json<Value>, (StatusCode, String)> {
    let mut map = st.mpc_sessions.lock().unwrap();
    cleanup_mpc_sessions(&mut map);
    let sess = map.get_mut(&req.action_id).ok_or_else(|| (StatusCode::BAD_REQUEST, "missing_session".to_string()))?;
    let z = sess
        .and_finish(st.server_id, req.gate_index, req.d, req.e)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    Ok(Json(json!({"z_share": z & 1})))
}

async fn mpc_finalize(State(st): State<AppState>, Json(req): Json<MpcFinalizeReq>) -> Result<Json<Value>, (StatusCode, String)> {
    let mut sess = {
        let mut map = st.mpc_sessions.lock().unwrap();
        cleanup_mpc_sessions(&mut map);
        map.remove(&req.action_id)
    }
    .ok_or_else(|| (StatusCode::BAD_REQUEST, "missing_session".to_string()))?;

    let outs = sess.finalize(st.server_id).map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    let kid = st.active_kid.clone();
    let key = st
        .mac_keys
        .get(&kid)
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "missing mac key".to_string()))?;

    let mut tag = [0u8; 16];
    OsRng.fill_bytes(&mut tag);
    let tag_b64 = B64.encode(tag);
    let ts = now_s() as i64;

    let mut outs_obj = serde_json::Map::new();
    for (k, v) in outs.iter() {
        outs_obj.insert(k.clone(), Value::from((*v & 1) as i64));
    }

    let mut payload: BTreeMap<&str, Value> = BTreeMap::new();
    payload.insert("v", Value::from(1));
    payload.insert("kind", Value::from("commit"));
    payload.insert("server_id", Value::from(st.server_id as i64));
    payload.insert("kid", Value::from(kid.clone()));
    payload.insert("ts", Value::from(ts));
    payload.insert("action_id", Value::from(req.action_id.clone()));
    payload.insert("program_id", Value::from(sess.program_id.clone()));
    payload.insert("request_sha256", Value::from(sess.request_sha256.clone()));
    payload.insert("outputs", Value::Object(outs_obj));
    payload.insert("commit_tag_share_b64", Value::from(tag_b64.clone()));

    let mac_b64 = sign_payload(key, &payload);
    let mut proof_obj = serde_json::Map::new();
    for (k, v) in payload.into_iter() {
        proof_obj.insert(k.to_string(), v);
    }
    proof_obj.insert("mac_b64".to_string(), Value::from(mac_b64));

    Ok(Json(json!({
        "ok": true,
        "outputs": outs,
        "proof": Value::Object(proof_obj),
    })))
}

fn load_bitsets(data_dir: &Path) -> HashMap<String, Arc<Vec<u8>>> {
    let mut out = HashMap::new();
    if let Ok(rd) = fs::read_dir(data_dir) {
        for ent in rd.flatten() {
            let p = ent.path();
            if p.extension().and_then(|s| s.to_str()) == Some("bitset") {
                if let Some(stem) = p.file_stem().and_then(|s| s.to_str()) {
                    if let Ok(b) = fs::read(&p) {
                        out.insert(stem.to_string(), Arc::new(b));
                    }
                }
            }
        }
    }
    out
}

fn load_blocks(data_dir: &Path) -> HashMap<String, (Arc<Vec<u8>>, usize)> {
    let mut out = HashMap::new();

    // Best-effort: read meta to get DFA block_size.
    let mut dfa_block: Option<(String, usize)> = None;
    let meta_path = data_dir.join("meta.json");
    if let Ok(s) = fs::read_to_string(&meta_path) {
        if let Ok(v) = serde_json::from_str::<Value>(&s) {
            if let Some(dfa) = v.get("dfa") {
                let db = dfa
                    .get("db")
                    .and_then(|x| x.as_str())
                    .unwrap_or("dfa_transitions")
                    .to_string();
                let bs = dfa.get("block_size").and_then(|x| x.as_u64()).unwrap_or(4) as usize;
                dfa_block = Some((db, bs));
            }
        }
    }

    if let Ok(rd) = fs::read_dir(data_dir) {
        for ent in rd.flatten() {
            let p = ent.path();
            if p.extension().and_then(|s| s.to_str()) == Some("blk") {
                if let Some(stem) = p.file_stem().and_then(|s| s.to_str()) {
                    if let Ok(b) = fs::read(&p) {
                        let bs = dfa_block
                            .as_ref()
                            .and_then(|(name, sz)| if name == stem { Some(*sz) } else { None })
                            .unwrap_or(4);
                        out.insert(stem.to_string(), (Arc::new(b), bs));
                    }
                }
            }
        }
    }
    out
}

#[tokio::main]
async fn main() {
    let server_id: u8 = env::var("SERVER_ID")
        .ok()
        .and_then(|s| s.parse::<u8>().ok())
        .unwrap_or(0);
    let port: u16 = env::var("PORT")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(9001);
    let data_dir = env::var("DATA_DIR").unwrap_or_else(|_| "policy_server/data".to_string());
    let data_dir = PathBuf::from(data_dir);

    let mut mac_keys = HashMap::new();
    let mac_keys_env = env::var("POLICY_MAC_KEYS").unwrap_or_default();
    if !mac_keys_env.trim().is_empty() {
        mac_keys = parse_mac_keys(&mac_keys_env);
    } else if let Ok(hexkey) = env::var("POLICY_MAC_KEY") {
        if !hexkey.trim().is_empty() {
            mac_keys.insert("0".to_string(), hex::decode(hexkey.trim()).unwrap_or_default());
        }
    }
    let active_kid = env::var("POLICY_MAC_ACTIVE_KID")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| mac_keys.keys().next().cloned().unwrap_or_else(|| "0".to_string()));

    let bitsets = Arc::new(load_bitsets(&data_dir));
    let blocks = Arc::new(load_blocks(&data_dir));

    let st = AppState {
        server_id,
        data_dir,
        mac_keys,
        active_kid,
        bitsets,
        blocks,
        mpc_sessions: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/meta", get(meta))
        .route("/pir/query_batch", post(pir_query_batch))
        .route("/pir/query_block_batch", post(pir_query_block_batch))
        .route("/pir/query_batch_signed", post(pir_query_batch_signed))
        .route("/pir/query_block_batch_signed", post(pir_query_block_batch_signed))
        .route("/mpc/init", post(mpc_init))
        .route("/mpc/and_mask", post(mpc_and_mask))
        .route("/mpc/and_finish", post(mpc_and_finish))
        .route("/mpc/finalize", post(mpc_finalize))
        .with_state(st);

    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
