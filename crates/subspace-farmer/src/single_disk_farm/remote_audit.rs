use std::collections::hash_map::HashMap;
use std::collections::HashSet;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Instant;
use std::{io, net::SocketAddr, sync::LazyLock};

use rayon::prelude::*;
use subspace_core_primitives::crypto::blake3_hash;
use subspace_core_primitives::{Blake3Hash, PublicKey, SBucket, SectorId, SectorIndex, SolutionRange};
use anyhow::Result;
use subspace_farmer_components::{auditing::{audit_plot_sync_qiniu, AuditResult, ChunkCandidate}, proving::SolutionCandidates, sector::SectorMetadataChecksummed, ReadAtOffset, ReadAtSync};
use parity_scale_codec::{Encode, Decode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub struct KeyWrap(pub String);

impl ReadAtSync for KeyWrap {
    fn read_at(&self, _buf: &mut [u8], _offset: u64) -> io::Result<()> {
        unimplemented!()
    }
    
    fn key(&self) -> Option<&str> {
        Some(self.0.as_str())
    }
}

#[derive(Clone, bincode::Encode, bincode::Decode)]
struct ReqMsg {
    key: String,
    public_key: [u8; subspace_core_primitives::PUBLIC_KEY_LENGTH],
    global_challenge: subspace_core_primitives::Blake3Hash,
    voting_solution_range: subspace_core_primitives::SolutionRange,
    sectors_metadata: Vec<Vec<u8>>,
    sectors_metadata_hash_set: HashSet<Blake3Hash>,
    maybe_sector_being_modified: Option<subspace_core_primitives::SectorIndex>
}

#[derive(Clone, bincode::Encode, bincode::Decode)]
struct AuditOut {
    sector_index: subspace_core_primitives::SectorIndex,
    s_bucket: u16,
    sector_offset: u64,
    // (chunk_offset, solution_distance)
    winning_chunks: Vec<(u32, subspace_core_primitives::SolutionRange)>,
    best_solution_distance: subspace_core_primitives::SolutionRange
}

#[derive(Clone, bincode::Encode, bincode::Decode)]
enum ReplyMsg {
    Out(Vec<AuditOut>),
    Need(Vec<Blake3Hash>)
}

pub async fn call_audit_plot<'a, Plot>(
    public_key: &'a PublicKey,
    global_challenge: Blake3Hash,
    solution_range: SolutionRange,
    plot: &'a Plot,
    sectors_metadata: &'a [SectorMetadataChecksummed],
    maybe_sector_being_modified: Option<SectorIndex>,
) -> Result<Vec<AuditResult<'a, ReadAtOffset<'a, Plot>>>> 
    where
        Plot: ReadAtSync + 'a,
{
    let t = Instant::now();
    let sm_map = sectors_metadata.par_iter()
        .map(|metadata| {
            let v = metadata.encode();
            let k = blake3_hash(&v);
            (k, v)
        })
        .collect::<HashMap<_, _>>();
    tracing::debug!("    encode sectors metadata use: {:?}", t.elapsed());

    let mut need_key: Vec<Blake3Hash> = Vec::new();

    loop {
        let t = Instant::now();

        let need_data = need_key.iter()
        .map(|key| sm_map[key].clone())
        .collect::<Vec<_>>();

        let req = ReqMsg {
            key: plot.key().unwrap().to_owned(),
            public_key: public_key.as_ref().try_into().unwrap(),
            global_challenge,
            voting_solution_range: solution_range,
            sectors_metadata: need_data,
            sectors_metadata_hash_set: sm_map.keys().map(|v| *v).collect(),
            maybe_sector_being_modified
        };

        static DST: LazyLock<String> = LazyLock::new(|| std::env::var("REMOTE_AUDIT").unwrap());

        let data = bincode::encode_to_vec(req, bincode::config::standard())?;

        tracing::debug!("    encode req data use: {:?}", t.elapsed());

        let t = Instant::now();
        let mut stream = tokio::net::TcpStream::connect(DST.deref()).await?;
        stream.write_u64(data.len() as u64).await?;
        stream.write_all(&data).await?;

        let reply_len = stream.read_u64().await? as usize;
        let mut reply_buf = vec![0u8; reply_len];
        stream.read_exact(&mut reply_buf).await?;
        let reply: ReplyMsg = bincode::decode_from_slice(&reply_buf, bincode::config::standard())?.0;

        tracing::debug!("    call remote use: {:?}", t.elapsed());

        match reply {
            ReplyMsg::Out(out_list) => {
                let ret = out_list.into_iter()
                .map(|audit| {
                    let matedata = sectors_metadata.iter()
                    .find(|v| v.sector_index == audit.sector_index)
                    .unwrap();
            
                    let winning_chunks = audit.winning_chunks.into_iter()
                    .map(|(chunk_offset, solution_distance)| {
                        ChunkCandidate {
                            chunk_offset,
                            solution_distance
                        }
                    })
                    .collect::<Vec<_>>();
            
                    AuditResult {
                        sector_index: audit.sector_index,
                        solution_candidates: SolutionCandidates::new(
                            public_key,
                            SectorId::new(public_key.hash(), audit.sector_index),
                            SBucket::from(audit.s_bucket),
                            plot.offset(audit.sector_offset),
                            matedata,
                            winning_chunks.into(),
                        ),
                        best_solution_distance: audit.best_solution_distance,
                    }
                })
                .collect::<Vec<_>>();
            
                return Ok(ret);
            }
            ReplyMsg::Need(need) => {
                need_key = need;
            }
        }
    }
}

async fn audit_plot(
    mut stream: TcpStream
) -> Result<()> {
    // file key -> (metadata key -> metadata)
    static METADATA_LIST: LazyLock<
        parking_lot::Mutex<
            HashMap<String, Arc<tokio::sync::Mutex<HashMap<Blake3Hash, SectorMetadataChecksummed>>>>
        >
    > = LazyLock::new(|| parking_lot::Mutex::new(HashMap::new()));
    let req_len = stream.read_u64().await? as usize;

    // 100 MB
    if req_len > 1024 * 1024 * 100 {
        return Err(anyhow::anyhow!("bad request"));
    }

    let mut req_buf = vec![0u8; req_len];
    stream.read_exact(&mut req_buf).await?;
    let req: ReqMsg = bincode::decode_from_slice(&req_buf, bincode::config::standard())?.0;

    let pk = PublicKey::from(req.public_key);
    let fake_plot = KeyWrap(req.key.clone());

    let md = {
        let mut guard = METADATA_LIST.deref().lock();
        let r = (*guard).entry(req.key).or_insert_with(|| Arc::new(tokio::sync::Mutex::new(HashMap::new())));
        (*r).clone()
    };

    let mut md_guard = md.lock().await;

    for s in req.sectors_metadata {
        let mut input = s.as_slice();
        let key = blake3_hash(input);
        let sm = SectorMetadataChecksummed::decode(&mut input).unwrap();

        md_guard.insert(key, sm);
    }
    
    let md_keys = md_guard.keys().map(|v| *v).collect::<HashSet<Blake3Hash>>();
    let diff = req.sectors_metadata_hash_set.difference(&md_keys)
    .map(|v| *v)
    .collect::<Vec<_>>();

    if !diff.is_empty() {
        let reply = ReplyMsg::Need(diff);
        let out = bincode::encode_to_vec(reply, bincode::config::standard())?;
        stream.write_u64(out.len() as u64).await?;
        stream.write_all(&out).await?;
        return Ok(());
    }

    let sm_input = req.sectors_metadata_hash_set.par_iter()
    .map(|key| &md_guard[key])
    .collect::<Vec<_>>();

    let audit_res_list = audit_plot_sync_qiniu(
        &pk,
        &req.global_challenge,
        req.voting_solution_range,
        &fake_plot,
        &sm_input,
        req.maybe_sector_being_modified
    ).await?;
    
    let audit_list = audit_res_list.into_iter()
    .map(|res| {
        AuditOut {
            sector_index: res.sector_index,
            s_bucket: res.solution_candidates.s_bucket.into(),
            sector_offset: res.solution_candidates.sector.offset,
            winning_chunks: res.solution_candidates.chunk_candidates.into_iter()
            .map(|candidate| (candidate.chunk_offset, candidate.solution_distance))
            .collect::<Vec<_>>(),
            best_solution_distance: res.best_solution_distance
        }
    })
    .collect::<Vec<_>>();

    let reply = ReplyMsg::Out(audit_list);
    let out = bincode::encode_to_vec(reply, bincode::config::standard())?;
    stream.write_u64(out.len() as u64).await?;
    stream.write_all(&out).await?;
    Ok(())
}

pub async fn daemon(
    bind_addr: SocketAddr,
) -> Result<()> {
    tracing::info!("Listening on {}", bind_addr);
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;

    while let Ok((stream, _peer)) = listener.accept().await {
        tokio::spawn(async move {
            if let Err(e) = audit_plot(stream).await {
                tracing::error!("audit plot error: {:?}", e);
            }
        });
    }
    Ok(())
}