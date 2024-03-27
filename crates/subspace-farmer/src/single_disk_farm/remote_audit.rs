use std::collections::hash_map::HashMap;
use std::collections::HashSet;
use std::convert::Infallible;
use std::io::Read;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Instant;
use std::{io, net::SocketAddr, sync::LazyLock};

use http::Method;
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::Server;
use rayon::prelude::*;
use subspace_core_primitives::crypto::blake3_hash;
use subspace_core_primitives::{Blake3Hash, PublicKey, SBucket, SectorId, SectorIndex, SolutionRange};
use anyhow::Result;
use anyhow::anyhow;
use bytes::Buf;
use http::Response;
use hyper::{client::HttpConnector, http, Body, Client, Request};
use subspace_farmer_components::{auditing::{audit_plot_sync_qiniu, AuditResult, ChunkCandidate}, proving::SolutionCandidates, sector::SectorMetadataChecksummed, ReadAtOffset, ReadAtSync};
use parity_scale_codec::{Encode, Decode};

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
    tracing::info!("    encode sectors metadata use: {:?}", t.elapsed());

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

        static CLIENT: LazyLock<Client<HttpConnector>> = LazyLock::new(|| hyper::Client::new());
        static DST: LazyLock<String> = LazyLock::new(|| std::env::var("REMOTE_AUDIT").unwrap());

        let data = bincode::encode_to_vec(req, bincode::config::standard())?;

        tracing::info!("    encode req data use: {:?}", t.elapsed());

        let t = Instant::now();
        let req = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{}/auditplot", DST.deref()))
        .body(Body::from(data))?;

        let resp = CLIENT.request(req).await?;
        let (parts, body) = resp.into_parts();

        if parts.status != 200 {
            let bytes = hyper::body::to_bytes(body).await?;
            let msg = String::from_utf8(bytes.to_vec())?;
            return Err(anyhow!("HTTP response code: {}, message: {}", parts.status.as_u16(), msg));
        }

        let body = hyper::body::aggregate(body).await?;
        let reply: ReplyMsg = bincode::decode_from_std_read(&mut body.reader(), bincode::config::standard())?;
        tracing::info!("    call remote use: {:?}", t.elapsed());

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
    req: Request<Body>,
) -> Result<Response<Body>, http::Error> {
    // file key -> (metadata key -> metadata)
    static METADATA_LIST: LazyLock<
        parking_lot::Mutex<
            HashMap<String, Arc<tokio::sync::Mutex<HashMap<Blake3Hash, SectorMetadataChecksummed>>>>
        >
    > = LazyLock::new(|| parking_lot::Mutex::new(HashMap::new()));

    let fut = async {
        let body = hyper::body::aggregate(req.into_body()).await?;
        let req: ReqMsg = bincode::decode_from_std_read(&mut body.reader(), bincode::config::standard())?;

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
            return Result::<_, anyhow::Error>::Ok(Response::new(Body::from(out)));
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
        Result::<_, anyhow::Error>::Ok(Response::new(Body::from(out)))
    };

    match fut.await {
        Ok(resp) => Ok(resp),
        Err(e) => {
            tracing::error!("{}", e);

            Response::builder()
                .status(500)
                .body(Body::from(e.to_string()))
        }
    }
}

async fn router(
    req: Request<Body>,
) -> Result<Response<Body>, http::Error> {
    match req.uri().path() {
        "/auditplot" => audit_plot(req).await,
        _ => {
            Response::builder()
                .status(404)
                .body(Body::empty())
        }
    }
}

pub async fn daemon(
    bind_addr: SocketAddr,
) -> Result<()> {
    let make_service = make_service_fn(move |_addr: &AddrStream| {
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                router(req)
            }))
        }
    });

    tracing::info!("Listening on http://{}", bind_addr);

    Server::bind(&bind_addr)
    .serve(make_service)
    .await
    .map_err(|e| anyhow!(e))
}