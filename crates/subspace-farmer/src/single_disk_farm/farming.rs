pub mod rayon_files;

use crate::node_client;
use crate::node_client::NodeClient;
use crate::single_disk_farm::{remote_audit, Handlers};
use async_lock::{Mutex as AsyncMutex, RwLock as AsyncRwLock};
use futures::channel::mpsc;
use futures::StreamExt;
use parity_scale_codec::{Decode, Encode, Error, Input, Output};
use parking_lot::Mutex;
use rayon::ThreadPool;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{fmt, io};
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::{PosSeed, PublicKey, SectorIndex, Solution, SolutionRange};
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer_components::auditing::{audit_plot_sync, AuditingError};
use subspace_farmer_components::proving::{ProvableSolutions, ProvingError};
use subspace_farmer_components::reading::ReadSectorRecordChunksMode;
use subspace_farmer_components::sector::SectorMetadataChecksummed;
use subspace_farmer_components::ReadAtSync;
use subspace_proof_of_space::{Table, TableGenerator};
use subspace_rpc_primitives::{SlotInfo, SolutionResponse};
use thiserror::Error;
use tracing::{debug, error, info, trace, warn, Span};

/// Auditing details
#[derive(Debug, Copy, Clone, Encode, Decode)]
pub struct AuditingDetails {
    /// Number of sectors that were audited
    pub sectors_count: SectorIndex,
    /// Audit duration
    pub time: Duration,
}

/// Result of the proving
#[derive(Debug, Copy, Clone, Encode, Decode)]
pub enum ProvingResult {
    /// Proved successfully and accepted by the node
    Success,
    /// Proving took too long
    Timeout,
    /// Managed to prove within time limit, but node rejected solution, likely due to timeout on its
    /// end
    Rejected,
}

impl fmt::Display for ProvingResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ProvingResult::Success => "Success",
            ProvingResult::Timeout => "Timeout",
            ProvingResult::Rejected => "Rejected",
        })
    }
}

/// Proving details
#[derive(Debug, Copy, Clone, Encode, Decode)]
pub struct ProvingDetails {
    /// Whether proving ended up being successful
    pub result: ProvingResult,
    /// Audit duration
    pub time: Duration,
}

/// Various farming notifications
#[derive(Debug, Clone, Encode, Decode)]
pub enum FarmingNotification {
    /// Auditing
    Auditing(AuditingDetails),
    /// Proving
    Proving(ProvingDetails),
    /// Non-fatal farming error
    NonFatalError(Arc<FarmingError>),
}

/// Special decoded farming error
#[derive(Debug, Encode, Decode)]
pub struct DecodedFarmingError {
    /// String representation of an error
    error: String,
    /// Whether error is fatal
    is_fatal: bool,
}

impl fmt::Display for DecodedFarmingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}

/// Errors that happen during farming
#[derive(Debug, Error)]
pub enum FarmingError {
    /// Failed to subscribe to slot info notifications
    #[error("Failed to subscribe to slot info notifications: {error}")]
    FailedToSubscribeSlotInfo {
        /// Lower-level error
        error: node_client::Error,
    },
    /// Failed to retrieve farmer info
    #[error("Failed to retrieve farmer info: {error}")]
    FailedToGetFarmerInfo {
        /// Lower-level error
        error: node_client::Error,
    },
    /// Slot info notification stream ended
    #[error("Slot info notification stream ended")]
    SlotNotificationStreamEnded,
    /// Low-level auditing error
    #[error("Low-level auditing error: {0}")]
    LowLevelAuditing(#[from] AuditingError),
    /// Low-level proving error
    #[error("Low-level proving error: {0}")]
    LowLevelProving(#[from] ProvingError),
    /// I/O error occurred
    #[error("Farming I/O error: {0}")]
    Io(#[from] io::Error),
    /// Decoded farming error
    #[error("Decoded farming error {0}")]
    Decoded(DecodedFarmingError),
}

impl Encode for FarmingError {
    fn encode_to<O: Output + ?Sized>(&self, dest: &mut O) {
        let error = DecodedFarmingError {
            error: self.to_string(),
            is_fatal: self.is_fatal(),
        };

        error.encode_to(dest)
    }
}

impl Decode for FarmingError {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        DecodedFarmingError::decode(input).map(FarmingError::Decoded)
    }
}

impl FarmingError {
    /// String variant of the error, primarily for monitoring purposes
    pub fn str_variant(&self) -> &str {
        match self {
            FarmingError::FailedToSubscribeSlotInfo { .. } => "FailedToSubscribeSlotInfo",
            FarmingError::FailedToGetFarmerInfo { .. } => "FailedToGetFarmerInfo",
            FarmingError::LowLevelAuditing(_) => "LowLevelAuditing",
            FarmingError::LowLevelProving(_) => "LowLevelProving",
            FarmingError::Io(_) => "Io",
            FarmingError::Decoded(_) => "Decoded",
            FarmingError::SlotNotificationStreamEnded => "SlotNotificationStreamEnded",
        }
    }

    /// Whether this error is fatal and makes farm unusable
    pub fn is_fatal(&self) -> bool {
        match self {
            FarmingError::FailedToSubscribeSlotInfo { .. } => true,
            FarmingError::FailedToGetFarmerInfo { .. } => true,
            FarmingError::LowLevelAuditing(_) => true,
            FarmingError::LowLevelProving(error) => error.is_fatal(),
            FarmingError::Io(_) => true,
            FarmingError::Decoded(error) => error.is_fatal,
            FarmingError::SlotNotificationStreamEnded => true,
        }
    }
}

pub(super) async fn slot_notification_forwarder<NC>(
    node_client: &NC,
    mut slot_info_forwarder_sender: mpsc::Sender<SlotInfo>,
) -> Result<(), FarmingError>
where
    NC: NodeClient,
{
    info!("Subscribing to slot info notifications");

    let mut slot_info_notifications = node_client
        .subscribe_slot_info()
        .await
        .map_err(|error| FarmingError::FailedToSubscribeSlotInfo { error })?;

    while let Some(slot_info) = slot_info_notifications.next().await {
        debug!(?slot_info, "New slot");

        let slot = slot_info.slot_number;

        // Error means farmer is still solving for previous slot, which is too late and
        // we need to skip this slot
        if slot_info_forwarder_sender.try_send(slot_info).is_err() {
            debug!(%slot, "Slow farming, skipping slot");
        }
    }

    Err(FarmingError::SlotNotificationStreamEnded)
}

/// Plot audit options
#[derive(Debug)]
pub struct PlotAuditOptions<'a, PosTable>
where
    PosTable: Table,
{
    /// Public key of the farm
    pub public_key: &'a PublicKey,
    /// Reward address to use for solutions
    pub reward_address: &'a PublicKey,
    /// Slot info for the audit
    pub slot_info: SlotInfo,
    /// Metadata of all sectors plotted so far
    pub sectors_metadata: &'a [SectorMetadataChecksummed],
    /// Kzg instance
    pub kzg: &'a Kzg,
    /// Erasure coding instance
    pub erasure_coding: &'a ErasureCoding,
    /// Optional sector that is currently being modified (for example replotted) and should not be
    /// audited
    pub maybe_sector_being_modified: Option<SectorIndex>,
    /// Mode of reading chunks during proving
    pub read_sector_record_chunks_mode: ReadSectorRecordChunksMode,
    /// Proof of space table generator
    pub table_generator: &'a Mutex<PosTable::Generator>,
}

impl<'a, PosTable> Clone for PlotAuditOptions<'a, PosTable>
where
    PosTable: Table,
{
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, PosTable> Copy for PlotAuditOptions<'a, PosTable> where PosTable: Table {}

/// Plot auditing implementation
pub struct PlotAudit<Plot>(Plot)
where
    Plot: ReadAtSync;

impl<'a, Plot> PlotAudit<Plot>
where
    Plot: ReadAtSync + 'a,
{
    /// Create new instance
    pub fn new(plot: Plot) -> Self {
        Self(plot)
    }

    pub async fn audit_qiniu<PosTable>(
        &'a self,
        options: PlotAuditOptions<'a, PosTable>,
    ) -> Result<
        Vec<(
            SectorIndex,
            impl ProvableSolutions<Item = Result<Solution<PublicKey, PublicKey>, ProvingError>> + 'a,
        )>,
        AuditingError,
    >
        where
            PosTable: Table,
    {
        use std::collections::VecDeque;
        use subspace_farmer_components::auditing::audit_plot_sync_qiniu;
        use subspace_farmer_components::sector::RecordMetadata;
        use std::sync::LazyLock;

        let PlotAuditOptions {
            public_key,
            reward_address,
            slot_info,
            sectors_metadata,
            kzg,
            erasure_coding,
            maybe_sector_being_modified,
            read_sector_record_chunks_mode: mode,
            table_generator,
        } = options;

        static IS_REMOTE_AUDIT: LazyLock<bool> = LazyLock::new(|| std::env::var("REMOTE_AUDIT").is_ok());

        let audit_results = if *IS_REMOTE_AUDIT {
            let t = std::time::Instant::now();
            let res = remote_audit::call_audit_plot(
                public_key, 
                slot_info.global_challenge, 
                slot_info.voting_solution_range, 
                &self.0,
                sectors_metadata, 
                maybe_sector_being_modified
            ).await;
            tracing::info!("call remote audit plot use: {:?}", t.elapsed());

            match res {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!("call_audit_plot error: {:?}", e);
                    return Ok(Vec::new());
                }
            }
        } else {
            let sectors_metadata_ref_list = sectors_metadata.iter()
            .map(|v| v)
            .collect::<Vec<_>>();

            audit_plot_sync_qiniu(
                public_key,
                &slot_info.global_challenge,
                slot_info.voting_solution_range,
                &self.0,
                sectors_metadata_ref_list.as_slice(),
                maybe_sector_being_modified,
            ).await?
        };

        let ranges = audit_results
            .iter()
            .map(|res| {
                let sector = &res.solution_candidates.sector;
                let metadata = res.solution_candidates.sector_metadata;
                let offset = sector.offset;
                (offset, subspace_farmer_components::sector::SectorContentsMap::encoded_size(metadata.pieces_in_sector) as u64)
            })
            .collect::<Vec<_>>();

        if audit_results.is_empty() {
            return Ok(Vec::new());
        }

        let key = self.0.key().unwrap();
        let parts = randrw_s3_client::get_object_with_ranges(key, &ranges).await.unwrap();

        let mut record_index_list = Vec::new();
        let mut record_metadata_index_list = Vec::new();

        let mut output = audit_results
            .into_iter()
            .zip(parts)
            .filter_map(|(audit_results, part)| {
                let sector_index = audit_results.sector_index;
                let sector_offset = audit_results.solution_candidates.sector.offset;

                let sector_solutions = audit_results.solution_candidates.into_solutions_qiniu(
                    reward_address,
                    kzg,
                    erasure_coding,
                    mode,
                    |seed: &PosSeed| table_generator.lock().generate_parallel(seed),
                    part.data
                );

                let sector_solutions = match sector_solutions {
                    Ok(solutions) => solutions,
                    Err(error) => {
                        warn!(
                            %error,
                            %sector_index,
                            "Failed to turn solution candidates into solutions",
                        );

                        return None;
                    }
                };

                if sector_solutions.len() == 0 {
                    return None;
                }

                for chunk in sector_solutions.winning_chunks.iter() {
                    let record_offset_list = subspace_farmer_components::reading::read_sector_record_chunks_index(
                        chunk.piece_offset,
                        sector_solutions.sector_metadata.pieces_in_sector,
                        &sector_solutions.sector_contents_map,
                        &sector_solutions.s_bucket_offsets,
                        sector_offset
                    );

                    record_index_list.push(record_offset_list);


                    let record_metadata_offset = subspace_farmer_components::reading::read_record_metadata_index(
                        chunk.piece_offset,
                        sector_solutions.sector_metadata.pieces_in_sector
                    );
                    record_metadata_index_list.push(record_metadata_offset + sector_offset);
                }

                Some((sector_index, sector_solutions))
            })
            .collect::<Vec<_>>();

        let mut record_ranges = Vec::new();

        for sector_part in record_index_list.iter() {
            for index_opt in sector_part {
                if let Some(index) = index_opt {
                    record_ranges.push((index.0, subspace_core_primitives::crypto::Scalar::FULL_BYTES as u64));
                }
            }
        }

        let mut record_metadata_ranges = Vec::new();

        for i in record_metadata_index_list.iter() {
            record_metadata_ranges.push((*i, RecordMetadata::encoded_size() as u64));
        }

        let mut futs = Vec::new();

        for chunk in record_ranges.chunks(512) {
            let fut = async {
                randrw_s3_client::get_object_with_ranges(key, chunk).await.unwrap()
            };

            futs.push(fut);
        }

        let parts_list = futures::future::join_all(futs).await;
        let mut parts_merge = Vec::new();

        for mut parts in parts_list {
            parts_merge.append(&mut parts);
        }

        let mut record_parts = VecDeque::from(parts_merge);
        let mut record_metadata_parts = VecDeque::from(randrw_s3_client::get_object_with_ranges(key, &record_metadata_ranges).await.unwrap());

        for (_, solutions) in output.iter_mut() {
            for (chunk, record_indexs) in solutions.winning_chunks.iter_mut().zip(&record_index_list) {
                let mut record_data_list = Vec::new();

                for index in record_indexs {
                    match index {
                        Some((_offset, chunk_location, encoded_chunk_used)) => record_data_list.push(Some((record_parts.pop_front().unwrap().data, *chunk_location, *encoded_chunk_used))),
                        None => record_data_list.push(None)
                    }
                }

                chunk.record_record_metadata = Some((record_data_list, record_metadata_parts.pop_front().unwrap().data));
            }
        }
        Ok(output)
    }

    pub fn audit<PosTable>(
        &'a self,
        options: PlotAuditOptions<'a, PosTable>,
    ) -> Result<
        Vec<(
            SectorIndex,
            impl ProvableSolutions<Item = Result<Solution<PublicKey, PublicKey>, ProvingError>> + 'a,
        )>,
        AuditingError,
    >
    where
        PosTable: Table,
    {
        let PlotAuditOptions {
            public_key,
            reward_address,
            slot_info,
            sectors_metadata,
            kzg,
            erasure_coding,
            maybe_sector_being_modified,
            read_sector_record_chunks_mode: mode,
            table_generator,
        } = options;

        let audit_results = audit_plot_sync(
            public_key,
            &slot_info.global_challenge,
            slot_info.voting_solution_range,
            &self.0,
            sectors_metadata,
            maybe_sector_being_modified,
        )?;

        Ok(audit_results
            .into_iter()
            .filter_map(|audit_results| {
                let sector_index = audit_results.sector_index;

                let sector_solutions = audit_results.solution_candidates.into_solutions(
                    reward_address,
                    kzg,
                    erasure_coding,
                    mode,
                    |seed: &PosSeed| table_generator.lock().generate_parallel(seed),
                );

                let sector_solutions = match sector_solutions {
                    Ok(solutions) => solutions,
                    Err(error) => {
                        warn!(
                            %error,
                            %sector_index,
                            "Failed to turn solution candidates into solutions",
                        );

                        return None;
                    }
                };

                if sector_solutions.len() == 0 {
                    return None;
                }

                Some((sector_index, sector_solutions))
            })
            .collect())
    }
}

pub(super) struct FarmingOptions<NC, PlotAudit> {
    pub(super) public_key: PublicKey,
    pub(super) reward_address: PublicKey,
    pub(super) node_client: NC,
    pub(super) plot_audit: PlotAudit,
    pub(super) sectors_metadata: Arc<AsyncRwLock<Vec<SectorMetadataChecksummed>>>,
    pub(super) kzg: Kzg,
    pub(super) erasure_coding: ErasureCoding,
    pub(super) handlers: Arc<Handlers>,
    pub(super) modifying_sector_index: Arc<AsyncRwLock<Option<SectorIndex>>>,
    pub(super) slot_info_notifications: mpsc::Receiver<SlotInfo>,
    pub(super) thread_pool: ThreadPool,
    pub(super) read_sector_record_chunks_mode: ReadSectorRecordChunksMode,
    pub(super) global_mutex: Arc<AsyncMutex<()>>,
}

/// Starts farming process.
///
/// NOTE: Returned future is async, but does blocking operations and should be running in dedicated
/// thread.
pub(super) async fn farming<'a, PosTable, NC, Plot>(
    farming_options: FarmingOptions<NC, PlotAudit<Plot>>,
) -> Result<(), FarmingError>
where
    PosTable: Table,
    NC: NodeClient,
    Plot: ReadAtSync + 'a,
{
    let FarmingOptions {
        public_key,
        reward_address,
        node_client,
        plot_audit,
        sectors_metadata,
        kzg,
        erasure_coding,
        handlers,
        modifying_sector_index,
        mut slot_info_notifications,
        thread_pool,
        read_sector_record_chunks_mode,
        global_mutex,
    } = farming_options;

    let farmer_app_info = node_client
        .farmer_app_info()
        .await
        .map_err(|error| FarmingError::FailedToGetFarmerInfo { error })?;

    // We assume that each slot is one second
    let farming_timeout = farmer_app_info.farming_timeout;

    let table_generator = Arc::new(Mutex::new(PosTable::generator()));
    let span = Span::current();

    let handle = tokio::runtime::Handle::current();

    while let Some(slot_info) = slot_info_notifications.next().await {
        let slot = slot_info.slot_number;

        // Take mutex briefly to make sure farming is allowed right now
        global_mutex.lock().await;

        let result: Result<(), FarmingError> = try {
            let start = Instant::now();
            let sectors_metadata = sectors_metadata.read().await;

            debug!(%slot, sector_count = %sectors_metadata.len(), "Reading sectors");

            let mut sectors_solutions = {
                let modifying_sector_guard = modifying_sector_index.read().await;
                let maybe_sector_being_modified = modifying_sector_guard.as_ref().copied();

                thread_pool.install(|| {
                    let _span_guard = span.enter();

                    let options = PlotAuditOptions::<PosTable> {
                        public_key: &public_key,
                        reward_address: &reward_address,
                        slot_info,
                        sectors_metadata: &sectors_metadata,
                        kzg: &kzg,
                        erasure_coding: &erasure_coding,
                        maybe_sector_being_modified,
                        read_sector_record_chunks_mode,
                        table_generator: &table_generator,
                    };

                    let out = if std::env::var("RANDRW_S3_SERVER").is_ok() {
                        let convert = |v| -> Box<dyn Send + ProvableSolutions<Item = Result<Solution<PublicKey, PublicKey>, ProvingError>>> {
                            Box::new(v)
                        };
    
                        handle.block_on(plot_audit.audit_qiniu(options))?
                            .into_iter()
                            .map(|(a, b)| (a, convert(b)))
                            .collect::<Vec<_>>()
                    } else {
                        let convert = |v| -> Box<dyn Send + ProvableSolutions<Item = Result<Solution<PublicKey, PublicKey>, ProvingError>>> {
                            Box::new(v)
                        };
    
                        plot_audit.audit(options)?
                            .into_iter()
                            .map(|(a, b)| (a, convert(b)))
                            .collect::<Vec<_>>()
                    };
                    Result::<_, FarmingError>::Ok(out)
                })?
            };

            sectors_solutions.sort_by(|a, b| {
                let a_solution_distance =
                    a.1.best_solution_distance().unwrap_or(SolutionRange::MAX);
                let b_solution_distance =
                    b.1.best_solution_distance().unwrap_or(SolutionRange::MAX);

                a_solution_distance.cmp(&b_solution_distance)
            });

            handlers
                .farming_notification
                .call_simple(&FarmingNotification::Auditing(AuditingDetails {
                    sectors_count: sectors_metadata.len() as SectorIndex,
                    time: start.elapsed(),
                }));

            // Take mutex and hold until proving end to make sure nothing else major happens at the
            // same time
            let _proving_guard = global_mutex.lock().await;

            'solutions_processing: for (sector_index, mut sector_solutions) in sectors_solutions {
                if sector_solutions.is_empty() {
                    continue;
                }
                let mut start = Instant::now();
                while let Some(maybe_solution) = thread_pool.install(|| {
                    let _span_guard = span.enter();

                    sector_solutions.next()
                }) {
                    let solution = match maybe_solution {
                        Ok(solution) => solution,
                        Err(error) => {
                            error!(%slot, %sector_index, %error, "Failed to prove");
                            // Do not error completely as disk corruption or other reasons why
                            // proving might fail
                            start = Instant::now();
                            continue;
                        }
                    };

                    debug!(%slot, %sector_index, "Solution found");
                    trace!(?solution, "Solution found");

                    if start.elapsed() >= farming_timeout {
                        handlers
                            .farming_notification
                            .call_simple(&FarmingNotification::Proving(ProvingDetails {
                                result: ProvingResult::Timeout,
                                time: start.elapsed(),
                            }));
                        warn!(
                            %slot,
                            %sector_index,
                            "Proving for solution skipped due to farming time limit",
                        );

                        break 'solutions_processing;
                    }

                    let response = SolutionResponse {
                        slot_number: slot,
                        solution,
                    };

                    handlers.solution.call_simple(&response);

                    if let Err(error) = node_client.submit_solution_response(response).await {
                        handlers
                            .farming_notification
                            .call_simple(&FarmingNotification::Proving(ProvingDetails {
                                result: ProvingResult::Rejected,
                                time: start.elapsed(),
                            }));
                        warn!(
                            %slot,
                            %sector_index,
                            %error,
                            "Failed to send solution to node, skipping further proving for this slot",
                        );
                        break 'solutions_processing;
                    }

                    handlers
                        .farming_notification
                        .call_simple(&FarmingNotification::Proving(ProvingDetails {
                            result: ProvingResult::Success,
                            time: start.elapsed(),
                        }));
                    start = Instant::now();
                }
            }
        };

        if let Err(error) = result {
            if error.is_fatal() {
                return Err(error);
            } else {
                warn!(
                    %error,
                    "Non-fatal farming error"
                );

                handlers
                    .farming_notification
                    .call_simple(&FarmingNotification::NonFatalError(Arc::new(error)));
            }
        }
    }

    Ok(())
}
