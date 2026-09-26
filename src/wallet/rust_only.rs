//! RGB Rust-only methods module
//!
//! This module defines additional utility methods that are not exposed via FFI

use super::*;

/// RGB asset-specific information to color a transaction
#[derive(Clone, Debug)]
pub struct AssetColoringInfo {
    /// Map of vouts and asset amounts to color the transaction outputs
    pub output_map: HashMap<u32, u64>,
    /// Static blinding to keep the transaction construction deterministic
    pub static_blinding: Option<u64>,
}

/// RGB information to color a transaction
#[derive(Clone, Debug)]
pub struct ColoringInfo {
    /// Asset-specific information
    pub asset_info_map: HashMap<ContractId, AssetColoringInfo>,
    /// Static blinding to keep the transaction construction deterministic
    pub static_blinding: Option<u64>,
    /// Nonce for offchain TXs ordering
    pub nonce: Option<u64>,
}

/// Map of contract ID and list of its beneficiaries
pub type AssetBeneficiariesMap = BTreeMap<ContractId, Vec<BuilderSeal<GraphSeal>>>;

/// Indexer protocol
#[derive(Clone, Debug)]
pub enum IndexerProtocol {
    /// An indexer implementing the esplora protocol
    Esplora,
}

impl fmt::Display for IndexerProtocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Result of consignment validation (offchain or indexer-based).
#[cfg(feature = "esplora")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidateConsignmentResult {
    /// Whether the consignment is valid.
    pub valid: bool,
    /// Warnings from validation (when valid).
    pub warnings: Option<Vec<String>>,
    /// Error category (when invalid): "invalid" or "resolver".
    pub error: Option<String>,
    /// Detailed error/failure description (when invalid).
    pub details: Option<String>,
}

impl Wallet {
    /// Return all contract IDs currently held in the RGB stock.
    pub fn rgb_contract_ids(&self) -> Result<Vec<ContractId>, Error> {
        let runtime = self.rgb_runtime()?;
        Ok(runtime
            .contracts()?
            .into_iter()
            .map(|contract| contract.id)
            .collect())
    }

    /// Color a PSBT.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    pub fn color_psbt(
        &self,
        psbt: &mut Psbt,
        coloring_info: ColoringInfo,
    ) -> Result<(Fascia, AssetBeneficiariesMap), Error> {
        info!(self.logger, "Coloring PSBT...");
        let mut transaction = match psbt.clone().extract_tx() {
            Ok(tx) => tx,
            Err(ExtractTxError::MissingInputValue { tx }) => tx, // required for non-standard TXs
            Err(e) => return Err(InternalError::from(e).into()),
        };
        let mut opreturn_first = false;
        if transaction.output.iter().any(|o| o.script_pubkey.is_p2tr()) {
            opreturn_first = true;
        }

        if !transaction
            .output
            .iter()
            .any(|o| o.script_pubkey.is_op_return())
        {
            let opreturn_output = TxOut {
                value: BdkAmount::ZERO,
                script_pubkey: ScriptBuf::new_op_return([]),
            };
            if opreturn_first {
                transaction.output.insert(0, opreturn_output);
            } else {
                transaction.output.push(opreturn_output);
            }
            *psbt = Psbt::from_unsigned_tx(transaction).unwrap();
        }

        let runtime = self.rgb_runtime()?;

        let prev_outputs = psbt
            .unsigned_tx
            .input
            .iter()
            .map(|txin| txin.previous_output)
            .collect::<HashSet<OutPoint>>();

        let mut all_transitions: HashMap<ContractId, Transition> = HashMap::new();
        let mut asset_beneficiaries: AssetBeneficiariesMap = bmap![];
        let assignment_name = FieldName::from(RGB_STATE_ASSET_OWNER);

        for (contract_id, asset_coloring_info) in coloring_info.asset_info_map.clone() {
            let schema = AssetSchema::get_from_contract_id(contract_id, &runtime)?;

            let mut asset_transition_builder =
                runtime.transition_builder(contract_id, "transfer")?;

            let mut asset_available_amt = 0;
            for (_, opout_state_map) in
                runtime.contract_assignments_for(contract_id, prev_outputs.iter().copied())?
            {
                for (opout, state) in opout_state_map {
                    if let AllocatedState::Amount(amt) = &state {
                        asset_available_amt += amt.as_u64();
                    }
                    asset_transition_builder = asset_transition_builder.add_input(opout, state)?;
                }
            }

            let mut beneficiaries = vec![];
            let mut sending_amt = 0;
            for (mut vout, amount) in asset_coloring_info.output_map {
                if amount == 0 {
                    continue;
                }
                if opreturn_first {
                    vout += 1;
                }
                sending_amt += amount;
                if vout as usize > psbt.outputs.len() {
                    return Err(Error::InvalidColoringInfo {
                        details: s!("invalid vout in output_map, does not exist in the given PSBT"),
                    });
                }
                let graph_seal = if let Some(blinding) = asset_coloring_info.static_blinding {
                    GraphSeal::with_blinded_vout(vout, blinding)
                } else {
                    GraphSeal::new_random_vout(vout)
                };
                let seal = BuilderSeal::Revealed(graph_seal);
                beneficiaries.push(seal);

                match schema {
                    AssetSchema::Nia | AssetSchema::Ifa => {
                        asset_transition_builder = asset_transition_builder.add_fungible_state(
                            assignment_name.clone(),
                            seal,
                            amount,
                        )?;
                    }
                }
            }
            if sending_amt > asset_available_amt {
                return Err(Error::InvalidColoringInfo {
                    details: format!(
                        "total amount in output_map ({sending_amt}) greater than available ({asset_available_amt})"
                    ),
                });
            }

            if let Some(nonce) = coloring_info.nonce {
                asset_transition_builder = asset_transition_builder.set_nonce(nonce);
            }

            let transition = asset_transition_builder.complete_transition()?;
            all_transitions.insert(contract_id, transition);
            asset_beneficiaries.insert(contract_id, beneficiaries);
        }

        let opreturn_index = psbt
            .unsigned_tx
            .output
            .iter()
            .enumerate()
            .find(|(_, o)| o.script_pubkey.is_op_return())
            .expect("psbt should have an op_return output")
            .0;
        let opreturn_output = psbt.outputs.get_mut(opreturn_index).unwrap();
        opreturn_output.set_opret_host();
        if let Some(blinding) = coloring_info.static_blinding {
            opreturn_output
                .set_mpc_entropy(blinding)
                .map_err(InternalError::from)?;
        }

        for (contract_id, transition) in all_transitions {
            for opout in transition.inputs() {
                psbt.set_rgb_contract_consumer(contract_id, opout, transition.id())
                    .map_err(InternalError::from)?;
            }
            psbt.push_rgb_transition(transition)
                .map_err(InternalError::from)?;
        }

        psbt.set_rgb_close_method(CloseMethod::OpretFirst);
        psbt.set_as_unmodifiable();
        let fascia = psbt.rgb_commit().map_err(|e| Error::Internal {
            details: e.to_string(),
        })?;

        info!(self.logger, "Color PSBT completed");
        Ok((fascia, asset_beneficiaries))
    }

    /// Color a PSBT, consume the RGB fascia and return the related consignment.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    pub async fn color_psbt_and_consume(
        &self,
        psbt: &mut Psbt,
        coloring_info: ColoringInfo,
    ) -> Result<Vec<RgbTransfer>, Error> {
        info!(self.logger, "Coloring PSBT and consuming...");
        let (fascia, asset_beneficiaries) = self.color_psbt(psbt, coloring_info.clone())?;

        let witness_txid = psbt.get_txid();

        let mut runtime = self.rgb_runtime()?;
        runtime.consume_fascia(fascia, None)?;

        let mut transfers = vec![];
        for (contract_id, beneficiaries) in asset_beneficiaries {
            let mut beneficiaries_witness = vec![];
            let mut beneficiaries_blinded = vec![];
            for builder_seal in beneficiaries {
                match builder_seal {
                    BuilderSeal::Revealed(seal) => {
                        let explicit_seal = ExplicitSeal::with(witness_txid, seal.vout);
                        beneficiaries_witness.push(explicit_seal);
                    }
                    BuilderSeal::Concealed(secret_seal) => {
                        beneficiaries_blinded.push(secret_seal);
                    }
                };
            }
            transfers.push(runtime.transfer(
                contract_id,
                beneficiaries_witness,
                beneficiaries_blinded,
                Some(witness_txid),
            )?);
        }
        drop(runtime);
        self.flush().await?;

        info!(self.logger, "Color PSBT and consume completed");
        Ok(transfers)
    }

    /// Consume an RGB fascia.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    pub fn consume_fascia_in_memory(
        &self,
        fascia: Fascia,
        witness_ord: Option<WitnessOrd>,
    ) -> Result<(), Error> {
        let mut runtime = self.rgb_runtime()?;
        runtime.consume_fascia(fascia, witness_ord)?;
        Ok(())
    }

    /// Consume an RGB fascia and durably flush the updated stock.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    pub async fn consume_fascia(
        &self,
        fascia: Fascia,
        witness_ord: Option<WitnessOrd>,
    ) -> Result<(), Error> {
        info!(self.logger, "Consuming fascia...");
        self.consume_fascia_in_memory(fascia, witness_ord)?;
        self.flush().await?;
        info!(self.logger, "Consume fascia completed");
        Ok(())
    }

    /// Manually set the [`WitnessOrd`] of a witness TX.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    #[cfg(feature = "esplora")]
    pub fn upsert_witness(
        &self,
        witness_id: RgbTxid,
        witness_ord: WitnessOrd,
    ) -> Result<(), Error> {
        let mut runtime = self.rgb_runtime()?;
        runtime.upsert_witness(witness_id, witness_ord)?;
        Ok(())
    }

    /// Return `true` if a batch transfer with the given `txid` exists in the wallet database
    /// and is not in `Failed` status. Used to detect idempotent replay of `send_end` after a
    /// crash-inject reload: if the transfer is already present with a non-failed status, the
    /// broadcast already happened and the caller may treat the operation as succeeded.
    pub fn is_batch_transfer_sent(&self, txid: &str) -> Result<bool, Error> {
        let batch_transfers = self.database.iter_batch_transfers()?;
        Ok(batch_transfers
            .iter()
            .any(|bt| bt.txid.as_deref() == Some(txid) && bt.status != TransferStatus::Failed))
    }

    /// Return the current `Online` handle if the wallet has gone online, or `None` otherwise.
    pub fn get_online(&self) -> Option<Online> {
        self.online_data.as_ref().map(|od| Online {
            id: od.id,
            indexer_url: od.indexer_url.clone(),
        })
    }

    #[cfg(feature = "esplora")]
    pub(crate) fn save_new_asset_internal(
        &self,
        runtime: &RgbRuntime,
        contract_id: ContractId,
        asset_schema: AssetSchema,
        valid_contract: ValidContract,
        valid_transfer: ValidTransfer,
    ) -> Result<(), Error> {
        let timestamp = valid_contract.genesis.timestamp;
        let local_asset_data = match &asset_schema {
            AssetSchema::Nia => {
                let contract = runtime.contract_wrapper::<NonInflatableAsset>(contract_id)?;
                let spec = contract.spec();
                let ticker = spec.ticker().to_string();
                let name = spec.name().to_string();
                let details = spec.details().map(|d| d.to_string());
                let precision = spec.precision.into();
                let initial_supply = contract.total_issued_supply().into();
                let media_idx = if let Some(attachment) = contract.contract_terms().media {
                    Some(self.get_or_insert_media(
                        hex::encode(attachment.digest),
                        attachment.ty.to_string(),
                    )?)
                } else {
                    None
                };
                LocalAssetData {
                    name,
                    precision,
                    ticker: Some(ticker),
                    details,
                    media_idx,
                    initial_supply,
                    max_supply: None,
                    known_circulating_supply: None,
                    reject_list_url: None,
                }
            }
            AssetSchema::Ifa => {
                let contract = runtime.contract_wrapper::<InflatableFungibleAsset>(contract_id)?;
                let spec = contract.spec();
                let ticker = spec.ticker().to_string();
                let name = spec.name().to_string();
                let details = spec.details().map(|d| d.to_string());
                let precision = spec.precision.into();
                let media_idx = if let Some(attachment) = contract.contract_terms().media {
                    Some(self.get_or_insert_media(
                        hex::encode(attachment.digest),
                        attachment.ty.to_string(),
                    )?)
                } else {
                    None
                };
                let initial_supply = contract.total_issued_supply().into();
                let max_supply = contract.max_supply().into();
                let known_circulating_supply = IfaWrapper::with(valid_transfer.contract_data())
                    .total_issued_supply()
                    .into();
                let reject_list_url = contract.reject_list_url().map(|u| u.to_string());
                LocalAssetData {
                    name,
                    precision,
                    ticker: Some(ticker),
                    details,
                    media_idx,
                    initial_supply,
                    max_supply: Some(max_supply),
                    known_circulating_supply: Some(known_circulating_supply),
                    reject_list_url,
                }
            }
        };

        self.add_asset_to_db(
            contract_id.to_string(),
            &asset_schema,
            None,
            timestamp,
            local_asset_data,
        )?;

        Ok(())
    }

    /// Return the consignment file path for a send transfer of an asset.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    pub fn get_send_consignment_path(&self, asset_id: &str, transfer_id: &str) -> PathBuf {
        let transfer_dir = self.get_transfer_dir(transfer_id);
        let asset_transfer_dir = self.get_asset_transfer_dir(transfer_dir, asset_id);
        asset_transfer_dir.join(CONSIGNMENT_FILE)
    }

    /// Post a consignment to the proxy server.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    #[cfg(feature = "esplora")]
    pub async fn post_consignment(
        &self,
        proxy_url: &str,
        recipient_id: String,
        consignment_bytes: &[u8],
        txid: String,
        vout: Option<u32>,
    ) -> Result<(), Error> {
        info!(self.logger, "Posting consignment...");
        let consignment_res = self
            .wasm_proxy_client
            .post_consignment(
                proxy_url,
                recipient_id.clone(),
                consignment_bytes,
                txid.clone(),
                vout,
            )
            .await?;
        debug!(
            self.logger,
            "Consignment POST response: {:?}", consignment_res
        );

        if let Some(err) = consignment_res.error {
            if err.code == -101 {
                return Err(Error::RecipientIDAlreadyUsed);
            }
            return Err(Error::InvalidTransportEndpoint {
                details: format!("proxy error: {}", err.message),
            });
        }
        if consignment_res.result.is_none() {
            return Err(Error::InvalidTransportEndpoint {
                details: s!("invalid result"),
            });
        }

        info!(self.logger, "Post consignment completed");
        Ok(())
    }

    /// Get the height at which a transaction was mined.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    #[cfg(feature = "esplora")]
    pub async fn get_tx_height(&self, online: Online, txid: String) -> Result<Option<u32>, Error> {
        info!(self.logger, "Getting TX height...");
        self.check_online(online)?;
        let _ = RgbTxid::from_str(&txid).map_err(|_| Error::InvalidTxid)?;
        let height = self.indexer().get_tx_height(&txid).await?;
        info!(self.logger, "Get TX height completed");
        Ok(height)
    }

    /// Accept an RGB transfer by retrieving and validating its consignment from a proxy server.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    #[cfg(feature = "esplora")]
    pub async fn accept_transfer(
        &mut self,
        online: Online,
        txid: String,
        vout: u32,
        consignment_endpoint: RgbTransport,
        blinding: u64,
    ) -> Result<(RgbTransfer, Vec<Assignment>), Error> {
        info!(self.logger, "Accepting transfer...");
        self.check_online(online)?;
        let witness_id = RgbTxid::from_str(&txid).map_err(|_| Error::InvalidTxid)?;
        let proxy_url = TransportEndpoint::try_from(consignment_endpoint)?.endpoint;

        let consignment_res = self
            ._get_consignment_async(&proxy_url, txid.clone())
            .await?;
        let consignment_bytes = general_purpose::STANDARD
            .decode(consignment_res.consignment)
            .map_err(InternalError::from)?;
        let consignment = RgbTransfer::load(&consignment_bytes[..]).map_err(InternalError::from)?;

        let schema_id = consignment.schema_id().to_string();
        let asset_schema: AssetSchema = schema_id.try_into()?;
        self.check_schema_support(&asset_schema)?;
        debug!(
            self.logger,
            "Got consignment for asset with {} schema", asset_schema
        );

        let mut runtime = self.rgb_runtime()?;

        let graph_seal = GraphSeal::with_blinded_vout(vout, blinding);
        runtime.store_secret_seal(graph_seal)?;

        let wasm_resolver =
            crate::utils::WasmResolver::from_consignment(&consignment, self.chain_net());
        let resolver = crate::utils::OffchainResolverWasm {
            witness_id,
            consignment: &consignment,
            fallback: &wasm_resolver,
        };

        debug!(self.logger, "Validating consignment...");
        let asset_schema: AssetSchema = consignment.schema_id().try_into()?;
        let trusted_typesystem = asset_schema.types();
        let validation_config = ValidationConfig {
            chain_net: self.chain_net(),
            trusted_typesystem,
            ..Default::default()
        };
        let valid_consignment = match consignment.clone().validate(&resolver, &validation_config) {
            Ok(consignment) => consignment,
            Err(ValidationError::InvalidConsignment(e)) => {
                error!(self.logger, "Consignment is invalid: {}", e);
                return Err(Error::InvalidConsignment);
            }
            Err(ValidationError::ResolverError(e)) => {
                warn!(self.logger, "Network error during consignment validation");
                return Err(Error::Network {
                    details: e.to_string(),
                });
            }
        };
        let validity = valid_consignment.validation_status().validity();
        debug!(self.logger, "Consignment validity: {:?}", validity);

        let valid_contract = valid_consignment.clone().into_valid_contract();
        runtime
            .import_contract(valid_contract, &resolver)
            .expect("failure importing validated contract");

        let received_rgb_assignments =
            self.extract_received_assignments(&consignment, witness_id, Some(vout), None);

        runtime.accept_transfer(valid_consignment, &resolver)?;
        drop(runtime);
        self.flush().await?;

        info!(self.logger, "Accept transfer completed");
        Ok((
            consignment,
            received_rgb_assignments.into_values().collect(),
        ))
    }

    /// Update RGB witnesses.
    ///
    /// Pre-fetches witness data from esplora before calling the sync RGB stock method.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    #[cfg(feature = "esplora")]
    pub async fn update_witnesses(
        &mut self,
        online: Online,
        after_height: u32,
        force_witnesses: Vec<RgbTxid>,
    ) -> Result<UpdateRes, Error> {
        info!(self.logger, "Updating witnesses...");
        self.check_online(online)?;

        let mut cache = HashMap::new();
        for witness_id in &force_witnesses {
            let txid_str = witness_id.to_string();
            let txid = Txid::from_str(&txid_str).map_err(|_| Error::InvalidTxid)?;
            if let Some((tx, block_height, block_time)) =
                self.indexer().get_tx_with_status(&txid).await?
            {
                let witness_ord = match block_height.zip(block_time) {
                    Some((h, t)) => {
                        if let Some(height) = NonZeroU32::new(h) {
                            if let Some(pos) = WitnessPos::bitcoin(height, t as i64) {
                                WitnessOrd::Mined(pos)
                            } else {
                                WitnessOrd::Tentative
                            }
                        } else {
                            WitnessOrd::Tentative
                        }
                    }
                    None => WitnessOrd::Tentative,
                };
                cache.insert(*witness_id, WitnessStatus::Resolved(tx, witness_ord));
            }
        }

        let resolver = crate::utils::PreFetchResolver::new(cache, self.chain_net());
        let update_res =
            self.rgb_runtime()?
                .update_witnesses(&resolver, after_height, force_witnesses)?;

        info!(self.logger, "Update witnesses completed");
        Ok(update_res)
    }
}

/// Check whether the provided URL points to a valid proxy.
///
/// An error is raised if the provided proxy URL is invalid or if the service is running an
/// unsupported protocol version.
#[cfg(feature = "esplora")]
pub async fn check_proxy_url(proxy_url: &str) -> Result<(), Error> {
    crate::utils::check_proxy_async(proxy_url).await
}

/// Validate a consignment using the witness bundled in the consignment (offchain).
///
/// This works before the witness transaction is broadcast. The consignment bytes are
/// the raw strict-encoded consignment (not base64). The `txid` is the witness
/// transaction ID. The fallback resolver uses witness data from the consignment itself.
///
/// Returns a `ValidateConsignmentResult` with validity status, warnings, and error details.
#[cfg(feature = "esplora")]
pub fn validate_consignment_offchain(
    consignment_bytes: &[u8],
    txid: &str,
    bitcoin_network: BitcoinNetwork,
) -> Result<ValidateConsignmentResult, Error> {
    let consignment = RgbTransfer::load(consignment_bytes).map_err(|e| Error::Internal {
        details: format!("Failed to load consignment: {e}"),
    })?;

    let witness_id = RgbTxid::from_str(txid).map_err(|_| Error::InvalidTxid)?;
    let chain_net: ChainNet = bitcoin_network.into();
    let asset_schema: AssetSchema = consignment.schema_id().try_into()?;
    let trusted_typesystem = asset_schema.types();

    let wasm_resolver = crate::utils::WasmResolver::from_consignment(&consignment, chain_net);
    let resolver = crate::utils::OffchainResolverWasm {
        witness_id,
        consignment: &consignment,
        fallback: &wasm_resolver,
    };

    let validation_config = ValidationConfig {
        chain_net,
        trusted_typesystem,
        ..Default::default()
    };

    match consignment.clone().validate(&resolver, &validation_config) {
        Ok(valid_consignment) => {
            let status = valid_consignment.validation_status();
            Ok(ValidateConsignmentResult {
                valid: true,
                warnings: Some(
                    status
                        .warnings
                        .iter()
                        .map(|w| w.to_string())
                        .collect::<Vec<_>>(),
                ),
                error: None,
                details: None,
            })
        }
        Err(ValidationError::InvalidConsignment(failure)) => Ok(ValidateConsignmentResult {
            valid: false,
            warnings: None,
            error: Some("invalid".to_string()),
            details: Some(failure.to_string()),
        }),
        Err(ValidationError::ResolverError(e)) => Ok(ValidateConsignmentResult {
            valid: false,
            warnings: None,
            error: Some("resolver".to_string()),
            details: Some(e.to_string()),
        }),
    }
}

/// One amount a consignment assigns, and the operation that assigned it.
#[cfg(feature = "esplora")]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "camel_case", serde(rename_all = "camelCase"))]
pub struct HistoryAllocation {
    /// Amount in the asset's indivisible units — for a UDA, the fraction of the token. Apply
    /// the asset precision to display it. `None` when the state is not a quantity at all.
    pub amount: Option<u64>,
    /// Index of the token this allocation is of, for a schema that has more than one.
    pub token: Option<u32>,
    /// `"asset"` for the asset itself, `"inflation"` for an inflation right, `"link"` for a
    /// contract link, or the numeric assignment type for anything else a schema defines.
    pub state: String,
    /// Where the amount is assigned, as `"<txid>:<vout>"`.
    ///
    /// `None` when the consignment carries only the blinded seal, which is what a blinded
    /// receive looks like to everyone but its receiver: the amount is in the open, the
    /// destination is not.
    pub seal: Option<String>,
    /// The operation that created this allocation.
    pub op: String,
    /// Index of the assignment within that operation.
    pub index: u16,
}

/// One step of a chain of custody: an operation and the bitcoin transaction it commits to.
#[cfg(feature = "esplora")]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "camel_case", serde(rename_all = "camelCase"))]
pub struct HistoryStep {
    /// Position in the chain, `0` being the issuance.
    pub index: u32,
    /// `"issuance"` or `"transfer"`.
    pub kind: String,
    /// The operations bundled into this step. A step carries more than one when a single
    /// transaction moves several allocations of the contract at once.
    pub ops: Vec<String>,
    /// The bitcoin transaction this step is committed to. `None` for the issuance, which
    /// commits to nothing: it is the receiver's first transfer that anchors it.
    pub witness_txid: Option<String>,
    /// Whether the consignment carries that transaction in full. When it does not, only its
    /// id is known and the transaction has to be looked up on bitcoin to be seen.
    pub witness_included: bool,
    /// How the commitment sits in the transaction: `"tapret"` or `"opret"`.
    pub commitment: Option<String>,
    /// The bundle this step commits to, as it is named in the commitment.
    pub bundle_id: Option<String>,
    /// Whether the chain of custody ends here.
    pub terminal: bool,
    /// The allocations this step consumes, resolved against the operations that created them.
    pub spends: Vec<HistoryAllocation>,
    /// The allocations this step creates.
    pub creates: Vec<HistoryAllocation>,
}

/// A file the genesis commits to. The consignment carries the commitment, never the bytes:
/// whoever hands the file over is checked against the digest, and a reader that has not been
/// handed it knows what it is looking for and that it does not have it.
#[cfg(feature = "esplora")]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "camel_case", serde(rename_all = "camelCase"))]
pub struct ConsignmentMedia {
    /// The attachment slot the genesis filed the file under. `None` for the asset's own media.
    pub index: Option<u8>,
    /// Media type the genesis states, as `type/subtype`.
    pub mime: String,
    /// SHA-256 of the file, hex encoded.
    pub digest: String,
}

#[cfg(feature = "esplora")]
impl ConsignmentMedia {
    fn of(attachment: &Attachment, index: Option<u8>) -> Self {
        ConsignmentMedia {
            index,
            mime: attachment.ty.to_string(),
            digest: hex::encode(attachment.digest),
        }
    }
}

/// The media a fungible schema commits to, which hangs off the contract terms.
#[cfg(feature = "esplora")]
fn terms_media(terms: ContractTerms) -> Option<ConsignmentMedia> {
    terms.media.as_ref().map(|a| ConsignmentMedia::of(a, None))
}

/// What the consignment says about the asset itself. Only available once it validates: the
/// contract state these fields are read from is what validation produces.
#[cfg(feature = "esplora")]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "camel_case", serde(rename_all = "camelCase"))]
pub struct ConsignmentAsset {
    /// `"NIA"`, `"CFA"`, `"UDA"`, `"IFA"` or `"PFA"`.
    pub schema: String,
    /// Ticker the genesis states. A CFA has none.
    pub ticker: Option<String>,
    /// Name the genesis states.
    pub name: String,
    /// Free-form details the genesis states, when it states any.
    pub details: Option<String>,
    /// Decimal places the amounts in this consignment are denominated in.
    pub precision: u8,
    /// Supply issued by the genesis, in indivisible units. A UDA states none.
    pub issued_supply: Option<u64>,
    /// The ceiling an inflatable asset may be inflated to.
    pub max_supply: Option<u64>,
    /// Whoever the genesis names as the issuer. Nothing checks that the name is deserved.
    pub issuer: String,
    /// Unix timestamp the genesis carries.
    pub issued_at: i64,
    /// The file the contract commits to as the asset's own image, when it commits to one.
    pub media: Option<ConsignmentMedia>,
    /// Further files the genesis commits to. Only a UDA files any.
    pub attachments: Vec<ConsignmentMedia>,
}

/// What a consignment contains, read without a wallet.
#[cfg(feature = "esplora")]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "camel_case", serde(rename_all = "camelCase"))]
pub struct ConsignmentHistory {
    /// Whether the consignment validates against the witnesses it carries.
    pub valid: bool,
    /// Whether this is a transfer. A contract consignment carries the genesis alone.
    pub transfer: bool,
    /// Warnings from validation.
    pub warnings: Vec<String>,
    /// Error category when it does not validate: `"invalid"` or `"resolver"`.
    pub error: Option<String>,
    /// Failure description when it does not validate.
    pub details: Option<String>,
    /// The contract the consignment is about. Read before validation, so it is always there.
    pub contract_id: String,
    /// Schema id of that contract, as a string.
    pub schema_id: String,
    /// The chain the contract was issued on, as the genesis states it.
    pub chain_net: String,
    /// The asset, once the consignment validates.
    pub asset: Option<ConsignmentAsset>,
    /// The chain of custody, issuance first. Empty when the consignment does not validate:
    /// what an invalid consignment claims about its own history is not a history.
    pub steps: Vec<HistoryStep>,
}

/// The asset schemas a consignment can be read against.
///
/// Which one it is decides the type system validation runs with. That type system comes from
/// the schema, never from the consignment: a consignment states its own types, and trusting
/// those would let a forged one decide what its state means.
#[cfg(feature = "esplora")]
#[derive(Clone, Copy, Debug)]
enum ReadableSchema {
    Nia,
    Cfa,
    Uda,
    Ifa,
    Pfa,
}

#[cfg(feature = "esplora")]
impl ReadableSchema {
    fn of(schema_id: rgbstd::SchemaId) -> Option<Self> {
        Some(match schema_id {
            id if id == NIA_SCHEMA_ID => Self::Nia,
            id if id == CFA_SCHEMA_ID => Self::Cfa,
            id if id == UDA_SCHEMA_ID => Self::Uda,
            id if id == IFA_SCHEMA_ID => Self::Ifa,
            id if id == PFA_SCHEMA_ID => Self::Pfa,
            _ => return None,
        })
    }

    fn name(self) -> &'static str {
        match self {
            Self::Nia => "NIA",
            Self::Cfa => "CFA",
            Self::Uda => "UDA",
            Self::Ifa => "IFA",
            Self::Pfa => "PFA",
        }
    }

    fn types(self) -> TypeSystem {
        match self {
            Self::Nia => NonInflatableAsset::types(),
            Self::Cfa => CollectibleFungibleAsset::types(),
            Self::Uda => UniqueDigitalAsset::types(),
            Self::Ifa => InflatableFungibleAsset::types(),
            Self::Pfa => PermissionedFungibleAsset::types(),
        }
    }
}

/// Name an assignment type the way the asset schemas use it.
#[cfg(feature = "esplora")]
fn assignment_state_name(ty: rgbstd::AssignmentType) -> String {
    match ty {
        t if t == OS_ASSET => s!("asset"),
        t if t == OS_INFLATION => s!("inflation"),
        t if t == OS_LINK => s!("link"),
        t => t.to_string(),
    }
}

/// Read one operation's assignments: what it creates, and where.
///
/// Both fungible and structured state are read. A UDA's owned state is structured — a token
/// index and a fraction of it — and a schema that had none of either would still be walked
/// for its seals.
#[cfg(feature = "esplora")]
fn collect_assignments<Seal: ExposedSeal>(
    assignments: &Assignments<Seal>,
    opid: OpId,
    seal_of: impl Fn(&Seal) -> String,
    created: &mut HashMap<Opout, HistoryAllocation>,
    into: &mut Vec<HistoryAllocation>,
) {
    for (ty, typed_assigns) in assignments.iter() {
        let mut push =
            |no: usize, amount: Option<u64>, token: Option<u32>, seal: Option<String>| {
                let allocation = HistoryAllocation {
                    amount,
                    token,
                    state: assignment_state_name(*ty),
                    seal,
                    op: opid.to_string(),
                    index: no as u16,
                };
                created.insert(Opout::new(opid, *ty, no as u16), allocation.clone());
                into.push(allocation);
            };
        for (no, assignment) in typed_assigns.as_fungible().iter().enumerate() {
            match assignment {
                Assign::Revealed { seal, state } => {
                    push(no, Some(state.as_u64()), None, Some(seal_of(seal)))
                }
                Assign::ConfidentialSeal { state, .. } => {
                    push(no, Some(state.as_u64()), None, None)
                }
            }
        }
        for (no, assignment) in typed_assigns.as_structured().iter().enumerate() {
            let (seal, state) = match assignment {
                Assign::Revealed { seal, state } => (Some(seal_of(seal)), state),
                Assign::ConfidentialSeal { state, .. } => (None, state),
            };
            // Structured state is opaque bytes until something says what type it is. The one
            // the asset schemas define is a token index and a fraction of it; anything else is
            // reported as an assignment without a quantity rather than guessed at.
            let allocation = Allocation::from_strict_serialized(state.clone().into()).ok();
            push(
                no,
                allocation.map(|a| a.fraction().into()),
                allocation.map(|a| a.token_index().into()),
                seal,
            );
        }
    }
}

/// Order the bundles by what they spend: a bundle comes after every bundle that created an
/// allocation it consumes.
///
/// The consignment stores its bundles sorted by witness id, which says nothing about the
/// order they happened in, and offchain there are no block heights to sort by. The spending
/// graph is the only ordering a consignment carries on its own, and it is the one a reader
/// is after: this is who had the asset before whom. Ties — bundles that do not depend on
/// each other — are broken by witness id, so the same consignment always reads the same way.
#[cfg(feature = "esplora")]
fn order_bundles<const TRANSFER: bool>(consignment: &Consignment<TRANSFER>) -> Vec<usize> {
    let bundles: Vec<_> = consignment.bundles.iter().collect();
    let mut producer = HashMap::new();
    for (i, bw) in bundles.iter().enumerate() {
        for KnownTransition { opid, .. } in bw.bundle.known_transitions.iter() {
            producer.insert(*opid, i);
        }
    }

    let mut pending: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); bundles.len()];
    for (i, bw) in bundles.iter().enumerate() {
        for opout in bw.bundle.input_map.keys() {
            if let Some(&j) = producer.get(&opout.op) {
                if j != i {
                    pending[i].insert(j);
                }
            }
        }
    }

    let mut order = Vec::with_capacity(bundles.len());
    let mut placed = vec![false; bundles.len()];
    while order.len() < bundles.len() {
        let next = (0..bundles.len())
            .filter(|&i| !placed[i] && pending[i].iter().all(|j| placed[*j]))
            .min_by_key(|&i| bundles[i].witness_id().to_string());
        // A consignment whose bundles spend each other in a cycle is not a chain of custody,
        // but it must not hang or lose steps here: whatever is left keeps its stored order.
        let Some(next) = next else {
            order.extend((0..bundles.len()).filter(|&i| !placed[i]));
            break;
        };
        placed[next] = true;
        order.push(next);
    }
    order
}

/// Read a consignment: what it transfers, and the bitcoin transaction behind every step.
///
/// Takes the consignment as it was handed over — the raw strict-encoded bytes, or the ASCII
/// armored text a wallet exports — and the bitcoin network. The witness transactions come
/// from the consignment itself, so this needs no wallet, no seed, no data directory and no
/// network access, and the caller does not have to know any txid in advance: a consignment
/// names its own. A contract consignment is read too, and reports the issuance alone.
///
/// The consignment is validated first, exactly as [`validate_consignment_offchain`] does it,
/// and the history is reported only when it validates.
#[cfg(feature = "esplora")]
pub fn consignment_history(
    consignment_bytes: &[u8],
    bitcoin_network: BitcoinNetwork,
) -> Result<ConsignmentHistory, Error> {
    // 🚨 `std::str::from_utf8`, not `str::from_utf8`: the associated form is newer than
    // this crate's MSRV, and clippy fails the build on it.
    let armored = || std::str::from_utf8(consignment_bytes).ok().map(str::trim);
    // rgb-lib stores the *validated* copy of a container under its own magic — `VCO` for a
    // contract, `VTF` for a transfer. The payload after the magic is the same consignment
    // encoding, and that copy is what a wallet's `assets/` directory hands out, so read it
    // by patching the magic rather than decoding it twice.
    let bytes: std::borrow::Cow<[u8]> = if consignment_bytes.len() >= 7 && &consignment_bytes[..4] == b"RGB\0" {
        match &consignment_bytes[4..7] {
            magic @ (b"VCO" | b"VTF") => {
                let mut v = consignment_bytes.to_vec();
                v[4..7].copy_from_slice(if magic == b"VCO" { b"CON" } else { b"TFR" });
                std::borrow::Cow::Owned(v)
            }
            _ => std::borrow::Cow::Borrowed(consignment_bytes),
        }
    } else {
        std::borrow::Cow::Borrowed(consignment_bytes)
    };
    if let Ok(transfer) = RgbTransfer::load(&*bytes) {
        return history_of(transfer, bitcoin_network);
    }
    if let Ok(contract) = RgbContract::load(&*bytes) {
        return history_of(contract, bitcoin_network);
    }
    if let Some(text) = armored() {
        if let Ok(transfer) = RgbTransfer::from_str(text) {
            return history_of(transfer, bitcoin_network);
        }
        if let Ok(contract) = RgbContract::from_str(text) {
            return history_of(contract, bitcoin_network);
        }
    }
    Err(Error::Internal {
        details: s!("Failed to load consignment: not a consignment, in bytes or ASCII armor"),
    })
}

#[cfg(feature = "esplora")]
fn history_of<const TRANSFER: bool>(
    consignment: Consignment<TRANSFER>,
    bitcoin_network: BitcoinNetwork,
) -> Result<ConsignmentHistory, Error> {
    let chain_net: ChainNet = bitcoin_network.into();
    let schema_id = consignment.schema_id();
    let schema = ReadableSchema::of(schema_id).ok_or(Error::UnknownRgbSchema {
        schema_id: schema_id.to_string(),
    })?;

    let mut history = ConsignmentHistory {
        valid: false,
        transfer: TRANSFER,
        warnings: vec![],
        error: None,
        details: None,
        contract_id: consignment.contract_id().to_string(),
        schema_id: schema_id.to_string(),
        chain_net: consignment.genesis.chain_net.to_string(),
        asset: None,
        steps: vec![],
    };

    let resolver = crate::utils::WasmResolver::from_consignment(&consignment, chain_net);
    let validation_config = ValidationConfig {
        chain_net,
        trusted_typesystem: schema.types(),
        ..Default::default()
    };

    let valid = match consignment.clone().validate(&resolver, &validation_config) {
        Ok(valid) => valid,
        Err(ValidationError::InvalidConsignment(failure)) => {
            history.error = Some(s!("invalid"));
            history.details = Some(failure.to_string());
            return Ok(history);
        }
        Err(ValidationError::ResolverError(e)) => {
            history.error = Some(s!("resolver"));
            history.details = Some(e.to_string());
            return Ok(history);
        }
    };
    history.valid = true;
    history.warnings = valid
        .validation_status()
        .warnings
        .iter()
        .map(|w| w.to_string())
        .collect();

    let data = valid.contract_data();
    let (ticker, name, details, precision, issued_supply, max_supply, media, attachments) =
        match schema {
            ReadableSchema::Nia => {
                let wrapper = NiaWrapper::with(data);
                let spec = wrapper.spec();
                (
                    Some(spec.ticker().to_string()),
                    spec.name().to_string(),
                    spec.details().map(|d| d.to_string()),
                    spec.precision.into(),
                    Some(wrapper.total_issued_supply().into()),
                    None,
                    terms_media(wrapper.contract_terms()),
                    vec![],
                )
            }
            ReadableSchema::Cfa => {
                let wrapper = CfaWrapper::with(data);
                (
                    None,
                    wrapper.name().to_string(),
                    wrapper.details().map(|d| d.to_string()),
                    wrapper.precision().into(),
                    Some(wrapper.total_issued_supply().into()),
                    None,
                    terms_media(wrapper.contract_terms()),
                    vec![],
                )
            }
            ReadableSchema::Uda => {
                let wrapper = UdaWrapper::with(data);
                let spec = wrapper.spec();
                // A UDA hangs its files off the token, not off the contract terms: `media` is the
                // one face every holder is handed, and every further slot is an attachment the
                // genesis commits to just as firmly.
                let token = wrapper.token_data();
                (
                    Some(spec.ticker().to_string()),
                    spec.name().to_string(),
                    spec.details().map(|d| d.to_string()),
                    spec.precision.into(),
                    None,
                    None,
                    token
                        .media
                        .as_ref()
                        .map(|a| ConsignmentMedia::of(a, None))
                        .or_else(|| terms_media(wrapper.contract_terms())),
                    token
                        .attachments
                        .iter()
                        .map(|(index, a)| ConsignmentMedia::of(a, Some(*index)))
                        .collect(),
                )
            }
            ReadableSchema::Ifa => {
                let wrapper = IfaWrapper::with(data);
                let spec = wrapper.spec();
                (
                    Some(spec.ticker().to_string()),
                    spec.name().to_string(),
                    spec.details().map(|d| d.to_string()),
                    spec.precision.into(),
                    Some(wrapper.total_issued_supply().into()),
                    Some(wrapper.max_supply().into()),
                    terms_media(wrapper.contract_terms()),
                    vec![],
                )
            }
            ReadableSchema::Pfa => {
                let wrapper = PfaWrapper::with(data);
                let spec = wrapper.spec();
                (
                    Some(spec.ticker().to_string()),
                    spec.name().to_string(),
                    spec.details().map(|d| d.to_string()),
                    spec.precision.into(),
                    Some(wrapper.total_issued_supply().into()),
                    None,
                    terms_media(wrapper.contract_terms()),
                    vec![],
                )
            }
        };
    history.asset = Some(ConsignmentAsset {
        schema: schema.name().to_string(),
        ticker,
        name,
        details,
        precision,
        issued_supply,
        max_supply,
        issuer: consignment.genesis.issuer.to_string(),
        issued_at: consignment.genesis.timestamp,
        media,
        attachments,
    });

    // Every allocation the consignment reveals, by the assignment that created it, so that
    // what a later step spends can be reported as the amount it is rather than a reference.
    let mut created: HashMap<Opout, HistoryAllocation> = HashMap::new();

    let genesis_opid = consignment.genesis.id();
    let mut issuance = HistoryStep {
        index: 0,
        kind: s!("issuance"),
        ops: vec![genesis_opid.to_string()],
        witness_txid: None,
        witness_included: false,
        commitment: None,
        bundle_id: None,
        terminal: false,
        spends: vec![],
        creates: vec![],
    };
    collect_assignments(
        &consignment.genesis.assignments,
        genesis_opid,
        |seal| format!("{}:{}", seal.txid, seal.vout.into_u32()),
        &mut created,
        &mut issuance.creates,
    );
    history.steps.push(issuance);

    for (position, i) in order_bundles(&consignment).into_iter().enumerate() {
        let bw = &consignment.bundles[i];
        let witness_id = bw.witness_id();
        let bundle_id = bw.bundle.bundle_id();
        let mut step = HistoryStep {
            index: position as u32 + 1,
            kind: s!("transfer"),
            ops: vec![],
            witness_txid: Some(witness_id.to_string()),
            witness_included: bw.pub_witness.tx().is_some(),
            commitment: Some(match bw.anchor.dbc_proof {
                rgbstd::validation::DbcProof::Tapret(_) => s!("tapret"),
                rgbstd::validation::DbcProof::Opret(_) => s!("opret"),
            }),
            bundle_id: Some(bundle_id.to_string()),
            terminal: consignment.terminals.contains_key(&bundle_id),
            spends: vec![],
            creates: vec![],
        };

        // Resolvable because validation walked the same graph: an input whose creating
        // operation is missing is one of the failures it reports.
        for opout in bw.bundle.input_map.keys() {
            if let Some(allocation) = created.get(opout) {
                step.spends.push(allocation.clone());
            }
        }

        for KnownTransition { opid, transition } in bw.bundle.known_transitions.iter() {
            step.ops.push(opid.to_string());
            collect_assignments(
                &transition.assignments,
                *opid,
                |seal| {
                    let txid = match seal.txid {
                        // The seal is on an output of this step's own transaction, which is
                        // how a witness receive is written before there is a txid to name.
                        TxPtr::WitnessTx => witness_id.to_string(),
                        TxPtr::Txid(txid) => txid.to_string(),
                    };
                    format!("{}:{}", txid, seal.vout.into_u32())
                },
                &mut created,
                &mut step.creates,
            );
        }

        history.steps.push(step);
    }

    Ok(history)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_consignment_offchain_invalid_bytes() {
        let result = validate_consignment_offchain(
            b"not a valid consignment",
            "0000000000000000000000000000000000000000000000000000000000000000",
            BitcoinNetwork::Regtest,
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, Error::Internal { details: ref d } if d.contains("Failed to load consignment")),
            "expected Internal error with load failure, got: {err:?}"
        );
    }

    #[test]
    fn validate_consignment_offchain_invalid_txid() {
        let result = validate_consignment_offchain(
            b"not a valid consignment",
            "not-a-txid",
            BitcoinNetwork::Regtest,
        );
        // Will fail on consignment load before txid parsing
        assert!(result.is_err());
    }

    #[test]
    fn validate_consignment_result_serde_roundtrip() {
        let result = ValidateConsignmentResult {
            valid: true,
            warnings: Some(vec!["warn1".to_string()]),
            error: None,
            details: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: ValidateConsignmentResult = serde_json::from_str(&json).unwrap();
        assert!(deserialized.valid);
        assert_eq!(deserialized.warnings.unwrap(), vec!["warn1".to_string()]);
        assert!(deserialized.error.is_none());

        let result_invalid = ValidateConsignmentResult {
            valid: false,
            warnings: None,
            error: Some("invalid".to_string()),
            details: Some("schema mismatch".to_string()),
        };
        let json = serde_json::to_string(&result_invalid).unwrap();
        let deserialized: ValidateConsignmentResult = serde_json::from_str(&json).unwrap();
        assert!(!deserialized.valid);
        assert_eq!(deserialized.error.unwrap(), "invalid");
    }

    /// A regtest NIA transfer with three steps: the issuance, a first send that keeps 900 as
    /// change and blinds 100 to a receiver, and a second send that spends that change.
    #[cfg(feature = "esplora")]
    const TRANSFER_NIA: &[u8] = include_bytes!("../../tests/fixtures/transfer_nia_regtest.rgb");

    #[cfg(feature = "esplora")]
    #[test]
    fn consignment_history_reads_a_chain_of_custody() {
        let history = consignment_history(TRANSFER_NIA, BitcoinNetwork::Regtest).unwrap();
        assert!(history.valid, "{:?} {:?}", history.error, history.details);

        let asset = history
            .asset
            .expect("a valid consignment reports its asset");
        assert_eq!(asset.schema, "NIA");
        assert_eq!(asset.ticker.as_deref(), Some("USDT"));
        assert_eq!(asset.issued_supply, Some(1000));

        assert_eq!(history.steps.len(), 3);
        assert_eq!(history.steps[0].kind, "issuance");
        assert!(
            history.steps[0].witness_txid.is_none(),
            "an issuance commits to nothing"
        );
        assert_eq!(history.steps[0].creates[0].amount, Some(1000));

        for step in &history.steps[1..] {
            assert_eq!(step.kind, "transfer");
            assert!(
                step.witness_txid.is_some(),
                "a transfer names the transaction it commits to"
            );
            assert_eq!(step.commitment.as_deref(), Some("opret"));
        }
        assert!(
            history.steps[2].terminal,
            "the last step is where the history ends"
        );

        // The amounts of the second step: what it keeps, and what it sends to a blinded seal.
        let amounts: Vec<Option<u64>> = history.steps[1].creates.iter().map(|a| a.amount).collect();
        assert_eq!(amounts, vec![Some(900), Some(100)]);
        assert!(
            history.steps[1].creates[1].seal.is_none(),
            "a blinded receive states the amount and hides the destination"
        );
    }

    #[cfg(feature = "esplora")]
    #[test]
    fn consignment_history_reads_the_validated_copy_a_wallet_stores() {
        // rgb-lib keeps a validated copy of a container under the `VTF`/`VCO` magic, and the
        // `assets/` directory of a wallet backup hands out exactly those copies. The payload
        // is the same, so the reading must be the same.
        let mut vtf = TRANSFER_NIA.to_vec();
        assert_eq!(&vtf[4..7], b"TFR", "the fixture is a plain transfer container");
        vtf[4..7].copy_from_slice(b"VTF");
        let plain = consignment_history(TRANSFER_NIA, BitcoinNetwork::Regtest).unwrap();
        let validated = consignment_history(&vtf, BitcoinNetwork::Regtest).unwrap();
        assert_eq!(validated.contract_id, plain.contract_id);
        assert_eq!(validated.steps.len(), plain.steps.len());
        assert!(validated.valid);
    }

    #[cfg(feature = "esplora")]
    #[test]
    fn consignment_history_orders_steps_by_what_they_spend() {
        let history = consignment_history(TRANSFER_NIA, BitcoinNetwork::Regtest).unwrap();

        // Every allocation a step spends was created by a step before it. This is the whole
        // point of the ordering, and it does not come for free: the consignment stores its
        // bundles sorted by witness id, which here is the reverse of what happened.
        let stored_order_would_differ =
            history.steps[1].witness_txid > history.steps[2].witness_txid;
        assert!(
            stored_order_would_differ,
            "this fixture no longer exercises the ordering"
        );

        let mut seen: Vec<(String, u16)> = vec![];
        for step in &history.steps {
            for spent in &step.spends {
                assert!(
                    seen.contains(&(spent.op.clone(), spent.index)),
                    "step {} spends an allocation no earlier step created",
                    step.index
                );
            }
            seen.extend(step.creates.iter().map(|a| (a.op.clone(), a.index)));
        }
    }

    #[cfg(feature = "esplora")]
    #[test]
    fn consignment_history_reports_a_consignment_for_another_chain_as_invalid() {
        // Not an error: the file parses, it just does not describe the chain it was read
        // against, and saying so is the answer.
        let history = consignment_history(TRANSFER_NIA, BitcoinNetwork::Mainnet).unwrap();
        assert!(!history.valid);
        assert!(history.error.is_some());
        assert!(
            history.steps.is_empty(),
            "an invalid consignment reports no history"
        );
        assert_eq!(
            history.contract_id,
            "rgb:CDj3EZIH-NphNYJB-9T6b5yd-ggRZy3Y-Whsd~sh-PCG4vhA"
        );
    }

    #[cfg(feature = "esplora")]
    #[test]
    fn consignment_history_refuses_bytes_that_are_not_a_consignment() {
        let result = consignment_history(b"not a valid consignment", BitcoinNetwork::Regtest);
        assert!(
            matches!(result, Err(Error::Internal { details: ref d }) if d.contains("Failed to load consignment")),
            "got: {result:?}"
        );
    }

    #[cfg(feature = "esplora")]
    #[test]
    fn consignment_history_reads_the_ascii_armored_form() {
        // What a wallet exports to be pasted somewhere is the armored text, not the bytes.
        let armored = RgbTransfer::load(TRANSFER_NIA).unwrap().to_string();
        assert!(
            armored.starts_with("-----BEGIN RGB CONSIGNMENT-----"),
            "{armored:.40}"
        );

        let from_armor = consignment_history(armored.as_bytes(), BitcoinNetwork::Regtest).unwrap();
        let from_bytes = consignment_history(TRANSFER_NIA, BitcoinNetwork::Regtest).unwrap();
        assert!(from_armor.valid);
        assert_eq!(
            serde_json::to_string(&from_armor).unwrap(),
            serde_json::to_string(&from_bytes).unwrap(),
            "the same consignment read two ways is not the same consignment"
        );
    }

    #[cfg(feature = "esplora")]
    #[test]
    fn every_asset_schema_is_read_against_its_own_type_system() {
        fn check<I: IssuerWrapper>(expected: &str) {
            let schema = ReadableSchema::of(I::schema().schema_id())
                .unwrap_or_else(|| panic!("{expected} is not among the schemas that can be read"));
            assert_eq!(schema.name(), expected);
            // 🚨 The type system has to be the one that schema issues under. A copy-paste in
            // the dispatch would validate one schema's consignments against another's types,
            // and the failure would read as a corrupt file rather than as a mistake here.
            assert_eq!(
                schema.types(),
                I::types(),
                "{expected} is read against another schema's types"
            );
        }
        check::<NonInflatableAsset>("NIA");
        check::<CollectibleFungibleAsset>("CFA");
        check::<UniqueDigitalAsset>("UDA");
        check::<InflatableFungibleAsset>("IFA");
        check::<PermissionedFungibleAsset>("PFA");
    }

    #[cfg(feature = "esplora")]
    #[test]
    fn a_structured_assignment_is_read_back_as_the_allocation_it_holds() {
        // A UDA's owned state is a token index and a fraction of it, carried as opaque bytes.
        // There is no UDA consignment to hand this file, so the conversion is pinned against
        // the one the library uses to write that state in the first place.
        let allocation = Allocation::with(7u32, 42u64);
        let written = rgbstd::RevealedData::from(allocation);
        let read =
            Allocation::from_strict_serialized(written.into()).expect("state is an allocation");
        assert_eq!(u32::from(read.token_index()), 7);
        assert_eq!(u64::from(read.fraction()), 42);
    }

    #[cfg(feature = "esplora")]
    #[test]
    fn structured_state_that_is_not_an_allocation_is_reported_without_a_quantity() {
        // 🚨 The From<RevealedData> conversion expects and would abort the process here.
        let nonsense =
            rgbstd::RevealedData::new(amplify::confinement::SmallBlob::from_checked(vec![0xff; 3]));
        assert!(Allocation::from_strict_serialized(nonsense.into()).is_err());
    }

    #[cfg(feature = "esplora")]
    #[test]
    fn consignment_history_refuses_a_schema_it_cannot_read() {
        // The type system comes from the schema, so a schema this build does not have is not
        // something to read anyway: there is nothing to check the contract's state against.
        assert!(ReadableSchema::of(rgbstd::SchemaId::from_array([0u8; 32])).is_none());
    }

    #[test]
    fn indexer_protocol_display() {
        assert_eq!(IndexerProtocol::Esplora.to_string(), "Esplora");
    }
}
