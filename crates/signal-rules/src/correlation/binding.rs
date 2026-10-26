//! Internal common inventory/limits, borrowing the real detector enrollment.
//! Runtime sources are never converted into authentication configuration.
use super::*;
use crate::state_journal::Config as JournalConfig;

pub(super) struct SourceView {
    pub stream: Uuid,
    pub binding: [u8; 32],
    pub config_revision: String,
}
pub(super) struct Limits {
    pub sources: Vec<SourceView>,
    pub lateness_ms: i64,
    pub correlation_ms: i64,
    pub extra_lookback_ms: i64,
    pub max_events: usize,
    pub max_keys: usize,
    pub max_episodes: usize,
    pub max_state_bytes: usize,
    pub authority_keys_sha256: [u8; 32],
}
enum Detector<'a> {
    Authentication(&'a Binding),
    Runtime(&'a d14::RuntimeBinding),
}
pub(super) struct BindingView<'a> {
    pub config: Limits,
    pub digest: [u8; 32],
    detector: Detector<'a>,
}
impl<'a> BindingView<'a> {
    pub fn authentication(b: &'a Binding) -> Self {
        let c = &b.config;
        Self {
            config: Limits {
                sources: c
                    .sources
                    .iter()
                    .map(|s| SourceView {
                        stream: s.stream,
                        binding: s.binding,
                        config_revision: s.config_revision.clone(),
                    })
                    .collect(),
                lateness_ms: c.lateness_ms,
                correlation_ms: c.correlation_ms,
                extra_lookback_ms: c.window_ms,
                max_events: c.max_events,
                max_keys: c.max_keys,
                max_episodes: c.max_episodes,
                max_state_bytes: c.max_state_bytes,
                authority_keys_sha256: c.authority_keys_sha256,
            },
            digest: b.digest,
            detector: Detector::Authentication(b),
        }
    }
    pub fn runtime(b: &'a d14::RuntimeBinding) -> Self {
        let c = &b.config;
        Self {
            config: Limits {
                sources: c
                    .sources
                    .iter()
                    .map(|s| SourceView {
                        stream: s.stream,
                        binding: s.binding,
                        config_revision: s.config_revision.clone(),
                    })
                    .collect(),
                lateness_ms: c.lateness_ms,
                correlation_ms: c.correlation_ms,
                extra_lookback_ms: 0,
                max_events: c.max_events,
                max_keys: c.max_keys,
                max_episodes: c.max_episodes,
                max_state_bytes: c.max_state_bytes,
                authority_keys_sha256: c.authority_keys_sha256,
            },
            digest: b.digest,
            detector: Detector::Runtime(b),
        }
    }
    pub fn version(&self) -> u16 {
        match self.detector {
            Detector::Authentication(_) => 1,
            Detector::Runtime(_) => 2,
        }
    }
    /// Explicit bridge for authentication-specific operations during extraction;
    /// a runtime inventory cannot accidentally be interpreted as D11.
    pub fn authentication_binding(&self) -> Result<&'a Binding, Error> {
        match self.detector {
            Detector::Authentication(b) => Ok(b),
            Detector::Runtime(_) => Err(Error::Invalid),
        }
    }
    pub fn runtime_binding(&self) -> Option<&'a d14::RuntimeBinding> {
        match self.detector {
            Detector::Runtime(b) => Some(b),
            Detector::Authentication(_) => None,
        }
    }
    pub fn journal_config(&self) -> JournalConfig {
        let (partition, domain): (Uuid, &[u8]) = match self.detector {
            Detector::Authentication(b) => (
                b.config.partition,
                b"PLATFORM::SIGNAL/correlation/sources/v1\0",
            ),
            Detector::Runtime(b) => (
                b.config.partition,
                b"PLATFORM::SIGNAL/correlation/D14-sources/v2\0",
            ),
        };
        JournalConfig {
            schema_version: 1,
            source_stream: partition,
            source_binding: hash(domain, &self.digest),
            enrollment_binding: self.digest,
            max_record_bytes: 32 * 1024 * 1024,
            max_state_bytes: self.config.max_state_bytes,
            max_outputs: self.config.max_episodes,
            max_output_bytes: 65536,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn runtime_inventory_contains_only_runtime_positions_and_no_authentication_config()
    -> Result<(), Error> {
        let c = RuleContext::new(std::time::Duration::from_secs(1));
        let source = d14::RuntimeSource {
            stream: Uuid::from_u128(1),
            binding: [1; 32],
            config_revision: "source".into(),
            source_type: "runtime".into(),
            source_name: "fixture".into(),
            host: "host".into(),
            metadata_config_sha256: [2; 32],
            audit_arch: 0xc000003e,
            reads: true,
            connects: true,
        };
        let authorities = [d14::Role::Asset, d14::Role::Destination]
            .into_iter()
            .enumerate()
            .map(|(i, role)| d14::PolicyAuthority {
                id: Uuid::from_u128(100 + i as u128),
                binding: [10 + i as u8; 32],
                source_type: "policy".into(),
                source_name: format!("policy-{i}"),
                account: None,
                resource: None,
                config_revision: "source".into(),
                authority_keys_sha256: [3; 32],
                role,
                policy_revision: "policy".into(),
                policy_config_sha256: [4; 32],
            })
            .collect();
        let b = d14::RuntimeBinding::new(
            d14::RuntimeConfig {
                schema_version: 2,
                partition: Uuid::from_u128(2),
                revision: "revision".into(),
                title: "Runtime candidate".into(),
                severity: DetectionSeverity::High,
                authority_keys_sha256: [5; 32],
                sources: vec![source],
                policy_authorities: authorities,
                correlation_ms: 10,
                lateness_ms: 1,
                ttl_ms: 100,
                max_events: 8,
                max_keys: 8,
                max_episodes: 8,
                max_state_bytes: 4096,
            },
            &c,
        )?;
        let v = BindingView::runtime(&b);
        assert_eq!(v.version(), 2);
        assert!(v.authentication_binding().is_err());
        assert_eq!(v.config.sources.len(), 1);
        assert_eq!(v.config.sources[0].stream, Uuid::from_u128(1));
        let state = State::new_with(&v);
        assert_eq!(state.schema_version, 2);
        assert_eq!(state.positions, vec![(Uuid::from_u128(1), 0)]);
        assert_eq!(b.journal_config().enrollment_binding, b.digest);
        Ok(())
    }
}
