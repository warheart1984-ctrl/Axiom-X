//! Wolf CoG OS Governance Types for Axiom-X Kernel
//!
//! Constitutional governance types that integrate the kernel with
//! Wolf CoG OS's governance stack (authorityLedger, intentLedger,
//! executionMemory, LIRL, LawPulse, MRI Instrument).

use core::fmt;
use core::time::Duration;
use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::collections::BTreeMap;

/// Kernel actor representing the kernel as a constitutional entity
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KernelActor {
    pub actor_id: String,
    pub authority_level: AuthorityLevel,
    pub capabilities: CapabilitySet,
}

/// Authority level of an actor
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuthorityLevel {
    Root,
    System,
    User,
    Restricted,
}

/// Set of capabilities an actor possesses
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct CapabilitySet {
    pub capabilities: alloc::collections::BTreeSet<String>,
}

impl CapabilitySet {
    pub fn new() -> Self {
        Self { capabilities: alloc::collections::BTreeSet::new() }
    }

    pub fn with_capability(mut self, cap: &str) -> Self {
        self.capabilities.insert(cap.to_string());
        self
    }

    pub fn has(&self, cap: &str) -> bool {
        self.capabilities.contains(cap)
    }
}

/// Process record representing a governed process
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProcessRecord {
    pub pid: u64,
    pub arena_id: String,
    pub authority: String,
    pub intent: String,
    pub memory_handle: String,
    pub receipts: alloc::vec::Vec<String>,
    pub state: ProcessState,
}

/// Process execution state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProcessState {
    Created,
    Runnable,
    Running,
    Blocked,
    Terminated,
}

/// Kernel event representing a constitutional decision
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KernelEvent {
    pub event_id: String,
    pub timestamp: u64, // nanoseconds since boot
    pub actor: ActorRef,
    pub intent: String,
    pub evidence: alloc::vec::Vec<String>,
    pub metadata: alloc::collections::BTreeMap<String, alloc::string::String>,
    pub syscall: Option<SyscallContext>,
}

/// Reference to an actor (kernel or process)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ActorRef {
    Kernel(KernelActor),
    Process(ProcessRecord),
}

/// Enforcement result from constitutional validation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnforcementResult {
    pub allowed: bool,
    pub reason: Option<String>,
    pub modified_event: Option<KernelEvent>,
}

impl EnforcementResult {
    pub fn allowed() -> Self {
        Self { allowed: true, reason: None, modified_event: None }
    }

    pub fn denied(reason: &str) -> Self {
        Self { allowed: false, reason: Some(reason.to_string()), modified_event: None }
    }
}

/// Syscall context for governance
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SyscallContext {
    pub sysno: u64,
    pub args: [u64; 6],
    pub return_type: ReturnType,
}

/// Syscall return type for governance
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReturnType {
    Void,
    I64,
    U64,
    Bool,
    Ptr,
}

/// Syscall event for governance tracking
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SyscallEvent {
    pub event_id: String,
    pub timestamp: u64,
    pub actor: ActorRef,
    pub syscall: SyscallContext,
    pub authority_ref: String,
    pub intent_ref: String,
    pub memory_ref: String,
    pub lirl_receipt: Option<String>,
    pub metadata: alloc::collections::BTreeMap<String, alloc::string::String>,
}

/// Kernel governance configuration
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceConfig {
    pub enable_enforcement: bool,
    pub enable_lirl: bool,
    pub enable_memory_logging: bool,
    pub enable_mri: bool,
    pub strict_mode: bool,
}

impl Default for GovernanceConfig {
    fn default() -> Self {
        Self {
            enable_enforcement: true,
            enable_lirl: true,
            enable_memory_logging: true,
            enable_mri: true,
            strict_mode: false,
        }
    }
}

/// Convert SyscallEvent to KernelEvent for emitter
impl From<SyscallEvent> for KernelEvent {
    fn from(syscall: SyscallEvent) -> Self {
        KernelEvent {
            event_id: syscall.event_id,
            timestamp: syscall.timestamp,
            actor: syscall.actor,
            intent: syscall.intent_ref,
            evidence: alloc::vec::Vec::new(),
            metadata: syscall.metadata,
            syscall: Some(syscall.syscall),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_set() {
        let caps = CapabilitySet::new()
            .with_capability("syscall")
            .with_capability("memory");
        assert!(caps.has("syscall"));
        assert!(caps.has("memory"));
        assert!(!caps.has("network"));
    }

    #[test]
    fn test_enforcement_result() {
        let allowed = EnforcementResult::allowed();
        assert!(allowed.allowed);
        assert!(allowed.reason.is_none());

        let denied = EnforcementResult::denied("access denied");
        assert!(!denied.allowed);
        assert_eq!(denied.reason, Some("access denied".to_string()));
    }

    #[test]
    fn test_syscall_context() {
        let ctx = SyscallContext {
            sysno: 1,
            args: [1, 2, 3, 0, 0, 0],
            return_type: ReturnType::I64,
        };
        assert!((ctx.sysno == 1) && (ctx.return_type == ReturnType::I64));
    }
}