//! Wolf CoG OS Governance Interfaces
//!
//! Constitutional contracts that define the governance boundary between
//! the kernel and the Wolf CoG OS governance stack.

use core::fmt;
use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::collections::BTreeMap;

use crate::governance_types::{
    KernelEvent, ProcessRecord, SyscallEvent, SyscallContext,
    EnforcementResult, KernelActor,
    ReturnType, CapabilitySet, AuthorityLevel,
    GovernanceConfig,
};

/// Governed kernel emitter - records all kernel decisions
pub trait GovernedKernelEmitter: fmt::Debug + Send + Sync {
    /// Emit a kernel event to the governance layer
    fn emit(&mut self, event: KernelEvent);

    /// Emit a syscall event specifically
    fn emit_syscall(&mut self, event: crate::governance_types::SyscallEvent);

    /// Flush pending events
    fn flush(&mut self);
}

/// LIRL (Ledger of Intent and Resource Log) kernel bridge
pub trait LirlKernelBridge: fmt::Debug + Send + Sync {
    /// Register a new process in LIRL
    fn register_process(&mut self, proc: ProcessRecord) -> String;

    /// Update an existing process in LIRL
    fn update_process(&mut self, proc: ProcessRecord, delta: ProcessDelta) -> String;

    /// Finalize a process in LIRL
    fn finalize_process(&mut self, proc: ProcessRecord) -> String;

    /// Issue a receipt for a syscall
    fn issue_syscall_receipt(&mut self, event: &crate::governance_types::SyscallEvent) -> String;
}

/// Process delta for LIRL updates
#[derive(Debug, Clone, Default)]
pub struct ProcessDelta {
    pub arena_id: Option<String>,
    pub authority: Option<String>,
    pub intent: Option<String>,
    pub memory_handle: Option<String>,
    pub state: Option<crate::governance_types::ProcessState>,
}

/// MRI (Mission Readiness Instrument) kernel feed
pub trait MriKernelFeed: fmt::Debug + Send + Sync {
    /// Push a trajectory sample to MRI
    fn push_trajectory_sample(&mut self, sample: TrajectorySample);

    /// Push a confidence tensor to MRI
    fn push_confidence_tensor(&mut self, tensor: ConfidenceTensor);
}

/// Trajectory sample for MRI
#[derive(Debug, Clone)]
pub struct TrajectorySample {
    pub timestamp: u64,
    pub pid: u64,
    pub cpu_usage: f64,
    pub memory_usage: u64,
    pub syscall_rate: f64,
    pub latency_ns: u64,
}

/// Confidence tensor for MRI
#[derive(Debug, Clone)]
pub struct ConfidenceTensor {
    pub dimensions: [u32; 4],
    pub data: alloc::vec::Vec<f32>,
}

/// Constitutional kernel enforcer
pub trait ConstitutionalKernelEnforcer: fmt::Debug + Send + Sync {
    /// Validate an event against constitutional rules
    fn validate(&self, event: &crate::governance_types::KernelEvent) -> crate::governance_types::EnforcementResult;

    /// Enforce the event (modify, block, or allow)
    fn enforce(&mut self, event: &mut crate::governance_types::KernelEvent);
}

/// Governed kernel interface - the unified governance surface
pub trait GovernedKernelInterface: fmt::Debug + Send + Sync {
    /// Get the event emitter
    fn emitter(&mut self) -> &mut dyn GovernedKernelEmitter;

    /// Get the LIRL bridge
    fn lirl(&mut self) -> &mut dyn LirlKernelBridge;

    /// Get the MRI feed
    fn mri(&mut self) -> &mut dyn MriKernelFeed;

    /// Get the constitutional enforcer
    fn enforcer(&mut self) -> &mut dyn ConstitutionalKernelEnforcer;

    /// Get the governance configuration
    fn config(&self) -> &crate::governance_types::GovernanceConfig;

    /// Register a kernel actor
    fn register_kernel_actor(&mut self, actor: crate::governance_types::KernelActor);

    /// Register a process
    fn register_process(&mut self, proc: crate::governance_types::ProcessRecord);
}

/// Governed syscall wrapper - enforces constitutional checks
pub trait GovernedSyscall: fmt::Debug + Send + Sync {
    /// Execute a syscall with full governance
    fn execute(
        &mut self,
        event: crate::governance_types::SyscallEvent,
        handler: &mut dyn FnMut(),
    );
}

/// Syscall table entry for governance
pub struct SyscallTableEntry {
    pub name: &'static str,
    pub return_type: crate::governance_types::ReturnType,
    pub required_capability: Option<&'static str>,
    pub arena_restriction: Option<&'static str>,
}

/// Governance kernel registry
pub trait GovernanceRegistry: fmt::Debug + Send + Sync {
    /// Register a kernel actor
    fn register_kernel_actor(&mut self, actor: crate::governance_types::KernelActor);

    /// Register a process
    fn register_process(&mut self, proc: crate::governance_types::ProcessRecord);

    /// Get process by PID
    fn get_process(&self, pid: u64) -> Option<crate::governance_types::ProcessRecord>;

    /// Get all processes in an arena
    fn processes_in_arena(&self, arena: &str) -> alloc::vec::Vec<u64>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance_types::{EnforcementResult, SyscallContext, ReturnType};

    #[test]
    fn test_enforcement_result_allowed() {
        let result = crate::governance_types::EnforcementResult::allowed();
        assert!(result.allowed);
        assert!(result.reason.is_none());
    }

    #[test]
    fn test_enforcement_result_denied() {
        let result = crate::governance_types::EnforcementResult::denied("test");
        assert!(!result.allowed);
        assert_eq!(result.reason, Some("test".to_string()));
    }

    #[test]
    fn test_syscall_context() {
        let ctx = SyscallContext {
            sysno: 1,
            args: [1, 2, 3, 0, 0, 0],
            return_type: ReturnType::I64,
        };
        assert_eq!(ctx.sysno, 1);
        assert_eq!(ctx.return_type, ReturnType::I64);
    }
}