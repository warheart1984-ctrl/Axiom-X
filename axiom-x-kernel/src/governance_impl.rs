//! Wolf CoG OS Governance Implementations
//!
//! Default implementations of the governance interfaces.

use core::fmt;
use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use spin::Mutex;
use crate::governance_types::{
    KernelEvent, ProcessRecord, SyscallEvent, SyscallContext,
    EnforcementResult, KernelActor,
    ReturnType, CapabilitySet, AuthorityLevel,
    GovernanceConfig,
};
use crate::governance_interfaces::{
    GovernedKernelEmitter, LirlKernelBridge, MriKernelFeed, ConstitutionalKernelEnforcer,
    GovernedSyscall, GovernanceRegistry, ProcessDelta, TrajectorySample, ConfidenceTensor,
    SyscallTableEntry,
};

/// Default kernel event emitter
#[derive(Debug, Default)]
pub struct DefaultKernelEmitter {
    events: Mutex<alloc::vec::Vec<KernelEvent>>,
}

impl DefaultKernelEmitter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_events(&self) -> alloc::vec::Vec<KernelEvent> {
        self.events.lock().clone()
    }

    pub fn clear(&mut self) {
        self.events.lock().clear();
    }
}

impl crate::governance_interfaces::GovernedKernelEmitter for DefaultKernelEmitter {
    fn emit(&mut self, event: KernelEvent) {
        self.events.lock().push(event);
    }

    fn emit_syscall(&mut self, event: crate::governance_types::SyscallEvent) {
        self.events.lock().push(event.into());
    }

    fn flush(&mut self) {
        // In a real implementation, this would flush to persistent storage
        // or send to the governance daemon
    }
}

/// Default LIRL kernel bridge
#[derive(Debug, Default)]
pub struct DefaultLirlBridge {
    receipts: Mutex<alloc::collections::BTreeMap<String, String>>,
    counter: Mutex<u64>,
}

impl DefaultLirlBridge {
    pub fn new() -> Self {
        Self::default()
    }
}

impl crate::governance_interfaces::LirlKernelBridge for DefaultLirlBridge {
    fn register_process(&mut self, proc: crate::governance_types::ProcessRecord) -> String {
        let mut counter = self.counter.lock();
        *counter += 1;
        let receipt_id = format!("receipt-{}", *counter);
        self.receipts.lock().insert(proc.pid.to_string(), receipt_id.clone());
        receipt_id
    }

    fn update_process(&mut self, proc: crate::governance_types::ProcessRecord, delta: crate::governance_interfaces::ProcessDelta) -> String {
        let mut counter = self.counter.lock();
        *counter += 1;
        let receipt_id = format!("receipt-update-{}", *counter);
        self.receipts.lock().insert(proc.pid.to_string(), receipt_id.clone());
        receipt_id
    }

    fn finalize_process(&mut self, proc: crate::governance_types::ProcessRecord) -> String {
        let mut counter = self.counter.lock();
        *counter += 1;
        let receipt_id = format!("receipt-final-{}", *counter);
        self.receipts.lock().remove(&proc.pid.to_string());
        receipt_id
    }

    fn issue_syscall_receipt(&mut self, event: &crate::governance_types::SyscallEvent) -> String {
        let mut counter = self.counter.lock();
        *counter += 1;
        let receipt_id = format!("receipt-syscall-{}", *counter);
        receipt_id
    }
}

/// Default MRI kernel feed
#[derive(Debug, Default)]
pub struct DefaultMriFeed {
    samples: Mutex<alloc::vec::Vec<crate::governance_interfaces::TrajectorySample>>,
    tensors: Mutex<alloc::vec::Vec<crate::governance_interfaces::ConfidenceTensor>>,
}

impl DefaultMriFeed {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_samples(&self) -> alloc::vec::Vec<crate::governance_interfaces::TrajectorySample> {
        self.samples.lock().clone()
    }

    pub fn get_tensors(&self) -> alloc::vec::Vec<crate::governance_interfaces::ConfidenceTensor> {
        self.tensors.lock().clone()
    }
}

impl crate::governance_interfaces::MriKernelFeed for DefaultMriFeed {
    fn push_trajectory_sample(&mut self, sample: crate::governance_interfaces::TrajectorySample) {
        self.samples.lock().push(sample);
    }

    fn push_confidence_tensor(&mut self, tensor: crate::governance_interfaces::ConfidenceTensor) {
        self.tensors.lock().push(tensor);
    }
}

/// Default constitutional kernel enforcer
#[derive(Debug, Default)]
pub struct DefaultConstitutionalEnforcer {
    config: crate::governance_types::GovernanceConfig,
}

impl DefaultConstitutionalEnforcer {
    pub fn new(config: crate::governance_types::GovernanceConfig) -> Self {
        Self { config }
    }
}

impl crate::governance_interfaces::ConstitutionalKernelEnforcer for DefaultConstitutionalEnforcer {
    fn validate(&self, event: &crate::governance_types::KernelEvent) -> crate::governance_types::EnforcementResult {
        if !self.config.enable_enforcement {
            return crate::governance_types::EnforcementResult::allowed();
        }

        // Check if event has required fields
        if event.event_id.is_empty() {
            return crate::governance_types::EnforcementResult::denied("empty event_id");
        }

        if event.evidence.is_empty() && self.config.strict_mode {
            return crate::governance_types::EnforcementResult::denied("no evidence provided");
        }

        crate::governance_types::EnforcementResult::allowed()
    }

    fn enforce(&mut self, event: &mut crate::governance_types::KernelEvent) {
        // In a real implementation, this would:
        // 1. Log the enforcement decision
        // 2. Potentially modify the event
        // 3. Trigger any side effects (alerts, metrics, etc.)
        
        // For now, just log
        crate::serial_puts(&alloc::format!("[ENFORCE] Event {} allowed\n", event.event_id));
    }
}

/// Default governed syscall wrapper
#[derive(Debug, Default)]
pub struct DefaultGovernedSyscall {
    enforcer: DefaultConstitutionalEnforcer,
    // Would hold references to emitter, LIRL, MRI in real impl
}

impl DefaultGovernedSyscall {
    pub fn new(config: crate::governance_types::GovernanceConfig) -> Self {
        Self {
            enforcer: DefaultConstitutionalEnforcer::new(config),
        }
    }
}

impl crate::governance_interfaces::GovernedSyscall for DefaultGovernedSyscall {
    fn execute(
        &mut self,
        event: crate::governance_types::SyscallEvent,
        handler: &mut dyn FnMut(),
    ) {
        // Validate - convert SyscallEvent to KernelEvent for enforcer
        let kernel_event: crate::governance_types::KernelEvent = event.into();
        let result = self.enforcer.validate(&kernel_event);
        if !result.allowed {
            // Log blocked syscall
            crate::serial_puts(&alloc::format!("[GOV] Blocked syscall: {}\n", kernel_event.event_id));
            return;
        }

        // Enforce
        let mut event_mut = kernel_event;
        self.enforcer.enforce(&mut event_mut);

        // Execute handler
        handler();
    }
}

/// Default governance registry
#[derive(Debug)]
pub struct DefaultGovernanceRegistry {
    processes: spin::Mutex<alloc::collections::BTreeMap<u64, crate::governance_types::ProcessRecord>>,
    kernel_actor: spin::Mutex<Option<crate::governance_types::KernelActor>>,
    emitter: DefaultKernelEmitter,
    lirl: DefaultLirlBridge,
    mri: DefaultMriFeed,
    enforcer: DefaultConstitutionalEnforcer,
}

impl DefaultGovernanceRegistry {
    pub fn new() -> Self {
        Self {
            processes: spin::Mutex::new(alloc::collections::BTreeMap::new()),
            kernel_actor: spin::Mutex::new(None),
            emitter: DefaultKernelEmitter::new(),
            lirl: DefaultLirlBridge::new(),
            mri: DefaultMriFeed::new(),
            enforcer: DefaultConstitutionalEnforcer::new(crate::governance_types::GovernanceConfig::default()),
        }
    }
}

impl crate::governance_interfaces::GovernanceRegistry for DefaultGovernanceRegistry {
    fn register_kernel_actor(&mut self, actor: crate::governance_types::KernelActor) {
        *self.kernel_actor.lock() = Some(actor);
    }

    fn register_process(&mut self, proc: crate::governance_types::ProcessRecord) {
        self.processes.lock().insert(proc.pid, proc);
    }

    fn get_process(&self, pid: u64) -> Option<crate::governance_types::ProcessRecord> {
        self.processes.lock().get(&pid).cloned()
    }

    fn processes_in_arena(&self, arena: &str) -> alloc::vec::Vec<u64> {
        self.processes.lock()
            .iter()
            .filter(|(_, proc)| proc.arena_id == arena)
            .map(|(pid, _)| *pid)
            .collect()
    }
}

impl crate::governance_interfaces::GovernedKernelEmitter for DefaultGovernanceRegistry {
    fn emit(&mut self, event: crate::governance_types::KernelEvent) {
        self.emitter.emit(event);
    }

    fn emit_syscall(&mut self, event: crate::governance_types::SyscallEvent) {
        self.emitter.emit_syscall(event);
    }

    fn flush(&mut self) {
        self.emitter.flush();
    }
}

impl crate::governance_interfaces::LirlKernelBridge for DefaultGovernanceRegistry {
    fn register_process(&mut self, proc: crate::governance_types::ProcessRecord) -> String {
        self.lirl.register_process(proc)
    }

    fn update_process(&mut self, proc: crate::governance_types::ProcessRecord, delta: crate::governance_interfaces::ProcessDelta) -> String {
        self.lirl.update_process(proc, delta)
    }

    fn finalize_process(&mut self, proc: crate::governance_types::ProcessRecord) -> String {
        self.lirl.finalize_process(proc)
    }

    fn issue_syscall_receipt(&mut self, event: &crate::governance_types::SyscallEvent) -> String {
        self.lirl.issue_syscall_receipt(event)
    }
}

impl crate::governance_interfaces::MriKernelFeed for DefaultGovernanceRegistry {
    fn push_trajectory_sample(&mut self, sample: crate::governance_interfaces::TrajectorySample) {
        self.mri.push_trajectory_sample(sample)
    }

    fn push_confidence_tensor(&mut self, tensor: crate::governance_interfaces::ConfidenceTensor) {
        self.mri.push_confidence_tensor(tensor)
    }
}

impl crate::governance_interfaces::ConstitutionalKernelEnforcer for DefaultGovernanceRegistry {
    fn validate(&self, event: &crate::governance_types::KernelEvent) -> crate::governance_types::EnforcementResult {
        self.enforcer.validate(event)
    }

    fn enforce(&mut self, event: &mut crate::governance_types::KernelEvent) {
        self.enforcer.enforce(event)
    }
}

impl crate::governance_interfaces::GovernedKernelInterface for DefaultGovernanceRegistry {
    fn emitter(&mut self) -> &mut dyn crate::governance_interfaces::GovernedKernelEmitter {
        self
    }

    fn lirl(&mut self) -> &mut dyn crate::governance_interfaces::LirlKernelBridge {
        self
    }

    fn mri(&mut self) -> &mut dyn crate::governance_interfaces::MriKernelFeed {
        self
    }

    fn enforcer(&mut self) -> &mut dyn crate::governance_interfaces::ConstitutionalKernelEnforcer {
        self
    }

    fn config(&self) -> &crate::governance_types::GovernanceConfig {
        &self.enforcer.config
    }

    fn register_kernel_actor(&mut self, actor: crate::governance_types::KernelActor) {
        crate::governance_interfaces::GovernanceRegistry::register_kernel_actor(self, actor)
    }

    fn register_process(&mut self, proc: crate::governance_types::ProcessRecord) {
        crate::governance_interfaces::GovernanceRegistry::register_process(self, proc)
    }
}

/// Default syscall table
pub static SYSCALL_TABLE: &[(u64, crate::governance_interfaces::SyscallTableEntry)] = &[
    (0, crate::governance_interfaces::SyscallTableEntry { name: "read", return_type: crate::governance_types::ReturnType::I64, required_capability: Some("syscall"), arena_restriction: None }),
    (1, crate::governance_interfaces::SyscallTableEntry { name: "write", return_type: crate::governance_types::ReturnType::I64, required_capability: Some("syscall"), arena_restriction: None }),
    (2, crate::governance_interfaces::SyscallTableEntry { name: "open", return_type: crate::governance_types::ReturnType::I64, required_capability: Some("syscall"), arena_restriction: None }),
    (3, crate::governance_interfaces::SyscallTableEntry { name: "close", return_type: crate::governance_types::ReturnType::I64, required_capability: Some("syscall"), arena_restriction: None }),
    (9, crate::governance_interfaces::SyscallTableEntry { name: "mmap", return_type: crate::governance_types::ReturnType::I64, required_capability: Some("memory"), arena_restriction: None }),
    (11, crate::governance_interfaces::SyscallTableEntry { name: "munmap", return_type: crate::governance_types::ReturnType::I64, required_capability: Some("memory"), arena_restriction: None }),
    (12, crate::governance_interfaces::SyscallTableEntry { name: "brk", return_type: crate::governance_types::ReturnType::I64, required_capability: Some("memory"), arena_restriction: None }),
    (57, crate::governance_interfaces::SyscallTableEntry { name: "fork", return_type: crate::governance_types::ReturnType::I64, required_capability: Some("process"), arena_restriction: None }),
    (59, crate::governance_interfaces::SyscallTableEntry { name: "execve", return_type: crate::governance_types::ReturnType::I64, required_capability: Some("process"), arena_restriction: None }),
    (60, crate::governance_interfaces::SyscallTableEntry { name: "exit", return_type: crate::governance_types::ReturnType::Void, required_capability: Some("process"), arena_restriction: None }),
    (500, crate::governance_interfaces::SyscallTableEntry { name: "ax_sched_profile", return_type: crate::governance_types::ReturnType::I64, required_capability: Some("scheduler"), arena_restriction: None }),
    (501, crate::governance_interfaces::SyscallTableEntry { name: "ax_get_evidence", return_type: crate::governance_types::ReturnType::I64, required_capability: Some("evidence"), arena_restriction: None }),
    (502, crate::governance_interfaces::SyscallTableEntry { name: "ax_replay_token", return_type: crate::governance_types::ReturnType::I64, required_capability: Some("evidence"), arena_restriction: None }),
    (503, crate::governance_interfaces::SyscallTableEntry { name: "ax_alloc_res", return_type: crate::governance_types::ReturnType::I64, required_capability: Some("resource"), arena_restriction: None }),
];

/// Default governance configuration
pub fn default_governance_config() -> crate::governance_types::GovernanceConfig {
    crate::governance_types::GovernanceConfig::default()
}

/// Default governed syscall wrapper
#[derive(Debug)]
pub struct DefaultGovernedSyscallWrapper {
    enforcer: DefaultConstitutionalEnforcer,
}

impl DefaultGovernedSyscallWrapper {
    pub fn new(config: crate::governance_types::GovernanceConfig) -> Self {
        Self {
            enforcer: DefaultConstitutionalEnforcer::new(config),
        }
    }
}

impl crate::governance_interfaces::GovernedSyscall for DefaultGovernedSyscallWrapper {
    fn execute(
        &mut self,
        event: crate::governance_types::SyscallEvent,
        handler: &mut dyn FnMut(),
    ) {
        // Convert SyscallEvent to KernelEvent for enforcer
        let sysno = event.syscall.sysno;
        let kernel_event: crate::governance_types::KernelEvent = event.into();
        let result = self.enforcer.validate(&kernel_event);
        if !result.allowed {
            crate::serial_puts(&alloc::format!("[GOV] Blocked syscall: {}\n", sysno));
            return;
        }

        let mut event_mut = kernel_event;
        // In real impl, enforcer would modify event
        crate::serial_puts(&alloc::format!("[GOV] Allowed syscall: {}\n", sysno));
        
        handler();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance_types::{EnforcementResult, SyscallContext, ReturnType};

    #[test]
    fn test_default_emitter() {
        let mut emitter = DefaultKernelEmitter::new();
        let event = crate::governance_types::KernelEvent {
            event_id: "test".to_string(),
            timestamp: 0,
            actor: crate::governance_types::ActorRef::Kernel(crate::governance_types::KernelActor {
                actor_id: "kernel".to_string(),
                authority_level: crate::governance_types::AuthorityLevel::Root,
                capabilities: crate::governance_types::CapabilitySet::new(),
            }),
            intent: "test".to_string(),
            evidence: Vec::new(),
            metadata: alloc::collections::BTreeMap::new(),
            syscall: None,
        };
        
        emitter.emit(event);
        assert_eq!(emitter.get_events().len(), 1);
    }

    #[test]
    fn test_default_lirl_bridge() {
        let mut bridge = DefaultLirlBridge::new();
        let proc = crate::governance_types::ProcessRecord {
            pid: 1,
            arena_id: "test".to_string(),
            authority: "root".to_string(),
            intent: "test".to_string(),
            memory_handle: "mem-1".to_string(),
            receipts: Vec::new(),
            state: crate::governance_types::ProcessState::Runnable,
        };
        
        let receipt = bridge.register_process(proc);
        assert!(!receipt.is_empty());
    }

    #[test]
    fn test_default_enforcer() {
        let enforcer = DefaultConstitutionalEnforcer::new(crate::governance_types::GovernanceConfig::default());
        let event = crate::governance_types::KernelEvent {
            event_id: "test".to_string(),
            timestamp: 0,
            actor: crate::governance_types::ActorRef::Kernel(crate::governance_types::KernelActor {
                actor_id: "kernel".to_string(),
                authority_level: crate::governance_types::AuthorityLevel::Root,
                capabilities: crate::governance_types::CapabilitySet::new(),
            }),
            intent: "test".to_string(),
            evidence: Vec::new(),
            metadata: alloc::collections::BTreeMap::new(),
            syscall: None,
        };
        
        let result = enforcer.validate(&event);
        assert!(result.allowed);
    }

    #[test]
    fn test_default_governed_syscall() {
        let mut wrapper = DefaultGovernedSyscallWrapper::new(crate::governance_types::GovernanceConfig::default());
        let event = crate::governance_types::SyscallEvent {
            event_id: "test".to_string(),
            timestamp: 0,
            actor: crate::governance_types::ActorRef::Kernel(crate::governance_types::KernelActor {
                actor_id: "kernel".to_string(),
                authority_level: crate::governance_types::AuthorityLevel::Root,
                capabilities: crate::governance_types::CapabilitySet::new(),
            }),
            syscall: crate::governance_types::SyscallContext {
                sysno: 1,
                args: [0; 6],
                return_type: crate::governance_types::ReturnType::I64,
            },
            authority_ref: "root".to_string(),
            intent_ref: "test".to_string(),
            memory_ref: "mem-1".to_string(),
            lirl_receipt: None,
            metadata: alloc::collections::BTreeMap::new(),
        };
        
        let mut called = false;
        DefaultGovernedSyscallWrapper::new(crate::governance_types::GovernanceConfig::default())
            .execute(event, &mut || { called = true; });
        assert!(called);
    }
}