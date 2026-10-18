//! Capability - The authority algebra
//!
//! Defines capabilities, rights, constraints, and the capability algebra.

#![cfg_attr(not(feature = "std"), no_std)]


use core::fmt;
use heapless::Vec as HeaplessVec;
use spin::Mutex;

use axiom_x_principal::{Principal, AuthorityClass, UNDELEGATABLE_AUTHORITIES};

/// Capability ID - unique identifier for a capability
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(transparent)]
pub struct CapabilityId(pub u64);

impl CapabilityId {
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    pub const fn next(&self) -> Self {
        CapabilityId(self.0.wrapping_add(1))
    }
}

impl core::fmt::Display for CapabilityId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "cap-{}", self.0)
    }
}

/// Rights - what operations are permitted (bitmask-based)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Rights(pub u64);

impl Rights {
    pub const fn new(bits: u64) -> Self {
        Self(bits)
    }

    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn all() -> Self {
        Self(u64::MAX)
    }

    pub const fn bits(&self) -> u64 {
        self.0
    }

    pub const fn has(&self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    pub const fn contains(&self, other: Self) -> bool {
        self.has(other)
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    pub const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    pub const fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }

pub const fn remove(&mut self, other: Self) {
        self.0 &= !other.0;
    }

    /// Memory rights
    pub const MAP: Self = Self(1 << 0);
    pub const READ: Self = Self(1 << 1);
    pub const WRITE: Self = Self(1 << 2);
    pub const EXECUTE: Self = Self(1 << 3);
    pub const UNMAP: Self = Self(1 << 4);

    // Memory allocation
    pub const ALLOC: Self = Self(1 << 5);
    pub const FREE: Self = Self(1 << 6);

    // IPC rights
    pub const SEND: Self = Self(1 << 7);
    pub const RECV: Self = Self(1 << 8);
    pub const CREATE_EP: Self = Self(1 << 9);

    // Process control
    pub const SPAWN: Self = Self(1 << 10);
    pub const KILL: Self = Self(1 << 11);
    pub const SCHEDULE: Self = Self(1 << 12);

    // Device rights
    pub const MAP_DEVICE: Self = Self(1 << 13);
    pub const PROGRAM_DEVICE: Self = Self(1 << 14);
    pub const RESET_DEVICE: Self = Self(1 << 15);

    // Capability management
    pub const DELEGATE: Self = Self(1 << 16);
    pub const REVOKE: Self = Self(1 << 17);
    pub const REVOKE_DESCENDANTS: Self = Self(1 << 18);

    // Governance
    pub const ATTEST: Self = Self(1 << 19);
    pub const POLICY: Self = Self(1 << 20);
    pub const EVIDENCE: Self = Self(1 << 21);

    // Scheduler
    pub const PRIORITY: Self = Self(1 << 22);
    pub const AFFINITY: Self = Self(1 << 23);

    // Hardware
    pub const MSI: Self = Self(1 << 24);
    pub const IO_PORT: Self = Self(1 << 25);
    pub const PHYS_MEM: Self = Self(1 << 26);

    // Composite rights
    pub const ALL: Self = Self(u64::MAX);
    pub const NONE: Self = Self(0);

    pub const MEMORY: Self = Self(Self::MAP.0 | Self::READ.0 | Self::WRITE.0 | Self::EXECUTE.0 | Self::UNMAP.0);
    pub const MEMORY_ALLOC: Self = Self(Self::ALLOC.0 | Self::FREE.0);
    pub const IPC: Self = Self(Self::SEND.0 | Self::RECV.0 | Self::CREATE_EP.0);
    pub const PROCESS: Self = Self(Self::SPAWN.0 | Self::KILL.0 | Self::SCHEDULE.0);
    pub const DEVICE: Self = Self(Self::MAP_DEVICE.0 | Self::PROGRAM_DEVICE.0 | Self::RESET_DEVICE.0);
    pub const CAP_MGMT: Self = Self(Self::DELEGATE.0 | Self::REVOKE.0 | Self::REVOKE_DESCENDANTS.0);
    pub const GOVERNANCE: Self = Self(Self::ATTEST.0 | Self::POLICY.0 | Self::EVIDENCE.0);
    pub const SCHEDULER: Self = Self(Self::PRIORITY.0 | Self::AFFINITY.0);
    pub const HARDWARE: Self = Self(Self::MSI.0 | Self::IO_PORT.0 | Self::PHYS_MEM.0);

    pub const WOLF_FULL: Self = Self::all();
    pub const SERVICE_BASE: Self = Self(Self::MAP.0 | Self::READ.0 | Self::WRITE.0 | Self::EXECUTE.0 | Self::SEND.0 | Self::RECV.0);
    pub const PROCESS_BASE: Self = Self(Self::MAP.0 | Self::READ.0 | Self::WRITE.0 | Self::EXECUTE.0 | Self::SEND.0 | Self::RECV.0 | Self::MAP.0 | Self::UNMAP.0);
}

impl Default for Rights {
    fn default() -> Self {
        Self::empty()
    }
}

impl core::ops::BitOr for Rights {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

impl core::ops::BitOrAssign for Rights {
    fn bitor_assign(&mut self, rhs: Self) {
        self.insert(rhs);
    }
}

impl core::ops::BitAnd for Rights {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        self.intersection(rhs)
    }
}

/// Constraints on capability usage
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Constraints {
    /// Maximum memory this capability can map/allocate (bytes)
    pub memory_limit: u64,

    /// Maximum CPU time per scheduling quantum (nanoseconds)
    pub cpu_quota_ns: u64,

    /// Allowed device command classes (bitmask)
    pub device_cmd_classes: u64,

    /// Allowed system call numbers (bitmask, up to 64 syscalls)
    pub syscall_mask: u64,

    /// Maximum number of child capabilities that can be delegated
    pub max_delegation_depth: u8,

    /// Allowed memory regions (physical address ranges)
    pub allowed_regions: HeaplessVec<Region, 8>,

    /// Allowed device command classes
    pub allowed_cmd_classes: HeaplessVec<u16, 16>,

    /// Maximum CPU cores this capability can schedule on
    pub max_cpu_cores: u8,

    /// Must match this policy hash
    pub policy_hash: u64,
}

impl Constraints {
    pub fn unrestricted() -> Self {
        Self::default()
    }

    pub fn memory_only(bytes: u64) -> Self {
        Self {
            memory_limit: bytes,
            ..Default::default()
        }
    }

    pub fn cpu_only(ns: u64) -> Self {
        Self {
            cpu_quota_ns: ns,
            ..Default::default()
        }
    }

    pub fn with_policy_hash(hash: u64) -> Self {
        Self {
            policy_hash: hash,
            ..Default::default()
        }
    }

    pub fn with_memory_limit(mut self, limit: u64) -> Self {
        self.memory_limit = limit;
        self
    }

    pub fn with_cpu_quota(mut self, ns: u64) -> Self {
        self.cpu_quota_ns = ns;
        self
    }

    pub fn with_device_cmd(mut self, class: u16) -> Self {
        self.allowed_cmd_classes.push(class).ok();
        self
    }

    pub fn with_syscall(mut self, sysno: u64) -> Self {
        if sysno < 64 {
            self.syscall_mask |= 1 << sysno;
        }
        self
    }
}

/// Memory region descriptor
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct Region {
    pub base: u64,
    pub length: u64,
    pub flags: u32,
    _reserved: u32,
}

impl Region {
    pub fn new(base: u64, length: u64, flags: u32) -> Self {
        Self { base, length, flags, _reserved: 0 }
    }

    pub fn end(&self) -> u64 {
        self.base + self.length
    }

    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.end()
    }

    pub fn overlaps(&self, other: &Region) -> bool {
        self.base < other.end() && other.base < self.end()
    }
}

/// Capability object - what the capability grants access to
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityObject {
    /// Memory region
    Memory(Region),
    /// IPC endpoint
    Endpoint(u64),
    /// Hardware device
    Device(u64),
    /// Process
    Process(u64),
    /// Service
    Service(u64),
    /// Scheduler
    Scheduler(u64),
    /// Governance
    Governance(u64),
}

impl CapabilityObject {
    pub fn memory(region: Region) -> Self {
        CapabilityObject::Memory(region)
    }

    pub fn endpoint(id: u64) -> Self {
        CapabilityObject::Endpoint(id)
    }

    pub fn device(id: u64) -> Self {
        CapabilityObject::Device(id)
    }

    pub fn process(id: u64) -> Self {
        CapabilityObject::Process(id)
    }

    pub fn service(id: u64) -> Self {
        CapabilityObject::Service(id)
    }
}

/// Capability token - the actual authority token
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    /// Unique capability ID
    pub id: CapabilityId,

    /// What this capability grants access to
    pub object: CapabilityObject,

    /// What operations are permitted
    pub rights: Rights,

    /// Constraints on usage
    pub constraints: Constraints,

    /// Authority class of this capability
    pub authority: u8, // AuthorityClass as u8

    /// Lineage information
    pub lineage: Lineage,

    /// Generation for revocation
    pub generation: u64,

    /// Root capability ID for revocation
    pub root_id: CapabilityId,
}

impl Capability {
    pub fn new(
        id: CapabilityId,
        object: CapabilityObject,
        rights: Rights,
        constraints: Constraints,
        authority: axiom_x_principal::AuthorityClass,
        parent: Option<&Capability>,
    ) -> Self {
        let lineage = Lineage::new(
            parent.map(|p| p.id),
            None, // issuer filled by caller
            parent.map(|p| p.generation + 1).unwrap_or(0),
        );

        Self {
            id,
            object,
            rights,
            constraints,
            authority: authority as u8,
            lineage,
            generation: 0,
            root_id: parent.map(|p| p.root_id).unwrap_or(CapabilityId(0)),
        }
    }

    pub fn root(
        id: CapabilityId,
        object: CapabilityObject,
        rights: Rights,
        constraints: Constraints,
        authority: axiom_x_principal::AuthorityClass,
    ) -> Self {
        let lineage = Lineage::root();
        Self {
            id,
            object,
            rights,
            constraints,
            authority: authority as u8,
            lineage,
            generation: 0,
            root_id: CapabilityId(0),
        }
    }

    pub fn has_right(&self, right: Rights) -> bool {
        self.rights.contains(right)
    }

    pub fn has_all_rights(&self, rights: Rights) -> bool {
        self.rights.contains(rights)
    }

    pub fn check_constraints(&self, memory_bytes: u64, cpu_ns: u64) -> bool {
        if memory_bytes > self.constraints.memory_limit {
            return false;
        }
        // Additional constraint checks would go here
        true
    }

    pub fn can_delegate(&self) -> bool {
        self.rights.contains(Rights::DELEGATE)
            && self.constraints.max_delegation_depth > 0
    }
}

/// Lineage information for capability provenance
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Lineage {
    /// Parent capability ID
    pub parent: Option<CapabilityId>,

    /// Who issued this capability
    pub issuer: Option<u64>, // Principal ID as u64

    /// Generation number (depth in delegation tree)
    pub generation: u64,

    /// Timestamp (nanoseconds since boot)
    pub timestamp_ns: u64,

    /// Delegation chain hash
    pub chain_hash: u64,
}

impl Lineage {
    pub fn new(parent: Option<CapabilityId>, issuer: Option<u64>, generation: u64) -> Self {
        Self {
            parent,
            issuer,
            generation,
            timestamp_ns: 0, // TODO: use actual timestamp
            chain_hash: 0,
        }
    }

    pub fn root() -> Self {
        Self {
            parent: None,
            issuer: None,
            generation: 0,
            timestamp_ns: 0,
            chain_hash: 0,
        }
    }

    pub fn derived(&self, issuer: u64) -> Self {
        Self {
            parent: None, // Will be set by delegation
            issuer: Some(issuer),
            generation: self.generation + 1,
            timestamp_ns: 0,
            chain_hash: 0,
        }
    }
}

/// Capability root for generational revocation
#[derive(Debug)]
pub struct CapabilityRoot {
    pub id: CapabilityId,
    pub generation: spin::Mutex<u64>,
}

impl CapabilityRoot {
    pub fn new(id: CapabilityId) -> Self {
        Self {
            id,
            generation: Mutex::new(0),
        }
    }

    pub fn current_generation(&self) -> u64 {
        *self.generation.lock()
    }

    pub fn revoke(&self) -> u64 {
        let mut gen = self.generation.lock();
        *gen = gen.wrapping_add(1);
        *gen
    }

    pub fn current_token(&self) -> CapabilityToken {
        CapabilityToken {
            root_id: CapabilityId(0), // Will be set by caller
            generation: *self.generation.lock(),
        }
    }
}

/// Capability token with generation for revocation checking
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityToken {
    pub root_id: CapabilityId,
    pub generation: u64,
}

impl CapabilityToken {
    pub fn new(root_id: CapabilityId, generation: u64) -> Self {
        Self { root_id, generation }
    }

    pub fn is_valid(&self, root: &CapabilityRoot) -> bool {
        root.current_generation() == self.generation
    }
}

/// Capability builder for ergonomic construction
pub struct CapabilityBuilder {
    id: Option<CapabilityId>,
    object: Option<CapabilityObject>,
    rights: Rights,
    constraints: Constraints,
    authority: axiom_x_principal::AuthorityClass,
    parent: Option<Capability>,
    issuer: Option<u64>,
}

impl CapabilityBuilder {
    pub fn new() -> Self {
        Self {
            id: None,
            object: None,
            rights: Rights::empty(),
            constraints: Constraints::default(),
            authority: axiom_x_principal::AuthorityClass::Process,
            parent: None,
            issuer: None,
        }
    }

    pub fn id(mut self, id: CapabilityId) -> Self {
        self.id = Some(id);
        self
    }

    pub fn object(mut self, object: CapabilityObject) -> Self {
        self.object = Some(object);
        self
    }

    pub fn rights(mut self, rights: Rights) -> Self {
        self.rights = rights;
        self
    }

    pub fn add_right(mut self, right: Rights) -> Self {
        self.rights |= right;
        self
    }

    pub fn constraints(mut self, constraints: Constraints) -> Self {
        self.constraints = constraints;
        self
    }

    pub fn authority(mut self, authority: axiom_x_principal::AuthorityClass) -> Self {
        self.authority = authority;
        self
    }

    pub fn parent(mut self, parent: &Capability) -> Self {
        self.parent = Some(parent.clone());
        self
    }

    pub fn issuer(mut self, issuer: u64) -> Self {
        self.issuer = Some(issuer);
        self
    }

    pub fn build(self, next_id: &mut u64) -> Capability {
        let id = self.id.unwrap_or_else(|| {
            let id = *next_id;
            *next_id = next_id.wrapping_add(1);
            CapabilityId(id)
        });

        let parent = self.parent.as_ref();
        let mut cap = Capability::new(
            id,
            self.object.expect("object required"),
            self.rights,
            self.constraints,
            self.authority,
            self.parent.as_ref(),
        );

        cap.lineage.issuer = self.issuer;
        if let Some(parent) = parent {
            cap.root_id = parent.root_id;
        }

        cap
    }
}

impl Default for CapabilityBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rights_operations() {
        let mut rights = Rights::empty();
        rights.insert(Rights::READ);
        rights.insert(Rights::WRITE);
        assert!(rights.contains(Rights::READ));
        assert!(rights.contains(Rights::WRITE));
        assert!(!rights.contains(Rights::EXECUTE));

        let mem = Rights::MEMORY;
        assert!(mem.contains(Rights::READ));
        assert!(mem.contains(Rights::WRITE));
        assert!(mem.contains(Rights::EXECUTE));
    }

    #[test]
    fn test_capability_builder() {
        let mut next_id = 1u64;
        let cap = CapabilityBuilder::new()
            .object(CapabilityObject::memory(Region::new(0x1000, 4096, 0)))
            .rights(Rights::READ | Rights::WRITE)
            .constraints(Constraints::memory_only(4096))
            .authority(axiom_x_principal::AuthorityClass::Process)
            .build(&mut next_id);

        assert!(cap.has_right(Rights::READ));
        assert!(cap.has_right(Rights::WRITE));
        assert!(!cap.has_right(Rights::EXECUTE));
        assert_eq!(cap.constraints.memory_limit, 4096);
    }

    #[test]
    fn test_capability_delegation() {
        let mut next_id = 1u64;
        let parent = CapabilityBuilder::new()
            .object(CapabilityObject::endpoint(1))
            .rights(Rights::SEND | Rights::RECV | Rights::DELEGATE)
            .authority(axiom_x_principal::AuthorityClass::Wolf)
            .build(&mut next_id);

        let mut next_id2 = next_id;
        let child = CapabilityBuilder::new()
            .object(CapabilityObject::endpoint(1))
            .rights(Rights::SEND)
            .authority(axiom_x_principal::AuthorityClass::Process)
            .parent(&parent)
            .build(&mut next_id2);

        // Attenuated to SEND only: the child must not be able to delegate.
        assert!(!child.can_delegate());
        assert_eq!(child.lineage.generation, 1);
        assert_eq!(child.lineage.parent, Some(parent.id));
    }

}
