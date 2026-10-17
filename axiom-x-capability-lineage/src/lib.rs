//! Capability Lineage - Delegation, provenance, and generational revocation
//!
//! Defines the capability delegation graph, provenance tracking, and
//! generational revocation system.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use core::fmt;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use heapless::Vec as HeaplessVec;
use spin::Mutex;

use axiom_x_capability::{Capability, CapabilityId, CapabilityToken, CapabilityRoot, Lineage, CapabilityObject, Rights, Constraints, CapabilityBuilder};
use axiom_x_principal::{Principal, AuthorityClass, UNDELEGATABLE_AUTHORITIES};

/// Delegation record - records a capability delegation
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DelegationRecord {
    /// The capability that was delegated
    pub capability_id: u64, // CapabilityId as u64

    /// The parent capability that delegated
    pub parent_id: u64, // CapabilityId as u64

    /// The new capability created
    pub child_id: u64, // CapabilityId as u64

    /// Who performed the delegation
    pub delegator: u64, // Principal as u64

    /// Rights that were delegated
    pub delegated_rights: u64, // Rights as u64

    /// Constraints applied
    pub constraints_hash: u64, // Hash of Constraints

    /// Generation at time of delegation
    pub generation: u64,

    /// Timestamp (nanoseconds since boot)
    pub timestamp_ns: u64,

    /// Delegation chain hash
    pub chain_hash: u64,
}

impl DelegationRecord {
    pub fn new(
        capability_id: u64,
        parent_id: u64,
        child_id: u64,
        delegator: u64,
        delegated_rights: u64,
        constraints_hash: u64,
        generation: u64,
    ) -> Self {
        Self {
            capability_id,
            parent_id,
            child_id,
            delegator,
            delegated_rights,
            constraints_hash,
            generation,
            timestamp_ns: 0, // TODO: actual timestamp
            chain_hash: 0, // TODO: compute
        }
    }
}

/// Delegation result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegationResult {
    Success,
    InvalidParent,
    InsufficientRights,
    DelegationNotAllowed,
    MaxDepthExceeded,
    ConstraintsViolation,
    ParentRevoked,
}

/// Capability delegation service
pub struct DelegationService {
    /// Root capabilities for revocation
    roots: spin::Mutex<alloc::collections::BTreeMap<u64, crate::axiom_x_capability::CapabilityRoot>>, // CapabilityId -> CapabilityRoot

    /// Delegation history
    history: Mutex<HeaplessVec<DelegationRecord, 1024>>,

    /// Capability ID generator
    next_id: Mutex<u64>,
}

impl DelegationService {
    pub fn new() -> Self {
        Self {
            roots: Mutex::new(alloc::collections::BTreeMap::new()),
            history: Mutex::new(HeaplessVec::new()),
            next_id: Mutex::new(1),
        }
    }

    /// Get next capability ID
    fn next_id(&self) -> u64 {
        let mut id = self.next_id.lock();
        let id = *id;
        *id += 1;
        id
    }

    /// Create a new root capability
    pub fn create_root(&self, capability: &crate::axiom_x_capability::Capability) -> u64 {
        let mut roots = self.roots.lock();
        let root = crate::axiom_x_capability::CapabilityRoot::new(crate::axiom_x_capability::CapabilityId(capability.id.0));
        let id = capability.id.0;
        roots.insert(capability.id.0, crate::axiom_x_capability::CapabilityRoot::new(crate::axiom_x_capability::CapabilityId(capability.id.0)));
        id
    }

    /// Delegate a capability
    pub fn delegate(
        &self,
        parent: &crate::axiom_x_capability::Capability,
        child_rights: crate::axiom_x_capability::Rights,
        child_constraints: crate::axiom_x_capability::Constraints,
        child_object: crate::axiom_x_capability::CapabilityObject,
        child_authority: crate::axiom_x_principal::AuthorityClass,
        delegator: u64, // Principal as u64
    ) -> Result<crate::axiom_x_capability::Capability, DelegationResult> {
        // Check if parent can delegate
        if !parent.can_delegate() {
            return Err(DelegationResult::DelegationNotAllowed);
        }

        // Check if parent has the rights being delegated
        if !parent.rights.contains(child_rights) {
            return Err(DelegationResult::InsufficientRights);
        }

        // Check delegation depth
        if parent.lineage.generation >= parent.constraints.max_delegation_depth as u64 {
            return Err(DelegationResult::MaxDepthExceeded);
        }

        // Check if parent is revoked
        let roots = self.roots.lock();
        if let Some(root) = roots.get(&parent.root_id.0) {
            if root.current_generation() != parent.generation {
                return Err(DelegationResult::ParentRevoked);
            }
        } else {
            return Err(DelegationResult::InvalidParent);
        }
        drop(roots);

        // Check constraints
        if !child_constraints.check_constraints(0, 0) {
            return Err(DelegationResult::ConstraintsViolation);
        }

        // Check authority delegation rules
        // Kernel authority cannot be delegated
        if parent.authority == crate::axiom_x_principal::AuthorityClass::Kernel as u8 {
            return Err(DelegationResult::DelegationNotAllowed);
        }

        // All checks passed - create child capability
        let child = crate::axiom_x_capability::CapabilityBuilder::new()
            .id(crate::axiom_x_capability::CapabilityId(self.next_id()))
            .object(parent.object.clone())
            .rights(child_rights)
            .constraints(child_constraints)
            .authority(crate::axiom_x_principal::AuthorityClass::try_from(child_authority as u8).unwrap_or(crate::axiom_x_principal::AuthorityClass::Process))
            .parent(&crate::axiom_x_capability::Capability {
                id: parent.id,
                object: parent.object.clone(),
                rights: parent.rights,
                constraints: parent.constraints.clone(),
                authority: parent.authority,
                lineage: parent.lineage.clone(),
                generation: parent.generation,
                root_id: parent.root_id,
            })
            .issuer(0) // TODO: actual delegator principal
            .build(&mut crate::axiom_x_capability::CapabilityId(parent.id.next()));

        // Record delegation
        let record = DelegationRecord::new(
            parent.id.0,
            parent.id.0,
            child.id.0,
            0, // delegator
            child.rights.bits(),
            0, // constraints hash
            child.lineage.generation,
        );

        let mut history = self.history.lock();
        history.push(record).ok();

        Ok(child)
    }

    /// Revoke a capability and all its descendants
    pub fn revoke(&self, capability_id: u64) -> Result<u64, ()> {
        let mut roots = self.roots.lock();
        if let Some(root) = roots.get_mut(&capability_id) {
            let new_gen = root.revoke();
            Ok(root.current_generation())
        } else {
            Err(())
        }
    }

    /// Check if a capability token is still valid
    pub fn is_valid(&self, token: &crate::axiom_x_capability::CapabilityToken) -> bool {
        let roots = self.roots.lock();
        if let Some(root) = roots.get(&token.root_id.0) {
            root.current_generation() == token.generation
        } else {
            false
        }
    }

    /// Get delegation history for a capability
    pub fn get_history(&self, capability_id: u64) -> HeaplessVec<DelegationRecord, 64> {
        let history = self.history.lock();
        let mut result = HeaplessVec::new();
        for record in history.iter() {
            if record.capability_id == capability_id || record.parent_id == capability_id || record.child_id == capability_id {
                result.push(record.clone()).ok();
            }
        }
        result
    }

    /// Get all descendants of a capability
    pub fn get_descendants(&self, capability_id: u64) -> HeaplessVec<u64, 64> {
        let history = self.history.lock();
        let mut descendants = HeaplessVec::new();
        for record in history.iter() {
            if record.parent_id == capability_id {
                descendants.push(record.child_id).ok();
            }
        }
        descendants
    }

    /// Get delegator of a capability
    pub fn get_delegator(&self, capability_id: u64) -> Option<u64> {
        let history = self.history.lock();
        for record in history.iter() {
            if record.child_id == capability_id {
                return Some(record.delegator);
            }
        }
        None
    }
}

/// Delegation result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegationResult {
    Success,
    InvalidParent,
    InsufficientRights,
    DelegationNotAllowed,
    MaxDepthExceeded,
    ConstraintsViolation,
    ParentRevoked,
}

/// Capability validation service
pub struct CapabilityValidator {
    delegation_service: DelegationService,
}

impl CapabilityValidator {
    pub fn new(delegation_service: DelegationService) -> Self {
        Self { delegation_service }
    }

    /// Validate a capability for use
    pub fn validate(&self, capability: &crate::axiom_x_capability::Capability, requested_rights: crate::axiom_x_capability::Rights) -> ValidationResult {
        // Check if capability has required rights
        if !capability.has_all_rights(requested_rights) {
            return ValidationResult::InsufficientRights;
        }

        // Check constraints
        if !capability.check_constraints(0, 0) {
            return ValidationResult::ConstraintsViolation;
        }

        // Check if revoked
        let token = crate::axiom_x_capability::CapabilityToken {
            root_id: capability.root_id,
            generation: capability.generation,
        };

        if !self.capability_service.is_valid(&token) {
            return ValidationResult::Revoked;
        }

        // Check delegation depth
        if capability.lineage.generation > capability.constraints.max_delegation_depth as u64 {
            return ValidationResult::MaxDepthExceeded;
        }

        ValidationResult::Valid
    }

    /// Validate and extract rights intersection
    pub fn validate_and_intersect(&self, capability: &crate::axiom_x_capability::Capability, requested: crate::axiom_x_capability::Rights) -> Result<crate::axiom_x_capability::Rights, ValidationResult> {
        let result = self.validate(capability, requested);
        if result != ValidationResult::Valid {
            return Err(result);
        }
        Ok(capability.rights & requested)
    }
}

/// Validation result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationResult {
    Valid,
    InsufficientRights,
    ConstraintsViolation,
    Revoked,
    MaxDepthExceeded,
    InvalidCapability,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::axiom_x_capability::{Capability, CapabilityId, Rights, Constraints, CapabilityObject, CapabilityBuilder};
    use crate::axiom_x_principal::AuthorityClass;

    #[test]
    fn test_delegation_service() {
        let service = DelegationService::new();
        let mut next_id = 1u64;

        // Create root capability
        let root = crate::axiom_x_capability::CapabilityBuilder::new()
            .object(crate::axiom_x_capability::CapabilityObject::endpoint(1))
            .rights(crate::axiom_x_capability::Rights::SEND | crate::axiom_x_capability::Rights::RECV | crate::axiom_x_capability::Rights::DELEGATE)
            .authority(crate::axiom_x_principal::AuthorityClass::Wolf)
            .build(&mut 1);

        // Delegate
        let child = DelegationService::new().delegate(
            &crate::axiom_x_capability::Capability::new(
                crate::axiom_x_capability::CapabilityId(1),
                crate::axiom_x_capability::CapabilityObject::endpoint(1),
                crate::axiom_x_capability::Rights::SEND | crate::axiom_x_capability::Rights::RECV | crate::axiom_x_capability::Rights::DELEGATE,
                crate::axiom_x_capability::Constraints::default(),
                crate::axiom_x_principal::AuthorityClass::Wolf,
                None,
            ),
            crate::axiom_x_capability::Rights::SEND,
            crate::axiom_x_capability::Constraints::default(),
            crate::axiom_x_capability::CapabilityObject::endpoint(1),
            crate::axiom_x_principal::AuthorityClass::Process,
            1, // Wolf
        ).expect("Delegation should succeed");

        assert!(child.rights.contains(crate::axiom_x_capability::Rights::SEND));
        assert!(!child.rights.contains(crate::axiom_x_capability::Rights::RECV));
    }

    #[test]
    fn test_generational_revocation() {
        let service = DelegationService::new();
        let root_id = 1u64;

        // Create root
        let mut cap = crate::axiom_x_capability::Capability::new(
            crate::axiom_x_capability::CapabilityId(1),
            crate::axiom_x_capability::CapabilityObject::endpoint(1),
            crate::axiom_x_capability::Rights::SEND | crate::axiom_x_capability::Rights::DELEGATE,
            crate::axiom_x_capability::Constraints::default(),
            crate::axiom_x_principal::AuthorityClass::Wolf,
            None,
        );

        // Revoke
        let service = DelegationService::new();
        service.create_root(&cap);
        let new_gen = service.revoke(1).expect("Revocation should succeed");
        assert!(new_gen > 0);
    }
}