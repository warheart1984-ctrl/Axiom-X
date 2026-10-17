//! Principal - The authority holder identity
//!
//! Defines who can possess authority in the system.

#![cfg_attr(not(feature = "std"), no_std)]

use core::fmt;

/// The entity that can possess and exercise authority
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, zerocopy::IntoBytes, zerocopy::Unaligned)]
#[repr(u8)]
pub enum Principal {
    /// The kernel itself
    Kernel = 0,
    /// Wolf CoG OS (PID 1)
    Wolf = 1,
    /// A user process
    Process = 2,
    /// A system service
    Service = 3,
    /// A governance rule/decision
    GovernanceRule = 4,
}

impl Principal {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn is_kernel(&self) -> bool {
        matches!(self, Principal::Kernel)
    }

    pub fn is_wolf(&self) -> bool {
        matches!(self, Principal::Wolf)
    }

    pub fn is_process(&self) -> bool {
        matches!(self, Principal::Process)
    }

    pub fn is_service(&self) -> bool {
        matches!(self, Principal::Service)
    }

    pub fn is_governance_rule(&self) -> bool {
        matches!(self, Principal::GovernanceRule)
    }
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Principal::Kernel => write!(f, "Kernel"),
            Principal::Wolf => write!(f, "Wolf"),
            Principal::Process => write!(f, "Process"),
            Principal::Service => write!(f, "Service"),
            Principal::GovernanceRule => write!(f, "GovernanceRule"),
        }
    }
}

/// Authority class - what kind of authority this represents
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, zerocopy::IntoBytes, zerocopy::Unaligned)]
#[repr(u8)]
pub enum AuthorityClass {
    /// Kernel owns this authority (never delegated)
    Kernel = 0,
    /// Wolf CoG OS authority
    Wolf = 1,
    /// Process authority (derived from Wolf)
    Process = 2,
    /// Service authority (derived from Wolf)
    Service = 3,
}

impl AuthorityClass {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn is_kernel(&self) -> bool {
        matches!(self, AuthorityClass::Kernel)
    }

    pub fn is_wolf(&self) -> bool {
        matches!(self, AuthorityClass::Wolf)
    }
}

/// Authority classes that cannot be delegated
pub const UNDELEGATABLE_AUTHORITIES: &[AuthorityClass] = &[
    AuthorityClass::Kernel,
];

impl fmt::Display for AuthorityClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthorityClass::Kernel => write!(f, "Kernel"),
            AuthorityClass::Wolf => write!(f, "Wolf"),
            AuthorityClass::Process => write!(f, "Process"),
            AuthorityClass::Service => write!(f, "Service"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_principal_values() {
        assert_eq!(Principal::Kernel as u8, 0);
        assert_eq!(Principal::Wolf as u8, 1);
        assert_eq!(Principal::Process as u8, 2);
        assert_eq!(Principal::Service as u8, 3);
        assert_eq!(Principal::GovernanceRule as u8, 4);
    }

    #[test]
    fn test_authority_class_values() {
        assert_eq!(AuthorityClass::Kernel as u8, 0);
        assert_eq!(AuthorityClass::Wolf as u8, 1);
        assert_eq!(AuthorityClass::Process as u8, 2);
        assert_eq!(AuthorityClass::Service as u8, 3);
    }

    #[test]
    fn test_undelegatable() {
        assert!(UNDELEGATABLE_AUTHORITIES.contains(&AuthorityClass::Kernel));
        assert!(!UNDELEGATABLE_AUTHORITIES.contains(&AuthorityClass::Wolf));
        assert!(!UNDELEGATABLE_AUTHORITIES.contains(&AuthorityClass::Process));
        assert!(!UNDELEGATABLE_AUTHORITIES.contains(&AuthorityClass::Service));
    }
}