//! Axiom-X Mathematical Foundations
//!
//! Core mathematical primitives for the Axiom-X microkernel:
//! - Memory resource algebra with conservation laws
//! - Scheduler mathematics (cost functions, thermal models, optimization)
//!
//! Status: `partial` — core types and invariants implemented; integration with kernel TODO.

#![no_std]

pub mod memory_algebra;
pub mod scheduler_math;

pub use memory_algebra::*;
pub use scheduler_math::*;

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_memory_and_scheduler_integration() {
        // Allocate memory for a process
        let mut alloc = FrameAllocator::new(1000);
        let req = AllocRequest {
            count: 10,
            region_type: RegionType::ProcessRwData,
            owner_pid: 1,
            flags: RegionFlags::READ | RegionFlags::WRITE | RegionFlags::USER,
            alignment: 1,
        };
        let AllocResult::Success(region) = alloc.allocate(req).unwrap() else { panic!() };

        // Add process to scheduler
        let mut sched = SchedulerState::new(1, 10_000_000);
        sched.add_process(1, SchedProfile::Interactive, Some(0)).unwrap();

        // Simulate process running and using its memory
        let measurements = [ProcessMeasurement {
            index: 0,
            latency_ns: 5_000_000,
            dt_ns: 10_000_000,
            instructions_retired: 1_000_000,
            cache_misses: 100,
            cpu_load: 0.5,
        }];

        let decision = sched.tick(&measurements);
        assert!(!decision.is_idle());
        assert_eq!(decision.selected_pid, 1);

        // Free memory when process exits
        let result = alloc.free(region.base, 1).unwrap();
        assert_eq!(result, FreeResult::Success);
        assert!(alloc.verify_conservation());
    }
}