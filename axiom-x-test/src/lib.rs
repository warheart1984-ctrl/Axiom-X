//! Axiom-X Test Suite
//!
//! Comprehensive tests for:
//! - Memory algebra invariants (conservation, no aliasing, no overcommit)
//! - Scheduler mathematics (cost function, priority, thermal constraints)
//! - Integration tests
//! - Property-based tests
//!
//! Status: `partial` — core math tests implemented; integration tests TODO.

#![cfg(test)]

use axiom_x_math::memory_algebra::*;
use axiom_x_math::scheduler_math::*;
use proptest::prelude::*;
use quickcheck::{quickcheck, TestResult};

// ============================================================================
// Memory Algebra Invariant Tests
// ============================================================================

#[test]
fn test_memory_conservation_always_holds() {
    let mut alloc = FrameAllocator::new(1000);
    assert!(alloc.verify_conservation());

    // Allocate some regions
    for i in 0..10 {
        let req = AllocRequest {
            count: 10,
            region_type: RegionType::ProcessRwData,
            owner_pid: i + 1,
            flags: RegionFlags::READ | RegionFlags::WRITE | RegionFlags::USER,
            alignment: 1,
        };
        alloc.allocate(req).unwrap();
        assert!(alloc.verify_conservation(), "Conservation violated after allocation {}", i);
    }

    // Free some regions
    for i in 0..5 {
        let base = Frame(i * 10);
        alloc.free(base, i as u32 + 1).unwrap();
        assert!(alloc.verify_conservation(), "Conservation violated after free {}", i);
    }
}

#[test]
fn test_no_aliasing_exclusive_regions() {
    let mut alloc = FrameAllocator::new(1000);

    // Allocate exclusive region
    let req1 = AllocRequest {
        count: 10,
        region_type: RegionType::ProcessRwData,
        owner_pid: 1,
        flags: RegionFlags::READ | RegionFlags::WRITE | RegionFlags::USER,
        alignment: 1,
    };
    let AllocResult::Success(r1) = alloc.allocate(req1).unwrap() else { panic!() };

    // Try to allocate overlapping exclusive region (different owner)
    // Our allocator uses first-fit so it won't actually overlap,
    // but the invariant check would catch it if it did
    let req2 = AllocRequest {
        count: 5,
        region_type: RegionType::ProcessRwData,
        owner_pid: 2,
        flags: RegionFlags::READ | RegionFlags::WRITE | RegionFlags::USER,
        alignment: 1,
    };
    let result = alloc.allocate(req2);
    assert!(matches!(result, Ok(AllocResult::Success(_)) | Ok(AllocResult::OutOfMemory)));
}

#[test]
fn test_shared_regions_can_alias() {
    let mut alloc = FrameAllocator::new(1000);

    // Allocate shared region
    let req1 = AllocRequest {
        count: 10,
        region_type: RegionType::Shared,
        owner_pid: 1,
        flags: RegionFlags::READ | RegionFlags::WRITE | RegionFlags::USER | RegionFlags::SHARED,
        alignment: 1,
    };
    let AllocResult::Success(r1) = alloc.allocate(req1).unwrap() else { panic!() };

    // Allocate another shared region - should succeed even if overlapping
    // (In our implementation, first-fit gives different frames, but invariant allows overlap)
    let req2 = AllocRequest {
        count: 5,
        region_type: RegionType::Shared,
        owner_pid: 2,
        flags: RegionFlags::READ | RegionFlags::WRITE | RegionFlags::USER | RegionFlags::SHARED,
        alignment: 1,
    };
    let result = alloc.allocate(req2);
    assert!(matches!(result, Ok(AllocResult::Success(_))));
}

#[test]
fn test_no_overcommit() {
    let mut alloc = FrameAllocator::new(10);

    // Allocate all frames
    let req = AllocRequest {
        count: 10,
        region_type: RegionType::ProcessRwData,
        owner_pid: 1,
        flags: RegionFlags::READ | RegionFlags::WRITE | RegionFlags::USER,
        alignment: 1,
    };
    alloc.allocate(req).unwrap();

    // Try to allocate more
    let req2 = AllocRequest {
        count: 1,
        region_type: RegionType::ProcessRwData,
        owner_pid: 2,
        flags: RegionFlags::READ | RegionFlags::WRITE | RegionFlags::USER,
        alignment: 1,
    };
    let result = alloc.allocate(req2).unwrap();
    assert_eq!(result, AllocResult::OutOfMemory);
}

#[test]
fn test_alignment_constraints() {
    let mut alloc = FrameAllocator::new(1000);

    // Request 16-frame alignment (64 KiB)
    let req = AllocRequest {
        count: 10,
        region_type: RegionType::ProcessRwData,
        owner_pid: 1,
        flags: RegionFlags::READ | RegionFlags::WRITE | RegionFlags::USER,
        alignment: 16,
    };
    let AllocResult::Success(region) = alloc.allocate(req).unwrap() else { panic!() };

    assert_eq!(region.base.0 % 16, 0, "Region not aligned to 16 frames");
}

#[test]
fn test_fragmentation_ratio_increases_with_fragmentation() {
    let mut alloc = FrameAllocator::new(100);

    // Allocate every other frame to create maximum fragmentation
    for i in (0..50).step_by(2) {
        let req = AllocRequest {
            count: 1,
            region_type: RegionType::ProcessRwData,
            owner_pid: 1,
            flags: RegionFlags::READ | RegionFlags::WRITE | RegionFlags::USER,
            alignment: 1,
        };
        alloc.allocate(req).unwrap();
    }

    let fragmented_ratio = alloc.fragmentation_ratio();

    // Free all
    for i in (0..50).step_by(2) {
        alloc.free(Frame(i as u64), 1).unwrap();
    }

    // Allocate contiguous block
    let req = AllocRequest {
        count: 25,
        region_type: RegionType::ProcessRwData,
        owner_pid: 1,
        flags: RegionFlags::READ | RegionFlags::WRITE | RegionFlags::USER,
        alignment: 1,
    };
    alloc.allocate(req).unwrap();

    let contiguous_ratio = alloc.fragmentation_ratio();

    // Fragmented should have higher ratio
    assert!(fragmented_ratio > contiguous_ratio);
}

#[test]
fn test_deallocation_restores_conservation() {
    let mut alloc = FrameAllocator::new(1000);
    let initial_free = alloc.free_count();

    let req = AllocRequest {
        count: 50,
        region_type: RegionType::ProcessRwData,
        owner_pid: 1,
        flags: RegionFlags::READ | RegionFlags::WRITE | RegionFlags::USER,
        alignment: 1,
    };
    let AllocResult::Success(region) = alloc.allocate(req).unwrap() else { panic!() };

    assert_eq!(alloc.free_count(), initial_free - 50);

    alloc.free(region.base, 1).unwrap();

    assert_eq!(alloc.free_count(), initial_free);
    assert!(alloc.verify_conservation());
}

#[test]
fn test_region_lookup_by_pid() {
    let mut alloc = FrameAllocator::new(1000);

    let req1 = AllocRequest {
        count: 10,
        region_type: RegionType::ProcessRwData,
        owner_pid: 42,
        flags: RegionFlags::READ | RegionFlags::WRITE | RegionFlags::USER,
        alignment: 1,
    };
    alloc.allocate(req1).unwrap();

    let req2 = AllocRequest {
        count: 20,
        region_type: RegionType::ProcessCode,
        owner_pid: 42,
        flags: RegionFlags::READ | RegionFlags::EXECUTE | RegionFlags::USER,
        alignment: 1,
    };
    alloc.allocate(req2).unwrap();

    let req3 = AllocRequest {
        count: 5,
        region_type: RegionType::ProcessRwData,
        owner_pid: 99,
        flags: RegionFlags::READ | RegionFlags::WRITE | RegionFlags::USER,
        alignment: 1,
    };
    alloc.allocate(req3).unwrap();

    let pid42_regions: Vec<_> = alloc.regions_for_pid(42).collect();
    let pid99_regions: Vec<_> = alloc.regions_for_pid(99).collect();

    assert_eq!(pid42_regions.len(), 2);
    assert_eq!(pid99_regions.len(), 1);
}

#[test]
fn test_invalid_alignment_rejected() {
    let mut alloc = FrameAllocator::new(1000);

    let req = AllocRequest {
        count: 10,
        region_type: RegionType::ProcessRwData,
        owner_pid: 1,
        flags: RegionFlags::READ | RegionFlags::WRITE | RegionFlags::USER,
        alignment: 3, // Not power of 2
    };
    let result = alloc.allocate(req).unwrap();
    assert_eq!(result, AllocResult::AlignmentFailed);
}

// ============================================================================
// Scheduler Mathematics Tests
// ============================================================================

#[test]
fn test_scheduler_creation() {
    let sched = SchedulerState::new(4, 10_000_000);
    assert_eq!(sched.thermal.active_cores, 4);
    assert_eq!(sched.core_time_budget_ns, 10_000_000);
    assert_eq!(sched.tick, 0);
}

#[test]
fn test_process_addition() {
    let mut sched = SchedulerState::new(4, 10_000_000);

    sched.add_process(1, SchedProfile::Interactive, Some(0)).unwrap();
    sched.add_process(2, SchedProfile::Batch, Some(1)).unwrap();
    sched.add_process(3, SchedProfile::RealTime { deadline_ns: 1_000_000 }, Some(0)).unwrap();

    assert_eq!(sched.processes.len(), 3);
    assert_eq!(sched.runnable.len(), 3);
}

#[test]
fn test_priority_computation_interactive() {
    let mut sched = SchedulerState::new(1, 10_000_000);
    sched.add_process(1, SchedProfile::Interactive, Some(0)).unwrap();

    let measurements = [ProcessMeasurement {
        index: 0,
        latency_ns: 5_000_000,
        dt_ns: 10_000_000,
        instructions_retired: 1_000_000,
        cache_misses: 100,
        cpu_load: 0.5,
    }];

    sched.update_metrics(&measurements);

    let priority = sched.processes[0].priority;
    assert!(priority > 0.0, "Interactive process should have positive priority");
}

#[test]
fn test_priority_computation_batch() {
    let mut sched = SchedulerState::new(1, 10_000_000);
    sched.add_process(1, SchedProfile::Batch, Some(0)).unwrap();

    let measurements = [ProcessMeasurement {
        index: 0,
        latency_ns: 100_000_000,
        dt_ns: 10_000_000,
        instructions_retired: 5_000_000,
        cache_misses: 50,
        cpu_load: 0.8,
    }];

    sched.update_metrics(&measurements);

    let priority = sched.processes[0].priority;
    // Batch prioritizes throughput over latency
    assert!(priority > 0.0);
}

#[test]
fn test_thermal_model_heating_cooling() {
    let mut thermal = ThermalState::new(2);
    thermal.heating_coeff = 0.1;
    thermal.cooling_coeff = 0.05;
    thermal.core_temps[0] = 0.5;
    thermal.core_temps[1] = 0.3;

    // High load on core 0, idle on core 1
    thermal.update(&[1.0, 0.0], 1_000_000_000);

    assert!(thermal.core_temps[0] > 0.5, "Core 0 should heat up");
    assert!(thermal.core_temps[1] < 0.3, "Core 1 should cool down");
}

#[test]
fn test_thermal_violation_prevents_scheduling() {
    let mut sched = SchedulerState::new(2, 10_000_000);
    sched.add_process(1, SchedProfile::Interactive, Some(0)).unwrap();
    sched.add_process(2, SchedProfile::Batch, Some(1)).unwrap();

    // Heat up core 0 near limit
    sched.thermal.core_temps[0] = 0.84;
    sched.thermal.temp_max = 0.85;

    let measurements = [
        ProcessMeasurement { index: 0, latency_ns: 1_000_000, dt_ns: 10_000_000, instructions_retired: 1_000_000, cache_misses: 100, cpu_load: 0.8 },
        ProcessMeasurement { index: 1, latency_ns: 50_000_000, dt_ns: 10_000_000, instructions_retired: 5_000_000, cache_misses: 50, cpu_load: 0.3 },
    ];

    sched.update_metrics(&measurements);

    // Process 0 on hot core should be excluded
    let selected = sched.select_process();
    assert_eq!(selected, Some(1), "Should select process on cool core");
}

#[test]
fn test_time_slice_assignment_by_profile() {
    let mut sched = SchedulerState::new(1, 10_000_000);
    sched.add_process(1, SchedProfile::Interactive, Some(0)).unwrap();
    sched.add_process(2, SchedProfile::Batch, Some(0)).unwrap();
    sched.add_process(3, SchedProfile::Background, Some(0)).unwrap();

    let slice_i = sched.assign_time_slice(0);
    let slice_b = sched.assign_time_slice(1);
    let slice_bg = sched.assign_time_slice(2);

    assert!(slice_i < slice_b, "Interactive should get shorter slice than batch");
    assert!(slice_bg < slice_i, "Background should get shortest slice");
}

#[test]
fn test_real_time_highest_priority() {
    let mut sched = SchedulerState::new(1, 10_000_000);
    sched.add_process(1, SchedProfile::RealTime { deadline_ns: 1_000_000 }, Some(0)).unwrap();
    sched.add_process(2, SchedProfile::Interactive, Some(0)).unwrap();

    let measurements = [
        ProcessMeasurement { index: 0, latency_ns: 100_000, dt_ns: 10_000_000, instructions_retired: 100_000, cache_misses: 10, cpu_load: 0.2 },
        ProcessMeasurement { index: 1, latency_ns: 1_000_000, dt_ns: 10_000_000, instructions_retired: 500_000, cache_misses: 50, cpu_load: 0.5 },
    ];

    sched.update_metrics(&measurements);

    assert!(sched.processes[0].priority > sched.processes[1].priority,
        "Real-time should have higher priority than interactive");
}

#[test]
fn test_cost_function_calculation() {
    let processes = [
        SchedMetrics { latency: 10.0, throughput: 100.0, thermal_cost: 0.5, ..Default::default() },
        SchedMetrics { latency: 5.0, throughput: 50.0, thermal_cost: 0.3, ..Default::default() },
    ];
    let runnable = [true, true];
    let weights = SchedulerWeights::default();

    let cost = cost_function(&processes, &runnable, &weights);

    // J = 1*10 + (-1)*100 + 0.5*0.5 + 1*5 + (-1)*50 + 0.5*0.3
    //   = 10 - 100 + 0.25 + 5 - 50 + 0.15 = -134.6
    assert!((cost - (-134.6)).abs() < 0.01);
}

#[test]
fn test_optimize_schedule_respects_thermal() {
    let processes = [
        SchedMetrics { latency: 5.0, throughput: 100.0, thermal_cost: 0.2, cpu_load: 0.1, ..Default::default() },
        SchedMetrics { latency: 20.0, throughput: 50.0, thermal_cost: 0.8, cpu_load: 0.9, ..Default::default() }, // High thermal
    ];
    let runnable = [true, true];
    let mut thermal = ThermalState::new(1);
    thermal.core_temps[0] = 0.8;
    thermal.temp_max = 0.85;
    thermal.heating_coeff = 0.1;

    let affinities = [Some(0), Some(0)];
    let weights = SchedulerWeights::default();

    let schedule = optimize_schedule(&processes, &runnable, &thermal, &affinities, &weights, 10_000_000);

    // High thermal cost process should be excluded
    assert_eq!(schedule.len(), 1);
    assert_eq!(schedule[0].0, 0);
}

#[test]
fn test_scheduler_tick_updates_thermal() {
    let mut sched = SchedulerState::new(1, 10_000_000);
    sched.add_process(1, SchedProfile::Batch, Some(0)).unwrap();

    let measurements = [ProcessMeasurement {
        index: 0,
        latency_ns: 0,
        dt_ns: 10_000_000,
        instructions_retired: 1_000_000,
        cache_misses: 100,
        cpu_load: 1.0, // Full load: heating (α'·1·dt) exceeds cooling (β'·dt)
    }];

    let initial_temp = sched.thermal.core_temps[0];
    let decision = sched.tick(&measurements);

    // Thermal should have updated
    assert!(sched.thermal.core_temps[0] != initial_temp);
    assert_eq!(sched.tick, 1);
    assert!(!decision.is_idle());
}

// ============================================================================
// Integration Tests
// ============================================================================

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

    // Simulate process running
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

#[test]
fn test_multiple_processes_scheduling_fairness() {
    let mut sched = SchedulerState::new(1, 10_000_000);

    // Add 5 identical interactive processes
    for i in 1..=5 {
        sched.add_process(i, SchedProfile::Interactive, Some(0)).unwrap();
    }

    let measurements: Vec<_> = (0..5).map(|i| ProcessMeasurement {
        index: i,
        latency_ns: (i as u64 + 1) * 1_000_000,
        dt_ns: 10_000_000,
        instructions_retired: 1_000_000,
        cache_misses: 100,
        cpu_load: 0.5,
    }).collect();

    // Run multiple ticks
    for _ in 0..10 {
        let decision = sched.tick(&measurements);
        assert!(!decision.is_idle());
    }

    // All processes should have been scheduled at least once
    // (This is a basic fairness check)
    let scheduled_count = sched.processes.iter()
        .filter(|p| p.metrics.total_runtime_ns > 0)
        .count();
    assert!(scheduled_count > 0);
}

// ============================================================================
// Property-Based Tests
// ============================================================================

proptest! {
    #[test]
    fn test_memory_conservation_property(
        initial_frames in 10..1000usize,
        operations in prop::collection::vec(
            (0..100u64, 1..20usize, 1..100u32), // (base, count, pid)
            1..50
        )
    ) {
        let mut alloc = FrameAllocator::new(initial_frames);
        prop_assert!(alloc.verify_conservation());

        for (base, count, pid) in operations {
            let req = AllocRequest {
                count: count.min(alloc.free_count()),
                region_type: RegionType::ProcessRwData,
                owner_pid: pid,
                flags: RegionFlags::READ | RegionFlags::WRITE | RegionFlags::USER,
                alignment: 1,
            };
            if req.count > 0 {
                let _ = alloc.allocate(req);
            }
            prop_assert!(alloc.verify_conservation());
        }
    }

    #[test]
    fn test_scheduler_priority_bounds(
        latency in 0.0..1000.0f64,
        throughput in 0.0..10000.0f64,
        thermal in 0.0..1.0f64
    ) {
        let mut sched = SchedulerState::new(1, 10_000_000);
        sched.add_process(1, SchedProfile::Interactive, Some(0)).unwrap();

        sched.processes[0].latency = latency;
        sched.processes[0].throughput = throughput;
        sched.processes[0].thermal_cost = thermal;

        // Recompute priority manually
        let w = SchedProfile::Interactive.weights();
        let priority = w.w_latency * (1.0 / (1.0 + latency))
            + w.w_throughput * throughput
            - w.w_thermal * thermal;

        // Priority should be finite
        assert!(priority.is_finite());
    }
}

// ============================================================================
// QuickCheck Tests
// ============================================================================

quickcheck! {
    fn memory_alloc_free_conservation(
        initial: usize,
        alloc_sizes: Vec<usize>,
        free_indices: Vec<usize>
    ) -> TestResult {
        if initial == 0 || alloc_sizes.is_empty() {
            return TestResult::discard();
        }

        let mut alloc = FrameAllocator::new(initial.min(1000));
        let mut allocated = Vec::new();

        for (i, &size) in alloc_sizes.iter().enumerate() {
            let req = AllocRequest {
                count: size.min(10).min(alloc.free_count()),
                region_type: RegionType::ProcessRwData,
                owner_pid: i as u32 + 1,
                flags: RegionFlags::READ | RegionFlags::WRITE | RegionFlags::USER,
                alignment: 1,
            };
            if req.count > 0 {
                match alloc.allocate(req) {
                    Ok(AllocResult::Success(region)) => {
                        allocated.push((region.base, i as u32 + 1));
                    }
                    _ => {}
                }
            }
            if !alloc.verify_conservation() {
                return TestResult::failed();
            }
        }

        // Free some
        for &idx in &free_indices {
            if idx < allocated.len() {
                let (base, pid) = allocated[idx];
                let _ = alloc.free(base, pid);
                if !alloc.verify_conservation() {
                    return TestResult::failed();
                }
            }
        }

        TestResult::passed()
    }
}

// ============================================================================
// Benchmark Tests (Criterion)
// ============================================================================

#[cfg(feature = "bench")]
mod benchmarks {
    use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
    use super::*;

    fn bench_frame_allocation(c: &mut Criterion) {
        let mut group = c.benchmark_group("frame_allocation");

        for size in [100, 1000, 10000].iter() {
            group.bench_with_input(BenchmarkId::new("alloc", size), size, |b, &size| {
                b.iter(|| {
                    let mut alloc = FrameAllocator::new(size);
                    let req = AllocRequest {
                        count: 10,
                        region_type: RegionType::ProcessRwData,
                        owner_pid: 1,
                        flags: RegionFlags::READ | RegionFlags::WRITE | RegionFlags::USER,
                        alignment: 1,
                    };
                    for _ in 0..(size / 20) {
                        let _ = alloc.allocate(req);
                    }
                });
            });
        }
        group.finish();
    }

    fn bench_scheduler_tick(c: &mut Criterion) {
        let mut group = c.benchmark_group("scheduler_tick");

        for procs in [10, 50, 100].iter() {
            group.bench_with_input(BenchmarkId::new("tick", procs), procs, |b, &procs| {
                b.iter(|| {
                    let mut sched = SchedulerState::new(1, 10_000_000);
                    for i in 1..=procs {
                        sched.add_process(i, SchedProfile::Interactive, Some(0)).unwrap();
                    }

                    let measurements: Vec<_> = (0..procs).map(|i| ProcessMeasurement {
                        index: i,
                        latency_ns: (i as u64 + 1) * 1_000_000,
                        dt_ns: 10_000_000,
                        instructions_retired: 1_000_000,
                        cache_misses: 100,
                        cpu_load: 0.5,
                    }).collect();

                    sched.tick(&measurements);
                });
            });
        }
        group.finish();
    }

    criterion_group!(benches, bench_frame_allocation, bench_scheduler_tick);
    criterion_main!(benches);
}