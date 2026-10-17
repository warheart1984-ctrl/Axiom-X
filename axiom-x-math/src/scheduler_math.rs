//! Scheduler Mathematics for Axiom-X
//!
//! Implements the mathematical core of scheduling:
//! - State vectors per process (L_i, T_i, H_i)
//! - Cost function J = α·latency + β·throughput + γ·thermal
//! - Constrained optimization with conservation laws
//! - Priority computation derived from cost function
//!
//! Status: `partial` — core math implemented; integration with kernel TODO.

use core::fmt;
use heapless::Vec;

/// Maximum runnable processes
pub const MAX_PROCESSES: usize = 256;

/// Scheduler weights (tunable at boot)
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SchedulerWeights {
    /// Weight on latency (favor responsiveness)
    pub w_latency: f64,
    /// Weight on throughput (favor sustained work)
    pub w_throughput: f64,
    /// Weight on thermal cost (avoid overheating)
    pub w_thermal: f64,
    /// Cost function α (latency)
    pub alpha: f64,
    /// Cost function β (throughput, negative = maximize)
    pub beta: f64,
    /// Cost function γ (thermal)
    pub gamma: f64,
}

impl Default for SchedulerWeights {
    fn default() -> Self {
        Self {
            w_latency: 1.0,
            w_throughput: 1.0,
            w_thermal: 0.5,
            alpha: 1.0,
            beta: -1.0, // Negative = maximize throughput
            gamma: 0.5,
        }
    }
}

/// Per-process scheduler metrics (state vector x_i(t))
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct SchedMetrics {
    /// Latency estimate L_i (time since last run, or deadline proximity)
    pub latency: f64,
    /// Throughput contribution T_i (work done per unit time)
    pub throughput: f64,
    /// Thermal cost estimate H_i (CPU load × thermal coefficient)
    pub thermal_cost: f64,
    /// CPU load fraction (0.0-1.0); the physical input to the thermal model
    pub cpu_load: f64,
    /// Derived priority S_i
    pub priority: f64,
    /// Time since last scheduled (ns)
    pub last_run_ns: u64,
    /// Accumulated runtime (ns)
    pub total_runtime_ns: u64,
    /// Instructions retired (for throughput estimation)
    pub instructions_retired: u64,
    /// Cache misses (for memory pressure estimation)
    pub cache_misses: u64,
}

/// Process scheduling profile (contract)
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum SchedProfile {
    /// Interactive: low latency, moderate throughput
    #[default]
    Interactive,
    /// Batch: high throughput, latency tolerant
    Batch,
    /// Real-time: deadline-aware, highest priority
    RealTime { deadline_ns: u64 },
    /// Background: lowest priority, thermal-friendly
    Background,
    /// Custom weights
    Custom(SchedulerWeights),
}

impl SchedProfile {
    pub fn weights(&self) -> SchedulerWeights {
        match self {
            Self::Interactive => SchedulerWeights {
                w_latency: 2.0,
                w_throughput: 0.5,
                w_thermal: 0.3,
                alpha: 2.0,
                beta: -0.5,
                gamma: 0.3,
            },
            Self::Batch => SchedulerWeights {
                w_latency: 0.3,
                w_throughput: 2.0,
                w_thermal: 0.5,
                alpha: 0.3,
                beta: -2.0,
                gamma: 0.5,
            },
            Self::RealTime { .. } => SchedulerWeights {
                w_latency: 5.0,
                w_throughput: 1.0,
                w_thermal: 0.2,
                alpha: 5.0,
                beta: -1.0,
                gamma: 0.2,
            },
            Self::Background => SchedulerWeights {
                w_latency: 0.1,
                w_throughput: 0.2,
                w_thermal: 2.0,
                alpha: 0.1,
                beta: -0.2,
                gamma: 2.0,
            },
            Self::Custom(w) => *w,
        }
    }
}

/// Thermal model state
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ThermalState {
    /// Per-core temperature (normalized 0.0-1.0)
    pub core_temps: [f64; 64], // Up to 64 cores
    /// Active core count
    pub active_cores: usize,
    /// Thermal coefficient α' (heating per load unit)
    pub heating_coeff: f64,
    /// Cooling coefficient β' (cooling per time unit)
    pub cooling_coeff: f64,
    /// Maximum safe temperature (normalized)
    pub temp_max: f64,
    /// Time since last thermal update (ns)
    pub last_update_ns: u64,
}

impl Default for ThermalState {
    fn default() -> Self {
        Self::new(1)
    }
}

impl ThermalState {
    pub fn new(max_cores: usize) -> Self {
        let mut temps = [0.0; 64];
        for i in 0..max_cores.min(64) {
            temps[i] = 0.3; // Start at 30% thermal capacity
        }
        Self {
            core_temps: temps,
            active_cores: max_cores.min(64),
            heating_coeff: 0.01,
            cooling_coeff: 0.005,
            temp_max: 0.85, // 85% of thermal limit
            last_update_ns: 0,
        }
    }

    /// Update thermal model: T(t+1) = T(t) + α'·load - β'·cooling
    pub fn update(&mut self, load_per_core: &[f64], dt_ns: u64) {
        let dt = dt_ns as f64 / 1_000_000_000.0; // Convert to seconds
        for i in 0..self.active_cores {
            let load = load_per_core.get(i).copied().unwrap_or(0.0).clamp(0.0, 1.0);
            let heating = self.heating_coeff * load * dt;
            let cooling = self.cooling_coeff * dt;
            self.core_temps[i] = (self.core_temps[i] + heating - cooling).clamp(0.0, 1.0);
        }
        self.last_update_ns += dt_ns;
    }

    /// Check if scheduling a process on core would violate thermal envelope
    pub fn would_violate(&self, core: usize, additional_load: f64) -> bool {
        if core >= self.active_cores {
            return false;
        }
        let projected = self.core_temps[core] + self.heating_coeff * additional_load;
        projected > self.temp_max
    }

    /// Get thermal cost for a process (based on its typical load and core affinity)
    pub fn process_thermal_cost(&self, core: usize, process_load: f64) -> f64 {
        if core >= self.active_cores {
            return 0.0;
        }
        self.core_temps[core] * process_load * self.gamma_cost()
    }

    fn gamma_cost(&self) -> f64 {
        // Exponential cost as temperature approaches limit
        let margin = self.temp_max - self.core_temps.iter().cloned().fold(0.0, f64::max);
        if margin <= 0.0 { 10.0 } else { 1.0 / margin }
    }
}

/// Global scheduler state
#[derive(Debug)]
pub struct SchedulerState {
    /// Process IDs (parallel to `processes`)
    pub pids: Vec<u32, MAX_PROCESSES>,
    /// Per-process metrics
    pub processes: Vec<SchedMetrics, MAX_PROCESSES>,
    /// Process profiles (contracts)
    pub profiles: Vec<SchedProfile, MAX_PROCESSES>,
    /// Process runnable flags
    pub runnable: Vec<bool, MAX_PROCESSES>,
    /// Process core affinity
    pub affinity: Vec<Option<usize>, MAX_PROCESSES>,
    /// Core time budget per tick (ns)
    pub core_time_budget_ns: u64,
    /// Thermal model
    pub thermal: ThermalState,
    /// Scheduler tick counter
    pub tick: u64,
    /// Current weights (can be overridden per-process)
    pub global_weights: SchedulerWeights,
    /// Nominal reference throughput (instructions/sec) for normalizing T_i,
    /// keeping α·L, β·T, γ·H on comparable scales in J.
    pub throughput_reference: f64,
}

impl SchedulerState {
    pub fn new(max_cores: usize, time_slice_ns: u64) -> Self {
        Self {
            pids: Vec::new(),
            processes: Vec::new(),
            profiles: Vec::new(),
            runnable: Vec::new(),
            affinity: Vec::new(),
            core_time_budget_ns: time_slice_ns,
            thermal: ThermalState::new(max_cores),
            tick: 0,
            global_weights: SchedulerWeights::default(),
            throughput_reference: 1_000_000_000.0, // 1 GHz-class core
        }
    }

    /// Add a process to scheduler
    pub fn add_process(&mut self, pid: u32, profile: SchedProfile, affinity: Option<usize>) -> Result<(), &'static str> {
        if self.processes.len() >= MAX_PROCESSES {
            return Err("process table full");
        }
        self.pids.push(pid).map_err(|_| "pids full")?;
        self.processes.push(SchedMetrics::default()).map_err(|_| "processes full")?;
        self.profiles.push(profile).map_err(|_| "profiles full")?;
        self.runnable.push(true).map_err(|_| "runnable full")?;
        self.affinity.push(affinity).map_err(|_| "affinity full")?;
        Ok(())
    }

    /// Remove a process
    pub fn remove_process(&mut self, index: usize) -> Option<SchedMetrics> {
        if index >= self.processes.len() {
            return None;
        }
        self.pids.remove(index);
        self.profiles.remove(index);
        self.runnable.remove(index);
        self.affinity.remove(index);
        Some(self.processes.remove(index))
    }

    /// Update metrics for all runnable processes
    pub fn update_metrics(&mut self, measurements: &[ProcessMeasurement]) {
        for m in measurements {
            if let Some(metrics) = self.processes.get_mut(m.index) {
                metrics.latency = m.latency_ns as f64 / 1_000_000.0; // Convert to ms
                let instr_per_sec = m.instructions_retired as f64
                    / (m.dt_ns as f64 / 1_000_000_000.0).max(1e-6); // Floor: 1µs, in seconds
                // Normalize T_i against the reference so β·T stays on the
                // same scale as α·L and γ·H instead of dominating J.
                metrics.throughput = instr_per_sec / self.throughput_reference;
                metrics.cpu_load = m.cpu_load;
                metrics.thermal_cost = self.thermal.process_thermal_cost(
                    self.affinity[m.index].unwrap_or(0),
                    m.cpu_load,
                );
                metrics.last_run_ns = m.dt_ns; // Use dt_ns as proxy for last run
                metrics.total_runtime_ns += m.dt_ns;
                metrics.instructions_retired = m.instructions_retired;
                metrics.cache_misses = m.cache_misses;
            }
        }

        // Compute priorities
        for (i, metrics) in self.processes.iter_mut().enumerate() {
            if !self.runnable[i] {
                metrics.priority = f64::NEG_INFINITY;
                continue;
            }
            let w = self.profiles[i].weights();
            metrics.priority =
                w.w_latency * (1.0 / (1.0 + metrics.latency))
                + w.w_throughput * metrics.throughput
                - w.w_thermal * metrics.thermal_cost;
        }
    }

    /// Select best process to run (returns index)
    pub fn select_process(&mut self) -> Option<usize> {
        let mut best_idx = None;
        let mut best_priority = f64::NEG_INFINITY;

        for (i, &runnable) in self.runnable.iter().enumerate() {
            if !runnable {
                continue;
            }

            // Check thermal constraint: `would_violate` projects a physical
            // load fraction (0-1), not the dimensionless thermal cost.
            let core = self.affinity[i].unwrap_or(0);
            let metrics = &self.processes[i];
            if self.thermal.would_violate(core, metrics.cpu_load) {
                continue;
            }

            if metrics.priority > best_priority {
                best_priority = metrics.priority;
                best_idx = Some(i);
            }
        }

        best_idx
    }

    /// Assign time slice to selected process
    pub fn assign_time_slice(&mut self, idx: usize) -> u64 {
        if idx >= self.processes.len() {
            return self.core_time_budget_ns;
        }
        let metrics = &self.processes[idx];
        let w = self.profiles[idx].weights();

        // Adjust slice based on profile
        let base_slice = self.core_time_budget_ns;
        let adjusted = match self.profiles[idx] {
            SchedProfile::Interactive => base_slice / 2,      // Shorter slices for responsiveness
            SchedProfile::RealTime { .. } => base_slice,      // Full slice
            SchedProfile::Batch => base_slice * 2,            // Longer slices for throughput
            SchedProfile::Background => base_slice / 4,       // Minimal slices
            SchedProfile::Custom(_) => base_slice,
        };

        // Thermal throttling
        let core = self.affinity[idx].unwrap_or(0);
        let thermal_margin = self.thermal.temp_max - self.thermal.core_temps[core];
        let thermal_factor = (thermal_margin / self.thermal.temp_max).clamp(0.1, 1.0);

        ((adjusted as f64 * thermal_factor) as u64).max(100_000) // Min 100μs
    }

    /// Perform scheduler tick
    pub fn tick(&mut self, measurements: &[ProcessMeasurement]) -> SchedulerDecision {
        self.tick += 1;

        // Update thermal model from physical load fractions (cpu_load),
        // not from thermal costs — the model heats by load, not by cost.
        let mut load_per_core = heapless::Vec::<f64, 64>::new();
        for c in 0..self.thermal.active_cores {
            let load: f64 = self.processes.iter()
                .zip(self.runnable.iter())
                .zip(self.affinity.iter())
                .filter_map(|((m, &r), &a)| {
                    if r && a == Some(c) { Some(m.cpu_load) } else { None }
                })
                .sum::<f64>()
                .clamp(0.0, 1.0);
            let _ = load_per_core.push(load);
        }

        self.thermal.update(&load_per_core, self.core_time_budget_ns);

        // Update metrics
        self.update_metrics(measurements);

        // Select process
        if let Some(idx) = self.select_process() {
            let time_slice = self.assign_time_slice(idx);
            let metrics = self.processes[idx];
            let decision = SchedulerDecision {
                selected_pid: self.pids[idx], // real pid, not table index
                time_slice_ns: time_slice,
                metrics,
                thermal_state: self.thermal,
                weights_used: self.profiles[idx].weights(),
                tick: self.tick,
                timestamp_ns: self.tick * self.core_time_budget_ns,
            };
            decision
        } else {
            // No runnable process - idle
            SchedulerDecision::idle(self.tick, self.thermal)
        }
    }
}

/// Measurement from hardware counters
#[derive(Debug, Clone, Copy)]
pub struct ProcessMeasurement {
    pub index: usize,
    pub latency_ns: u64,
    pub dt_ns: u64,
    pub instructions_retired: u64,
    pub cache_misses: u64,
    pub cpu_load: f64,
}

/// Scheduler decision with evidence
#[derive(Debug, Clone)]
pub struct SchedulerDecision {
    pub selected_pid: u32,
    pub time_slice_ns: u64,
    pub metrics: SchedMetrics,
    pub thermal_state: ThermalState,
    pub weights_used: SchedulerWeights,
    pub tick: u64,
    pub timestamp_ns: u64,
}

impl SchedulerDecision {
    pub fn idle(tick: u64, thermal: ThermalState) -> Self {
        Self {
            selected_pid: u32::MAX,
            time_slice_ns: 0,
            metrics: SchedMetrics::default(),
            thermal_state: thermal,
            weights_used: SchedulerWeights::default(),
            tick,
            timestamp_ns: 0,
        }
    }

    /// Check if this is an idle decision
    pub fn is_idle(&self) -> bool {
        self.selected_pid == u32::MAX
    }
}

/// Cost function evaluation
pub fn cost_function(
    processes: &[SchedMetrics],
    runnable: &[bool],
    weights: &SchedulerWeights,
) -> f64 {
    let mut total = 0.0;
    for (m, &r) in processes.iter().zip(runnable.iter()) {
        if !r { continue; }
        total += weights.alpha * m.latency
            + weights.beta * m.throughput
            + weights.gamma * m.thermal_cost;
    }
    total
}

/// Constrained optimization: minimize J subject to conservation laws.
/// Greedy: the marginal cost of each runnable candidate is evaluated with
/// `cost_function`; candidates are scheduled in ascending marginal cost
/// (most negative = most beneficial to J), then the time budget is split
/// to conserve the total.
pub fn optimize_schedule(
    processes: &[SchedMetrics],
    runnable: &[bool],
    thermal: &ThermalState,
    affinities: &[Option<usize>],
    weights: &SchedulerWeights,
    time_budget_ns: u64,
) -> heapless::Vec<(usize, u64), MAX_PROCESSES> {
    // Build thermal-constrained candidates with their marginal J contribution
    let mut candidates = heapless::Vec::<(usize, f64), MAX_PROCESSES>::new();
    for (i, (&r, m)) in runnable.iter().zip(processes.iter()).enumerate() {
        if !r { continue; }
        let core = affinities[i].unwrap_or(0);
        // Thermal envelope is a hard constraint on the physical load fraction
        if thermal.would_violate(core, m.cpu_load) { continue; }

        let marginal = cost_function(
            core::slice::from_ref(m),
            core::slice::from_ref(&r),
            weights,
        );

        let _ = candidates.push((i, marginal));
    }

    // Minimize J: ascending marginal cost (β<0 makes high throughput best)
    candidates.sort_unstable_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(core::cmp::Ordering::Equal));

    // Assign time slices greedily
    let mut schedule = heapless::Vec::<(usize, u64), MAX_PROCESSES>::new();
    let mut remaining = time_budget_ns;

    for &(idx, _) in &candidates {
        if remaining == 0 { break; }
        let slice = (remaining / (candidates.len() - schedule.len()) as u64).max(100_000);
        let _ = schedule.push((idx, slice.min(remaining)));
        remaining -= slice.min(remaining);
    }

    schedule
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scheduler_state_creation() {
        let sched = SchedulerState::new(4, 10_000_000);
        assert_eq!(sched.thermal.active_cores, 4);
        assert_eq!(sched.core_time_budget_ns, 10_000_000);
    }

    #[test]
    fn test_add_process() {
        let mut sched = SchedulerState::new(4, 10_000_000);
        sched.add_process(1, SchedProfile::Interactive, Some(0)).unwrap();
        assert_eq!(sched.processes.len(), 1);
        assert_eq!(sched.runnable[0], true);
        assert_eq!(sched.affinity[0], Some(0));
    }

    #[test]
    fn test_priority_computation() {
        let mut sched = SchedulerState::new(4, 10_000_000);
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
        let metrics = sched.processes[0];
        assert!(metrics.priority > 0.0);
    }

    #[test]
    fn test_thermal_model_update() {
        let mut thermal = ThermalState::new(2);
        thermal.heating_coeff = 0.1;
        thermal.cooling_coeff = 0.05;
        thermal.core_temps[0] = 0.5;
        thermal.core_temps[1] = 0.3;

        thermal.update(&[1.0, 0.0], 1_000_000_000);

        assert!(thermal.core_temps[0] > 0.5);
        assert!(thermal.core_temps[1] < 0.3);
    }

    #[test]
    fn test_thermal_violation_check() {
        let mut thermal = ThermalState::new(1);
        thermal.temp_max = 0.8;
        thermal.core_temps[0] = 0.75;
        thermal.heating_coeff = 0.1;

        assert!(thermal.would_violate(0, 0.6));
        assert!(!thermal.would_violate(0, 0.4));
    }

    #[test]
    fn test_process_selection_respects_thermal() {
        let mut sched = SchedulerState::new(2, 10_000_000);
        sched.add_process(1, SchedProfile::Interactive, Some(0)).unwrap();
        sched.add_process(2, SchedProfile::Batch, Some(1)).unwrap();

        sched.thermal.core_temps[0] = 0.84;
        sched.thermal.core_temps[1] = 0.3;
        sched.thermal.temp_max = 0.85;

        let measurements = [
            ProcessMeasurement { index: 0, latency_ns: 1_000_000, dt_ns: 10_000_000, instructions_retired: 1_000_000, cache_misses: 100, cpu_load: 0.8 },
            ProcessMeasurement { index: 1, latency_ns: 50_000_000, dt_ns: 10_000_000, instructions_retired: 5_000_000, cache_misses: 50, cpu_load: 0.3 },
        ];

        sched.update_metrics(&measurements);

        let selected = sched.select_process();
        assert_eq!(selected, Some(1));
    }

    #[test]
    fn test_cost_function() {
        let processes = [
            SchedMetrics { latency: 10.0, throughput: 100.0, thermal_cost: 0.5, ..Default::default() },
            SchedMetrics { latency: 5.0, throughput: 50.0, thermal_cost: 0.3, ..Default::default() },
        ];
        let runnable = [true, true];
        let weights = SchedulerWeights::default();

        let cost = cost_function(&processes, &runnable, &weights);
        assert!((cost - (-134.6)).abs() < 0.01);
    }

    #[test]
    fn test_optimize_schedule_basic() {
        let processes = [
            SchedMetrics { latency: 1.0, throughput: 10.0, thermal_cost: 0.1, ..Default::default() },
            SchedMetrics { latency: 20.0, throughput: 50.0, thermal_cost: 0.1, ..Default::default() },
            SchedMetrics { latency: 100.0, throughput: 200.0, thermal_cost: 1.0, ..Default::default() },
        ];
        let runnable = [true, true, true];
        let thermal = ThermalState::new(1);
        let affinities = [Some(0), Some(0), Some(0)];
        // Use weights that heavily prioritize latency and heavily penalize thermal
        let weights = SchedulerWeights {
            w_latency: 10.0,
            w_throughput: 0.01,
            w_thermal: 5.0,
            alpha: 10.0,
            beta: -0.01,
            gamma: 5.0,
        };

        let schedule = optimize_schedule(&processes, &runnable, &thermal, &affinities, &weights, 10_000_000);

        assert!(!schedule.is_empty());
        assert_eq!(schedule.iter().map(|(_, s)| s).sum::<u64>(), 10_000_000);
        // Process 0 has lowest latency and thermal cost, should be scheduled first
        assert_eq!(schedule[0].0, 0);
    }

    #[test]
    fn test_time_slice_assignment_by_profile() {
        let mut sched = SchedulerState::new(1, 10_000_000);
        sched.add_process(1, SchedProfile::Interactive, Some(0)).unwrap();
        sched.add_process(2, SchedProfile::Batch, Some(0)).unwrap();
        sched.add_process(3, SchedProfile::Background, Some(0)).unwrap();

        let slice_interactive = sched.assign_time_slice(0);
        let slice_batch = sched.assign_time_slice(1);
        let slice_background = sched.assign_time_slice(2);

        assert!(slice_interactive < slice_batch);
        assert!(slice_background < slice_interactive);
    }

    #[test]
    fn test_real_time_profile_priority() {
        let mut sched = SchedulerState::new(1, 10_000_000);
        sched.add_process(1, SchedProfile::RealTime { deadline_ns: 1_000_000 }, Some(0)).unwrap();
        sched.add_process(2, SchedProfile::Interactive, Some(0)).unwrap();

        // Real-time process: very low latency, moderate throughput
        // Interactive process: higher latency, but much higher throughput
        // RealTime weights: w_latency=5, w_throughput=1, w_thermal=0.2
        // Interactive weights: w_latency=2, w_throughput=0.5, w_thermal=0.3
        let measurements = [
            ProcessMeasurement { index: 0, latency_ns: 10_000, dt_ns: 10_000_000, instructions_retired: 5_000_000, cache_misses: 10, cpu_load: 0.2 },
            ProcessMeasurement { index: 1, latency_ns: 5_000_000, dt_ns: 10_000_000, instructions_retired: 1_000_000, cache_misses: 50, cpu_load: 0.5 },
        ];

        sched.update_metrics(&measurements);

        // RealTime process (index 0) has lower latency (10μs vs 5ms) and higher throughput (5M vs 1M)
        // Should have higher priority with RealTime weights
        assert!(sched.processes[0].priority > sched.processes[1].priority,
            "RealTime priority {:.2} should exceed Interactive priority {:.2}",
            sched.processes[0].priority, sched.processes[1].priority);
    }

    #[test]
    fn test_selected_pid_is_real_pid() {
        let mut sched = SchedulerState::new(1, 10_000_000);
        sched.add_process(101, SchedProfile::Interactive, Some(0)).unwrap();
        sched.add_process(202, SchedProfile::Batch, Some(0)).unwrap();

        let measurements = [
            ProcessMeasurement { index: 0, latency_ns: 1_000_000, dt_ns: 10_000_000, instructions_retired: 1_000_000, cache_misses: 100, cpu_load: 0.3 },
            ProcessMeasurement { index: 1, latency_ns: 2_000_000, dt_ns: 10_000_000, instructions_retired: 1_000_000, cache_misses: 100, cpu_load: 0.3 },
        ];
        sched.update_metrics(&measurements);

        let decision = sched.tick(&measurements);
        assert!(!decision.is_idle());
        // Process 0 (pid 101) has lower latency -> higher priority; the
        // decision must carry the real pid, not the table index.
        assert_eq!(decision.selected_pid, 101);

        // Pid must remain correct after removing another process shifts indices
        sched.remove_process(1);
        let decision = sched.tick(&measurements);
        assert_eq!(decision.selected_pid, 101);
    }

    #[test]
    fn test_throughput_normalized_against_reference() {
        let mut sched = SchedulerState::new(1, 10_000_000);
        sched.add_process(1, SchedProfile::Batch, Some(0)).unwrap();

        let measurements = [ProcessMeasurement {
            index: 0,
            latency_ns: 0,
            dt_ns: 10_000_000,
            instructions_retired: 1_000_000,
            cache_misses: 100,
            cpu_load: 0.5,
        }];
        sched.update_metrics(&measurements);
        // 1e6 instr / 10 ms = 1e8 instr/s; / 1e9 reference = 0.1
        assert!((sched.processes[0].throughput - 0.1).abs() < 1e-9);
    }

    #[test]
    fn test_optimize_schedule_minimizes_cost_function() {
        let processes = [
            SchedMetrics { latency: 10.0, throughput: 10.0, thermal_cost: 0.1, cpu_load: 0.1, ..Default::default() },
            SchedMetrics { latency: 10.0, throughput: 1000.0, thermal_cost: 0.1, cpu_load: 0.1, ..Default::default() },
        ];
        let runnable = [true, true];
        let thermal = ThermalState::new(1);
        let affinities = [Some(0), Some(0)];
        let weights = SchedulerWeights::default();

        let schedule = optimize_schedule(&processes, &runnable, &thermal, &affinities, &weights, 10_000_000);

        // Marginal J: p0 = 10 - 10 + 0.05 = 0.05; p1 = 10 - 1000 + 0.05 = -989.95.
        // Minimizing J schedules the higher-throughput process first.
        assert_eq!(schedule[0].0, 1);
    }
}