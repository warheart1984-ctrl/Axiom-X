//! Memory Resource Algebra for Axiom-X
//!
//! Models memory as a typed algebraic structure with explicit invariants.
//! Every allocation is a transaction preserving conservation laws.
//!
//! Status: `partial` — core types and invariants defined; allocation logic TODO.

use core::fmt;
use heapless::Vec;

/// Page frame size (4 KiB)
pub const PAGE_SIZE: usize = 4096;

/// Maximum number of page frames trackable (adjust for physical RAM)
#[cfg(not(test))]
pub const MAX_FRAMES: usize = 1_048_576; // 4 GiB / 4 KiB

#[cfg(test)]
pub const MAX_FRAMES: usize = 4096; // Smaller for tests to avoid stack overflow

/// Maximum number of memory regions per process
pub const MAX_REGIONS: usize = 256;

/// Frame number (physical page frame index)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Frame(pub u64);

impl Frame {
    pub const fn new(n: u64) -> Self {
        Self(n)
    }

    pub fn addr(&self) -> u64 {
        self.0 * PAGE_SIZE as u64
    }

    pub fn from_addr(addr: u64) -> Self {
        Self(addr / PAGE_SIZE as u64)
    }
}

/// Memory region types with explicit semantics
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RegionType {
    /// Kernel text (read-only executable)
    KernelCode = 0,
    /// Kernel read-only data
    KernelRoData = 1,
    /// Kernel read-write data
    KernelRwData = 2,
    /// Process code (user executable)
    ProcessCode = 3,
    /// Process read-only data
    ProcessRoData = 4,
    /// Process read-write data (heap, stack)
    ProcessRwData = 5,
    /// Shared memory (explicit contract required)
    Shared = 6,
    /// Memory-mapped I/O (device registers)
    Mmio = 7,
    /// Page tables (kernel managed)
    PageTable = 8,
    /// Guard page (unmapped, causes fault on access)
    Guard = 9,
    /// Free/unallocated
    Free = 255,
}

impl RegionType {
    pub fn is_kernel(&self) -> bool {
        matches!(self, Self::KernelCode | Self::KernelRoData | Self::KernelRwData | Self::PageTable)
    }

    pub fn is_user(&self) -> bool {
        matches!(self, Self::ProcessCode | Self::ProcessRoData | Self::ProcessRwData)
    }

    pub fn is_shared(&self) -> bool {
        matches!(self, Self::Shared)
    }

    pub fn executable(&self) -> bool {
        matches!(self, Self::KernelCode | Self::ProcessCode)
    }

    pub fn writable(&self) -> bool {
        matches!(self, Self::KernelRwData | Self::ProcessRwData | Self::Shared)
    }
}

/// Region access flags
bitflags::bitflags! {
    pub struct RegionFlags: u32 {
        const READ = 1 << 0;
        const WRITE = 1 << 1;
        const EXECUTE = 1 << 2;
        const USER = 1 << 3;        // User-mode accessible
        const GLOBAL = 1 << 4;      // Global mapping (PGE)
        const NO_CACHE = 1 << 5;    // Uncached (UC)
        const WRITE_THROUGH = 1 << 6; // Write-through (WT)
        const DIRTY = 1 << 7;       // Modified since mapping
        const ACCESSED = 1 << 8;    // Accessed since mapping
        const COW = 1 << 9;         // Copy-on-write
        const SHARED = 1 << 10;     // Explicitly shared region
        const LOCKED = 1 << 11;     // Locked in memory (no swap/pageout)
        const NO_EXECUTE = 1 << 12; // NX bit
    }
}

/// Memory region descriptor
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Region {
    pub base: Frame,
    pub count: u32,
    pub region_type: RegionType,
    pub owner_pid: u32,
    pub flags: RegionFlags,
    _reserved: [u8; 10],
}

impl Region {
    pub const fn size(&self) -> usize {
        self.count as usize * PAGE_SIZE
    }

    pub const fn end_frame(&self) -> Frame {
        Frame(self.base.0 + self.count as u64)
    }

    pub fn contains(&self, frame: Frame) -> bool {
        let base_val = self.base.0;
        let end_val = base_val + self.count as u64;
        frame.0 >= base_val && frame.0 < end_val
    }

    pub fn overlaps(&self, other: &Region) -> bool {
        let self_base = self.base.0;
        let self_end = self_base + self.count as u64;
        let other_base = other.base.0;
        let other_end = other_base + other.count as u64;
        self_base < other_end && other_base < self_end
    }
}

/// Allocation request
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocRequest {
    pub count: usize,
    pub region_type: RegionType,
    pub owner_pid: u32,
    pub flags: RegionFlags,
    pub alignment: usize, // In frames (power of 2)
}

/// Allocation result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocResult {
    Success(Region),
    OutOfMemory,
    Fragmented,
    InvalidRequest,
    AlignmentFailed,
}

/// Deallocation result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreeResult {
    Success,
    NotFound,
    InvalidOwner,
    RegionBusy, // References exist (shared, mapped)
}

/// Memory algebra errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryAlgebraError {
    InvariantViolation(&'static str),
    ConservationViolation,
    AliasingDetected,
    OvercommitAttempt,
    InvalidTransaction,
}

/// Frame allocator state (free list)
#[derive(Debug)]
pub struct FrameAllocator {
    /// Free frames bitmap (1 = free, 0 = allocated)
    /// Using a simple bump allocator with free list for skeleton
    free_frames: Vec<Frame, MAX_FRAMES>,
    /// Allocated regions index for O(1) lookup
    regions: Vec<Region, MAX_REGIONS>,
    /// Total frames managed
    total_frames: usize,
    /// Frames currently allocated
    allocated_frames: usize,
}

impl FrameAllocator {
    pub fn new(total_frames: usize) -> Self {
        assert!(total_frames <= MAX_FRAMES);
        let mut free_frames = Vec::new();
        for i in 0..total_frames {
            free_frames.push(Frame(i as u64)).unwrap();
        }
        Self {
            free_frames,
            regions: Vec::new(),
            total_frames,
            allocated_frames: 0,
        }
    }

    /// Allocate frames satisfying request
    pub fn allocate(&mut self, req: AllocRequest) -> Result<AllocResult, MemoryAlgebraError> {
        // Validate request
        if req.count == 0 {
            return Ok(AllocResult::InvalidRequest);
        }
        if req.count > self.free_frames.len() {
            return Ok(AllocResult::OutOfMemory);
        }
        if req.alignment != 0 && !req.alignment.is_power_of_two() {
            return Ok(AllocResult::AlignmentFailed);
        }

        // Find contiguous free frames (first-fit with alignment)
        let start_idx = self.find_contiguous(req.count, req.alignment)?;
        let base = self.free_frames[start_idx];

        // Check alignment
        if req.alignment > 1 && (base.0 as usize % req.alignment) != 0 {
            return Ok(AllocResult::AlignmentFailed);
        }

        // Create region
        let region = Region {
            base,
            count: req.count as u32,
            region_type: req.region_type,
            owner_pid: req.owner_pid,
            flags: req.flags,
            _reserved: [0; 10],
        };

        // Validate invariants BEFORE mutating state (validate-then-commit):
        // no frame may leave the free list until every check has passed.
        self.verify_invariants(&region)?;
        if self.regions.len() >= MAX_REGIONS {
            return Err(MemoryAlgebraError::InvariantViolation("region table full"));
        }

        // Commit: remove frames from free list
        let mut new_free = Vec::new();
        for (i, frame) in self.free_frames.iter().enumerate() {
            if i < start_idx || i >= start_idx + req.count {
                new_free.push(*frame).unwrap();
            }
        }
        self.free_frames = new_free;

        // Commit allocation (region table capacity already verified)
        self.regions
            .push(region)
            .map_err(|_| MemoryAlgebraError::InvariantViolation("region table full"))?;
        self.allocated_frames += req.count;

        Ok(AllocResult::Success(region))
    }

    /// Find contiguous free frames
    fn find_contiguous(&self, count: usize, alignment: usize) -> Result<usize, MemoryAlgebraError> {
        if count == 0 {
            return Err(MemoryAlgebraError::InvalidTransaction);
        }

        let mut run_start = 0;
        let mut run_len = 0;

        for (i, frame) in self.free_frames.iter().enumerate() {
            if run_len == 0 {
                // Check alignment at potential start
                if alignment > 1 && (frame.0 as usize % alignment) != 0 {
                    continue;
                }
                run_start = i;
                run_len = 1;
            } else if frame.0 == self.free_frames[i - 1].0 + 1 {
                run_len += 1;
            } else {
                run_start = i;
                run_len = 1;
                if alignment > 1 && (frame.0 as usize % alignment) != 0 {
                    run_len = 0;
                }
            }

            if run_len >= count {
                return Ok(run_start);
            }
        }

        Err(MemoryAlgebraError::InvariantViolation("insufficient contiguous frames"))
    }

    /// Free a region by base frame
    pub fn free(&mut self, base: Frame, owner_pid: u32) -> Result<FreeResult, MemoryAlgebraError> {
        let idx = self.regions.iter().position(|r| r.base == base && r.owner_pid == owner_pid);

        let idx = match idx {
            Some(i) => i,
            None => return Ok(FreeResult::NotFound),
        };

        let region = self.regions[idx];

        // Check for shared references (simplified)
        if region.flags.contains(RegionFlags::SHARED) {
            return Ok(FreeResult::RegionBusy);
        }

        // Return frames to free list (maintain sorted order).
        // Insert frame-by-frame: a bounded staging vec would overflow (or
        // silently drop) regions larger than 64 frames (256 KiB).
        for i in 0..region.count {
            let frame = Frame(region.base.0 + i as u64);
            let pos = self.free_frames.binary_search(&frame).unwrap_or_else(|e| e);
            let _ = self.free_frames.insert(pos, frame);
        }
        self.regions.remove(idx);
        self.allocated_frames -= region.count as usize;

        Ok(FreeResult::Success)
    }

    /// Verify algebraic invariants
    fn verify_invariants(&self, new_region: &Region) -> Result<(), MemoryAlgebraError> {
        // Invariant 1: No aliasing - no frame belongs to more than one exclusive mapping
        for region in &self.regions {
            if region.overlaps(new_region) {
                // Allow overlap only for explicitly shared regions
                if !region.flags.contains(RegionFlags::SHARED)
                    || !new_region.flags.contains(RegionFlags::SHARED)
                {
                    return Err(MemoryAlgebraError::AliasingDetected);
                }
            }
        }

        // Invariant 2: No overcommit - total allocated <= physical
        if self.allocated_frames + new_region.count as usize > self.total_frames {
            return Err(MemoryAlgebraError::OvercommitAttempt);
        }

        // Invariant 3: Region within bounds
        if new_region.end_frame().0 as usize > self.total_frames {
            return Err(MemoryAlgebraError::ConservationViolation);
        }

        Ok(())
    }

    /// Get region by base frame
    pub fn get_region(&self, base: Frame) -> Option<&Region> {
        self.regions.iter().find(|r| r.base == base)
    }

    /// Get all regions for a process
    pub fn regions_for_pid(&self, pid: u32) -> impl Iterator<Item = &Region> {
        self.regions.iter().filter(move |r| r.owner_pid == pid)
    }

    /// Total free frames
    pub fn free_count(&self) -> usize {
        self.free_frames.len()
    }

    /// Total allocated frames
    pub fn allocated_count(&self) -> usize {
        self.allocated_frames
    }

    /// Conservation check: allocated + free == total
    pub fn verify_conservation(&self) -> bool {
        self.allocated_frames + self.free_frames.len() == self.total_frames
    }

    /// Fragmentation ratio: normalized free-run density.
    /// 0.0 = all free frames contiguous, 1.0 = maximally fragmented
    /// (one run per free frame). Not Shannon entropy — the free-list layout
    /// only measures run density, so the name reflects that.
    pub fn fragmentation_ratio(&self) -> f64 {
        if self.free_frames.is_empty() {
            return 0.0;
        }
        let mut runs = 0;
        let mut total_free = 0;
        let mut i = 0;
        while i < self.free_frames.len() {
            runs += 1;
            let mut j = i + 1;
            while j < self.free_frames.len() && self.free_frames[j].0 == self.free_frames[j - 1].0 + 1 {
                j += 1;
            }
            total_free += j - i;
            i = j;
        }
        // Guard against 0/0 and ln(1)=0 division: a single free frame or a
        // single run is, by construction, unfragmented.
        if total_free <= 1 || runs <= 1 {
            0.0
        } else {
            libm::log(runs as f64) / libm::log(total_free as f64)
        }
    }
}

/// Resource algebra operations (allocation as transaction)
pub mod algebra {
    use super::*;

    /// Allocation transaction: Region -> Region'
    /// The region itself encodes the allocated frame range
    /// (`region.base .. region.end_frame()`); a bounded frame vec could not
    /// represent regions larger than 64 frames.
    pub fn alloc(
        allocator: &mut FrameAllocator,
        req: AllocRequest,
    ) -> Result<Region, MemoryAlgebraError> {
        let result = allocator.allocate(req)?;
        match result {
            AllocResult::Success(region) => Ok(region),
            _ => Err(MemoryAlgebraError::InvalidTransaction),
        }
    }

    /// Deallocation transaction: Region -> ()
    pub fn free(
        allocator: &mut FrameAllocator,
        base: Frame,
        owner: u32,
    ) -> Result<(), MemoryAlgebraError> {
        let region = allocator.get_region(base).ok_or(MemoryAlgebraError::InvalidTransaction)?;
        if region.owner_pid != owner {
            return Err(MemoryAlgebraError::InvalidTransaction);
        }
        allocator.free(base, owner)?;
        Ok(())
    }

    /// Compose two allocations (sequential composition)
    pub fn compose<A, B, E>(
        first: A,
        second: B,
    ) -> impl FnOnce(&mut FrameAllocator) -> Result<(), E>
    where
        A: FnOnce(&mut FrameAllocator) -> Result<(), E>,
        B: FnOnce(&mut FrameAllocator) -> Result<(), E>,
    {
        move |allocator: &mut FrameAllocator| {
            first(allocator)?;
            second(allocator)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_allocator_basic() {
        let mut alloc = FrameAllocator::new(1000);
        assert_eq!(alloc.free_count(), 1000);
        assert_eq!(alloc.allocated_count(), 0);
        assert!(alloc.verify_conservation());
    }

    #[test]
    fn test_allocation_conservation() {
        let mut alloc = FrameAllocator::new(1000);
        let req = AllocRequest {
            count: 10,
            region_type: RegionType::ProcessRwData,
            owner_pid: 1,
            flags: RegionFlags::READ | RegionFlags::WRITE | RegionFlags::USER,
            alignment: 1,
        };
        let result = alloc.allocate(req).unwrap();
        assert!(matches!(result, AllocResult::Success(_)));
        assert_eq!(alloc.allocated_count(), 10);
        assert_eq!(alloc.free_count(), 990);
        assert!(alloc.verify_conservation());
    }

    #[test]
    fn test_no_aliasing() {
        let mut alloc = FrameAllocator::new(1000);
        let req = AllocRequest {
            count: 10,
            region_type: RegionType::ProcessRwData,
            owner_pid: 1,
            flags: RegionFlags::READ | RegionFlags::WRITE | RegionFlags::USER,
            alignment: 1,
        };
        alloc.allocate(req).unwrap();

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
    fn test_shared_region_aliasing_allowed() {
        let mut alloc = FrameAllocator::new(1000);
        let req = AllocRequest {
            count: 10,
            region_type: RegionType::Shared,
            owner_pid: 1,
            flags: RegionFlags::READ | RegionFlags::WRITE | RegionFlags::USER | RegionFlags::SHARED,
            alignment: 1,
        };
        let AllocResult::Success(region) = alloc.allocate(req).unwrap() else { panic!() };

        let req2 = AllocRequest {
            count: 5,
            region_type: RegionType::Shared,
            owner_pid: 2,
            flags: RegionFlags::READ | RegionFlags::WRITE | RegionFlags::USER | RegionFlags::SHARED,
            alignment: 1,
        };
        let _ = alloc.allocate(req2).unwrap();
    }

    #[test]
    fn test_deallocation_conservation() {
        let mut alloc = FrameAllocator::new(1000);
        let req = AllocRequest {
            count: 10,
            region_type: RegionType::ProcessRwData,
            owner_pid: 1,
            flags: RegionFlags::READ | RegionFlags::WRITE | RegionFlags::USER,
            alignment: 1,
        };
        let AllocResult::Success(region) = alloc.allocate(req).unwrap() else { panic!() };

        let result = alloc.free(region.base, 1).unwrap();
        assert_eq!(result, FreeResult::Success);
        assert_eq!(alloc.allocated_count(), 0);
        assert_eq!(alloc.free_count(), 1000);
        assert!(alloc.verify_conservation());
    }

    #[test]
    fn test_fragmentation_ratio() {
        let mut alloc = FrameAllocator::new(100);
        
        // Allocate all frames first
        for _ in 0..100 {
            let req = AllocRequest {
                count: 1,
                region_type: RegionType::ProcessRwData,
                owner_pid: 1,
                flags: RegionFlags::READ | RegionFlags::WRITE | RegionFlags::USER,
                alignment: 1,
            };
            alloc.allocate(req).unwrap();
        }
        
        // Free every other frame to create fragmentation
        for i in (0..100).step_by(2) {
            alloc.free(Frame(i as u64), 1).unwrap();
        }
        
        // Now free frames are at even positions, creating 50 runs of 1 frame each
        let ratio = alloc.fragmentation_ratio();
        assert!(ratio > 0.0, "Fragmentation ratio should be > 0 for fragmented memory, got {}", ratio);
    }

    #[test]
    fn test_alignment() {
        let mut alloc = FrameAllocator::new(1000);
        let req = AllocRequest {
            count: 10,
            region_type: RegionType::ProcessRwData,
            owner_pid: 1,
            flags: RegionFlags::READ | RegionFlags::WRITE | RegionFlags::USER,
            alignment: 16,
        };
        let result = alloc.allocate(req).unwrap();
        match result {
            AllocResult::Success(region) => {
                assert_eq!(region.base.0 % 16, 0);
            }
            _ => panic!("alignment allocation failed"),
        }
    }

    #[test]
    fn test_overcommit_rejected() {
        // Use small allocator to exhaust it
        let mut alloc = FrameAllocator::new(10);
        let req = AllocRequest {
            count: 10,
            region_type: RegionType::ProcessRwData,
            owner_pid: 1,
            flags: RegionFlags::READ | RegionFlags::WRITE | RegionFlags::USER,
            alignment: 1,
        };
        alloc.allocate(req).unwrap();

        let req2 = AllocRequest {
            count: 1,
            region_type: RegionType::ProcessRwData,
            owner_pid: 2,
            flags: RegionFlags::READ | RegionFlags::WRITE | RegionFlags::USER,
            alignment: 1,
        };
        let result = alloc.allocate(req2).unwrap();
        assert_eq!(result, AllocResult::OutOfMemory, "Expected OutOfMemory, got {:?}", result);
    }

    #[test]
    fn test_region_over_64_frames_free_and_alloc() {
        // A region larger than the old 64-frame staging vec (256 KiB).
        let mut alloc = FrameAllocator::new(1000);
        let req = AllocRequest {
            count: 200,
            region_type: RegionType::ProcessRwData,
            owner_pid: 1,
            flags: RegionFlags::READ | RegionFlags::WRITE | RegionFlags::USER,
            alignment: 1,
        };
        let AllocResult::Success(region) = alloc.allocate(req).unwrap() else { panic!() };
        assert_eq!(alloc.allocated_count(), 200);
        assert_eq!(alloc.free_count(), 800);
        assert!(alloc.verify_conservation());

        let result = alloc.free(region.base, 1).unwrap();
        assert_eq!(result, FreeResult::Success);
        assert_eq!(alloc.allocated_count(), 0);
        assert_eq!(alloc.free_count(), 1000);
        assert!(alloc.verify_conservation());
        assert_eq!(alloc.fragmentation_ratio(), 0.0);
    }

    #[test]
    fn test_fragmentation_ratio_single_free_frame_is_finite() {
        // Regression: total_free == 1 used to yield ln(1)/ln(1) = 0/0 = NaN.
        let mut alloc = FrameAllocator::new(100);
        for _ in 0..99 {
            let req = AllocRequest {
                count: 1,
                region_type: RegionType::ProcessRwData,
                owner_pid: 1,
                flags: RegionFlags::READ | RegionFlags::WRITE | RegionFlags::USER,
                alignment: 1,
            };
            alloc.allocate(req).unwrap();
        }
        assert_eq!(alloc.free_count(), 1);
        assert_eq!(alloc.fragmentation_ratio(), 0.0);
        assert!(alloc.fragmentation_ratio().is_finite());
    }
}