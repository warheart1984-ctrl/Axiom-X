//! Axiom-X Syscall Interface
//!
//! Core syscall numbers and structures for Axiom-X microkernel.
//! Includes both POSIX-compatible syscalls and Axiom-X native syscalls.
//!
//! Status: `declared` — interface defined; implementation in kernel crate.

#![no_std]

use core::arch::asm;
use core::fmt;
use axiom_x_math::memory_algebra::{RegionType, RegionFlags};
use axiom_x_math::scheduler_math::{SchedProfile, SchedulerWeights};
use zerocopy::{IntoBytes, FromZeros, Immutable, KnownLayout};

/// Syscall numbers (matching Linux x86_64 where compatible)
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromZeros, Immutable, KnownLayout)]
pub enum SyscallNumber {
    // Process management
    Read = 0,
    Write = 1,
    Open = 2,
    Close = 3,
    Stat = 4,
    Fstat = 5,
    Lstat = 6,
    Poll = 7,
    Lseek = 8,
    Mmap = 9,
    Mprotect = 10,
    Munmap = 11,
    Brk = 12,
    RtSigaction = 13,
    RtSigprocmask = 14,
    RtSigreturn = 15,
    Ioctl = 16,
    Pread64 = 17,
    Pwrite64 = 18,
    Readv = 19,
    Writev = 20,
    Access = 21,
    Pipe = 22,
    Select = 23,
    SchedYield = 24,
    Mremap = 25,
    Msync = 26,
    Mincore = 27,
    Madvise = 28,
    Shmget = 29,
    Shmat = 30,
    Shmctl = 31,
    Dup = 32,
    Dup2 = 33,
    Pause = 34,
    Nanosleep = 35,
    Getitimer = 36,
    Alarm = 37,
    Setitimer = 38,
    Getpid = 39,
    Sendfile = 40,
    Socket = 41,
    Connect = 42,
    Accept = 43,
    Sendto = 44,
    Recvfrom = 45,
    Sendmsg = 46,
    Recvmsg = 47,
    Shutdown = 48,
    Bind = 49,
    Listen = 50,
    Getsockname = 51,
    Getsockopt = 52,
    Setsockopt = 53,
    Clone = 56,
    Fork = 57,
    Vfork = 58,
    Execve = 59,
    Exit = 60,
    Wait4 = 61,
    Kill = 62,
    Uname = 63,
    Semget = 64,
    Semop = 65,
    Semctl = 66,
    Shmdt = 67,
    Msgget = 68,
    Msgsnd = 69,
    Msgrcv = 70,
    Msgctl = 71,
    Fcntl = 72,
    Flock = 73,
    Fsync = 74,
    Fdatasync = 75,
    Truncate = 76,
    Ftruncate = 77,
    Getdents = 78,
    Getcwd = 79,
    Chdir = 80,
    Fchdir = 81,
    Rename = 82,
    Mkdir = 83,
    Rmdir = 84,
    Creat = 85,
    Link = 86,
    Unlink = 87,
    Symlink = 88,
    Readlink = 89,
    Chmod = 90,
    Fchmod = 91,
    Chown = 92,
    Fchown = 93,
    Lchown = 94,
    Umask = 95,
    Gettimeofday = 96,
    Getrlimit = 97,
    Getrusage = 98,
    Sysinfo = 99,
    Times = 100,
    Ptrace = 101,
    Getuid = 102,
    Syslog = 103,
    Getgid = 104,
    Setuid = 105,
    Setgid = 106,
    Geteuid = 107,
    Getegid = 108,
    Setpgid = 109,
    Getppid = 110,
    Getpgrp = 111,
    Setsid = 112,
    Setreuid = 113,
    Setregid = 114,
    Getgroups = 115,
    Setgroups = 116,
    Setresuid = 117,
    Getresuid = 118,
    Setresgid = 119,
    Getresgid = 120,
    Getpgid = 121,
    Setfsuid = 122,
    Setfsgid = 123,
    Getsid = 124,
    Capget = 125,
    Capset = 126,
    RtSigpending = 127,
    RtSigtimedwait = 128,
    RtSigqueueinfo = 129,
    RtSigsuspend = 130,
    Sigaltstack = 131,
    Utime = 132,
    Mknod = 133,
    Uselib = 134,
    Personality = 135,
    Ustat = 136,
    Statfs = 137,
    Fstatfs = 138,
    Sysfs = 139,
    Getpriority = 140,
    Setpriority = 141,
    SchedSetparam = 142,
    SchedGetparam = 143,
    SchedSetscheduler = 144,
    SchedGetscheduler = 145,
    SchedGetPriorityMax = 146,
    SchedGetPriorityMin = 147,
    SchedRrGetInterval = 148,
    Mlock = 149,
    Munlock = 150,
    Mlockall = 151,
    Munlockall = 152,
    Vhangup = 153,
    ModifyLdt = 154,
    PivotRoot = 155,
    Sysctl = 156,
    Prctl = 157,
    ArchPrctl = 158,
    Adjtimex = 159,
    Setrlimit = 160,
    Chroot = 161,
    Sync = 162,
    Acct = 163,
    Settimeofday = 164,
    Mount = 165,
    Umount2 = 166,
    Swapon = 167,
    Swapoff = 168,
    Reboot = 169,
    Sethostname = 170,
    Setdomainname = 171,
    Iopl = 172,
    Ioperm = 173,
    CreateModule = 174,
    InitModule = 175,
    DeleteModule = 176,
    GetKernelSyms = 177,
    QueryModule = 178,
    Quotactl = 179,
    Nfsservctl = 180,
    Getpmsg = 181,
    Putpmsg = 182,
    AfsSyscall = 183,
    Tuxcall = 184,
    Security = 185,
    Getdents64 = 217,
    Fcntl64 = 218,
    Stat64 = 220,
    Lstat64 = 221,
    Fstat64 = 222,
    Lchown32 = 223,
    Getuid32 = 224,
    Getgid32 = 225,
    Setuid32 = 226,
    Setgid32 = 227,
    Geteuid32 = 228,
    Getegid32 = 229,
    Setreuid32 = 230,
    Setregid32 = 231,
    Getgroups32 = 232,
    Setgroups32 = 233,
    Fchown32 = 234,
    Setresuid32 = 235,
    Getresuid32 = 236,
    Setresgid32 = 237,
    Getresgid32 = 238,
    Chown32 = 239,
    Setfsuid32 = 242,
    Setfsgid32 = 243,
    Mkdirat = 247,
    Mknodat = 248,
    Fchownat = 249,
    Futimesat = 250,
    Newfstatat = 251,
    Unlinkat = 252,
    Renameat = 253,
    Linkat = 254,
    Symlinkat = 255,
    Readlinkat = 256,
    Fchmodat = 257,
    Faccessat = 258,
    Pselect6 = 259,
    Ppoll = 260,
    Unshare = 261,
    SetRobustList = 262,
    GetRobustList = 263,
    Splice = 264,
    Tee = 265,
    Vmsplice = 266,
    MovePages = 267,
    Utimensat = 268,
    EpollCreate = 269,
    EpollCtl = 270,
    EpollWait = 271,
    EpollPwait = 272,
    Getcpu = 273,
    GetRandom = 274,
    MemfdCreate = 275,
    KexecFileLoad = 276,
    Bpf = 277,
    Execveat = 278,
    Userfaultfd = 279,
    Membarrier = 280,
    Mlock2 = 281,
    CopyFileRange = 282,
    Preadv2 = 283,
    Pwritev2 = 284,
    PkeyMprotect = 285,
    PkeyAlloc = 286,
    PkeyFree = 287,
    Statx = 288,
    IoPgetevents = 289,
    Rseq = 290,
    Kcmp = 291,
    Fadvise64 = 292,
    Waitid = 293,
    Clone3 = 294,
    Openat = 295,
    Mkdirat2 = 296,
    CloseRange = 297,
    Openat2 = 298,
    PidfdSendSignal = 299,
    IoUringSetup = 300,
    IoUringEnter = 301,
    IoUringRegister = 302,
    OpenTree = 303,
    MoveMount = 304,
    Fsopen = 305,
    Fsconfig = 306,
    Fsmount = 307,
    Fspick = 308,
    PidfdOpen = 309,
    CloseRange2 = 311,
    PidfdGetfd = 313,
    Faccessat2 = 314,
    ProcessMadvise = 315,
    EpollPwait2 = 316,
    MountSetattr = 317,
    QuotactlFd = 318,
    LandlockCreateRuleset = 319,
    LandlockAddRule = 320,
    LandlockRestrictSelf = 321,
    MemfdSecret = 322,
    ProcessMRelease = 323,
    FutexWaitv = 324,
    SetMemfdSecret = 325,

    // ========================================================================
    // Axiom-X Native Syscalls (500-599)
    // ========================================================================

    /// Set scheduling profile for current process
    AxSchedProfile = 500,

    /// Get evidence record for last kernel decision affecting process
    AxGetEvidence = 501,

    /// Request replay token for debugging
    AxReplayToken = 502,

    /// Request resource bundle (CPU, memory, I/O)
    AxAllocRes = 503,

    /// Free resource bundle
    AxFreeRes = 504,

    /// Create shared memory region with contract
    AxShare = 505,

    /// Enter isolation domain
    AxIsolate = 506,

    /// Check invariant
    AxVerifyInvariant = 507,

    /// Get kernel metrics
    AxGetMetrics = 508,

    /// Set thermal policy
    AxSetThermalPolicy = 509,

    /// Get thermal state
    AxGetThermalState = 510,

    /// Create process with explicit contract
    AxSpawn = 511,

    /// Wait for process with contract verification
    AxWaitContract = 512,

    /// Signal with evidence
    AxSignalEvidence = 513,
}

impl SyscallNumber {
    pub fn is_axiom_x(&self) -> bool {
        *self as u64 >= 500 && (*self as u64) < 600
    }

    pub fn is_posix(&self) -> bool {
        (*self as u64) < 500
    }
}

impl TryFrom<u64> for SyscallNumber {
    type Error = ();

    /// Convert a raw syscall number to its symbolic variant, if known.
    fn try_from(value: u64) -> Result<Self, Self::Error> {
        let n = match value {
            0 => Self::Read,
            1 => Self::Write,
            2 => Self::Open,
            3 => Self::Close,
            4 => Self::Stat,
            5 => Self::Fstat,
            6 => Self::Lstat,
            7 => Self::Poll,
            8 => Self::Lseek,
            9 => Self::Mmap,
            10 => Self::Mprotect,
            11 => Self::Munmap,
            12 => Self::Brk,
            13 => Self::RtSigaction,
            14 => Self::RtSigprocmask,
            15 => Self::RtSigreturn,
            16 => Self::Ioctl,
            17 => Self::Pread64,
            18 => Self::Pwrite64,
            19 => Self::Readv,
            20 => Self::Writev,
            21 => Self::Access,
            22 => Self::Pipe,
            23 => Self::Select,
            24 => Self::SchedYield,
            25 => Self::Mremap,
            26 => Self::Msync,
            27 => Self::Mincore,
            28 => Self::Madvise,
            29 => Self::Shmget,
            30 => Self::Shmat,
            31 => Self::Shmctl,
            32 => Self::Dup,
            33 => Self::Dup2,
            34 => Self::Pause,
            35 => Self::Nanosleep,
            36 => Self::Getitimer,
            37 => Self::Alarm,
            38 => Self::Setitimer,
            39 => Self::Getpid,
            40 => Self::Sendfile,
            41 => Self::Socket,
            42 => Self::Connect,
            43 => Self::Accept,
            44 => Self::Sendto,
            45 => Self::Recvfrom,
            46 => Self::Sendmsg,
            47 => Self::Recvmsg,
            48 => Self::Shutdown,
            49 => Self::Bind,
            50 => Self::Listen,
            51 => Self::Getsockname,
            52 => Self::Getsockopt,
            53 => Self::Setsockopt,
            56 => Self::Clone,
            57 => Self::Fork,
            58 => Self::Vfork,
            59 => Self::Execve,
            60 => Self::Exit,
            61 => Self::Wait4,
            62 => Self::Kill,
            63 => Self::Uname,
            64 => Self::Semget,
            65 => Self::Semop,
            66 => Self::Semctl,
            67 => Self::Shmdt,
            68 => Self::Msgget,
            69 => Self::Msgsnd,
            70 => Self::Msgrcv,
            71 => Self::Msgctl,
            72 => Self::Fcntl,
            73 => Self::Flock,
            74 => Self::Fsync,
            75 => Self::Fdatasync,
            76 => Self::Truncate,
            77 => Self::Ftruncate,
            78 => Self::Getdents,
            79 => Self::Getcwd,
            80 => Self::Chdir,
            81 => Self::Fchdir,
            82 => Self::Rename,
            83 => Self::Mkdir,
            84 => Self::Rmdir,
            85 => Self::Creat,
            86 => Self::Link,
            87 => Self::Unlink,
            88 => Self::Symlink,
            89 => Self::Readlink,
            90 => Self::Chmod,
            91 => Self::Fchmod,
            92 => Self::Chown,
            93 => Self::Fchown,
            94 => Self::Lchown,
            95 => Self::Umask,
            96 => Self::Gettimeofday,
            97 => Self::Getrlimit,
            98 => Self::Getrusage,
            99 => Self::Sysinfo,
            100 => Self::Times,
            101 => Self::Ptrace,
            102 => Self::Getuid,
            103 => Self::Syslog,
            104 => Self::Getgid,
            105 => Self::Setuid,
            106 => Self::Setgid,
            107 => Self::Geteuid,
            108 => Self::Getegid,
            109 => Self::Setpgid,
            110 => Self::Getppid,
            111 => Self::Getpgrp,
            112 => Self::Setsid,
            113 => Self::Setreuid,
            114 => Self::Setregid,
            115 => Self::Getgroups,
            116 => Self::Setgroups,
            117 => Self::Setresuid,
            118 => Self::Getresuid,
            119 => Self::Setresgid,
            120 => Self::Getresgid,
            121 => Self::Getpgid,
            122 => Self::Setfsuid,
            123 => Self::Setfsgid,
            124 => Self::Getsid,
            125 => Self::Capget,
            126 => Self::Capset,
            127 => Self::RtSigpending,
            128 => Self::RtSigtimedwait,
            129 => Self::RtSigqueueinfo,
            130 => Self::RtSigsuspend,
            131 => Self::Sigaltstack,
            132 => Self::Utime,
            133 => Self::Mknod,
            134 => Self::Uselib,
            135 => Self::Personality,
            136 => Self::Ustat,
            137 => Self::Statfs,
            138 => Self::Fstatfs,
            139 => Self::Sysfs,
            140 => Self::Getpriority,
            141 => Self::Setpriority,
            142 => Self::SchedSetparam,
            143 => Self::SchedGetparam,
            144 => Self::SchedSetscheduler,
            145 => Self::SchedGetscheduler,
            146 => Self::SchedGetPriorityMax,
            147 => Self::SchedGetPriorityMin,
            148 => Self::SchedRrGetInterval,
            149 => Self::Mlock,
            150 => Self::Munlock,
            151 => Self::Mlockall,
            152 => Self::Munlockall,
            153 => Self::Vhangup,
            154 => Self::ModifyLdt,
            155 => Self::PivotRoot,
            156 => Self::Sysctl,
            157 => Self::Prctl,
            158 => Self::ArchPrctl,
            159 => Self::Adjtimex,
            160 => Self::Setrlimit,
            161 => Self::Chroot,
            162 => Self::Sync,
            163 => Self::Acct,
            164 => Self::Settimeofday,
            165 => Self::Mount,
            166 => Self::Umount2,
            167 => Self::Swapon,
            168 => Self::Swapoff,
            169 => Self::Reboot,
            170 => Self::Sethostname,
            171 => Self::Setdomainname,
            172 => Self::Iopl,
            173 => Self::Ioperm,
            174 => Self::CreateModule,
            175 => Self::InitModule,
            176 => Self::DeleteModule,
            177 => Self::GetKernelSyms,
            178 => Self::QueryModule,
            179 => Self::Quotactl,
            180 => Self::Nfsservctl,
            181 => Self::Getpmsg,
            182 => Self::Putpmsg,
            183 => Self::AfsSyscall,
            184 => Self::Tuxcall,
            185 => Self::Security,
            217 => Self::Getdents64,
            218 => Self::Fcntl64,
            220 => Self::Stat64,
            221 => Self::Lstat64,
            222 => Self::Fstat64,
            223 => Self::Lchown32,
            224 => Self::Getuid32,
            225 => Self::Getgid32,
            226 => Self::Setuid32,
            227 => Self::Setgid32,
            228 => Self::Geteuid32,
            229 => Self::Getegid32,
            230 => Self::Setreuid32,
            231 => Self::Setregid32,
            232 => Self::Getgroups32,
            233 => Self::Setgroups32,
            234 => Self::Fchown32,
            235 => Self::Setresuid32,
            236 => Self::Getresuid32,
            237 => Self::Setresgid32,
            238 => Self::Getresgid32,
            239 => Self::Chown32,
            242 => Self::Setfsuid32,
            243 => Self::Setfsgid32,
            247 => Self::Mkdirat,
            248 => Self::Mknodat,
            249 => Self::Fchownat,
            250 => Self::Futimesat,
            251 => Self::Newfstatat,
            252 => Self::Unlinkat,
            253 => Self::Renameat,
            254 => Self::Linkat,
            255 => Self::Symlinkat,
            256 => Self::Readlinkat,
            257 => Self::Fchmodat,
            258 => Self::Faccessat,
            259 => Self::Pselect6,
            260 => Self::Ppoll,
            261 => Self::Unshare,
            262 => Self::SetRobustList,
            263 => Self::GetRobustList,
            264 => Self::Splice,
            265 => Self::Tee,
            266 => Self::Vmsplice,
            267 => Self::MovePages,
            268 => Self::Utimensat,
            269 => Self::EpollCreate,
            270 => Self::EpollCtl,
            271 => Self::EpollWait,
            272 => Self::EpollPwait,
            273 => Self::Getcpu,
            274 => Self::GetRandom,
            275 => Self::MemfdCreate,
            276 => Self::KexecFileLoad,
            277 => Self::Bpf,
            278 => Self::Execveat,
            279 => Self::Userfaultfd,
            280 => Self::Membarrier,
            281 => Self::Mlock2,
            282 => Self::CopyFileRange,
            283 => Self::Preadv2,
            284 => Self::Pwritev2,
            285 => Self::PkeyMprotect,
            286 => Self::PkeyAlloc,
            287 => Self::PkeyFree,
            288 => Self::Statx,
            289 => Self::IoPgetevents,
            290 => Self::Rseq,
            291 => Self::Kcmp,
            292 => Self::Fadvise64,
            293 => Self::Waitid,
            294 => Self::Clone3,
            295 => Self::Openat,
            296 => Self::Mkdirat2,
            297 => Self::CloseRange,
            298 => Self::Openat2,
            299 => Self::PidfdSendSignal,
            300 => Self::IoUringSetup,
            301 => Self::IoUringEnter,
            302 => Self::IoUringRegister,
            303 => Self::OpenTree,
            304 => Self::MoveMount,
            305 => Self::Fsopen,
            306 => Self::Fsconfig,
            307 => Self::Fsmount,
            308 => Self::Fspick,
            309 => Self::PidfdOpen,
            311 => Self::CloseRange2,
            313 => Self::PidfdGetfd,
            314 => Self::Faccessat2,
            315 => Self::ProcessMadvise,
            316 => Self::EpollPwait2,
            317 => Self::MountSetattr,
            318 => Self::QuotactlFd,
            319 => Self::LandlockCreateRuleset,
            320 => Self::LandlockAddRule,
            321 => Self::LandlockRestrictSelf,
            322 => Self::MemfdSecret,
            323 => Self::ProcessMRelease,
            324 => Self::FutexWaitv,
            325 => Self::SetMemfdSecret,
            500 => Self::AxSchedProfile,
            501 => Self::AxGetEvidence,
            502 => Self::AxReplayToken,
            503 => Self::AxAllocRes,
            504 => Self::AxFreeRes,
            505 => Self::AxShare,
            506 => Self::AxIsolate,
            507 => Self::AxVerifyInvariant,
            508 => Self::AxGetMetrics,
            509 => Self::AxSetThermalPolicy,
            510 => Self::AxGetThermalState,
            511 => Self::AxSpawn,
            512 => Self::AxWaitContract,
            513 => Self::AxSignalEvidence,
            _ => return Err(()),
        };
        Ok(n)
    }
}

/// Syscall argument register mapping (x86_64 System V ABI)
/// RAX = syscall number
/// RDI, RSI, RDX, R10, R8, R9 = args 0-5
/// Return value in RAX
#[repr(C)]
#[derive(Debug, Clone, Copy, IntoBytes, FromZeros, Immutable, KnownLayout)]
pub struct SyscallArgs {
    pub arg0: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
    pub arg4: u64,
    pub arg5: u64,
}

/// Invoke a syscall
/// x86_64 System V ABI: syscall number in RAX, args in RDI, RSI, RDX, R10, R8, R9
/// Returns value in RAX
#[inline]
pub fn syscall(number: u64, args: &[u64; 6]) -> i64 {
    let mut ret: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") number,
            in("rdi") args[0],
            in("rsi") args[1],
            in("rdx") args[2],
            in("r10") args[3],
            in("r8") args[4],
            in("r9") args[5],
            lateout("rax") ret,
            lateout("rcx") _, lateout("r11") _,
            options(nostack)
        );
    }
    ret
}

/// Syscall return value
#[repr(C)]
#[derive(Debug, Clone, Copy, IntoBytes, FromZeros, Immutable, KnownLayout)]
pub struct SyscallResult {
    pub value: i64,
    pub error: i32,
    pub _pad: u32,
}

// ---------------------------------------------------------------------------
// POD forms of math domain types for the wire/storage layer.
// The math types in `axiom-x-math` stay free of any serialization concern;
// these flat POD structs carry primitives only so they can implement the
// zerocopy traits, and conversions bridge the two layers at log time.
// ---------------------------------------------------------------------------

/// Wire code for a math `RegionType` (see `axiom_x_math::memory_algebra`).
pub fn region_type_code(rt: RegionType) -> u8 {
    rt as u8
}

/// Wire bitfield for a math `RegionFlags` (see `axiom_x_math::memory_algebra`).
pub fn region_flags_bits(flags: RegionFlags) -> u32 {
    flags.bits()
}

/// Scheduler weights, POD form of math `SchedulerWeights`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, IntoBytes, FromZeros, Immutable, KnownLayout)]
pub struct SchedulerWeightsPOD {
    pub w_latency: f64,
    pub w_throughput: f64,
    pub w_thermal: f64,
    pub alpha: f64,
    pub beta: f64,
    pub gamma: f64,
}

impl From<SchedulerWeights> for SchedulerWeightsPOD {
    fn from(w: SchedulerWeights) -> Self {
        Self {
            w_latency: w.w_latency,
            w_throughput: w.w_throughput,
            w_thermal: w.w_thermal,
            alpha: w.alpha,
            beta: w.beta,
            gamma: w.gamma,
        }
    }
}

impl From<&SchedulerWeights> for SchedulerWeightsPOD {
    fn from(w: &SchedulerWeights) -> Self {
        Self::from(*w)
    }
}

/// Scheduling profile, POD form of math `SchedProfile`.
///
/// `kind` codes: 0=Interactive, 1=Batch, 2=RealTime, 3=Background, 4=Custom.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, IntoBytes, FromZeros, Immutable, KnownLayout)]
pub struct SchedProfilePOD {
    pub deadline_ns: u64,
    pub custom_weights: SchedulerWeightsPOD,
    pub kind: u8,
    pub _pad: [u8; 7],
}

impl From<&SchedProfile> for SchedProfilePOD {
    fn from(p: &SchedProfile) -> Self {
        let (kind, deadline_ns) = match p {
            SchedProfile::Interactive => (0u8, 0u64),
            SchedProfile::Batch => (1u8, 0u64),
            SchedProfile::RealTime { deadline_ns } => (2u8, *deadline_ns),
            SchedProfile::Background => (3u8, 0u64),
            SchedProfile::Custom(_) => (4u8, 0u64),
        };
        Self {
            deadline_ns,
            custom_weights: SchedulerWeightsPOD::from(p.weights()),
            kind,
            _pad: [0; 7],
        }
    }
}

impl From<&SchedProfile> for SchedulerWeightsPOD {
    fn from(p: &SchedProfile) -> Self {
        Self::from(p.weights())
    }
}

/// Evidence record for kernel decisions
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct EvidenceRecord {
    pub decision_type: EvidenceType,
    pub timestamp_ns: u64,
    pub process_pid: u32,
    pub core: u32,
    pub details: EvidenceDetails,
    pub invariants_checked: u64, // Bitmask of invariants verified
    pub replay_token: u64,
}

/// Type of kernel decision
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromZeros, Immutable, KnownLayout)]
pub enum EvidenceType {
    Schedule = 0,
    MemoryAlloc = 1,
    MemoryFree = 2,
    MemoryMap = 3,
    MemoryUnmap = 4,
    ProcessCreate = 5,
    ProcessExit = 6,
    ProcessBlock = 7,
    ProcessWake = 8,
    IoSubmit = 9,
    IoComplete = 10,
    IsolationEnter = 11,
    IsolationExit = 12,
    InvariantCheck = 13,
    ThermalThrottle = 14,
    ContractEnforce = 15,
}

/// Evidence details (union-like)
#[repr(C)]
#[derive(Clone, Copy)]
pub union EvidenceDetails {
    pub schedule: ScheduleEvidence,
    pub memory: MemoryEvidence,
    pub process: ProcessEvidence,
    pub io: IoEvidence,
    pub isolation: IsolationEvidence,
    pub thermal: ThermalEvidence,
    pub invariant: InvariantEvidence,
    pub contract: ContractEvidence,
    pub raw: [u64; 8],
}

impl fmt::Debug for EvidenceDetails {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EvidenceDetails")
            .field("raw", unsafe { &self.raw })
            .finish()
    }
}

/// Scheduling decision evidence
#[repr(C)]
#[derive(Debug, Clone, Copy, IntoBytes, FromZeros, Immutable, KnownLayout)]
pub struct ScheduleEvidence {
    pub time_slice_ns: u64,
    pub priority: f64,
    pub latency_ms: f64,
    pub throughput: f64,
    pub thermal_cost: f64,
    pub weights: SchedulerWeightsPOD,
    pub selected_pid: u32,
    pub runnable_count: u32,
}

/// Memory decision evidence
#[repr(C)]
#[derive(Debug, Clone, Copy, IntoBytes, FromZeros, Immutable, KnownLayout)]
pub struct MemoryEvidence {
    pub region_base: u64,
    pub region_size: u64,
    pub free_before: u64,
    pub free_after: u64,
    pub fragmentation: f64,
    /// Wire bitfield for math `RegionFlags` (`region_flags_bits`).
    pub flags: u32,
    pub owner_pid: u32,
    /// Wire code for math `RegionType` (`region_type_code`).
    pub region_type: u8,
    pub _pad: [u8; 7],
}

/// Process decision evidence
#[repr(C)]
#[derive(Debug, Clone, Copy, IntoBytes, FromZeros, Immutable, KnownLayout)]
pub struct ProcessEvidence {
    pub pid: u32,
    pub parent_pid: u32,
    pub profile: SchedProfilePOD,
    pub entry_point: u64,
    pub stack_top: u64,
    pub addr_space_id: u64,
}

/// I/O decision evidence
#[repr(C)]
#[derive(Debug, Clone, Copy, IntoBytes, FromZeros, Immutable, KnownLayout)]
pub struct IoEvidence {
    pub device_id: u32,
    pub operation: u32,
    pub queue_depth: u32,
    pub _pad: u32,
    pub offset: u64,
    pub length: u64,
    pub latency_ns: u64,
}

/// Isolation evidence
#[repr(C)]
#[derive(Debug, Clone, Copy, IntoBytes, FromZeros, Immutable, KnownLayout)]
pub struct IsolationEvidence {
    pub domain_id: u64,
    pub process_pid: u32,
    pub action: u32, // 0=enter, 1=exit, 2=violate
    pub contract_id: u64,
}

/// Thermal evidence
#[repr(C)]
#[derive(Debug, Clone, Copy, IntoBytes, FromZeros, Immutable, KnownLayout)]
pub struct ThermalEvidence {
    pub temp_before: f64,
    pub temp_after: f64,
    pub load: f64,
    pub core: u32,
    pub throttled: u32,
}

/// Invariant check evidence
#[repr(C)]
#[derive(Debug, Clone, Copy, IntoBytes, FromZeros, Immutable, KnownLayout)]
pub struct InvariantEvidence {
    pub invariant_id: u32,
    pub passed: u32,
    pub details: [u64; 4],
}

/// Contract enforcement evidence
#[repr(C)]
#[derive(Debug, Clone, Copy, IntoBytes, FromZeros, Immutable, KnownLayout)]
pub struct ContractEvidence {
    pub contract_id: u64,
    pub metrics: [f64; 4],
    pub rule_id: u32,
    pub process_pid: u32,
    pub satisfied: u32,
    pub _pad: u32,
}

/// Resource allocation request (AxAllocRes)
#[repr(C)]
#[derive(Debug, Clone, Copy, IntoBytes, FromZeros, Immutable, KnownLayout)]
pub struct ResourceRequest {
    pub cpu_quota_ns: u64,      // Hard limit per period
    pub cpu_period_ns: u64,     // Quota period
    pub memory_bytes: u64,      // Memory limit
    pub memory_guaranteed: u64, // Guaranteed reservation
    pub io_bandwidth: u64,      // I/O bandwidth (bytes/sec)
    pub io_latency_ns: u64,     // Max I/O latency
    pub gpu_memory: u64,        // GPU memory
    pub network_bandwidth: u64, // Network bandwidth
    pub contract_id: u64,       // Associated contract
    pub flags: u64,
    pub cpu_shares: u32,        // CPU weight (0-10000)
    pub gpu_compute: u32,       // GPU compute units
}

/// Resource allocation result
#[repr(C)]
#[derive(Debug, Clone, Copy, IntoBytes, FromZeros, Immutable, KnownLayout)]
pub struct ResourceAllocation {
    pub bundle_id: u64,
    pub granted_memory: u64,
    pub granted_io_bandwidth: u64,
    pub granted_gpu_memory: u64,
    pub granted_network: u64,
    pub expires_ns: u64,
    pub granted_cpu_shares: u32,
    pub _pad: u32,
}

/// Process spawn request (AxSpawn)
#[repr(C)]
#[derive(Debug, Clone, Copy, IntoBytes, FromZeros, Immutable, KnownLayout)]
pub struct SpawnRequest {
    pub entry_point: u64,
    pub stack_top: u64,
    pub arg_ptr: u64,
    pub env_ptr: u64,
    pub profile: SchedProfilePOD,
    pub resource_bundle: u64,
    pub isolation_domain: u64,
    pub contract_id: u64,
    pub flags: u64,
    pub arg_len: u32,
    pub env_len: u32,
    pub parent_pid: u32,
    pub _pad: u32,
}

/// Process spawn result
#[repr(C)]
#[derive(Debug, Clone, Copy, IntoBytes, FromZeros, Immutable, KnownLayout)]
pub struct SpawnResult {
    pub addr_space_id: u64,
    pub pid: u32,
    pub thread_id: u32,
}

/// Scheduling profile request (AxSchedProfile)
#[repr(C)]
#[derive(Debug, Clone, Copy, IntoBytes, FromZeros, Immutable, KnownLayout)]
pub struct SchedProfileRequest {
    pub profile: SchedProfilePOD,
    pub custom_weights: SchedulerWeightsPOD,
    pub deadline_ns: u64,
    pub period_ns: u64,
    pub affinity_mask: u64,
}

/// Thermal policy request (AxSetThermalPolicy)
#[repr(C)]
#[derive(Debug, Clone, Copy, IntoBytes, FromZeros, Immutable, KnownLayout)]
pub struct ThermalPolicyRequest {
    pub max_temp: f64,
    pub throttle_temp: f64,
    pub emergency_temp: f64,
    pub heating_coeff: f64,
    pub cooling_coeff: f64,
    pub core: u32,
    pub action: ThermalAction,
}

/// Thermal action on threshold breach
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromZeros, Immutable, KnownLayout)]
pub enum ThermalAction {
    Throttle = 0,
    Migrate = 1,
    Kill = 2,
    Notify = 3,
}

/// Isolation domain request (AxIsolate)
#[repr(C)]
#[derive(Debug, Clone, Copy, IntoBytes, FromZeros, Immutable, KnownLayout)]
pub struct IsolationRequest {
    pub domain_id: u64,
    pub contract_id: u64,
    pub capabilities: u64, // Bitmask of allowed operations
    pub action: IsolationAction,
    pub _pad: u32,
}

/// Isolation action
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromZeros, Immutable, KnownLayout)]
pub enum IsolationAction {
    Create = 0,
    Enter = 1,
    Exit = 2,
    Destroy = 3,
    Query = 4,
}

/// Verification request (AxVerifyInvariant)
#[repr(C)]
#[derive(Debug, Clone, Copy, IntoBytes, FromZeros, Immutable, KnownLayout)]
pub struct VerifyRequest {
    pub invariant_id: u32,
    pub target_pid: u32,
    pub target_addr: u64,
    pub expected_value: u64,
}

/// Metrics response (AxGetMetrics)
#[repr(C)]
#[derive(Debug, Clone, Copy, IntoBytes, FromZeros, Immutable, KnownLayout)]
pub struct KernelMetrics {
    pub uptime_ns: u64,
    pub total_processes: u32,
    pub runnable_processes: u32,
    pub memory_total: u64,
    pub memory_free: u64,
    pub memory_allocated: u64,
    pub cpu_utilization: [f64; 64],
    pub core_temps: [f64; 64],
    pub scheduler_ticks: u64,
    pub context_switches: u64,
    syscalls_total: u64,
    page_faults: u64,
    interrupts: u64,
}

impl Default for SyscallResult {
    fn default() -> Self {
        Self { value: 0, error: 0, _pad: 0 }
    }
}

impl SyscallResult {
    pub fn success(value: i64) -> Self {
        Self { value, error: 0, _pad: 0 }
    }

    pub fn error(errno: i32) -> Self {
        Self { value: -1, error: errno, _pad: 0 }
    }

    pub fn is_error(&self) -> bool {
        self.error != 0
    }
}

// Standard errno values
pub mod errno {
    pub const EPERM: i32 = 1;
    pub const ENOENT: i32 = 2;
    pub const ESRCH: i32 = 3;
    pub const EINTR: i32 = 4;
    pub const EIO: i32 = 5;
    pub const ENXIO: i32 = 6;
    pub const E2BIG: i32 = 7;
    pub const ENOEXEC: i32 = 8;
    pub const EBADF: i32 = 9;
    pub const ECHILD: i32 = 10;
    pub const EAGAIN: i32 = 11;
    pub const ENOMEM: i32 = 12;
    pub const EACCES: i32 = 13;
    pub const EFAULT: i32 = 14;
    pub const ENOTBLK: i32 = 15;
    pub const EBUSY: i32 = 16;
    pub const EEXIST: i32 = 17;
    pub const EXDEV: i32 = 18;
    pub const ENODEV: i32 = 19;
    pub const ENOTDIR: i32 = 20;
    pub const EISDIR: i32 = 21;
    pub const EINVAL: i32 = 22;
    pub const ENFILE: i32 = 23;
    pub const EMFILE: i32 = 24;
    pub const ENOTTY: i32 = 25;
    pub const ETXTBSY: i32 = 26;
    pub const EFBIG: i32 = 27;
    pub const ENOSPC: i32 = 28;
    pub const ESPIPE: i32 = 29;
    pub const EROFS: i32 = 30;
    pub const EMLINK: i32 = 31;
    pub const EPIPE: i32 = 32;
    pub const EDOM: i32 = 33;
    pub const ERANGE: i32 = 34;
    pub const EDEADLK: i32 = 35;
    pub const ENAMETOOLONG: i32 = 36;
    pub const ENOLCK: i32 = 37;
    pub const ENOSYS: i32 = 38;
    pub const ENOTEMPTY: i32 = 39;
    pub const ELOOP: i32 = 40;
    pub const EWOULDBLOCK: i32 = 11;
    pub const ENOMSG: i32 = 42;
    pub const EIDRM: i32 = 43;
    pub const ECHRNG: i32 = 44;
    pub const EL2NSYNC: i32 = 45;
    pub const EL3HLT: i32 = 46;
    pub const EL3RST: i32 = 47;
    pub const ELNRNG: i32 = 48;
    pub const EUNATCH: i32 = 49;
    pub const ENOCSI: i32 = 50;
    pub const EL2HLT: i32 = 51;
    pub const EBADE: i32 = 52;
    pub const EBADR: i32 = 53;
    pub const EXFULL: i32 = 54;
    pub const ENOANO: i32 = 55;
    pub const EBADRQC: i32 = 56;
    pub const EBADSLT: i32 = 57;
    pub const EDEADLOCK: i32 = 35;
    pub const EBFONT: i32 = 59;
    pub const ENOSTR: i32 = 60;
    pub const ENODATA: i32 = 61;
    pub const ETIME: i32 = 62;
    pub const ENOSR: i32 = 63;
    pub const ENONET: i32 = 64;
    pub const ENOPKG: i32 = 65;
    pub const EREMOTE: i32 = 66;
    pub const ENOLINK: i32 = 67;
    pub const EADV: i32 = 68;
    pub const ESRMNT: i32 = 69;
    pub const ECOMM: i32 = 70;
    pub const EPROTO: i32 = 71;
    pub const EMULTIHOP: i32 = 72;
    pub const EDOTDOT: i32 = 73;
    pub const EBADMSG: i32 = 74;
    pub const EOVERFLOW: i32 = 75;
    pub const ENOTUNIQ: i32 = 76;
    pub const EBADFD: i32 = 77;
    pub const EREMCHG: i32 = 78;
    pub const ELIBACC: i32 = 79;
    pub const ELIBBAD: i32 = 80;
    pub const ELIBSCN: i32 = 81;
    pub const ELIBMAX: i32 = 82;
    pub const ELIBEXEC: i32 = 83;
    pub const EILSEQ: i32 = 84;
    pub const ERESTART: i32 = 85;
    pub const ESTRPIPE: i32 = 86;
    pub const EUSERS: i32 = 87;
    pub const ENOTSOCK: i32 = 88;
    pub const EDESTADDRREQ: i32 = 89;
    pub const EMSGSIZE: i32 = 90;
    pub const EPROTOTYPE: i32 = 91;
    pub const ENOPROTOOPT: i32 = 92;
    pub const EPROTONOTSUPP: i32 = 93;
    pub const ESOCKTNOSUPP: i32 = 94;
    pub const EOPNOTSUPP: i32 = 95;
    pub const EPFNOSUPPORT: i32 = 96;
    pub const EAFNOSUPPORT: i32 = 97;
    pub const EADDRINUSE: i32 = 98;
    pub const EADDRNOTAVAIL: i32 = 99;
    pub const ENETDOWN: i32 = 100;
    pub const ENETUNREACH: i32 = 101;
    pub const ENETRESET: i32 = 102;
    pub const ECONNABORTED: i32 = 103;
    pub const ECONNRESET: i32 = 104;
    pub const ENOBUFS: i32 = 105;
    pub const EISCONN: i32 = 106;
    pub const ENOTCONN: i32 = 107;
    pub const ESHUTDOWN: i32 = 108;
    pub const ETOOMANYREFS: i32 = 109;
    pub const ETIMEDOUT: i32 = 110;
    pub const ECONNREFUSED: i32 = 111;
    pub const EHOSTDOWN: i32 = 112;
    pub const EHOSTUNREACH: i32 = 113;
    pub const EALREADY: i32 = 114;
    pub const EINPROGRESS: i32 = 115;
    pub const ESTALE: i32 = 116;
    pub const EUCLEAN: i32 = 117;
    pub const ENOTNAM: i32 = 118;
    pub const ENAVAIL: i32 = 119;
    pub const EISNAM: i32 = 120;
    pub const EREMOTEIO: i32 = 121;
    pub const EDQUOT: i32 = 122;
    pub const ENOMEDIUM: i32 = 123;
    pub const EMEDIUMTYPE: i32 = 124;
    pub const ECANCELED: i32 = 125;
    pub const ENOKEY: i32 = 126;
    pub const EKEYEXPIRED: i32 = 127;
    pub const EKEYREJECTED: i32 = 128;
    pub const EOWNERDEAD: i32 = 129;
    pub const ENOTRECOVERABLE: i32 = 130;
    pub const ERFKILL: i32 = 131;
    pub const EHWPOISON: i32 = 132;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_syscall_number_sizes() {
        assert_eq!(core::mem::size_of::<SyscallNumber>(), 8);
        assert_eq!(SyscallNumber::Read as u64, 0);
        assert_eq!(SyscallNumber::AxSchedProfile as u64, 500);
    }

    #[test]
    fn test_syscall_args_layout() {
        let args = SyscallArgs {
            arg0: 1, arg1: 2, arg2: 3, arg3: 4, arg4: 5, arg5: 6,
        };
        assert_eq!(core::mem::size_of::<SyscallArgs>(), 48);
    }

    #[test]
    fn test_evidence_record_layout() {
        let record = EvidenceRecord {
            decision_type: EvidenceType::Schedule,
            timestamp_ns: 0,
            process_pid: 0,
            core: 0,
            details: EvidenceDetails { raw: [0; 8] },
            invariants_checked: 0,
            replay_token: 0,
        };
        assert_eq!(core::mem::size_of::<EvidenceRecord>(), 136);
    }

    #[test]
    fn test_resource_request_layout() {
        let req = ResourceRequest {
            cpu_shares: 1000,
            cpu_quota_ns: 10_000_000,
            cpu_period_ns: 100_000_000,
            memory_bytes: 1024 * 1024 * 1024,
            memory_guaranteed: 512 * 1024 * 1024,
            io_bandwidth: 100 * 1024 * 1024,
            io_latency_ns: 1_000_000,
            gpu_memory: 0,
            gpu_compute: 0,
            network_bandwidth: 1_000_000_000,
            contract_id: 0,
            flags: 0,
        };
        assert_eq!(core::mem::size_of::<ResourceRequest>(), 88);
    }

    #[test]
    fn test_syscall_result() {
        let ok = SyscallResult::success(42);
        assert!(!ok.is_error());
        assert_eq!(ok.value, 42);

        let err = SyscallResult::error(errno::ENOMEM);
        assert!(err.is_error());
        assert_eq!(err.error, errno::ENOMEM);
    }
}