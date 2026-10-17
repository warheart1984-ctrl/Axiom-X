//! Embedded movie asset playback for axiom-x kernel
//!
//! Embeds movie assets (MP4, screenplay, metadata) at compile time via build script.
//! Provides a simple playback interface for future framebuffer integration.

#![no_std]

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Embedded movie asset metadata
#[derive(Debug, Clone, Copy)]
pub struct MovieAsset {
    /// Asset name (e.g., "boot_movie")
    pub name: &'static str,
    /// MP4 video data
    pub video: &'static [u8],
    /// Screenplay text
    pub screenplay: &'static str,
    /// Shot list JSON
    pub shot_list: &'static str,
    /// Metadata JSON
    pub metadata: &'static str,
    /// Frame data (raw RGBA frames)
    pub frames: &'static [u8],
    /// Frame dimensions
    pub width: u32,
    pub height: u32,
    /// Frames per second
    pub fps: f32,
}

/// Embedded boot movie asset (populated by build script)
/// 
/// The actual data is linked in via `include_bytes!` macros populated
/// by the build script's asset generation.
#[allow(dead_code)]
static BOOT_MOVIE: MovieAsset = MovieAsset {
    name: "axiom_x_boot",
    video: &[],
    screenplay: "",
    shot_list: "",
    metadata: "",
    frames: &[],
    width: 1280,
    height: 720,
    fps: 1.0,
};

/// Movie playback state
pub struct MoviePlayer {
    asset: &'static MovieAsset,
    current_frame: AtomicUsize,
    playing: AtomicBool,
    frame_delay_ms: u64,
}

impl MoviePlayer {
    /// Create a new player for the embedded boot movie
    pub fn new() -> Self {
        Self {
            asset: &BOOT_MOVIE,
            current_frame: AtomicUsize::new(0),
            playing: AtomicBool::new(false),
            frame_delay_ms: (1000.0 / BOOT_MOVIE.fps) as u64,
        }
    }

    /// Start playback
    pub fn play(&self) {
        self.playing.store(true, Ordering::Relaxed);
        self.current_frame.store(0, Ordering::Relaxed);
    }

    /// Stop playback
    pub fn stop(&self) {
        self.playing.store(false, Ordering::Relaxed);
        self.current_frame.store(0, Ordering::Relaxed);
    }

    /// Check if currently playing
    pub fn is_playing(&self) -> bool {
        self.playing.load(Ordering::Relaxed)
    }

    /// Get current frame data (for framebuffer integration)
    /// Returns (frame_data, width, height, frame_index, total_frames)
    pub fn current_frame(&self) -> Option<(&[u8], u32, u32, usize, usize)> {
        if !self.playing.load(Ordering::Relaxed) {
            return None;
        }
        if self.asset.frames.is_empty() {
            return None;
        }
        let frame_size = (self.asset.width * self.asset.height * 4) as usize; // RGBA
        let total_frames = self.asset.frames.len() / frame_size;
        let current = self.current_frame.load(Ordering::Relaxed);
        if current >= total_frames {
            return None;
        }
        let start = current * frame_size;
        let end = start + frame_size;
        Some((
            &self.asset.frames[start..end],
            self.asset.width,
            self.asset.height,
            current,
            total_frames,
        ))
    }

    /// Advance to next frame
    pub fn next_frame(&self) -> bool {
        if !self.playing.load(Ordering::Relaxed) {
            return false;
        }
        let frame_size = (self.asset.width * self.asset.height * 4) as usize;
        let total_frames = self.asset.frames.len() / frame_size;
        let current = self.current_frame.fetch_add(1, Ordering::Relaxed);
        if current + 1 >= total_frames {
            self.stop();
            false
        } else {
            true
        }
    }

    /// Get screenplay text
    pub fn screenplay(&self) -> &'static str {
        self.asset.screenplay
    }

    /// Get shot list JSON
    pub fn shot_list(&self) -> &'static str {
        self.asset.shot_list
    }

    /// Get metadata JSON
    pub fn metadata(&self) -> &'static str {
        self.asset.metadata
    }
}

impl Default for MoviePlayer {
    fn default() -> Self {
        Self::new()
    }
}

/// Global movie player instance (for kernel integration)
static MOVIE_PLAYER: MoviePlayer = MoviePlayer {
    asset: &BOOT_MOVIE,
    current_frame: AtomicUsize::new(0),
    playing: AtomicBool::new(false),
    frame_delay_ms: 1000,
};

/// Get the global movie player instance
pub fn global_player() -> &'static MoviePlayer {
    &MOVIE_PLAYER
}

/// Initialize movie subsystem (called during kernel init)
pub fn init_movie_subsystem() {
    // Asset data is linked in at compile time
    // This function exists for future framebuffer integration
}

/// Trait for framebuffer backends to implement movie playback
pub trait FramebufferMovieBackend {
    /// Draw a frame (RGBA) at the given position
    fn draw_frame(&mut self, x: u32, y: u32, width: u32, height: u32, data: &[u8]);
    /// Get framebuffer dimensions
    fn dimensions(&self) -> (u32, u32);
    /// Flush/swap buffers
    fn present(&mut self);
}

/// Play movie on a framebuffer backend
pub fn play_on_backend<B: FramebufferMovieBackend>(backend: &mut B, player: &MoviePlayer) {
    if !player.is_playing() {
        return;
    }
    if let Some((frame_data, w, h, _idx, _total)) = player.current_frame() {
        let (fb_w, fb_h) = backend.dimensions();
        let x = (fb_w.saturating_sub(w)) / 2;
        let y = (fb_h.saturating_sub(h)) / 2;
        backend.draw_frame(x, y, w, h, frame_data);
        backend.present();
    }
}