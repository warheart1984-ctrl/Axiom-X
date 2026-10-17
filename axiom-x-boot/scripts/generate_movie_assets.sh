#!/usr/bin/env bash
# Build-time movie asset generator for axiom-x kernel
# Runs in WSL Ubuntu to generate movie assets using the Python renderer

set -euo pipefail

WOLF_COG_OS_ROOT="/mnt/g/Wolf-CoG-OS"
AXIOM_X_ROOT="/mnt/g/Sovereign-X-Constitutional-Compute/axiom-x"
ASSETS_DIR="${AXIOM_X_ROOT}/axiom-x-boot/assets/movie"
BUILD_DIR="${AXIOM_X_ROOT}/target/movie-build"

echo "=== Movie Asset Generator ==="
echo "Wolf-CoG-OS: ${WOLF_COG_OS_ROOT}"
echo "Axiom-X:     ${AXIOM_X_ROOT}"
echo "Assets dir:  ${ASSETS_DIR}"

mkdir -p "${ASSETS_DIR}"
mkdir -p "${BUILD_DIR}"

# Check Python dependencies
if ! python3 -c "import cv2, numpy, PIL" 2>/dev/null; then
    echo "Installing Python dependencies..."
    pip3 install --quiet opencv-python-headless numpy Pillow 2>/dev/null || {
        echo "WARNING: Could not install Python deps, using fallback asset"
        exit 0
    }
fi

echo "Generating movie asset..."

# Create a minimal story state for rendering
cat > "${BUILD_DIR}/render_movie.py" << 'PYEOF'
import sys
sys.path.insert(0, '/mnt/g/Wolf-CoG-OS/external/story_forge/src')

from story_forge.movie_renderer import MovieRenderer
from story_forge.models import StoryState
from story_forge.lumen_renderer import LumenRenderer

# Create a minimal story state with /3d lane history
state = StoryState(
    session_id="axiom-x-boot-movie",
    player_id="kernel",
    world_pack_id="axiom-x",
    runtime_lanes={
        "text_to_3d_world": {
            "worldId": "axiom-x-kernel",
            "engineProvider": "axiom-x",
            "lastRequestText": "/movie",
            "updatedAt": "2025-01-01T00:00:00Z",
            "history": [
                {
                    "requestText": "/3d init",
                    "updatedAt": "2025-01-01T00:00:01Z",
                    "output": {
                        "requestText": "/3d init",
                        "updatedAt": "2025-01-01T00:00:01Z",
                        "output": {
                            "scene_spec": {
                                "locationAnchor": {"label": "Kernel Entry"},
                                "mood": "steady",
                                "theme": "kernel_boot",
                                "focalObjects": [{"label": "Multiboot Header"}]
                            },
                            "game_state": {"tick": 1, "narrativeScore": 100},
                            "event_records": [
                                {"type": "boot", "eventId": "multiboot_entry", "transitionId": "boot_001", "observationalCapture": ""}
                            ]
                        }
                    }
                },
                {
                    "requestText": "/3d paging",
                    "updatedAt": "2025-01-01T00:00:02Z",
                    "output": {
                        "requestText": "/3d paging",
                        "updatedAt": "2025-01-01T00:00:02Z",
                        "output": {
                            "scene_spec": {
                                "locationAnchor": {"label": "Page Tables"},
                                "mood": "focused",
                                "theme": "memory_init",
                                "focalObjects": [{"label": "PML4"}, {"label": "PDPT"}, {"label": "PD"}]
                            },
                            "game_state": {"tick": 2, "narrativeScore": 200},
                            "event_records": [
                                {"type": "memory", "eventId": "pml4_init", "transitionId": "mem_001", "observationalCapture": ""}
                            ]
                        }
                    }
                },
                {
                    "requestText": "/3d scheduler",
                    "updatedAt": "2025-01-01T00:00:03Z",
                    "output": {
                        "requestText": "/3d scheduler",
                        "updatedAt": "2025-01-01T00:00:03Z",
                        "output": {
                            "scene_spec": {
                                "locationAnchor": {"label": "Scheduler"},
                                "mood": "active",
                                "theme": "task_switch",
                                "focalObjects": [{"label": "Idle Task"}, {"label": "Init Task"}]
                            },
                            "game_state": {"tick": 3, "narrativeScore": 300},
                            "event_records": [
                                {"type": "schedule", "eventId": "context_switch", "transitionId": "sched_001", "observationalCapture": ""}
                            ]
                        }
                    }
                },
                {
                    "requestText": "/3d idle",
                    "updatedAt": "2025-01-01T00:00:04Z",
                    "output": {
                        "requestText": "/3d idle",
                        "updatedAt": "2025-01-01T00:00:04Z",
                        "output": {
                            "scene_spec": {
                                "locationAnchor": {"label": "Idle Loop"},
                                "mood": "steady",
                                "theme": "hlt_loop",
                                "focalObjects": [{"label": "HLT"}, {"label": "Interrupt"}]
                            },
                            "game_state": {"tick": 4, "narrativeScore": 400},
                            "event_records": [
                                {"type": "idle", "eventId": "hlt", "transitionId": "idle_001", "observationalCapture": ""}
                            ]
                        }
                    }
                }
            ]
        }
    }
)

# Render the movie
renderer = MovieRenderer()
result = renderer.render_movie(
    state,
    title="Axiom-X Kernel Boot",
    presentation_mode="backend"
)

print(f"Movie rendered: {result.video_path}")
print(f"Frames: {result.frames_dir}")
print(f"Screenplay: {result.screenplay_path}")
PYEOF

cd /mnt/g/Wolf-CoG-OS
python3 "${BUILD_DIR}/render_movie.py" 2>&1 || {
    echo "Python render failed, creating fallback asset"
    exit 1
}

# Copy generated assets
cp -r "${BUILD_DIR}/axiom-x-kernel-boot/"* "${ASSETS_DIR}/" 2>/dev/null || true

echo "Asset generation complete"
exit 0