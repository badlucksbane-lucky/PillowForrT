#!/usr/bin/env bash
# Build one libretro core to a standalone wasm module (no RetroArch).
# Usage: scripts/retro/build-core.sh <core-name> <git-url> [out-dir]
#   e.g. scripts/retro/build-core.sh fceumm https://github.com/libretro/libretro-fceumm.git
# Needs emsdk at ~/emsdk (git clone https://github.com/emscripten-core/emsdk; ./emsdk install latest; ./emsdk activate latest).
# Measured on the Pi 4 (aarch64, 1.8 GB): fceumm compiles in ~4.5 min with -j2, then links in ~10 s.
set -euo pipefail
name=$1; url=$2; out=${3:-$HOME/retro-build/out}
work=$HOME/retro-build; mkdir -p "$work" "$out"
source "$HOME/emsdk/emsdk_env.sh" >/dev/null
cd "$work"
[ -d "libretro-$name" ] || git clone --depth 1 "$url" "libretro-$name"
cd "libretro-$name"
# STATIC_LINKING=0 makes the core compile libretro-common's file streams itself
# (otherwise filestream_* / path_is_valid are left for RetroArch to provide).
nice -n 15 emmake make -f Makefile.libretro platform=emscripten STATIC_LINKING=0 -j2
# That make leaves a non-archive in *_libretro_emscripten.bc, so archive the objects ourselves.
rm -f "$work/lib$name.a"
find . -name '*.o' | xargs emar rcs "$work/lib$name.a"
fns=_malloc,_free,_retro_api_version,_retro_init,_retro_deinit,_retro_set_environment,_retro_set_video_refresh,_retro_set_audio_sample,_retro_set_audio_sample_batch,_retro_set_input_poll,_retro_set_input_state,_retro_get_system_info,_retro_get_system_av_info,_retro_load_game,_retro_unload_game,_retro_run,_retro_reset,_retro_serialize_size,_retro_serialize,_retro_unserialize,_retro_set_controller_port_device
# MEMFS stays on: fceumm opens the ROM by path even when it is also handed the data.
nice -n 15 emcc "$work/lib$name.a" -O2 -sEXPORTED_FUNCTIONS=$fns \
  -sEXPORTED_RUNTIME_METHODS=addFunction,removeFunction,UTF8ToString,HEAPU8,HEAP16,HEAP32,HEAPU32,HEAPU16,FS \
  -sALLOW_TABLE_GROWTH -sALLOW_MEMORY_GROWTH -sINITIAL_MEMORY=33554432 \
  -sMODULARIZE -sEXPORT_NAME=createCore -sENVIRONMENT=web,worker,node -sNO_EXIT_RUNTIME=1 \
  -o "$out/$name.js"
ls -la "$out/$name".*
