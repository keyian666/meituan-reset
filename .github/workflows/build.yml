name: build-dylib

on:
  push:
  workflow_dispatch:

jobs:
  build:
    runs-on: macos-15
    steps:
      - uses: actions/checkout@v4

      - name: Setup Theos
        run: |
          set -euo pipefail
          brew install ldid xz
          export THEOS=$HOME/theos
          git clone --recursive --depth 1 https://github.com/theos/theos.git "$THEOS"
          git clone --depth 1 https://github.com/theos/sdks.git "$THEOS/sdks"
          echo "THEOS=$THEOS" >> $GITHUB_ENV
          echo "=== theos root ==="
          ls "$THEOS"
          echo "=== sdks ==="
          ls "$THEOS/sdks" | head -20

      - name: Check substrate (hook engine)
        run: |
          set -euo pipefail
          echo "THEOS=$THEOS"
          echo "=== libsubstrate ==="
          find "$THEOS" -name "libsubstrate*" 2>/dev/null || echo "NO SUBSTRATE FILE"
          echo "=== vendor/lib ==="
          ls -la "$THEOS/vendor/lib" 2>/dev/null || echo "no vendor/lib"

      - name: Build
        run: |
          echo "=== files ==="
          ls -la
          echo "=== makefile candidates ==="
          ls -la Makefile makefile 2>/dev/null || true
          echo "=== build ==="
          make clean 2>/dev/null || true
          set -o pipefail
          make -j4 2>&1 | tee build.log
          echo "=== make exit: $? ==="
          echo "=== artifacts on disk ==="
          find . -name "*.dylib" 2>/dev/null || true
          ls -la packages 2>/dev/null || true

      - name: Verify dylib
        run: |
          set -euo pipefail
          mkdir -p out
          find . -name "MTDeviceSpoof.dylib" -exec cp {} out/ \;
          ls -la out/ || true
          if [ ! -f out/MTDeviceSpoof.dylib ]; then
            echo "::error::MTDeviceSpoof.dylib was not produced - see build.log artifact"
            exit 1
          fi
          file out/MTDeviceSpoof.dylib

      - name: Upload artifacts + log
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: build-output
          path: |
            out/
            build.log
          if-no-files-found: warn
