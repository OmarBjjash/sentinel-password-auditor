#!/usr/bin/env bash
# ==============================================================================
# Sentinel Password Auditor — Linux AppImage Build Script
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

APP_NAME="sentinel-password-checker"
ARCH="x86_64"
APPDIR="${SCRIPT_DIR}/build/AppDir"
DIST_DIR="${SCRIPT_DIR}/dist"

echo "===================================================================="
echo "  Building Linux AppImage for ${APP_NAME} (${ARCH})"
echo "===================================================================="

# 1. Ensure Python 3 and Tkinter
if ! command -v python3 &>/dev/null; then
    echo "[!] Error: python3 is not installed."
    exit 1
fi

# 2. Virtual Environment Setup
VENV_DIR="${SCRIPT_DIR}/.venv"
if [ ! -d "${VENV_DIR}" ]; then
    echo "[*] Creating virtual environment in ${VENV_DIR}..."
    python3 -m venv "${VENV_DIR}"
fi

# Activate venv
# shellcheck disable=SC1091
source "${VENV_DIR}/bin/activate"

# 3. Install build dependencies
echo "[*] Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt
pip install pyinstaller

# 4. Clean previous AppDir and build artifacts
echo "[*] Preparing build workspace..."
rm -rf "${APPDIR}"
mkdir -p "${APPDIR}/usr/bin"
mkdir -p "${APPDIR}/usr/share/applications"
mkdir -p "${APPDIR}/usr/share/icons/hicolor/256x256/apps"
mkdir -p "${DIST_DIR}"

# 5. Build application binary bundle with PyInstaller
echo "[*] Building application with PyInstaller..."
pyinstaller --noconfirm --onedir \
    --name "${APP_NAME}" \
    --distpath "${APPDIR}/usr/bin" \
    --collect-all customtkinter \
    --collect-all cryptography \
    --collect-all Registry \
    --collect-all passlib \
    --collect-all bcrypt \
    --collect-all reportlab \
    --collect-all pyescrypt \
    --hidden-import pyescrypt \
    --add-data "wordlist.txt:." \
    main.py

# 6. Copy Icon
if [ -f "assets/icons/sentinel.png" ]; then
    cp "assets/icons/sentinel.png" "${APPDIR}/sentinel.png"
    cp "assets/icons/sentinel.png" "${APPDIR}/usr/share/icons/hicolor/256x256/apps/sentinel.png"
else
    # Create minimal placeholder PNG if missing
    python3 -c "from PIL import Image; Image.new('RGBA', (64, 64), (37, 99, 235)).save('${APPDIR}/sentinel.png')"
    cp "${APPDIR}/sentinel.png" "${APPDIR}/usr/share/icons/hicolor/256x256/apps/sentinel.png"
fi

# 7. Create Desktop Entry
cat <<EOF > "${APPDIR}/${APP_NAME}.desktop"
[Desktop Entry]
Name=Sentinel Password Auditor
Comment=Automated password auditing and security policy assessment framework
Exec=AppRun %F
Icon=sentinel
Type=Application
Categories=Utility;Security;System;
Terminal=false
StartupWMClass=Sentinel
EOF
cp "${APPDIR}/${APP_NAME}.desktop" "${APPDIR}/usr/share/applications/${APP_NAME}.desktop"

# 8. Create AppRun launcher script
cat <<'EOF' > "${APPDIR}/AppRun"
#!/bin/sh
set -e
HERE="$(dirname "$(readlink -f "${0}")")"
export PATH="${HERE}/usr/bin/${APP_NAME}:${PATH}"
export LD_LIBRARY_PATH="${HERE}/usr/bin/${APP_NAME}:${LD_LIBRARY_PATH:-}"
export PYTHONHOME="${HERE}/usr/bin/${APP_NAME}"
exec "${HERE}/usr/bin/sentinel-password-checker/sentinel-password-checker" "$@"
EOF
chmod +x "${APPDIR}/AppRun"

# 9. Download appimagetool if not available
APPIMAGETOOL="${SCRIPT_DIR}/build/appimagetool"
if [ ! -f "${APPIMAGETOOL}" ]; then
    echo "[*] Downloading appimagetool..."
    wget -q https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage -O "${APPIMAGETOOL}" || \
    curl -sL https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage -o "${APPIMAGETOOL}"
    chmod +x "${APPIMAGETOOL}"
fi

# 10. Package AppImage
OUTPUT_APPIMAGE="${DIST_DIR}/${APP_NAME}-${ARCH}.AppImage"
echo "[*] Generating AppImage: ${OUTPUT_APPIMAGE}..."

export ARCH
# Use --appimage-extract-and-run in case running inside Docker/WSL without FUSE
if ! "${APPIMAGETOOL}" --appimage-extract-and-run "${APPDIR}" "${OUTPUT_APPIMAGE}"; then
    "${APPIMAGETOOL}" "${APPDIR}" "${OUTPUT_APPIMAGE}"
fi

chmod +x "${OUTPUT_APPIMAGE}"

echo "===================================================================="
echo "  [SUCCESS] AppImage build complete!"
echo "  Location: ${OUTPUT_APPIMAGE}"
echo "  Run via:  ./dist/${APP_NAME}-${ARCH}.AppImage"
echo "===================================================================="
