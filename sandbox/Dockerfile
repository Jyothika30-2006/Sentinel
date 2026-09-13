# =====================================================================
# Sentinel analysis sandbox image (REMnux-style, minimal).
#
# Purpose-built for NON-EXECUTING analysis of suspicious attachments:
#   * exiftool      -> metadata extraction
#   * oletools      -> macro detection (oleid/olevba)
#   * file          -> libmagic type detection
#   * binwalk       -> embedded/concatenated file carving
#   * pdfid         -> PDF exploit/anomaly detection
#   * capa          -> Mandiant FLARE capability detection
#   * yara          -> signature matching (rules mounted at /overlay/yara_rules)
#   * pecheck       -> PE structural analysis (comes with pefile)
#   * strings       -> string extraction (coreutils)
#
# Build:  docker build -t sentinel-sandbox:latest sandbox/
#
# The container is launched with --network none, --read-only, --cap-drop ALL,
# a read-only evidence mount, and is destroyed after each run (--rm). It
# NEVER has the ability to reach the network or modify evidence.
# =====================================================================

FROM python:3.11-slim

# Debian packages (exiftool, file/libmagic, binwalk, yara, antiword, unzip).
RUN apt-get update && apt-get install -y --no-install-recommends \
        libimage-exiftool-perl \
        file \
        binwalk \
        yara \
        unzip \
        p7zip-full \
        antiword \
    && rm -rf /var/lib/apt/lists/*

# Python analysis tools.
#   oletools  : macro detection (pure-Python, no macro VM execution)
#   pdfid     : Didier Stevens' PDF exploit scanner
#   flare-capa: Mandiant FLARE capability detection (ATT&CK mapping)
#   pefile    : PE parser (provides the `pecheck` CLI)
RUN pip install --no-cache-dir \
        oletools==0.60.2 \
        pdfid==0.2.8 \
        flare-capa==7.4.1 \
        pefile==2023.2.7

# Non-root user matches the host-side `--user 65534:65534` (nobody).
# The runtime flag sets it; the image itself stays minimal.

WORKDIR /tmp
ENTRYPOINT []
CMD ["python3"]
