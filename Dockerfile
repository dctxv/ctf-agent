FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap sqlmap ffuf nuclei dirsearch gobuster nikto \
    ripgrep \
    curl wget git jq unzip \
    python3 python3-pip python3-pwntools \
    gdb rlwrap \
    net-tools iputils-ping dnsutils \
    nftables iptables \
    john hashcat wordlists \
    ocl-icd-libopencl1 pocl-opencl-icd \
    gcc libc6-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# rockyou ships gzipped; decompress so wordlist attacks work without a setup step
RUN gunzip -kf /usr/share/wordlists/rockyou.txt.gz

RUN pip3 install --break-system-packages \
    semgrep \
    pykeepass pycryptodomex \
    uncompyle6 decompyle3 \
    pyotp \
    playwright

# Headless Chromium for the agent's browser tools (Angular/JS targets curl can't render)
RUN python3 -m playwright install --with-deps chromium

# Dependency-CVE scanners (kept in their own layers so the Chromium layer stays cached):
# pip-audit (Python) + osv-scanner (multi-ecosystem, pinned binary).
# pip-audit builds an ephemeral venv to audit, so it needs python3-venv present.
RUN apt-get update && apt-get install -y --no-install-recommends python3-venv \
    && rm -rf /var/lib/apt/lists/*
RUN pip3 install --break-system-packages pip-audit
RUN curl -fsSL https://github.com/google/osv-scanner/releases/download/v2.7.0/osv-scanner_linux_amd64 \
    -o /usr/local/bin/osv-scanner && chmod +x /usr/local/bin/osv-scanner

WORKDIR /workspace
CMD ["/bin/bash"]
