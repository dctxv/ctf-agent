FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap sqlmap ffuf nuclei dirsearch gobuster nikto \
    ripgrep \
    curl wget git jq unzip \
    python3 python3-pip python3-pwntools \
    gdb rlwrap \
    net-tools iputils-ping dnsutils \
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

WORKDIR /workspace
CMD ["/bin/bash"]
