FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap sqlmap ffuf nuclei dirsearch gobuster nikto \
    ripgrep \
    curl wget git jq unzip \
    python3 python3-pip python3-pwntools \
    gdb rlwrap \
    net-tools iputils-ping dnsutils \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --break-system-packages semgrep

WORKDIR /workspace
CMD ["/bin/bash"]
