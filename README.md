Citadel Shield 

This is a low-level network monitoring and filtering tool built with Rust and eBPF (Aya). It intercepts network packets at the XDP level (the fastest way possible in Linux) and visualizes everything in a terminal-based dashboard.
Why I built this

I wanted to see if I could build a high-performance packet filter that doesn't choke under load. By using XDP (Express Data Path), the logic runs directly in the kernel, making decisions about packets before they even reach the heavy parts of the Linux networking stack.
How it works

    Kernel Space: An eBPF program written in Rust that inspects incoming traffic and logs stats (or drops packets based on a blacklist) into BPF maps.

    User Space: A monitoring agent that reads those BPF maps asynchronously using tokio.

    Interface: A live TUI (Terminal User Interface) built with ratatui that shows real-time stats, hostnames, and packet counts.

Tech Stack

    Language: Rust (Stable)

    Kernel Interface: Aya (eBPF)

    Async Runtime: Tokio

    UI: Ratatui / Crossterm



    Note: You need a Linux machine with eBPF support and bpf-linker installed.

   1. Clone the repo.

   2.Update the interface name (e.g., eth0 or wlo1) in main.rs.

   3. Build and run
