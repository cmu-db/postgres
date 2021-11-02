# Setup

## Installation

1. `sudo pip3 install -r requirements.txt` -- the packages must be available to root's Python

## System configuration

- To `/etc/sysctl.d/myperf.conf` add
   ```
   kernel.perf_event_paranoid = -1
   kernel.kptr_restrict = 0
   ```
- You may need to increase `ulimit -n` before running `tscout`.
- You need to run with `sudo`.

# Usage

1. ```sudo python3 tscout.py `pgrep -ox postgres` ```

# Implementation

1. `clang_parser.py` parses C code into (struct name) -> (expanded struct fields).
2. `model.py` converts C types to BPF types, defines Operating Units (OUs) and metrics to be collected.
3. `tscout.py` uses the following input:
    - OUs and metrics from model.py
    - collector.c, markers.c, probes.c as codegen templates
4. `tscout.py` then attaches to the postmaster.