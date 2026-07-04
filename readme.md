
# av-switchyard

[![Releases Download Page](https://img.shields.io/github/v/release/Jeffrey-P-McAteer/av-switchyard)](https://github.com/Jeffrey-P-McAteer/av-switchyard/releases)

`av-switchyard` is a _primarially_ command-line Go utility which performs the following capabilities

 - Scans all host interfaces for all visible AV equipment and report details of each visible machine / universe / component.
    - Current Status: None
 - Daemon capability to serve as a bridge between `grandMA3` and AV equipment, with a relatively simple `av-switchyard.toml` configuration file able to alter how the hardware is presented to `grandMA3`. Assumed to run on same host as `grandMA3`, and during startup the daemon will kill previous running copies of itself to ensure only one lives at a time.
    - Current Status: None
 - Experimental stretch-goal: Daemon should bind to the system tray with an icon + menu for control, such as live config file re-reads. May only have limited platform support, with Windows x64 being the most important.
    - Current Status: not planned, but we'll see where the architecture takes us. Users prefer GUIs.
 - Release goal: Setup Github Actions to cross-compile and publish releases for all platforms. Plan is to make a new release as simple as "git push" on the developers side, and "download + double-click" on the user's side. Also likely to have a self-upgrade "--list-releases" and "--upgrade [explicit-release-version]" capabilities.

Design constraints:

 - Must run as single-executable on Windows x64, MacOS x64 + ARM64, and Linux x64.
    - Current Status: None

# Repository Layout

 - `av-switchyard/`
    - Go code implementing the tool itself
    - Build from Linux/MacOS hosts with `make build-all`, which compiles starting at `main.go` and outputs binaries to `av-switchyard/dist/av-switchyard-<target>`
    - Not even beginning to write a build script for Windows dev hosts, just run `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o dist/av-switchyard-windows-amd64.exe .` directly.

 - `graphics/`
    - Home of any icons and graphics used.
    - `graphics/render-icons-from-primary.py` script to turn a single primary asset into build-tool assets under `graphics/build/*`

 - `testbed/`
    - Contains all scripts and data for a test VM to simulate a real-world use of the tool.
    - Primary run script is `./testbed/setup-and-run-vm.py` wich uses `uv` to run the python code.
    - Requires OS files and `qemu-system-x86_64`, `qemu-img`, and an OVMF install of some sort.
    - Use `OVMF_CODE_FILE=/path/to/OVMF_CODE.fd` to override the automatic search under `/usr/share` - we do not hardcode paths which can be distro-specific.
    - Only supports simulating a Windows x64 VM and associated simulators for AV hardware (yet undetermined)

 - `historic-progress/`
    - Contains timestamped screenshots of the tool for future perspective on the development story

# Development Dependencies

High-level dependencies assumed, CLI tools:

 - `git`
 - `uv`
 - `go`
 - `make`

More task-specific dependencies will be auto-detected and printed if missing by individual scripts.

## Arch Linux Specific items

For all of our QEMU GL-accelerated hardware you may need the GL extensions installed. QEMU is apparently large
enough to merit breaking Arch's batteries-included packaging guidelines.

```bash
sudo pacman -S qemu-hw-display-virtio-gpu-gl qemu-hw-display-virtio-gpu-pci-gl qemu-hw-display-virtio-vga-gl
# There is also a super-package: qemu-full
```

# Development Zero-To-Hero

Presuming dependencies, run the following to get a binary for all supported targets:

```bash
./graphics/render-icons-from-primary.py
make -C av-switchyard build-all
./testbed/setup-and-run-vm.py
```

The VM will have the latest windows x64 build in the USB drive attached.

For testing on the host, several `run-*` targets exist which simply compile & run the output binary, forwarding all make targets except that one as CLI arguments.

Example:

```bash
make -C av-switchyard run-linux-amd64 -- --help
```

```
make: Entering directory '/j/proj/av-switchyard/av-switchyard'
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
   go build -o dist/av-switchyard-linux-amd64 .
dist/av-switchyard-linux-amd64 --help
Usage: switchyard <command> [flags]

Lighting protocol bridge

Flags:
  -h, --help                    Show context-sensitive help.
      --verbose                 Enable verbose logging.
      --config="config.yaml"    Configuration file.
      --listen=":9000"          Address to listen on.

Commands:
  run-daemon [flags]
    Run the bridge daemon.

  version [flags]
    Print version information.

Run "switchyard <command> --help" for more information on a command.
```

```bash
make -C av-switchyard run-linux-amd64 -- run-daemon
```

```
make: Entering directory '/j/proj/av-switchyard/av-switchyard'
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
   go build -o dist/av-switchyard-linux-amd64 .
dist/av-switchyard-linux-amd64 run-daemon
ctx.Selected().Type = %s 1
Running...
Verbose:  false
Config:   config.yaml
Listen:   :9000
ArtNet:   false
sACN:     false
Universe: 1
DryRun:   false
2026/07/04 08:49:17 listening on 0.0.0.0:6454 (net 0, universe 3), forwarding to 2.0.0.6:6454
```

# Prior art

Signifiant inspiration from [marshallpt/artnet-python-bridge](https://github.com/marshallpt/artnet-python-bridge), both for technical protocol-level knowledge
and control system logic.

# License

The code in this repository is under the GPLv2 license (v2 only), see `LICENSE.txt` for details.
The auto-upgrade clause has been removed because your legal rights shouldn't have that sort of volatility.

