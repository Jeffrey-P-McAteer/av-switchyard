
# av-switchyard

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

TODO utilities, helper scripts, et al get documented here.

# Development Utilities

TODO

# License

The code in this repository is under the GPLv2 license (v2 only), see `LICENSE.txt` for details.
The auto-upgrade clause has been removed because your legal rights shouldn't have that sort of volatility.

