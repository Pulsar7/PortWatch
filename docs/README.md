# PortWatch

## Description

A lightweight port scanner that monitors hosts for unexpected port states and sends alerts to a configured NTFY instance.

- Hosts and their expected open ports are defined in the configuration file (`hosts.json`).
- For each host, the scanner verifies:
  - Whether all expected ports are actually open.
  - Whether any additional, unexpected ports are open.

### Alerts

An alert is triggered if:
- A port is found open that is **not listed** in the configuration.
- A port that is **expected to be open** is found closed or filtered.

### Dependencies
 
Make sure `nmap` (https://nmap.org/) is installed and available on your system.

## Usage

__Setup__:

```SHELL
git clone https://github.com/Pulsar7/PortWatch.git
cd PortWatch
python3 -m venv .venv && source .venv/bin/activate
pip3 install -r requirements.txt
cp .sample.env .env
```

After copying the environment file, open `.env` and adjust the variables according to your setup (e.g., NTFY instance URL, hosts configuration, etc.).

### Implementation as systemd-timed-service

You can use the script however you want.
Here is an example:

#### run_port_watcher.sh

```BASH
#!/bin/bash

### Variables
WORK_DIR="/home/my_username/PortWatcher"
SCRIPT_FILEPATH="${WORK_DIR}/port_watch.py"

# Assuming, that `.venv/bin/activate` already exists.
source "${WORK_DIR}/.venv/bin/activate"
# Assuming that all required python-modules are already installed.
python3 "${SCRIPT_FILEPATH}"
```

#### port_watcher.service

```SHELL
[Unit]
Description=PortWatcher
After=network.target

[Service]
Type=simple
WorkingDirectory=/home/my_username/PortWatcher
ExecStart=/home/my_username/PortWatcher/run_port_watcher.sh
Restart=on-failure
StandardOutput=journal
StandardError=journal
```

#### port_watcher.timer

```SHELL
[Unit]
Description=Run PortWatcher

[Timer]
OnCalendar=daily  
Unit=port_watcher.service
Persistent=true

[Install]
WantedBy=timers.target
```