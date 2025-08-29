# PortWatch

## Description

A simple port-scanner that's scanning for unusual open-ports on certain services and sends out an alert to a given NTFY-instance.

- Define hosts in the config-file (**hosts.json**) that need to be scanned.
  - Add list of ports that should be open.

### Alerts

An alert is sent out when ports are open, that are not defined in the config-file or when ports that should be open are closed.


## Usage

__Setup__:

```SHELL
git clone https://github.com/Pulsar7/PortWatch.git
cd PortWatch
python3 -m venv .venv && source .venv/bin/activate
pip3 install -r requirements.txt
```

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