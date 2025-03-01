# Restore Statistics When Restarting Xray

Xray is a platform for building proxies. This fork was created from [XTLS/Xray-core](https://github.com/XTLS/Xray-core) to address the issue where Xray resets all user statistics upon restart.

## How It Works

Before stopping Xray, you need to call `xray api statsquery` and save its output to a file like this:

```bash
xray api statsquery > xray_stats.json
```

Then, when restarting Xray, use special flags to restore statistics from that file.

### Flags

These flags were added for the `xray run` command:

- `-restore-stats`: Restores statistics from a JSON file.
- `-statsfile=file`: Specifies the path to the JSON file used for restoring statistics. The default is `xray_stats.json`, located in the same directory as the Xray executable.

### Example

To run Xray with a specific configuration file and restore statistics from a JSON file:

```bash
xray run -c config.json -restore-stats -statsfile /path/to/stats.json
```

## How to Use It

First, you need to [install](#installation) this version of Xray.

Typically, `xray run` is not called manually; instead, it is managed via a systemd unit. To set up statistics restoring, modify the `ExecStart` line in the unit file by adding the `-restore-stats` and (optionally) `-statsfile` flags:

```
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json -restore-stats -statsfile /path/to/stats.json
```

⚠️ **Important:** Modifying the main unit file (`/etc/systemd/system/xray.service`) is not recommended, as updates may overwrite your changes.

### Using a Drop-In Override

A better approach is to use a Drop-In Override. If you installed Xray via the [official script](https://github.com/XTLS/Xray-install), you likely already have a drop-in override file, such as:

```
/etc/systemd/system/xray.service.d/10-donot_touch_single_conf.conf
```

Modify this file instead of the main service file.

If no override exists, create it:

```bash
sudo mkdir -p /etc/systemd/system/xray.service.d
sudo nano /etc/systemd/system/xray.service.d/override.conf
```

Your override file should look like this:

```
[Service]
ExecStart=
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json -restore-stats -statsfile /path/to/stats.json
```

The first `ExecStart=` clears the existing entry before adding the modified one.

You can either use the `-statsfile` flag to specify the path to your stats file or name your file `xray_stats.json` and place it in the same directory as the Xray executable (since that’s the default location).

Make sure xray can read the file and has access to it's directory.

After modifying the systemd unit configuration, reload systemd:

```bash
sudo systemctl daemon-reload
```

## Installation

### 1. Install Go

You need Go 1.24 or later. If this version is unavailable in your package manager, install it manually:

1. **Download & Install Go 1.24+:**
   ```bash
   wget https://go.dev/dl/go1.24.0.linux-amd64.tar.gz
   sudo tar -C /usr/local -xzf go1.24.0.linux-amd64.tar.gz
   ```

2. **Update Your PATH:**  
   Add this to your shell configuration file (`~/.bashrc`, `~/.profile`, or `~/.zshrc`):
   ```bash
   export PATH=$PATH:/usr/local/go/bin
   ```
   Apply the changes:
   ```bash
   source ~/.bashrc  # or source ~/.profile
   ```

3. **Verify Installation:**
   ```bash
   go version
   ```

### 2. Clone and Compile

#### 1. Clone the repository and navigate to its folder:

```bash
git clone https://github.com/five9th/Xray-core.git
cd Xray-core
```

#### 2. Install dependencies:

```bash
go mod tidy
```

#### 3. Build the project as shown in the official repo:

**Windows (PowerShell):**
```powershell
$env:CGO_ENABLED=0
go build -o xray.exe -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -v ./main
```

**Linux/macOS:**
```bash
CGO_ENABLED=0 go build -o xray -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -v ./main
```

### 3. Replace the Executable

After a successful compilation:

1. Stop the Xray service (don't forget to save statistics first).
2. Replace the existing Xray executable with the newly compiled one (consider making a backup before replacing it).
3. [Update the systemd unit file as described earlier](#how-to-use-it) and restart the Xray service.
4. Verify the service status:

```bash
sudo systemctl status xray
```

Xray will start even if statistics restoration fails, but an error message will be logged.

Successful restoration:
```
xray[110416]: Restoring stats from the previous session.
xray[110416]: Read stat entries: 18; Counters registered: 16.
```

Error example:
```
xray[110416]: error opening stats file: permission denied.
```