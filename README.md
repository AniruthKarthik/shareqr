# QRTunnel

Cross-platform file sharing via SSH reverse tunneling and QR codes. Allows sharing files with mobile devices anywhere in the world, even behind NAT/firewalls.

## Features

*   **Simple File Sharing:** Share one or more files directly from your command line.
*   **Receive Files:** Start in upload mode to receive files from any device with a web browser, like your phone.
*   **High-Speed LAN Sharing:** Use the `--lan` flag to share files directly over your local Wi-Fi/network at maximum speed, bypassing the internet.
*   **Smart Auto-Detection:** Automatically detects if the recipient is on the same Wi-Fi and switches to high-speed LAN transfer instantly, bypassing the tunnel.
*   **LAN Security (OTP):** High-speed LAN transfers are protected by a random 6-digit passcode displayed only on your terminal.
*   **Randomized Port:** Every run uses a different random port (20000-60000) for security and to prevent port conflicts.
*   **Secure Tunnels:** Supports both **SSH Tunneling** (default on Linux/macOS) and **ngrok** (default on Windows) for secure, public access even behind NATs/firewalls.
*   **SSH Tunneling:** Default on Linux/macOS! Uses `localhost.run` for instant tunneling without any account or sign-up.
*   **Ngrok Support:** Reliable tunneling via ngrok (requires free account), available on all platforms and default on Windows.
*   **QR Code Display:** Generates a scannable QR code in your terminal for easy access on mobile devices.
*   **Web Interface:** Provides a simple web page for recipients to download shared files, individually or as a ZIP archive.
*   **Ngrok Authtoken Management:** Interactive setup and status check for your ngrok authentication token.

## Installation

```bash
pip install qrtunnel
```

This will install `qrtunnel` and all its dependencies.

## Usage

### Sharing Files (PC to Phone)

To share one or more files:

```bash
qrtunnel <file_path1> [<file_path2> ...]
```

Example:
```bash
qrtunnel mydocument.pdf myimage.jpg
```

This will start a local HTTP server and create a public tunnel.
*   **Linux/macOS:** Defaults to **SSH tunneling** (no account needed).
*   **Windows:** Defaults to **ngrok** (requires account setup).

Scan the QR code with your phone to access the files.

### High-Speed LAN Sharing (Wi-Fi Mode)

If you and the recipient device are on the same Wi-Fi or local network, you can use the `--lan` flag. This is significantly faster than tunneling because data never leaves your local network.

```bash
qrtunnel <file_path1> --lan
```

**Benefits of LAN mode:**
*   **Maximum Speed:** Limited only by your router/network hardware (perfect for 10GB+ files).
*   **Privacy:** Data stays within your local network.
*   **Resumable:** Supports high-speed resumable downloads.
*   **Zero-Copy:** Uses optimized OS-level file streaming for minimum CPU usage.

### Receiving Files (Phone to PC)

To receive files on your computer, simply run `qrtunnel` without any file paths:

```bash
qrtunnel
```

This starts the server in upload mode. Scan the generated QR code on your phone, and you'll get a web page where you can select and upload a file to your computer.

### Tunnel Selection (Ngrok vs SSH)

`qrtunnel` supports two tunneling methods: **SSH (localhost.run)** and **ngrok**.

#### On Linux / macOS:
*   **Default:** SSH Tunneling (No sign-up required).
    ```bash
    qrtunnel <files>
    ```
*   **Use Ngrok:** To use ngrok instead (more stable, requires account):
    ```bash
    qrtunnel <files> --ngrok
    ```

#### On Windows:
*   **Default:** Ngrok (Requires account).
    ```bash
    qrtunnel <files>
    ```
*   **SSH Tunneling:** Not reliably supported on Windows.

### Ngrok Authentication Setup

If you use ngrok (default on Windows, optional on Linux/macOS), you'll need to set up your authtoken once:

```bash
qrtunnel --setup
```

Follow the on-screen instructions to get and save your ngrok authtoken.

### Check Ngrok Status

To check if your ngrok authtoken is configured:

```bash
qrtunnel --status
```

### Quitting the Server

The server will run until you press `q` in the terminal or use `Ctrl+C`.
