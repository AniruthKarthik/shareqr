# QRTunnel

Cross-platform file sharing via SSH reverse tunneling and QR codes. Allows sharing files with mobile devices anywhere in the world, even behind NAT/firewalls.

## Features

*   **Simple File Sharing:** Share one or more files directly from your command line.
*   **Receive Files:** Start in upload mode to receive files from any device with a web browser, like your phone.
*   **Secure Tunnels:** Supports both **SSH Tunneling** (default on Linux/macOS) and **ngrok** (default on Windows) for secure, public access even behind NATs/firewalls.
*   **SSH Tunneling:** Default on Linux/macOS! Uses `localhost.run` for instant tunneling without any account or sign-up.
*   **Ngrok Support:** Reliable tunneling via ngrok (requires free account), available on all platforms and default on Windows.
*   **QR Code Display:** Generates a scannable QR code in your terminal for easy access on mobile devices.
*   **Web Interface:** Provides a simple web page for recipients to download shared files, individually or as a ZIP archive.
*   **Ngrok Authtoken Management:** Interactive setup and status check for your ngrok authentication token.

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/AniruthKarthik/qrtunnel.git
    cd qrtunnel
    ```
2.  **Install the package:**
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
