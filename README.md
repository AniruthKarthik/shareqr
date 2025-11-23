# QRTunnel

Cross-platform file sharing via SSH reverse tunneling and QR codes. Allows sharing files with mobile devices anywhere in the world, even behind NAT/firewalls.

## Features

*   **Simple File Sharing:** Share one or more files directly from your command line.
*   **Secure Tunnels:** Utilizes ngrok for secure, public HTTPS tunnels, even behind NATs and firewalls.
*   **No-Auth Alternative:** For Mac/Linux users, an SSH-based tunnel (localhost.run) is available, requiring no ngrok account.
*   **QR Code Display:** Generates a scannable QR code in your terminal for easy access on mobile devices.
*   **Web Interface:** Provides a simple web page for recipients to download shared files, individually or as a ZIP archive.
*   **Ngrok Authtoken Management:** Interactive setup and status check for your ngrok authentication token.

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/AniruthKarthik/qrtunnel.git
    cd qrtunnel
    ```
2.  **Install dependencies:**
    ```bash
    pip install pyngrok qrcode[pil]
    ```

## Usage

### Basic Sharing

To share one or more files:

```bash
python qr.py <file_path1> [<file_path2> ...]
```

Example:
```bash
python qr.py mydocument.pdf myimage.jpg
```

This will start a local HTTP server, create a public tunnel (using ngrok by default), and display a QR code. Scan the QR code with your phone to access the files.

### Ngrok Authentication Setup

`qrtunnel` uses ngrok for reliable public tunnels. The first time you use it, or if you need to update your token, you'll be prompted to set up your ngrok authtoken. You can also do this manually:

```bash
python qr.py --setup
```

Follow the on-screen instructions to get and save your ngrok authtoken.

### Check Ngrok Status

To check if your ngrok authtoken is configured:

```bash
python qr.py --status
```

### No-Auth Sharing (Mac/Linux Only)

If you're on Mac or Linux and prefer not to use an ngrok account, you can use the `--noauth` flag. This will attempt to create an SSH tunnel via `localhost.run`.

```bash
python qr.py <file_path1> [<file_path2> ...] --noauth
```

**Note:** This option is not supported on Windows.

### Quitting the Server

The server will run until you press `q` in the terminal or use `Ctrl+C`.
