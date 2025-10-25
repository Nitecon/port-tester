# UDP/TCP Port Tester GUI

A simple Qt (PySide6) desktop app to test UDP and TCP ports in multiplayer/networked scenarios.

## Features

- Server tab
  - TCP server: listen, accept, log messages, optional echo.
  - UDP listener: bind, log datagrams, optional echo.
  - Live logs.
- Client tab
  - Send standard messages (Hello, Ping) or custom text.
  - Optional Base64-encode before sending.
  - Send via TCP or UDP to a target host:port.
  - TCP connect test (port open check).
  - UDP ping test (send and wait for reply with timeout).

## Requirements

- Python 3.10+
- macOS (tested), should work on Linux/Windows with Python and Qt dependencies installed.

Install dependencies:

```
pip install -r requirements.txt
```

## Run

```
python app.py
```

## Notes

- For UDP ping test to receive a reply, run the UDP listener with Echo enabled on the target host/port, or another process that replies.
- For TCP testing, the TCP server in the Server tab can echo back data if Echo is enabled.
