# Porter

Fast and clean TCP port scanner.

<p align="center">
  <img src="porter.jpg" width="100%" alt="Porter Banner">
</p>

## Philosophy

Porter is built to do one thing well: fast and accurate TCP connect scanning.
No service detection, no heavy fingerprinting, no scripting engine.

Simple input. Immediate feedback. Reliable output.

## Features

* Streams open ports immediately
* Popular-first port ordering
* Two-pass timeouts (fast pass, then retry slow)
* Connect-only scanning (no raw sockets)
* Cross-platform (Windows/macOS/Linux)

## Requirements

* Python 3.8+

## Installation

```bash
git clone https://github.com/5u5urrus/Porter.git
cd Porter
chmod +x porter.py
```

## Usage

```bash
python porter.py 1.1.1.1
```

Run with `-h` to see all options.

## Quick Examples

Default scan (balanced):

```bash
python porter.py 1.1.1.1
```

Super fast scan:

```bash
python porter.py 1.1.1.1 --tfast 0.15 --tslow 0.6 -c 600
```

More thorough scan:

```bash
python porter.py 1.1.1.1 --tfast 0.5 --tslow 2.0 -c 200
```

Scan popular ports only:

```bash
python porter.py 1.1.1.1 -p popular
```

Scan multiple targets:

```bash
python porter.py 1.1.1.1,1.1.1.3
python porter.py 1.1.1.7,1.1.1.10-34
```

Scan from file (one target per line):

```bash
python porter.py targets.txt
```

## Output

```
1.1.1.1:21 open
1.1.1.1:53 open
1.1.1.1:80 open
1.1.1.1:443 open
1.1.1.1:853 open

1.1.1.1  open: 21, 53, 80, 443, 853
```

## License

MIT

## Author

Vahe Demirkhanyan

