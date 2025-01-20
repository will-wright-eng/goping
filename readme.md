# GoPing

A modern reimplementation of the classic `ping` utility in Go, inspired by Mike Muuss's original 1983 creation. This project combines the simplicity of the original ping with modern features like geographic tracing, detailed protocol analysis, and comprehensive network path visualization.

## Features

- Classic ping functionality with ICMP echo request/reply
- Detailed protocol analysis with verbose output mode
- Geographic path tracing with ISP information
- Advanced statistics (min/avg/max/stddev RTT)
- Customizable packet size and interval
- IPv4 support with TTL control
- Path tracing with hop-by-hop analysis
- Integration with GeoIP database for location information
- Rich debugging output with packet-level details
- Configurable timeouts and intervals

## Requirements

- Go 1.21 or higher
- GeoLite2-City.mmdb database file (for geographic features)
- Root/Administrator privileges (required for ICMP)

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/goping

# Build the binary
make build
```

The compiled binary will be available in the `dist` directory.

## Usage

Basic usage:
```bash
sudo goping example.com
```

### Command Line Options

```bash
goping [options] host
  -s size        Size of ICMP packet payload (default: 56 bytes)
  -t ttl         Time To Live (default: 52 hops)
  -W timeout     Timeout for each ping (default: 1s)
  -i interval    Interval between pings (default: 1s)
  -v            Verbose output with ICMP and networking details
  -trace        Trace route to destination
  -geo          Show geographic information
```

## Examples

Simple ping:
```bash
$ sudo goping google.com
PING google.com (142.250.190.78): 56 data bytes
64 bytes from 142.250.190.78: icmp_seq=0 ttl=52 time=15.123 ms
64 bytes from 142.250.190.78: icmp_seq=1 ttl=52 time=14.877 ms
```

Verbose output with protocol details:
```bash
$ sudo goping -v google.com
PING google.com (142.250.190.78): 56 data bytes

ICMP Protocol Details
Type    Echo Request (Type 8)
Code    0
Identifier    1234
Total Size    64 bytes (Header: 8, Data: 56)
Checksum    Calculated over header and data

IPv4 Details
TTL    52 hops
Protocol    1 (ICMP)
ToS    0x00 (Normal Service)
Fragment    Don't Fragment bit set
```

Geographic trace with ISP information:
```bash
$ sudo goping -trace -geo google.com
Tracing route to google.com [142.250.190.78]
Maximum hops: 52, Packet size: 56 bytes

 1  192.168.1.1 (Local Network) 1.2 ms
 2  10.0.0.1 (ISP Gateway) 5.3 ms  New York, USA
 3  142.250.190.78 (Google LLC) 15.1 ms  Mountain View, USA
```

## Building from Source

Requirements:
- Go 1.21 or higher
- Make
- GeoLite2 City database

Steps:
```bash
make build    # Build the binary
make install  # Install to system
```

## Project Structure

```
.
├── Makefile
├── dist
│   └── goping
├── go.mod
├── go.sum
├── main.go
└── readme.md
```

## Dependencies

- github.com/oschwald/geoip2-golang - For GeoIP lookups
- github.com/sirupsen/logrus - For structured logging
- golang.org/x/net/icmp - For ICMP protocol implementation

## Notes

- Root/Administrator privileges are required to send ICMP packets
- Geographic features require the GeoLite2-City.mmdb database
- The program uses the ipapi.co service for ISP information (free tier)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## License

MIT License - see the [LICENSE](LICENSE) file for details

## Acknowledgments

- Mike Muuss, creator of the original `ping` utility
- MaxMind for the GeoLite2 database
- The Go networking community
