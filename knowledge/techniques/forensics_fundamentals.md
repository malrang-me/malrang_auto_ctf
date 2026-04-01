# Forensics Fundamental Techniques

## Memory Forensics (Volatility 3)
- `vol -f dump.raw windows.info` — OS info
- `vol -f dump.raw windows.pslist` — process list
- `vol -f dump.raw windows.pstree` — process tree
- `vol -f dump.raw windows.cmdline` — command lines
- `vol -f dump.raw windows.filescan` — file handles
- `vol -f dump.raw windows.dumpfiles --pid <PID>` — extract files
- `vol -f dump.raw windows.registry.hivelist` — registry hives
- `vol -f dump.raw windows.netscan` — network connections

## PCAP Analysis
- Wireshark/tshark: GUI/CLI packet analysis
- `tshark -r capture.pcap -T fields -e data` — extract raw data
- `tshark -r capture.pcap -Y "http" -T fields -e http.request.uri` — HTTP URIs
- Scapy: programmatic packet manipulation
- NetworkMiner: auto-extract files from PCAP

### Common PCAP Patterns
| Pattern | Tool | Command |
|---------|------|---------|
| HTTP file transfer | tshark | `tshark -r cap.pcap --export-objects http,output/` |
| DNS exfiltration | tshark | filter `dns.qry.name` for encoded data |
| FTP transfer | Wireshark | follow TCP stream on port 21/20 |
| Encrypted traffic | ssldump | needs key file for decryption |

## Disk / File System
- `binwalk -e file` — extract embedded files
- `foremost -i image.dd` — file carving
- `strings -a file | grep -i flag` — quick string search
- `file *` — identify all file types
- `fdisk -l image.dd` — partition table
- `mount -o loop,offset=X image.dd /mnt` — mount partition

## Steganography
- `steghide extract -sf image.jpg` — embedded data
- `zsteg image.png` — PNG LSB analysis
- `stegsolve` — visual bit plane analysis
- `exiftool image.jpg` — metadata
- `pngcheck -v image.png` — PNG structure validation

## Log Analysis
- `grep -r "flag\|admin\|root\|password" /var/log/`
- `awk '{print $1}' access.log | sort | uniq -c | sort -rn` — top IPs
- Timeline analysis: sort by timestamp, find anomalies

## Common CTF Forensics Flow
```
1. file/binwalk → identify format
2. strings → quick wins (embedded flags, URLs)
3. If memory dump → Volatility
4. If PCAP → Wireshark/tshark
5. If image → steganography tools
6. If disk → mount and explore
7. If log → grep patterns + timeline
```
