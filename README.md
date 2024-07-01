# stego-IPv6EH
The implementation of my research "On the Reduction of Overhead Ratio Incurred by Forward Error Correction in IPv6 Extension Header Steganography".
This is used only to verify the effectiveness of the steganography method.

## Usage
1. Clone the repository first.
2. (Optional) Set up Bind9 on the receiver side.
3. Modify receiver's IPv6 address in `config.py`.
4. On the receiver side, run "sudo python3 receiver.py".
5. On the sender side, run "sudo python3 sender.py <filename>".

## Stego Programs
- `config.py`
  - parameters setting
- `reedsolo.py`
  - RS code algorithm library
- `reedsolomon.py`
  - self-defined functions to call functions in `reedsolo.py`
  - RS Encoder & RS Decoder
- `pktop.py`
  - Stego packets manipulation.
  - Packet Generator & Packet Collector
- `sender.py`
  - the main program of stego sender
- `fileop.py`
  - File Reader
- `receiver.py`
  - the main program of stego receiver
- `dataop.py`
  - Codeword Extractor

## DNS Process Setting
- `dns_addRR.py`
  - Python script to generate RRs in “/etc/bind/pearl.org”
- `dns_reply.py`
  - deprecated
