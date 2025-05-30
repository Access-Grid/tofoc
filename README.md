# TOFOC - Tiny Open Format Offline Credential 

MIFARE DESFire shares no opinion about how applications or even file data should be formatted. This intends to be an open format for 64 bytes of data, where you can do quite a lot. It's purpose is to be open and allow for anyone to suggest edits, as well as provide a few reference implementations.

## Format Versions

TOFOC supports multiple format versions to accommodate different use cases:

### Version 0 (Basic)
- `start_time`: Start timestamp
- `end_time`: End timestamp  
- `id`: Credential ID (e.g., H10304)
- `allowed`: List of allowed door/access codes

### Version 1 (Simplified)
- Removes start_time for credentials with no time restrictions
- `end_time`: End timestamp
- `id`: Credential ID
- `allowed`: List of allowed access codes

### Version 2 (Time-based Access)
- `end_time`: End timestamp
- `id`: Credential ID
- `weekday_mask`: Bitmask for allowed days (0F = Monday to Friday)
- `daily_start`: Start time in hex (21C = 9:00 AM)
- `daily_end`: End time in hex (3FC = 5:00 PM)  
- `allowed`: List of allowed door codes
- `padding`: Additional padding bytes

### Version 3 (Block List)
- `end_time`: End timestamp
- `id`: Credential ID
- `blocked`: List of blocked door/access codes instead of allowed
- `padding`: Additional padding bytes

## Usage

1. Concatenate bytes from credential data
2. Hash the bytes
3. Generate ECC signature
4. Append first 16 bytes of ECC signature to original data
5. Share public key between reader/controller and file payload creation script

## Example

```
credential_payload = 0 68351080 68491080 1005400114 7e3f5f9 00005f9 00000DB
signature_start = 2f91cb797b3d8d15
final_payload = 0683510806849108010054001147e3f5f900005f900000db2f91cb797b3d8d15
```
