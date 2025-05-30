# TOFOC - Tiny Open Format Offline Credential

MIFARE DESFire shares no opinion about how applications or even file data should be formatted. TOFOC is an open, compact, and extensible 64-byte credential format intended for offline validation in access control environments.

It is designed to be:
- **Open**: Anyone can suggest edits or new formats.
- **Compact**: 64 bytes total, 44 bytes of data + 20 truncated ECC signature.
- **Secure**: Relies on DESFire's built-in file MACs and ECC signature verification that would take years to crack.
- **Flexible**: Supports multiple versions for different credential types.

## Format Versions

TOFOC supports multiple format versions to accommodate different access control needs:

### Version 0 (Basic)
- `version`: The version (1 byte)
- `start_time`: Start timestamp (4 bytes, Unix time)
- `expiration`: Expiration timestamp (4 bytes, Unix time)
- `card_details`: Credential ID (5 bytes, H10304 format)
- `allowed`: List of allowed door/access codes (2 bytes, up to 4 doors)
- `padding`: 0 bytes for the rest (min 1 byte, max 7 bytes)
- `signature`: First 10 bytes of an ECC signature signed by a private key, of which the reader has the public key

```python
version = 0x0
start_time = 0x68351080
expiration = 0x68491080
card_details = 0x1005400114
doors = [0x7e3f, 0x05f9, 0x00DB, 0xd3ad]
padding_byte = 0x0
credential_payload = version + start_time + expiration + card_details + doors + padding_byte
# Next line is the result of hashlib.sha256(credential_payload).digest()
payload_hash = 0x9189d32cdce8b054e4fb53b1caffb4743403002a8f5da3246b3359716f5f19b3
# Next line is the result of secret_key.sign_digest(payload_hash)
full_sig = 0x2f91cb797b3d8d154adf0f1369bdd331c66aa3edb13db874952edb33bbdfe4e7ef4349efa45684a260f88ec542156f7f5615e4d7a940b7b756e8a197910908b9
# Next line is the first 10 bytes (20 chars) of full_sig
signature_start = 0x2f91cb797b3d8d154adf
# Next line is credential_payload + signature_start
final_payload = 0x0683510806849108010054001147e3f05f900DBd3ad02f91cb797b3d8d154adf
```

### Version 1 (Simplified)
- Removes `start_time` for credentials with no time-based start restriction
- `expiration`: End timestamp
- `id`: Credential ID
- `allowed`: List of allowed access codes (shorter codes permitted)

### Version 2 (Time-based Access)
- `end_time`: End timestamp
- `id`: Credential ID
- `weekday_mask`: Bitmask for allowed days (e.g., `0F` = Monday to Friday)
- `daily_start`: Start time in hex (e.g., `21C` = 9:00 AM)
- `daily_end`: End time in hex (e.g., `3FC` = 5:00 PM)
- `allowed`: List of allowed door codes (up to 5, typically 16–24 bits)
- `padding`: Optional 1-byte padding

### Version 3 (Block List)
- `end_time`: End timestamp
- `id`: Credential ID
- `blocked`: List of **blocked** door/access codes (inverted logic)
- `padding`: Optional 1-byte padding

More formats (v4–v15) support features like door ranges, access groups, scan counters, rotating schedules, and ephemeral access. See `formats.md` for full spec.

---

## NFC Reader Implementation

### Payload Verification

To verify a TOFOC payload on an NFC reader:

1. **Read the payload** from the DESFire file (64 bytes total)
2. **Extract the signature** (last 20 bytes of the payload)
3. **Extract the credential data** (first 44 bytes of the payload)
4. **Hash the credential data** using SHA-256
5. **Verify the signature** using the stored public key and the hash
6. **Parse the credential** based on the version byte (first byte)

```python
def verify_payload(payload_bytes, public_key):
    # Split payload
    credential_data = payload_bytes[:44]
    signature = payload_bytes[44:]
    
    # Hash the credential data
    payload_hash = hashlib.sha256(credential_data).digest()
    
    # Verify signature (implementation depends on your crypto library)
    is_valid = public_key.verify_signature(signature, payload_hash)
    
    if is_valid:
        return parse_credential(credential_data)
    else:
        raise InvalidSignatureError("Payload signature verification failed")
```

### Version-Based Parsing

Parse the credential data based on the version byte:

```python
def parse_credential(data):
    version = data[0]
    
    if version == 0:
        return parse_version_0(data)
    elif version == 1:
        return parse_version_1(data)
    elif version == 2:
        return parse_version_2(data)
    elif version == 3:
        return parse_version_3(data)
    else:
        raise UnsupportedVersionError(f"Version {version} not supported")

def parse_version_0(data):
    version = data[0]
    start_time = int.from_bytes(data[1:5], 'big')
    expiration = int.from_bytes(data[5:9], 'big')
    card_id = data[9:14]  # 5 bytes H10304 format
    doors = [int.from_bytes(data[14+i*2:16+i*2], 'big') for i in range(4)]
    return {
        'version': version,
        'start_time': start_time,
        'expiration': expiration,
        'card_id': card_id,
        'allowed_doors': doors
    }

def parse_version_1(data):
    version = data[0]
    expiration = int.from_bytes(data[1:5], 'big')
    card_id = data[5:10]
    # Parse allowed codes (format may vary)
    return {
        'version': version,
        'expiration': expiration,
        'card_id': card_id,
        'allowed_codes': parse_allowed_codes(data[10:])
    }

def parse_version_2(data):
    version = data[0]
    end_time = int.from_bytes(data[1:5], 'big')
    card_id = data[5:10]
    weekday_mask = data[10]
    daily_start = int.from_bytes(data[11:13], 'big')
    daily_end = int.from_bytes(data[13:15], 'big')
    doors = [int.from_bytes(data[15+i*2:17+i*2], 'big') for i in range(5)]
    return {
        'version': version,
        'end_time': end_time,
        'card_id': card_id,
        'weekday_mask': weekday_mask,
        'daily_start': daily_start,
        'daily_end': daily_end,
        'allowed_doors': doors
    }

def parse_version_3(data):
    version = data[0]
    end_time = int.from_bytes(data[1:5], 'big')
    card_id = data[5:10]
    blocked_doors = parse_blocked_doors(data[10:])
    return {
        'version': version,
        'end_time': end_time,
        'card_id': card_id,
        'blocked_doors': blocked_doors
    }
```

### Access Validation

After parsing, validate access based on the credential type:

```python
def validate_access(credential, door_id, current_time):
    # Check expiration
    if 'expiration' in credential and current_time > credential['expiration']:
        return False
    if 'end_time' in credential and current_time > credential['end_time']:
        return False
        
    # Check start time (version 0)
    if 'start_time' in credential and current_time < credential['start_time']:
        return False
    
    # Check time-based access (version 2)
    if credential['version'] == 2:
        return validate_time_based_access(credential, door_id, current_time)
    
    # Check door access
    if 'allowed_doors' in credential:
        return door_id in credential['allowed_doors']
    elif 'blocked_doors' in credential:
        return door_id not in credential['blocked_doors']
    
    return False
```

---

## Usage

1. Concatenate fields as tightly packed bytes
2. Hash the byte array using SHA-256
3. Sign the hash with an ECC key (e.g., secp256k1)
4. Append the first 10 bytes (20 hex chars) of the signature to the original data
5. Write the full 64-byte payload to a DESFire file configured with secure MAC mode
6. Ensure reader and writer share the same public key for verification

---

## Example

```plaintext
credential_payload = 0 68351080 68491080 1005400114 7e3f 05f9 00DB
signature_start = 2f91cb797b3d8d15
final_payload = 0683510806849108010054001147e3f5f900005f900000db2f91cb797b3d8d15