# MeshConnect – Secure Offline Messaging & File Sharing

**MeshConnect** is an offline-first, decentralized, peer-to-peer Android messaging and encrypted file-sharing application built with Kotlin, Jetpack Compose, Room, Android Keystore, and Google Tink. It operates **without Internet, mobile data, cloud servers, Firebase, or external messaging backends**.

---

## 1. Architecture Overview

- **Cryptography (`com.example.crypto`)**
  - `IdentityKeyManager`: Generates per-device **X25519** key-agreement pairs, **Ed25519** digital signature pairs, unique Device ID, SHA-256 fingerprint, and 60-digit Safety Number. Private keys are sealed with an **Android Keystore** AES-256-GCM master wrapping key (`AndroidKeystoreProtector`) and are never transmitted or stored in Room.
  - `E2eeCryptoEngine`: Hybrid encryption using static + ephemeral **X25519** ECDH, **HKDF-SHA256** key derivation, **AES-256-GCM** for message/DEK/64 KB chunk encryption, **Ed25519** signature verification before decryption, and **SHA-256** integrity verification.
  - `LocalStorageCipher`: Encrypts sensitive Room database fields (message bodies, reply previews, group keys) at rest using a Keystore-sealed local database key.
  - `QrVerificationCodec`: Offline CameraX + ZXing QR verification signed with Ed25519.

- **Wireless Transports & Multi-Hop Relay (`com.example.network`)**
  - `WifiDirectTransport`: Native `WifiP2pManager` peer discovery, connection invitation, and Group Owner socket handoff.
  - `BleDiscoveryTransport`: `BluetoothLeAdvertiser` + `BluetoothLeScanner` beacon discovery and Bluetooth Classic RFCOMM fallback for lightweight control/text frames.
  - `WifiAwareTransport`: Android 8.0+ (`API 26+`) `WifiAwareManager` NAN publish/subscribe where supported by hardware.
  - `LocalWifiLanTransport`: Offline `NsdManager` (`_meshconnect._tcp.`) mDNS discovery and TCP socket server/client (`45455`).
  - `MeshRouter` & `MeshSyncWorker`: Store-and-forward multi-hop relay (`Device A -> B -> C -> D`) with duplicate suppression, TTL expiration, hop-limit loop protection, and user-controlled relay participation. Intermediate relays forward opaque encrypted envelopes and cannot decrypt message or file contents.

- **Link Quality Prediction (`com.example.ml`)**
  - `LightGbmLinkPredictor`: Evaluates `assets/link_quality_lgbm_model.json` (LightGBM GBDT JSON structure) across 5 wireless metrics (**RSSI, Packet Delivery Ratio, Latency, Packet Loss Rate, Throughput**), with deterministic fallback if the ML module is disabled or unavailable.
  - **Model Provenance Limitation**: The bundled tree ensemble uses baseline research-calibrated heuristic weights (`trained_on_field_data: false`), not an empirically trained user field dataset.

- **Local Persistence (`com.example.data.local`)**
  - Room Database (`MeshDatabase`) storing peers, conversations, encrypted messages, groups, per-recipient delivery statuses, chunked transfer states (for pause/resume), pending relay packets, and seen replay nonces.

---

## 2. Android Permissions Explained (No `INTERNET` Permission)

`android.permission.INTERNET` is intentionally omitted from `AndroidManifest.xml`.

- `ACCESS_WIFI_STATE`, `CHANGE_WIFI_STATE`, `ACCESS_NETWORK_STATE`, `CHANGE_NETWORK_STATE`: Normal permissions for Wi-Fi Direct, Wi-Fi Aware, and local P2P socket interfaces.
- `NEARBY_WIFI_DEVICES` (`neverForLocation`, Android 13+) / `ACCESS_FINE_LOCATION` (`maxSdkVersion="32"`): Required by Android OS for Wi-Fi Direct & Wi-Fi Aware peer discovery.
- `BLUETOOTH_SCAN`, `BLUETOOTH_ADVERTISE`, `BLUETOOTH_CONNECT` (Android 12+) / `BLUETOOTH`, `BLUETOOTH_ADMIN` (`maxSdkVersion="30"`): Required for BLE beacon discovery and RFCOMM fallback.
- `CAMERA`: Requested at runtime **only** when scanning a peer's QR verification code.
- `RECORD_AUDIO`: Requested at runtime **only** when recording an offline voice note.
- `FOREGROUND_SERVICE` + `FOREGROUND_SERVICE_CONNECTED_DEVICE`: Keeps local P2P listeners and multi-chunk transfers reliable on Android 14+.
- **Zero Broad Storage Permissions**: Uses Play-compliant Android Photo Picker (`PickVisualMedia`) and Storage Access Framework (`OpenDocument`).

---

## 3. Security Limitations & Hardware Constraints

1. **Trust-On-First-Use (TOFU) vs QR Verification**: Until two devices verify each other via out-of-band QR code or 60-digit Safety Number comparison, initial pairing relies on TOFU.
2. **Android Wi-Fi Direct Multi-Hop Limitation**: Android's `WifiP2pManager` does not natively route multi-hop IP mesh packets across simultaneous P2P groups. MeshConnect implements application-layer store-and-forward relay over sequential P2P/LAN/Bluetooth sessions.
3. **Metadata Visibility**: Nearby radios expose hardware beacons (BLE advertisements, Wi-Fi Direct device names) and relay nodes observe routing headers (`targetDeviceId`, `hopCount`), even though message/file payloads remain end-to-end encrypted.
4. **No Claim of Unverified Security**: Conduct independent cryptographic review and physical two-device field testing before high-sensitivity deployment.

---

## 4. Building Debug & Signed Release APKs

### Debug APK
```bash
./gradlew assembleDebug
# Output: app/build/outputs/apk/debug/app-debug.apk
```

### Signed Release APK
1. Generate a release keystore:
   ```bash
   keytool -genkey -v -keystore my-upload-key.jks -keyalg RSA -keysize 2048 -validity 10000 -alias upload
   ```
2. Export environment variables (`KEYSTORE_PATH`, `STORE_PASSWORD`, `KEY_PASSWORD`) and build:
   ```bash
   ./gradlew assembleRelease
   # Output: app/build/outputs/apk/release/app-release.apk
   ```

### Running Local JVM & Robolectric Tests
```bash
./gradlew :app:testDebugUnitTest
```

---

## 5. Two-Device Physical Testing Checklist

Install the APK on **at least two physical Android smartphones** (`Device A` and `Device B`), enable Airplane Mode (or turn off Mobile Data and Internet Wi-Fi routers), keep Wi-Fi & Bluetooth radios ON, and verify:

1. **Zero-Internet Operation**: Confirm both phones have Mobile Data OFF and no Internet Wi-Fi connected.
2. **Direct Device Discovery**: Open **Nearby**, tap **Start Scan**, and verify peer discovery via Wi-Fi Direct / BLE / Wi-Fi Aware (or hardware unsupported notice if chipset lacks NAN).
3. **Secure QR Pairing**: On `Device A`, open **Verify QR -> My QR Badge**; on `Device B`, scan it via **Scan Peer QR** and verify the 60-digit Safety Number matches.
4. **Private Messaging**: Send text & voice notes from `Device A` to `Device B`; verify delivery/read ticks and encrypted local storage.
5. **Group Messaging**: Create an encrypted group with multiple verified devices; verify per-recipient delivery status tracking and key epoch rotation when removing a member.
6. **Image Transfer**: Send JPG/PNG/WEBP via Photo Picker; verify acceptance prompt and SHA-256 verification.
7. **Video Transfer**: Send an MP4 video; verify chunked transfer progress without OOM.
8. **Large File Transfer**: Send PDF/DOCX/XLSX/ZIP over Wi-Fi Direct / Local LAN socket.
9. **Interrupted Transfer Recovery**: Tap **Pause** (or toggle Wi-Fi briefly) mid-transfer, reconnect, and tap **Resume** to recover from the persisted chunk offset.
10. **Encryption & Integrity Verification**: Run `CryptoEngineTest` (`testDebugUnitTest`) to verify tampered Ed25519 signatures and tampered AES-GCM ciphertexts are rejected.
11. **Unauthorized Device Rejection**: Block a peer in **Device Management** or send an unjoined broadcast and confirm incoming packets are rejected with a security event alert.
