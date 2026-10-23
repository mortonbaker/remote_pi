// Managed pairing — the pairing a device owner (Guardian, on the family
// tablets) ships as Android app restrictions, so a managed install is paired
// on first launch with nothing to scan or tap.
//
// The provisioning host (atlas01) mints the app's Owner key itself, writes
// its public half into the Pi's peers.json ahead of time, and hands the app
// everything else through managed config:
//
//   owner_seed  base64 Ed25519 seed (32 bytes) — this app's Owner identity
//   pi_epk      base64/base64url Ed25519 pubkey of the Pi
//   relay_url   http(s) URL of the relay the Pi listens on
//   room_id     the Pi's room (cwd-session) id
//   pi_name     display name for the Pi tile (optional)
//
// Missing or malformed config → null, and the app behaves exactly as an
// unmanaged install (QR / deep link pairing).

import 'dart:convert';

import 'package:app/data/preferences/preferences.dart';
import 'package:app/pairing/storage.dart';
import 'package:cryptography/cryptography.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:remote_pi_identity/remote_pi_identity.dart';

const _channel = MethodChannel('remotepi/managed_config');

class ManagedPairing {
  final OwnerIdentity identity;
  final String piEpk; // base64url, the form PeerRecord.remoteEpk uses
  final String relayUrl;
  final String roomId;
  final String piName;

  const ManagedPairing({
    required this.identity,
    required this.piEpk,
    required this.relayUrl,
    required this.roomId,
    required this.piName,
  });

  static Future<ManagedPairing?> load() async {
    if (defaultTargetPlatform != TargetPlatform.android || kIsWeb) return null;
    final Map<Object?, Object?>? raw;
    try {
      raw = await _channel.invokeMapMethod<Object?, Object?>('get');
    } catch (e) {
      debugPrint('[managed] config unavailable: $e');
      return null;
    }
    if (raw == null || raw.isEmpty) return null;
    String? s(String k) {
      final v = raw![k];
      return v is String && v.trim().isNotEmpty ? v.trim() : null;
    }

    final seedB64 = s('owner_seed');
    final epkB64 = s('pi_epk');
    final relay = s('relay_url');
    final room = s('room_id');
    if (seedB64 == null || epkB64 == null || relay == null || room == null) {
      debugPrint('[managed] config incomplete, ignoring');
      return null;
    }
    try {
      final seed = _decode(seedB64);
      final epk = _decode(epkB64);
      if (seed.length != 32 || epk.length != 32) return null;
      final kp = await Ed25519().newKeyPairFromSeed(seed);
      final pub = await kp.extractPublicKey();
      return ManagedPairing(
        identity: OwnerIdentity(
          ownerPk: Uint8List.fromList(pub.bytes),
          ownerSk: seed,
        ),
        piEpk: base64Url.encode(epk).replaceAll('=', ''),
        relayUrl: relay,
        roomId: room,
        piName: s('pi_name') ?? 'Pi',
      );
    } catch (e) {
      debugPrint('[managed] config malformed: $e');
      return null;
    }
  }

  /// Make local state match the managed pairing: relay set, exactly one
  /// peer (the managed Pi) on the managed room. Peers left over from an
  /// earlier identity are removed — they can never authenticate again.
  Future<void> apply(PairingStorage storage, Preferences prefs) async {
    await prefs.setRelayUrl(relayUrl);
    for (final p in await storage.listPeers()) {
      if (p.remoteEpk != piEpk) {
        await storage.deletePeerSilent(p.remoteEpk);
        await storage.deleteRooms(p.remoteEpk);
      }
    }
    final existing = await storage.loadPeer(piEpk);
    if (existing == null ||
        existing.relayUrl != relayUrl ||
        existing.roomId != roomId) {
      await storage.savePeer(PeerRecord(
        remoteEpk: piEpk,
        sessionName: existing?.sessionName ?? piName,
        relayUrl: relayUrl,
        pairedAt: DateTime.now().toUtc().toIso8601String(),
        roomId: roomId,
        nickname: existing?.nickname,
      ));
    }
    await prefs.setSelectedPeerEpk(piEpk);
    await prefs.setOnboardingCompleted(true);
    debugPrint('[managed] pairing applied');
  }
}

Uint8List _decode(String b64) {
  final norm = b64.replaceAll('-', '+').replaceAll('_', '/');
  final padded = norm.padRight((norm.length + 3) & ~3, '=');
  return Uint8List.fromList(base64.decode(padded));
}
