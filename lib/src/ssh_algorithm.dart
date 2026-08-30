import 'package:dartssh2/src/algorithm/ssh_cipher_type.dart';
import 'package:dartssh2/src/algorithm/ssh_hostkey_type.dart';
import 'package:dartssh2/src/algorithm/ssh_kex_type.dart';
import 'package:dartssh2/src/algorithm/ssh_mac_type.dart';

abstract class SSHAlgorithm {
  /// The name of the algorithm.
  String get name;

  const SSHAlgorithm();

  @override
  String toString() {
    return '$runtimeType($name)';
  }
}

extension SSHAlgorithmList<T extends SSHAlgorithm> on List<T> {
  List<String> toNameList() {
    return map((algorithm) => algorithm.name).toList();
  }

  T? getByName(String name) {
    for (var algorithm in this) {
      if (algorithm.name == name) {
        return algorithm;
      }
    }
    return null;
  }
}

class SSHAlgorithms {
  /// Algorithm used for the key exchange.
  final List<SSHKexType> kex;

  /// Algorithm used for the host key.
  final List<SSHHostkeyType> hostkey;

  /// Algorithm used for the encryption.
  final List<SSHCipherType> cipher;

  /// Algorithm used for the authentication.
  final List<SSHMacType> mac;

  /// Creates an algorithm preference set.
  ///
  /// Every list is ordered by preference: the first entry that the peer also
  /// supports is the one that gets negotiated (RFC 4253 §7.1). A weak entry
  /// kept last is not a downgrade risk, because the negotiated name is bound
  /// into the exchange hash the host key signs, so a peer in the middle cannot
  /// force it. It is reached only when the server genuinely offers nothing
  /// better.
  ///
  /// What is left out of the defaults is therefore what stays dangerous even
  /// as a last resort: `ssh-rsa`, whose SHA-1 host key signatures are open to
  /// chosen-prefix collisions and which OpenSSH disabled by default in 8.8,
  /// and the CBC ciphers, vulnerable to the plaintext recovery of
  /// CVE-2008-5161. `diffie-hellman-group1-sha1` (1024-bit DH), `hmac-md5` and
  /// the truncated `hmac-sha2-[256|512]-96` variants are out for the same
  /// reason.
  ///
  /// SHA-1 in the key exchange hash is weaker than what follows it but is not
  /// forgeable the way a signature is, and it is the only thing many older
  /// routers, NAS boxes and embedded servers speak. It stays last rather than
  /// leaving those unreachable. All of the omitted algorithms remain
  /// implemented and can be re-enabled explicitly.
  const SSHAlgorithms({
    this.kex = const [
      SSHKexType.x25519Rfc,
      SSHKexType.x25519,
      SSHKexType.nistp521,
      SSHKexType.nistp384,
      SSHKexType.nistp256,
      SSHKexType.dhGexSha256,
      SSHKexType.dh14Sha256,
      // SHA-1 based key exchange is kept last for old servers only.
      SSHKexType.dh14Sha1,
      SSHKexType.dhGexSha1,
    ],
    this.hostkey = const [
      SSHHostkeyType.ed25519,
      SSHHostkeyType.rsaSha512,
      SSHHostkeyType.rsaSha256,
      SSHHostkeyType.ecdsa521,
      SSHHostkeyType.ecdsa384,
      SSHHostkeyType.ecdsa256,
    ],
    this.cipher = const [
      SSHCipherType.aes256gcm,
      SSHCipherType.aes128gcm,
      SSHCipherType.chacha20poly1305,
      SSHCipherType.aes256ctr,
      SSHCipherType.aes128ctr,
    ],
    this.mac = const [
      // Encrypt-then-MAC is preferred over the encrypt-and-MAC variants.
      SSHMacType.hmacSha256Etm,
      SSHMacType.hmacSha512Etm,
      SSHMacType.hmacSha256,
      SSHMacType.hmacSha512,
      SSHMacType.hmacSha1,
    ],
  });
}
