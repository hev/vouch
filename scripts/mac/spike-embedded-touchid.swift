// Spike: can LAAuthenticationView (LocalAuthenticationEmbeddedUI, macOS 12+)
// host the Touch ID prompt for a Secure Enclave signature inside our own
// panel, so the system sheet never appears?
//
// Run on a Mac with Touch ID, from a logged-in Terminal:
//
//   swiftc scripts/mac/spike-embedded-touchid.swift -o /tmp/vouch-spike && /tmp/vouch-spike
//
// It makes a throwaway, ephemeral Secure Enclave key with the same access
// control vouch's key uses (biometryCurrentSet + privateKeyUsage), so the
// enrolled key is never touched. It then:
//
//  1. pairs an LAContext with an LAAuthenticationView in a small panel,
//  2. calls evaluateAccessControl(.useKeySign) on that context (the header
//     says the prompt is then drawn in the view, not the system alert), and
//  3. rebuilds the key from its blob with kSecUseAuthenticationContext set to
//     the same context, the way enclave/src/mac.rs does, and signs.
//
// Yes means: step 2 shows the fingerprint glyph in the panel with no system
// sheet, and step 3 prints "signature: ok" without a second prompt.
import AppKit
import LocalAuthentication
import LocalAuthenticationEmbeddedUI
import Security

let app = NSApplication.shared
app.setActivationPolicy(.accessory)
let context = LAContext()
var policyError: NSError?
let canBio = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &policyError)
print("canEvaluatePolicy(biometrics):", canBio, policyError.map { "error \($0.code): \($0.localizedDescription)" } ?? "")

var acError: Unmanaged<CFError>?
guard let acl = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
    [.privateKeyUsage, .biometryCurrentSet], &acError) else {
  print("SecAccessControlCreateWithFlags failed:", acError!.takeRetainedValue()); exit(1)
}
let attrs: [String: Any] = [
  kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
  kSecAttrKeySizeInBits as String: 256,
  kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
  kSecPrivateKeyAttrs as String: [kSecAttrIsPermanent as String: false, kSecAttrAccessControl as String: acl],
]
var keyError: Unmanaged<CFError>?
guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &keyError),
      let keyAttrs = SecKeyCopyAttributes(key) as? [String: Any],
      let blob = keyAttrs["toid"] as? Data else {
  print("throwaway enclave key failed:", keyError.map { "\($0.takeRetainedValue())" } ?? "no token blob"); exit(1)
}
print("throwaway enclave key: created (\(blob.count)-byte blob)")

let panel = NSPanel(contentRect: NSRect(x: 200, y: 200, width: 220, height: 140),
                    styleMask: [.titled, .nonactivatingPanel], backing: .buffered, defer: false)
panel.title = "vouch spike"
let view = LAAuthenticationView(context: context, controlSize: .large)
view.frame = NSRect(x: 80, y: 40, width: 60, height: 60)
panel.contentView?.addSubview(view)
panel.level = .statusBar
panel.orderFrontRegardless()

context.evaluateAccessControl(acl, operation: .useKeySign, localizedReason: "sign the vouch spike") { ok, error in
  print("evaluateAccessControl(.useKeySign) via LAAuthenticationView:", ok,
        error.map { "error \(($0 as NSError).code): \($0.localizedDescription)" } ?? "")
  if ok {
    let rebuild: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
      kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
      kSecUseAuthenticationContext as String: context,
      "toid": blob,
    ]
    var error: Unmanaged<CFError>?
    guard let bound = SecKeyCreateWithData(blob as CFData, rebuild as CFDictionary, &error) else {
      print("SecKeyCreateWithData failed:", error!.takeRetainedValue()); exit(1)
    }
    let signature = SecKeyCreateSignature(bound, .ecdsaSignatureMessageX962SHA256, Data("probe".utf8) as CFData, &error)
    print("signature:", signature != nil ? "ok (no second prompt means yes)" : "failed \(error!.takeRetainedValue())")
  }
  DispatchQueue.main.async { exit(0) }
}
DispatchQueue.main.asyncAfter(deadline: .now() + 30) { print("timeout: nobody answered"); exit(2) }
app.run()
