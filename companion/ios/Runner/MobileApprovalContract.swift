import CryptoKit
import Foundation

/// iOS approval-client rules kept free of UIKit and of the shared key code,
/// so the Swift package tests them on the macOS host (#60 phase 2). The
/// Secure Enclave key itself is the shared `ProductionApprovalKey`
/// (companion/macos/Runner), compiled into this Runner unchanged.
enum MobileApproval {
    /// The last native check on a `sign` reply before it leaves this
    /// process: only a `signed` reply whose bytes are a canonical ASN.1 DER
    /// ECDSA P-256 signature that verifies over the exact transcript with the
    /// reply's own public key is returned. Anything else signed becomes
    /// `failed` with no bytes. A reply that is not `signed` (cancel, error,
    /// refusal) never carries a signature or key.
    static func checked(outcome: String, publicKey: Data, signature: Data, transcript: Data)
        -> (outcome: String, publicKey: Data, signature: Data) {
        guard outcome == "signed" else { return (outcome, Data(), Data()) }
        guard (8...72).contains(signature.count),
              let key = try? P256.Signing.PublicKey(x963Representation: publicKey),
              let parsed = try? P256.Signing.ECDSASignature(derRepresentation: signature),
              parsed.derRepresentation == signature,
              key.isValidSignature(parsed, for: transcript) else { return ("failed", Data(), Data()) }
        return (outcome, publicKey, signature)
    }

    /// The `availability` reply: the sensor that gates the key, else unavailable.
    static func availabilityName(_ biometry: String?) -> String {
        guard let biometry, ["faceID", "touchID"].contains(biometry) else { return "unavailable" }
        return biometry
    }

    /// The system prompt's reason. Generic: it never names the request.
    static func reason(purpose: String, biometry: String) -> String {
        guard purpose == "enroll" else { return "Approve one provider request" }
        return "Enroll this device's \(biometry == "faceID" ? "Face ID" : "Touch ID") approval key"
    }
}

/// Which UIKit application notifications end what. UIKit's names are spelled
/// out so the package tests them without UIKit; `RunnerTests` checks them
/// against `UIApplication`'s constants on a simulator.
enum MobileLifecycle {
    static let willResignActive = "UIApplicationWillResignActiveNotification"
    static let didEnterBackground = "UIApplicationDidEnterBackgroundNotification"
    static let protectedDataWillBecomeUnavailable = "UIApplicationProtectedDataWillBecomeUnavailable"
    static let willTerminate = "UIApplicationWillTerminateNotification"

    /// An open Face ID / Touch ID prompt is cancelled when the app leaves the
    /// screen, the device locks (protected data goes away) or the app ends.
    /// Not on resign-active: iOS resigns the app active to present the
    /// biometric sheet itself, so that trigger would cancel every prompt.
    static let signerCancelTriggers = [didEnterBackground, protectedDataWillBecomeUnavailable, willTerminate]

    /// Sent to Flutter on the provider channel as `invalidate` with the
    /// argument `docs/mobile-clients.md` names (`inactive` or `close`), which
    /// retires the open review and clears passwords.
    static let providerInvalidations: [(name: String, reason: String)] = [
        (didEnterBackground, "inactive"), (protectedDataWillBecomeUnavailable, "inactive"), (willTerminate, "close"),
    ]

    /// Sent on `dev.vaultwarden.companionSlice/lifecycle` as `signal`. iOS
    /// reports only `locked`: calls, the app switcher and the notification
    /// shade already reach Flutter as `AppLifecycleState.inactive`.
    static let deviceSignals: [(name: String, signal: String)] = [(protectedDataWillBecomeUnavailable, "locked")]

    /// A prepared administrative ticket (`identity_prepare`) is dropped on any
    /// of these, resign-active included, as macOS drops it when inactive.
    static let managementInvalidations = providerInvalidations.map(\.name) + [willResignActive]
}
