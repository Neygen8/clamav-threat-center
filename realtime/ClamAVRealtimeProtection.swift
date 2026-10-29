import CoreServices
import CryptoKit
import Darwin
import Foundation

// Swift's Darwin overlay exposes `struct flock` under the same name as the
// BSD `flock(2)` function. Bind the function explicitly so this lock remains
// compatible with Python's `fcntl.flock` and other cooperating processes.
@_silgen_name("flock")
private func advisoryFlock(_ descriptor: Int32, _ operation: Int32) -> Int32

private struct QuarantineMetadata: Codable {
    let id: UUID
    let originalPath: String
    let storedFileName: String
    let signature: String
    let quarantinedAt: Date
    let state: String?
    let sha256: String?
    let fileSize: Int64?
    let stagingPath: String?
    let temporaryStoredFileName: String?
    let restoreMode: String?
    let restoreTemporaryPath: String?
    let restoreTemporaryDevice: UInt64?
    let restoreTemporaryInode: UInt64?
}

private struct ProtectionStatus: Codable {
    let running: Bool
    let startedAt: Date
    let heartbeatAt: Date
    let watchedPaths: [String]
    let scannedCount: Int
    let threatCount: Int
    let lastPath: String?
    let lastResult: String?
    let daemonConnected: Bool
    let reconciliationActive: Bool
    let reconciliationReason: String?
    let reconciliationQueuedCount: Int
    let lastReconciliationAt: Date?
    let eventLossCount: Int
}

private struct ProtectionEvent: Codable {
    let id: UUID
    let timestamp: Date
    let path: String
    let result: String
    let signature: String?
    let message: String
}

private struct FileFingerprint: Equatable {
    let device: UInt64
    let inode: UInt64
    let generation: UInt64
    let size: Int64
    let modificationSeconds: Int64
    let modificationNanoseconds: Int64
    let statusChangeSeconds: Int64
    let statusChangeNanoseconds: Int64
}

private struct ScanResult {
    let exitCode: Int32
    let output: String
}

private enum QuarantineOutcome {
    case quarantined
    case sourceMissing
    case sourceChanged
}

private enum VerifiedCopyOutcome: Equatable {
    case completed
    case sourceMissing
    case sourceChanged
}

private enum TransferIntegrityError: LocalizedError {
    case sourceChanged
    case destinationMismatch
    case stagingPreserved

    var errorDescription: String? {
        switch self {
        case .sourceChanged:
            return "The source file changed during validation."
        case .destinationMismatch:
            return "The integrity of the quarantine copy could not be verified."
        case .stagingPreserved:
            return "The source changed during the race; no new files were deleted and the owned file was preserved in the staging area."
        }
    }
}

private enum StagedSourceRecovery {
    case restored
    case preserved
    case missing
}

private struct CoordinationError: LocalizedError {
    let operation: String
    let code: Int32

    var errorDescription: String? {
        let detail = String(cString: strerror(code))
        return "Quarantine coordination failed (\(operation)): \(detail)"
    }
}

private final class QuarantineCoordinator {
    private let descriptor: Int32
    let lockURL: URL

    init(directoryURL: URL, lockURL: URL) throws {
        self.lockURL = lockURL

        let directoryResult = directoryURL.path.withCString {
            Darwin.mkdir($0, mode_t(S_IRWXU))
        }
        if directoryResult != 0 && errno != EEXIST {
            throw CoordinationError(operation: "create directory", code: errno)
        }

        var directoryInfo = stat()
        let directoryStatResult = directoryURL.path.withCString {
            Darwin.lstat($0, &directoryInfo)
        }
        guard directoryStatResult == 0 else {
            throw CoordinationError(operation: "directory verification", code: errno)
        }
        guard directoryInfo.st_mode & S_IFMT == S_IFDIR,
              directoryInfo.st_uid == getuid() else {
            throw CoordinationError(operation: "unsafe coordination directory", code: EACCES)
        }
        guard directoryURL.path.withCString({ Darwin.chmod($0, mode_t(S_IRWXU)) }) == 0 else {
            throw CoordinationError(operation: "directory permissions", code: errno)
        }

        let openedDescriptor = lockURL.path.withCString {
            Darwin.open(
                $0,
                O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW,
                mode_t(S_IRUSR | S_IWUSR)
            )
        }
        guard openedDescriptor >= 0 else {
            throw CoordinationError(operation: "open lock file", code: errno)
        }

        var lockInfo = stat()
        guard Darwin.fstat(openedDescriptor, &lockInfo) == 0 else {
            let errorCode = errno
            Darwin.close(openedDescriptor)
            throw CoordinationError(operation: "lock file verification", code: errorCode)
        }
        guard lockInfo.st_mode & S_IFMT == S_IFREG,
              lockInfo.st_uid == getuid(),
              lockInfo.st_nlink == 1 else {
            Darwin.close(openedDescriptor)
            throw CoordinationError(operation: "unsafe lockfile", code: EACCES)
        }
        guard Darwin.fchmod(openedDescriptor, mode_t(S_IRUSR | S_IWUSR)) == 0 else {
            let errorCode = errno
            Darwin.close(openedDescriptor)
            throw CoordinationError(operation: "lock file permissions", code: errorCode)
        }

        descriptor = openedDescriptor
    }

    deinit {
        Darwin.close(descriptor)
    }

    func withExclusiveLock<T>(_ operation: () throws -> T) throws -> T {
        while advisoryFlock(descriptor, LOCK_EX) != 0 {
            guard errno == EINTR else {
                throw CoordinationError(operation: "acquire lock", code: errno)
            }
        }
        defer { _ = advisoryFlock(descriptor, LOCK_UN) }
        return try operation()
    }
}

private func fileFingerprint(at url: URL) -> FileFingerprint? {
    var info = stat()
    let result = url.path.withCString { Darwin.lstat($0, &info) }
    guard result == 0, info.st_mode & S_IFMT == S_IFREG else { return nil }
    return FileFingerprint(
        device: UInt64(info.st_dev),
        inode: UInt64(info.st_ino),
        generation: UInt64(info.st_gen),
        size: Int64(info.st_size),
        modificationSeconds: Int64(info.st_mtimespec.tv_sec),
        modificationNanoseconds: Int64(info.st_mtimespec.tv_nsec),
        statusChangeSeconds: Int64(info.st_ctimespec.tv_sec),
        statusChangeNanoseconds: Int64(info.st_ctimespec.tv_nsec)
    )
}

private func ownedSingleLinkFingerprint(at url: URL) -> FileFingerprint? {
    var info = stat()
    let result = url.path.withCString { Darwin.lstat($0, &info) }
    guard result == 0,
          info.st_mode & S_IFMT == S_IFREG,
          info.st_uid == getuid(),
          info.st_nlink == 1 else { return nil }
    return fileFingerprint(at: url)
}

private func directoryDevice(at url: URL) throws -> UInt64 {
    var info = stat()
    let result = url.path.withCString { Darwin.lstat($0, &info) }
    guard result == 0, info.st_mode & S_IFMT == S_IFDIR else {
        throw CoordinationError(operation: "quarantine disk verification", code: result == 0 ? ENOTDIR : errno)
    }
    return UInt64(info.st_dev)
}

private func streamingSHA256(at url: URL) throws -> [UInt8] {
    let descriptor = url.path.withCString {
        Darwin.open($0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
    }
    guard descriptor >= 0 else {
        throw CoordinationError(operation: "open source for SHA-256", code: errno)
    }
    defer { Darwin.close(descriptor) }

    var before = stat()
    guard Darwin.fstat(descriptor, &before) == 0,
          before.st_mode & S_IFMT == S_IFREG else {
        throw TransferIntegrityError.sourceChanged
    }

    var hasher = SHA256()
    var buffer = [UInt8](repeating: 0, count: 1_048_576)
    while true {
        let readCount = buffer.withUnsafeMutableBytes { bytes -> Int in
            guard let baseAddress = bytes.baseAddress else { return 0 }
            return Darwin.read(descriptor, baseAddress, bytes.count)
        }
        if readCount < 0 {
            if errno == EINTR { continue }
            throw CoordinationError(operation: "read source for SHA-256", code: errno)
        }
        if readCount == 0 { break }
        hasher.update(data: Data(buffer[0..<readCount]))
    }

    var after = stat()
    guard Darwin.fstat(descriptor, &after) == 0 else {
        throw CoordinationError(operation: "SHA-256 source final verification", code: errno)
    }
    let beforeIdentity = FileFingerprint(
        device: UInt64(before.st_dev),
        inode: UInt64(before.st_ino),
        generation: UInt64(before.st_gen),
        size: Int64(before.st_size),
        modificationSeconds: Int64(before.st_mtimespec.tv_sec),
        modificationNanoseconds: Int64(before.st_mtimespec.tv_nsec),
        statusChangeSeconds: Int64(before.st_ctimespec.tv_sec),
        statusChangeNanoseconds: Int64(before.st_ctimespec.tv_nsec)
    )
    let afterIdentity = FileFingerprint(
        device: UInt64(after.st_dev),
        inode: UInt64(after.st_ino),
        generation: UInt64(after.st_gen),
        size: Int64(after.st_size),
        modificationSeconds: Int64(after.st_mtimespec.tv_sec),
        modificationNanoseconds: Int64(after.st_mtimespec.tv_nsec),
        statusChangeSeconds: Int64(after.st_ctimespec.tv_sec),
        statusChangeNanoseconds: Int64(after.st_ctimespec.tv_nsec)
    )
    guard beforeIdentity == afterIdentity,
          fileFingerprint(at: url) == afterIdentity else {
        throw TransferIntegrityError.sourceChanged
    }
    return Array(hasher.finalize())
}

private func hexadecimalDigest(_ digest: [UInt8]) -> String {
    digest.map { String(format: "%02x", $0) }.joined()
}

private func sameVolumeIdentityMatches(
    _ storedIdentity: FileFingerprint,
    expected: FileFingerprint
) -> Bool {
    storedIdentity.device == expected.device
        && storedIdentity.inode == expected.inode
        && storedIdentity.generation == expected.generation
        && storedIdentity.size == expected.size
        && storedIdentity.modificationSeconds == expected.modificationSeconds
        && storedIdentity.modificationNanoseconds == expected.modificationNanoseconds
}

private func renameExclusively(from sourceURL: URL, to destinationURL: URL) throws {
    let result = sourceURL.path.withCString { sourcePath in
        destinationURL.path.withCString { destinationPath in
            Darwin.renamex_np(sourcePath, destinationPath, UInt32(RENAME_EXCL))
        }
    }
    guard result == 0 else {
        throw CoordinationError(operation: "atomic file claim", code: errno)
    }
}

private func pathEntryExists(at url: URL) -> Bool {
    var info = stat()
    return url.path.withCString { Darwin.lstat($0, &info) } == 0
}

private func uniqueStagingURL(for originalURL: URL) -> URL {
    originalURL.deletingLastPathComponent().appendingPathComponent(
        ".clamav-quarantine-\(UUID().uuidString).stage"
    )
}

private func isPrivateStagingContainer(_ directoryURL: URL, for originalURL: URL) -> Bool {
    let name = directoryURL.lastPathComponent
    return directoryURL.deletingLastPathComponent().standardizedFileURL
        == originalURL.deletingLastPathComponent().standardizedFileURL
        && name.hasPrefix(".clamav-quarantine-")
        && name.hasSuffix(".stage-dir")
}

private func validatedPrivateStagingContainer(
    _ directoryURL: URL,
    for originalURL: URL,
    containsPayload: Bool
) -> Bool {
    guard isPrivateStagingContainer(directoryURL, for: originalURL) else { return false }
    var info = stat()
    guard directoryURL.path.withCString({ Darwin.lstat($0, &info) }) == 0,
          info.st_mode & S_IFMT == S_IFDIR,
          info.st_uid == getuid(),
          info.st_mode & mode_t(0o077) == 0 else { return false }
    if containsPayload {
        // APFS reports 3 links for this single-child directory, while exFAT
        // commonly synthesizes 1. Both are safe after the child is validated.
        return info.st_nlink == 1 || info.st_nlink == 2 || info.st_nlink == 3
    }
    return info.st_nlink == 1 || info.st_nlink == 2
}

private func cleanupPrivateStagingContainer(
    for stagingURL: URL,
    originalURL: URL,
    fileManager: FileManager = .default
) {
    let containerURL = stagingURL.deletingLastPathComponent()
    guard stagingURL.lastPathComponent == "payload",
          validatedPrivateStagingContainer(
              containerURL,
              for: originalURL,
              containsPayload: false
          ),
          !pathEntryExists(at: stagingURL) else { return }
    // rmdir is intentionally non-recursive: a raced-in entry makes cleanup
    // fail instead of deleting anything that was not part of this transaction.
    _ = containerURL.path.withCString { Darwin.rmdir($0) }
}

private func claimSource(
    originalURL: URL,
    stagingURL: URL,
    fileManager: FileManager = .default
) throws {
    let originalParent = originalURL.deletingLastPathComponent().standardizedFileURL
    let stagingParent = stagingURL.deletingLastPathComponent().standardizedFileURL
    if originalParent == stagingParent {
        try renameExclusively(from: originalURL, to: stagingURL)
        return
    }

    guard stagingURL.lastPathComponent == "payload",
          isPrivateStagingContainer(stagingParent, for: originalURL) else {
        throw CoordinationError(operation: "unsafe staging path", code: EACCES)
    }
    let creationResult = stagingParent.path.withCString {
        Darwin.mkdir($0, mode_t(S_IRWXU))
    }
    guard creationResult == 0 else {
        throw CoordinationError(operation: "create private staging directory", code: errno)
    }
    guard stagingParent.path.withCString({ Darwin.chmod($0, mode_t(S_IRWXU)) }) == 0,
          validatedPrivateStagingContainer(
              stagingParent,
              for: originalURL,
              containsPayload: false
          ),
          !pathEntryExists(at: stagingURL) else {
        cleanupPrivateStagingContainer(
            for: stagingURL,
            originalURL: originalURL,
            fileManager: fileManager
        )
        throw CoordinationError(operation: "private staging directory validation", code: EACCES)
    }

    let renameResult = originalURL.path.withCString { sourcePath in
        stagingURL.path.withCString { destinationPath in
            Darwin.rename(sourcePath, destinationPath)
        }
    }
    guard renameResult == 0 else {
        let errorCode = errno
        cleanupPrivateStagingContainer(
            for: stagingURL,
            originalURL: originalURL,
            fileManager: fileManager
        )
        throw CoordinationError(operation: "claim private staging file", code: errorCode)
    }
    guard validatedPrivateStagingContainer(
        stagingParent,
        for: originalURL,
        containsPayload: true
    ) else {
        throw CoordinationError(operation: "final private staging directory verification", code: EACCES)
    }
}

private func recoverStagedSource(
    stagingURL: URL,
    originalURL: URL
) -> StagedSourceRecovery {
    guard pathEntryExists(at: stagingURL) else { return .missing }

    do {
        // RENAME_EXCL never overwrites an existing user file.
        try renameExclusively(from: stagingURL, to: originalURL)
        cleanupPrivateStagingContainer(for: stagingURL, originalURL: originalURL)
        return .restored
    } catch {
        guard pathEntryExists(at: stagingURL) else { return .missing }
    }

    // If the original path was recreated, keep the stagingPath in metadata.
    // The preparing record keeps the payload visible in Threat Center and
    // recoverable on the next startup.
    return pathEntryExists(at: stagingURL) ? .preserved : .missing
}

private func verifiedCrossVolumeCopy(
    originalURL: URL,
    stagingURL requestedStagingURL: URL? = nil,
    temporaryStoredURL requestedTemporaryStoredURL: URL? = nil,
    storedURL: URL,
    expectedIdentity: FileFingerprint,
    expectedDigest: [UInt8],
    fileManager: FileManager = .default,
    afterCopy: ((URL) throws -> Void)? = nil,
    beforeStagingDeletion: ((URL) throws -> Void)? = nil
) throws -> VerifiedCopyOutcome {
    var stagingURL: URL?
    let claimAttempts = requestedStagingURL == nil ? 8 : 1
    for _ in 0..<claimAttempts {
        let candidate = requestedStagingURL ?? uniqueStagingURL(for: originalURL)
        do {
            // First claim the source atomically in its directory. Afterwards, only the
            // staging entry is deleted even if originalURL is recreated.
            try claimSource(
                originalURL: originalURL,
                stagingURL: candidate,
                fileManager: fileManager
            )
            stagingURL = candidate
            break
        } catch let error as CoordinationError where error.code == EEXIST {
            continue
        } catch let error as CoordinationError where error.code == ENOENT {
            return pathEntryExists(at: originalURL) ? .sourceChanged : .sourceMissing
        } catch {
            guard let currentIdentity = fileFingerprint(at: originalURL) else {
                return pathEntryExists(at: originalURL) ? .sourceChanged : .sourceMissing
            }
            guard currentIdentity == expectedIdentity else { return .sourceChanged }
            throw error
        }
    }
    guard let stagingURL else {
        throw CoordinationError(operation: "create unique staging name", code: EEXIST)
    }
    let temporaryStoredURL = requestedTemporaryStoredURL
        ?? storedURL.deletingLastPathComponent().appendingPathComponent(
            ".\(UUID().uuidString).payload.tmp"
        )

    func recoverThenThrow(_ error: Error) throws -> Never {
        switch recoverStagedSource(stagingURL: stagingURL, originalURL: originalURL) {
        case .restored, .missing:
            throw error
        case .preserved:
            throw TransferIntegrityError.stagingPreserved
        }
    }

    guard let claimedIdentity = ownedSingleLinkFingerprint(at: stagingURL),
          sameVolumeIdentityMatches(claimedIdentity, expected: expectedIdentity) else {
        switch recoverStagedSource(stagingURL: stagingURL, originalURL: originalURL) {
        case .restored, .missing:
            return .sourceChanged
        case .preserved:
            throw TransferIntegrityError.stagingPreserved
        }
    }

    do {
        // The final name never contains a partial payload. First copy to a hidden,
        // unique quarantine name, then publish after verification.
        try fileManager.copyItem(at: stagingURL, to: temporaryStoredURL)
        try afterCopy?(temporaryStoredURL)

        let storedDigest: [UInt8]
        do {
            storedDigest = try streamingSHA256(at: temporaryStoredURL)
        } catch {
            try recoverThenThrow(TransferIntegrityError.destinationMismatch)
        }
        guard let storedIdentity = fileFingerprint(at: temporaryStoredURL),
              storedIdentity.size == expectedIdentity.size,
              storedDigest == expectedDigest else {
            try recoverThenThrow(TransferIntegrityError.destinationMismatch)
        }

        try renameExclusively(from: temporaryStoredURL, to: storedURL)

        try beforeStagingDeletion?(stagingURL)

        guard let stagingIdentity = ownedSingleLinkFingerprint(at: stagingURL),
              sameVolumeIdentityMatches(stagingIdentity, expected: expectedIdentity) else {
            switch recoverStagedSource(stagingURL: stagingURL, originalURL: originalURL) {
            case .restored, .missing:
                return .sourceChanged
            case .preserved:
                throw TransferIntegrityError.stagingPreserved
            }
        }
        let stagingDigest: [UInt8]
        do {
            stagingDigest = try streamingSHA256(at: stagingURL)
        } catch TransferIntegrityError.sourceChanged {
            switch recoverStagedSource(stagingURL: stagingURL, originalURL: originalURL) {
            case .restored, .missing:
                return .sourceChanged
            case .preserved:
                throw TransferIntegrityError.stagingPreserved
            }
        }
        guard stagingDigest == expectedDigest,
              let finalStagingIdentity = ownedSingleLinkFingerprint(at: stagingURL),
              sameVolumeIdentityMatches(finalStagingIdentity, expected: expectedIdentity) else {
            switch recoverStagedSource(stagingURL: stagingURL, originalURL: originalURL) {
            case .restored, .missing:
                return .sourceChanged
            case .preserved:
                throw TransferIntegrityError.stagingPreserved
            }
        }

        do {
            try fileManager.removeItem(at: stagingURL)
            cleanupPrivateStagingContainer(
                for: stagingURL,
                originalURL: originalURL,
                fileManager: fileManager
            )
        } catch {
            guard pathEntryExists(at: stagingURL) else { return .completed }
            try recoverThenThrow(error)
        }
    } catch let error as TransferIntegrityError {
        // The controlled recovery paths above already handled staging.
        if pathEntryExists(at: stagingURL) {
            try recoverThenThrow(error)
        }
        throw error
    } catch {
        try recoverThenThrow(error)
    }
    return .completed
}

private func securePrivateRegularFile(at url: URL) throws {
    let descriptor = url.path.withCString {
        Darwin.open($0, O_RDWR | O_CLOEXEC | O_NOFOLLOW)
    }
    guard descriptor >= 0 else {
        throw CoordinationError(operation: "open private file", code: errno)
    }
    defer { Darwin.close(descriptor) }

    var info = stat()
    guard Darwin.fstat(descriptor, &info) == 0 else {
        throw CoordinationError(operation: "verify file", code: errno)
    }
    guard info.st_mode & S_IFMT == S_IFREG,
          info.st_uid == getuid(),
          info.st_nlink == 1 else {
        throw CoordinationError(operation: "insecure private file", code: EACCES)
    }
    guard Darwin.fchmod(descriptor, mode_t(S_IRUSR | S_IWUSR)) == 0 else {
        throw CoordinationError(operation: "private file permissions", code: errno)
    }
    guard Darwin.fsync(descriptor) == 0 else {
        throw CoordinationError(operation: "sync private file", code: errno)
    }
}

private func securelyPublishMetadata(_ data: Data, at metadataURL: URL) throws {
    try data.write(to: metadataURL, options: .atomic)
    try securePrivateRegularFile(at: metadataURL)
}

private func ensureSecureMetadata(_ data: Data, at metadataURL: URL) throws {
    let existingData = try? Data(contentsOf: metadataURL)
    if existingData == data {
        do {
            try securePrivateRegularFile(at: metadataURL)
            return
        } catch {
            // Atomic republication also repairs file permissions.
        }
    }
    try securelyPublishMetadata(data, at: metadataURL)
}

private func removeFailedDestination(
    storedURL: URL,
    metadataURL: URL,
    metadataData: Data,
    fileManager: FileManager = .default
) throws -> Bool {
    guard fileManager.fileExists(atPath: storedURL.path) else { return true }
    do {
        try fileManager.removeItem(at: storedURL)
        if !fileManager.fileExists(atPath: storedURL.path) { return true }
        try ensureSecureMetadata(metadataData, at: metadataURL)
        return false
    } catch {
        // A destination that cannot be cleaned up must never remain invisible.
        try ensureSecureMetadata(metadataData, at: metadataURL)
        return false
    }
}

private func restorePayloadOrPublishMetadata(
    originalURL: URL,
    storedURL: URL,
    metadataURL: URL,
    metadataData: Data,
    fileManager: FileManager = .default
) throws -> Bool {
    do {
        guard !fileManager.fileExists(atPath: originalURL.path) else {
            throw CocoaError(.fileWriteFileExists)
        }
        try fileManager.moveItem(at: storedURL, to: originalURL)
        try? fileManager.removeItem(at: metadataURL)
        return true
    } catch {
        // If restore is impossible, the payload remains in quarantine. Verify the
        // published metadata or republish it atomically with mode 0600.
        guard fileManager.fileExists(atPath: storedURL.path) else { throw error }
        try? fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: storedURL.path)

        try ensureSecureMetadata(metadataData, at: metadataURL)
        return false
    }
}

private final class RealtimeProtection {
    private let fileManager = FileManager.default
    private let homeDirectory = FileManager.default.homeDirectoryForCurrentUser
    private let applicationDirectory: URL
    private let quarantineDirectory: URL
    private let logDirectory: URL
    private let runtimeDirectory: URL
    private let statusURL: URL
    private let eventsURL: URL
    private let clamdConfigURL: URL
    private let watchedPaths: [String]
    private let clamdscanPath: String
    private var quarantineCoordinator: QuarantineCoordinator?

    private let startedAt = Date()
    private let eventQueue = DispatchQueue(label: "com.local.clamav.realtime.events")
    private let scanQueue = DispatchQueue(
        label: "com.local.clamav.realtime.scans",
        qos: .utility,
        attributes: .concurrent
    )
    private let reconciliationQueue = DispatchQueue(
        label: "com.local.clamav.realtime.reconciliation",
        qos: .utility
    )
    private let heartbeatQueue = DispatchQueue(label: "com.local.clamav.realtime.heartbeat", qos: .utility)
    private let stateLock = NSLock()
    private let eventLogLock = NSLock()
    private let fingerprintLock = NSLock()

    private var stream: FSEventStreamRef?
    private var heartbeatTimer: DispatchSourceTimer?
    private var pendingWork: [String: DispatchWorkItem] = [:]
    private var retryCounts: [String: Int] = [:]
    private var queuedScanPaths: [String] = []
    private var activeScanPaths: Set<String> = []
    private var recentFingerprints: [String: FileFingerprint] = [:]
    private var recentFingerprintOrder: [String] = []

    private var scannedCount = 0
    private var threatCount = 0
    private var lastPath: String?
    private var lastResult: String?
    private var daemonConnected = false
    private var isRunning = true
    private var reconciliationActive = false
    private var reconciliationReason: String?
    private var reconciliationQueuedCount = 0
    private var lastReconciliationAt: Date?
    private var eventLossCount = 0
    private var reconciliationScheduled = false
    private var reconciliationFollowUpReason: String?
    private var streamRebuildScheduled = false
    private var consecutiveTimedOutScans = 0
    private var lastTimedOutDaemonRestartAt: Date?

    private let delayedExtensions: Set<String> = [
        "crdownload", "download", "part", "partial", "tmp"
    ]
    // Container formats can expand into deeply nested content. clamd may keep
    // this work running after a client timeout, pinning CPU long after the
    // download arrives. Gatekeeper and VirusTotal checks remain available;
    // deep inspection is deliberately an on-demand operation.
    private let onDemandOnlyExtensions: Set<String> = [
        "dmg", "iso", "sparseimage", "sparsebundle", "zip", "7z", "rar",
        "tar", "gz", "bz2", "xz", "jar", "pkg", "xip", "cab", "cpio"
    ]
    private let ignoredComponents: Set<String> = [
        ".DS_Store", ".DocumentRevisions-V100", ".Spotlight-V100", ".TemporaryItems",
        ".Trashes", ".fseventsd", ".localized", ".git", "node_modules",
        ".venv", "venv", "__pycache__", ".npm", ".cache", ".tox",
        ".build", ".swiftpm", "DerivedData", "Pods"
    ]

    init() throws {
        applicationDirectory = homeDirectory
            .appendingPathComponent("Library/Application Support/ClamAV-Automation", isDirectory: true)
        quarantineDirectory = applicationDirectory.appendingPathComponent("Quarantine", isDirectory: true)
        logDirectory = homeDirectory
            .appendingPathComponent("Library/Logs/ClamAV-Automation", isDirectory: true)
        runtimeDirectory = homeDirectory
            .appendingPathComponent("Library/Caches/ClamAV-Automation", isDirectory: true)
        statusURL = applicationDirectory.appendingPathComponent("realtime-status.json")
        eventsURL = logDirectory.appendingPathComponent("realtime-events.jsonl")
        clamdConfigURL = applicationDirectory.appendingPathComponent("clamd.conf")
        watchedPaths = Self.loadWatchedPaths(
            from: applicationDirectory.appendingPathComponent("realtime-paths"),
            homeDirectory: homeDirectory
        )

        let candidates = ["/opt/homebrew/bin/clamdscan", "/usr/local/bin/clamdscan"]
        guard let executable = candidates.first(where: { FileManager.default.isExecutableFile(atPath: $0) }) else {
            throw ProtectionError.missingClamdscan
        }
        clamdscanPath = executable

        try preparePrivateDirectory(applicationDirectory)
        try preparePrivateDirectory(quarantineDirectory)
        try preparePrivateDirectory(logDirectory)
        try preparePrivateDirectory(runtimeDirectory)
        try protectExistingFile(eventsURL)

        let coordinationDirectory = applicationDirectory
            .appendingPathComponent("coordination", isDirectory: true)
        quarantineCoordinator = try QuarantineCoordinator(
            directoryURL: coordinationDirectory,
            lockURL: coordinationDirectory.appendingPathComponent("quarantine.lock")
        )
    }

    func start() throws {
        guard !watchedPaths.isEmpty else {
            throw ProtectionError.noWatchedPaths
        }

        refreshDaemonConnection()
        writeStatus()
        startHeartbeat()

        try startEventStream()
        scanQueue.async { [weak self] in
            guard let self else { return }
            let recoveredCount = self.recoverPreparingQuarantineRecords()
            if recoveredCount > 0 {
                self.appendEvent(ProtectionEvent(
                    id: UUID(),
                    timestamp: Date(),
                    path: self.quarantineDirectory.path,
                    result: "recovery",
                    signature: nil,
                    message: "\(recoveredCount) incomplete quarantine operations were safely reconciled."
                ))
            }
            // The stream begins at "now". Do not re-scan an existing backlog
            // whenever the service restarts; actual FSEvent-loss signals still
            // request a bounded reconciliation.
        }
    }

    private func startEventStream() throws {
        var context = FSEventStreamContext(
            version: 0,
            info: Unmanaged.passUnretained(self).toOpaque(),
            retain: nil,
            release: nil,
            copyDescription: nil
        )

        let callback: FSEventStreamCallback = { _, contextInfo, eventCount, rawPaths, flags, _ in
            guard let contextInfo else { return }
            let monitor = Unmanaged<RealtimeProtection>.fromOpaque(contextInfo).takeUnretainedValue()
            let paths = unsafeBitCast(rawPaths, to: NSArray.self) as? [String] ?? []
            monitor.receive(paths: paths, flags: flags, count: eventCount)
        }

        let creationFlags = FSEventStreamCreateFlags(
            kFSEventStreamCreateFlagFileEvents |
            kFSEventStreamCreateFlagWatchRoot |
            kFSEventStreamCreateFlagUseCFTypes
        )

        guard let createdStream = FSEventStreamCreate(
            kCFAllocatorDefault,
            callback,
            &context,
            watchedPaths as CFArray,
            FSEventStreamEventId(kFSEventStreamEventIdSinceNow),
            3.0,
            creationFlags
        ) else {
            throw ProtectionError.streamCreationFailed
        }

        stream = createdStream
        FSEventStreamSetDispatchQueue(createdStream, eventQueue)
        guard FSEventStreamStart(createdStream) else {
            FSEventStreamInvalidate(createdStream)
            FSEventStreamRelease(createdStream)
            stream = nil
            throw ProtectionError.streamStartFailed
        }
    }

    private func stopEventStream() {
        guard let stream else { return }
        FSEventStreamStop(stream)
        FSEventStreamInvalidate(stream)
        FSEventStreamRelease(stream)
        self.stream = nil
    }

    func stop() {
        stateLock.lock()
        isRunning = false
        stateLock.unlock()

        heartbeatTimer?.cancel()
        heartbeatTimer = nil

        stopEventStream()
        writeStatus()
    }

    private func recoverPreparingQuarantineRecords() -> Int {
        guard let quarantineCoordinator else { return 0 }
        do {
            return try quarantineCoordinator.withExclusiveLock {
                let decoder = JSONDecoder()
                let metadataRecords = try fileManager.contentsOfDirectory(
                    at: quarantineDirectory,
                    includingPropertiesForKeys: nil,
                    options: [.skipsHiddenFiles]
                )
                .filter { $0.pathExtension == "json" }
                .sorted { $0.path < $1.path }
                .compactMap { metadataURL -> (URL, QuarantineMetadata)? in
                    guard let data = try? Data(contentsOf: metadataURL),
                          let metadata = try? decoder.decode(QuarantineMetadata.self, from: data),
                          metadata.state == "preparing" || metadata.state == "restorePreparing" else {
                        return nil
                    }
                    return (metadataURL, metadata)
                }
                .sorted {
                    if $0.1.quarantinedAt != $1.1.quarantinedAt {
                        return $0.1.quarantinedAt < $1.1.quarantinedAt
                    }
                    return $0.0.path < $1.0.path
                }
                .prefix(64)

                let encoder = JSONEncoder()
                var remainingHashBytes: Int64 = 512 * 1_024 * 1_024
                var recoveredCount = 0

                func childURL(named name: String) -> URL? {
                    guard !name.isEmpty,
                          name != ".",
                          name != "..",
                          !name.contains("/") else { return nil }
                    let candidate = quarantineDirectory.appendingPathComponent(name)
                    guard candidate.deletingLastPathComponent().standardizedFileURL
                        == quarantineDirectory.standardizedFileURL else { return nil }
                    return candidate
                }

                func stagingURL(from metadata: QuarantineMetadata) -> URL? {
                    guard let path = metadata.stagingPath else { return nil }
                    let candidate = URL(fileURLWithPath: path).standardizedFileURL
                    let originalParent = URL(fileURLWithPath: metadata.originalPath)
                        .deletingLastPathComponent().standardizedFileURL
                    let stagingName = candidate.lastPathComponent
                    let realtimePattern = stagingName.hasPrefix(".clamav-quarantine-")
                        && stagingName.hasSuffix(".stage")
                    let pythonPattern = stagingName.hasPrefix(".clamav-quarantine-stage-")
                        && stagingName.count > ".clamav-quarantine-stage-".count
                    let containerName = candidate.deletingLastPathComponent().lastPathComponent
                    let nestedPattern = stagingName == "payload"
                        && candidate.deletingLastPathComponent()
                            .deletingLastPathComponent().standardizedFileURL == originalParent
                        && containerName.hasPrefix(".clamav-quarantine-")
                        && containerName.hasSuffix(".stage-dir")
                    let flatPattern = candidate.deletingLastPathComponent() == originalParent
                        && (realtimePattern || pythonPattern)
                    guard flatPattern || nestedPattern else { return nil }
                    return candidate
                }

                func restoreTemporaryURL(from metadata: QuarantineMetadata) -> URL? {
                    guard let path = metadata.restoreTemporaryPath else { return nil }
                    let candidate = URL(fileURLWithPath: path).standardizedFileURL
                    let destinationParent = URL(fileURLWithPath: metadata.originalPath)
                        .deletingLastPathComponent().standardizedFileURL
                    let name = candidate.lastPathComponent
                    let hiddenTemporary = candidate.deletingLastPathComponent() == destinationParent
                        && name.hasPrefix(".clamav-restore-")
                        && name.hasSuffix(".tmp")
                    let directTarget = candidate
                        == URL(fileURLWithPath: metadata.originalPath).standardizedFileURL
                    switch metadata.restoreMode {
                    case "directExclusive", "sameVolumeRename":
                        guard directTarget else { return nil }
                    case "hiddenTemporary":
                        guard hiddenTemporary else { return nil }
                    case nil:
                        guard hiddenTemporary else { return nil }
                    default:
                        return nil
                    }
                    return candidate
                }

                func recordedRestoreIdentityMatches(
                    _ url: URL,
                    metadata: QuarantineMetadata
                ) -> Bool {
                    var pathInfo = stat()
                    guard let expectedDevice = metadata.restoreTemporaryDevice,
                          let expectedInode = metadata.restoreTemporaryInode,
                          url.path.withCString({ Darwin.lstat($0, &pathInfo) }) == 0,
                          pathInfo.st_mode & S_IFMT == S_IFREG,
                          pathInfo.st_uid == getuid(),
                          pathInfo.st_nlink == 1 else { return false }
                    return UInt64(pathInfo.st_dev) == expectedDevice
                        && UInt64(pathInfo.st_ino) == expectedInode
                }

                func removeOwnedRestoreTemporary(
                    _ temporaryURL: URL,
                    metadata: QuarantineMetadata
                ) -> Bool {
                    guard let expectedDevice = metadata.restoreTemporaryDevice,
                          let expectedInode = metadata.restoreTemporaryInode,
                          recordedRestoreIdentityMatches(temporaryURL, metadata: metadata),
                          let identity = fileFingerprint(at: temporaryURL),
                          identity.device == expectedDevice,
                          identity.inode == expectedInode else { return false }
                    let cleanupURL = temporaryURL.deletingLastPathComponent().appendingPathComponent(
                        ".clamav-restore-cleanup-\(UUID().uuidString).tmp"
                    )
                    do {
                        try renameExclusively(from: temporaryURL, to: cleanupURL)
                        guard let claimedIdentity = fileFingerprint(at: cleanupURL),
                              claimedIdentity.device == expectedDevice,
                              claimedIdentity.inode == expectedInode else {
                            _ = try? renameExclusively(from: cleanupURL, to: temporaryURL)
                            return false
                        }
                        try fileManager.removeItem(at: cleanupURL)
                        return !pathEntryExists(at: cleanupURL)
                    } catch {
                        // Filesystems such as exFAT do not provide a no-clobber
                        // rename primitive. A path-based fallback could claim a
                        // replacement created after the inode check. Preserve
                        // the tracked output and restorePreparing metadata.
                        return false
                    }
                }

                var validationCache: [String: (FileFingerprint, String)] = [:]
                func payloadMatches(
                    _ url: URL,
                    expectedSize: Int64,
                    expectedHash: String
                ) -> Bool {
                    guard let identity = fileFingerprint(at: url),
                          identity.size == expectedSize else { return false }
                    if let cached = validationCache[url.path], cached.0 == identity {
                        return cached.1 == expectedHash
                    }
                    guard remainingHashBytes >= expectedSize else { return false }
                    remainingHashBytes -= expectedSize
                    guard let digest = try? streamingSHA256(at: url),
                          fileFingerprint(at: url) == identity else { return false }
                    let hash = hexadecimalDigest(digest)
                    validationCache[url.path] = (identity, hash)
                    return hash == expectedHash
                }

                for (metadataURL, metadata) in metadataRecords {
                    guard remainingHashBytes > 0,
                          let expectedHash = metadata.sha256?.lowercased(),
                          expectedHash.count == 64,
                          let expectedSize = metadata.fileSize,
                          expectedSize >= 0,
                          let storedURL = childURL(named: metadata.storedFileName) else { continue }

                    let temporaryURL = metadata.temporaryStoredFileName.flatMap(childURL(named:))
                    let stagedURL = stagingURL(from: metadata)
                    let finalExists = pathEntryExists(at: storedURL)
                    let finalValid = finalExists && payloadMatches(
                        storedURL,
                        expectedSize: expectedSize,
                        expectedHash: expectedHash
                    )

                    if metadata.state == "restorePreparing" {
                        let recordedOutputURL = restoreTemporaryURL(from: metadata)
                        if metadata.restoreTemporaryPath != nil, recordedOutputURL == nil {
                            continue
                        }

                        var storedValid = finalValid
                        var deletionValid = temporaryURL.map {
                            pathEntryExists(at: $0) && payloadMatches(
                                $0,
                                expectedSize: expectedSize,
                                expectedHash: expectedHash
                            )
                        } ?? false
                        let destinationURL = URL(fileURLWithPath: metadata.originalPath)
                            .standardizedFileURL
                        let isFinalPathOutput = metadata.restoreMode == "directExclusive"
                            || metadata.restoreMode == "sameVolumeRename"
                        let publishedHiddenOutput = !isFinalPathOutput
                            && !pathEntryExists(at: recordedOutputURL ?? destinationURL)
                            && recordedRestoreIdentityMatches(destinationURL, metadata: metadata)
                        let finalOutputURL: URL? = isFinalPathOutput
                            ? recordedOutputURL
                            : (publishedHiddenOutput ? destinationURL : nil)

                        func outputIsValid(_ outputURL: URL) -> Bool {
                            recordedRestoreIdentityMatches(outputURL, metadata: metadata)
                                && payloadMatches(
                                    outputURL,
                                    expectedSize: expectedSize,
                                    expectedHash: expectedHash
                                )
                        }

                        func readyMetadata() -> QuarantineMetadata {
                            QuarantineMetadata(
                                id: metadata.id,
                                originalPath: metadata.originalPath,
                                storedFileName: metadata.storedFileName,
                                signature: metadata.signature,
                                quarantinedAt: metadata.quarantinedAt,
                                state: "ready",
                                sha256: expectedHash,
                                fileSize: expectedSize,
                                stagingPath: nil,
                                temporaryStoredFileName: nil,
                                restoreMode: nil,
                                restoreTemporaryPath: nil,
                                restoreTemporaryDevice: nil,
                                restoreTemporaryInode: nil
                            )
                        }

                        func finalizeRestoredOutput(_ outputURL: URL) -> Bool {
                            guard outputIsValid(outputURL) else { return false }
                            if storedValid {
                                guard let temporaryURL,
                                      !pathEntryExists(at: temporaryURL) else { return false }
                                do {
                                    try renameExclusively(from: storedURL, to: temporaryURL)
                                } catch {
                                    return false
                                }
                                storedValid = false
                                deletionValid = payloadMatches(
                                    temporaryURL,
                                    expectedSize: expectedSize,
                                    expectedHash: expectedHash
                                )
                            }
                            if let temporaryURL, pathEntryExists(at: temporaryURL) {
                                guard deletionValid, outputIsValid(outputURL) else {
                                    if !pathEntryExists(at: storedURL) {
                                        _ = try? renameExclusively(from: temporaryURL, to: storedURL)
                                    }
                                    return false
                                }
                                do {
                                    try fileManager.removeItem(at: temporaryURL)
                                } catch {
                                    return false
                                }
                                guard !pathEntryExists(at: temporaryURL),
                                      outputIsValid(outputURL) else { return false }
                            }
                            guard !pathEntryExists(at: storedURL),
                                  temporaryURL.map({ !pathEntryExists(at: $0) }) ?? true,
                                  outputIsValid(outputURL) else { return false }
                            do {
                                try fileManager.removeItem(at: metadataURL)
                                guard !pathEntryExists(at: metadataURL) else { return false }
                                recoveredCount += 1
                                return true
                            } catch {
                                return false
                            }
                        }

                        // A final-path output is restored user data, never a
                        // disposable temporary. Complete exact output is kept
                        // while the quarantine source transaction is finished.
                        if let finalOutputURL, outputIsValid(finalOutputURL) {
                            _ = finalizeRestoredOutput(finalOutputURL)
                            continue
                        }

                        if isFinalPathOutput {
                            guard let directURL = recordedOutputURL else { continue }
                            if pathEntryExists(at: directURL) {
                                // On filesystems without RENAME_EXCL, safe
                                // no-clobber cleanup is unavailable. Preserve
                                // partial/ambiguous output and metadata.
                                guard storedValid,
                                      recordedRestoreIdentityMatches(
                                        directURL,
                                        metadata: metadata
                                      ),
                                      removeOwnedRestoreTemporary(
                                        directURL,
                                        metadata: metadata
                                      ) else { continue }
                            } else {
                                guard storedValid else { continue }
                            }
                            try securePrivateRegularFile(at: storedURL)
                            try securelyPublishMetadata(
                                try encoder.encode(readyMetadata()),
                                at: metadataURL
                            )
                            recoveredCount += 1
                            continue
                        }

                        // Canonical hidden temporary output is disposable only
                        // when the exact recorded inode can be claimed with a
                        // no-clobber rename.
                        if let recordedOutputURL, pathEntryExists(at: recordedOutputURL) {
                            guard removeOwnedRestoreTemporary(
                                recordedOutputURL,
                                metadata: metadata
                            ) else { continue }
                        }

                        if !storedValid, deletionValid, let temporaryURL {
                            do {
                                try renameExclusively(from: temporaryURL, to: storedURL)
                                storedValid = payloadMatches(
                                    storedURL,
                                    expectedSize: expectedSize,
                                    expectedHash: expectedHash
                                )
                            } catch {
                                continue
                            }
                        }

                        if storedValid {
                            if deletionValid, let temporaryURL, pathEntryExists(at: temporaryURL) {
                                try? fileManager.removeItem(at: temporaryURL)
                                guard !pathEntryExists(at: temporaryURL) else { continue }
                            }
                            try securePrivateRegularFile(at: storedURL)
                            try securelyPublishMetadata(
                                try encoder.encode(readyMetadata()),
                                at: metadataURL
                            )
                            recoveredCount += 1
                            continue
                        }

                        let noQuarantinePayload = !pathEntryExists(at: storedURL)
                            && (temporaryURL.map { !pathEntryExists(at: $0) } ?? true)
                        if noQuarantinePayload, outputIsValid(destinationURL) {
                            try? fileManager.removeItem(at: metadataURL)
                            if !pathEntryExists(at: metadataURL) { recoveredCount += 1 }
                        }
                        continue
                    }

                    if finalValid {
                        if let stagedURL, pathEntryExists(at: stagedURL) {
                            guard payloadMatches(
                                stagedURL,
                                expectedSize: expectedSize,
                                expectedHash: expectedHash
                            ) else { continue }
                            try? fileManager.removeItem(at: stagedURL)
                            guard !pathEntryExists(at: stagedURL) else { continue }
                            cleanupPrivateStagingContainer(
                                for: stagedURL,
                                originalURL: URL(fileURLWithPath: metadata.originalPath),
                                fileManager: fileManager
                            )
                        }
                        if let temporaryURL, pathEntryExists(at: temporaryURL) {
                            try? fileManager.removeItem(at: temporaryURL)
                            guard !pathEntryExists(at: temporaryURL) else { continue }
                        }
                        let ready = QuarantineMetadata(
                            id: metadata.id,
                            originalPath: metadata.originalPath,
                            storedFileName: metadata.storedFileName,
                            signature: metadata.signature,
                            quarantinedAt: metadata.quarantinedAt,
                            state: "ready",
                            sha256: expectedHash,
                            fileSize: expectedSize,
                            stagingPath: nil,
                            temporaryStoredFileName: nil,
                            restoreMode: nil,
                            restoreTemporaryPath: nil,
                            restoreTemporaryDevice: nil,
                            restoreTemporaryInode: nil
                        )
                        try securePrivateRegularFile(at: storedURL)
                        try securelyPublishMetadata(try encoder.encode(ready), at: metadataURL)
                        recoveredCount += 1
                        continue
                    }

                    let temporaryValid = temporaryURL.map {
                        pathEntryExists(at: $0) && payloadMatches(
                            $0,
                            expectedSize: expectedSize,
                            expectedHash: expectedHash
                        )
                    } ?? false
                    let stagedValid = stagedURL.map {
                        pathEntryExists(at: $0) && payloadMatches(
                            $0,
                            expectedSize: expectedSize,
                            expectedHash: expectedHash
                        )
                    } ?? false

                    if finalExists, temporaryValid || stagedValid {
                        try? fileManager.removeItem(at: storedURL)
                        guard !pathEntryExists(at: storedURL) else { continue }
                    }

                    if temporaryValid, let temporaryURL {
                        do {
                            try renameExclusively(from: temporaryURL, to: storedURL)
                        } catch {
                            continue
                        }
                    } else if stagedValid, let stagedURL, let temporaryURL {
                        if pathEntryExists(at: temporaryURL) {
                            try? fileManager.removeItem(at: temporaryURL)
                            guard !pathEntryExists(at: temporaryURL) else { continue }
                        }
                        do {
                            try fileManager.copyItem(at: stagedURL, to: temporaryURL)
                            guard payloadMatches(
                                temporaryURL,
                                expectedSize: expectedSize,
                                expectedHash: expectedHash
                            ) else { continue }
                            try renameExclusively(from: temporaryURL, to: storedURL)
                        } catch {
                            continue
                        }
                    } else {
                        let originalURL = URL(fileURLWithPath: metadata.originalPath)
                        let noTransactionArtifacts = !finalExists
                            && temporaryURL.map { !pathEntryExists(at: $0) } ?? true
                            && stagedURL.map { !pathEntryExists(at: $0) } ?? true
                        if noTransactionArtifacts,
                           payloadMatches(
                               originalURL,
                               expectedSize: expectedSize,
                               expectedHash: expectedHash
                           ) {
                            try? fileManager.removeItem(at: metadataURL)
                            recoveredCount += 1
                        }
                        continue
                    }

                    guard payloadMatches(
                        storedURL,
                        expectedSize: expectedSize,
                        expectedHash: expectedHash
                    ) else { continue }
                    if let stagedURL, pathEntryExists(at: stagedURL) {
                        guard stagedValid else { continue }
                        try? fileManager.removeItem(at: stagedURL)
                        guard !pathEntryExists(at: stagedURL) else { continue }
                        cleanupPrivateStagingContainer(
                            for: stagedURL,
                            originalURL: URL(fileURLWithPath: metadata.originalPath),
                            fileManager: fileManager
                        )
                    }
                    let ready = QuarantineMetadata(
                        id: metadata.id,
                        originalPath: metadata.originalPath,
                        storedFileName: metadata.storedFileName,
                        signature: metadata.signature,
                        quarantinedAt: metadata.quarantinedAt,
                        state: "ready",
                        sha256: expectedHash,
                        fileSize: expectedSize,
                        stagingPath: nil,
                        temporaryStoredFileName: nil,
                        restoreMode: nil,
                        restoreTemporaryPath: nil,
                        restoreTemporaryDevice: nil,
                        restoreTemporaryInode: nil
                    )
                    try securePrivateRegularFile(at: storedURL)
                    try securelyPublishMetadata(try encoder.encode(ready), at: metadataURL)
                    recoveredCount += 1
                }
                return recoveredCount
            }
        } catch {
            appendEvent(ProtectionEvent(
                id: UUID(),
                timestamp: Date(),
                path: quarantineDirectory.path,
                result: "error",
                signature: nil,
                message: "Incomplete quarantine operations could not be reconciled: \(error.localizedDescription)"
            ))
            return 0
        }
    }

    private static func loadWatchedPaths(from configurationURL: URL, homeDirectory: URL) -> [String] {
        let defaults = [
            homeDirectory.appendingPathComponent("Desktop", isDirectory: true).path,
            homeDirectory.appendingPathComponent("Downloads", isDirectory: true).path
        ]

        guard let contents = try? String(contentsOf: configurationURL, encoding: .utf8) else {
            return defaults.filter { FileManager.default.fileExists(atPath: $0) }
        }

        var seen = Set<String>()
        return contents
            .split(whereSeparator: \ .isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("#") }
            .map { line in
                line.replacingOccurrences(of: "$HOME", with: homeDirectory.path)
            }
            .map { NSString(string: $0).standardizingPath }
            .filter { path in
                guard path.hasPrefix("/"), FileManager.default.fileExists(atPath: path) else { return false }
                return seen.insert(path).inserted
            }
    }

    private func preparePrivateDirectory(_ url: URL) throws {
        try fileManager.createDirectory(
            at: url,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: url.path)
    }

    private func protectExistingFile(_ url: URL) throws {
        guard fileManager.fileExists(atPath: url.path) else { return }
        try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    private func receive(
        paths: [String],
        flags: UnsafePointer<FSEventStreamEventFlags>,
        count: Int
    ) {
        guard !paths.isEmpty else { return }
        let limit = min(paths.count, count)
        var recoveryReasons = Set<String>()
        var requiresStreamRebuild = false
        for index in 0..<limit {
            let eventFlags = flags[index]
            if eventFlags & UInt32(kFSEventStreamEventFlagMustScanSubDirs) != 0 {
                recoveryReasons.insert("must-scan-subdirs")
            }
            if eventFlags & UInt32(kFSEventStreamEventFlagUserDropped) != 0 {
                recoveryReasons.insert("user-dropped")
            }
            if eventFlags & UInt32(kFSEventStreamEventFlagKernelDropped) != 0 {
                recoveryReasons.insert("kernel-dropped")
            }
            if eventFlags & UInt32(kFSEventStreamEventFlagEventIdsWrapped) != 0 {
                recoveryReasons.insert("event-ids-wrapped")
                requiresStreamRebuild = true
            }
            if eventFlags & UInt32(kFSEventStreamEventFlagRootChanged) != 0 {
                recoveryReasons.insert("root-changed")
                requiresStreamRebuild = true
            }

            let interesting = kFSEventStreamEventFlagItemCreated |
                kFSEventStreamEventFlagItemModified |
                kFSEventStreamEventFlagItemRenamed |
                kFSEventStreamEventFlagItemInodeMetaMod
            guard eventFlags & UInt32(interesting) != 0 else { continue }
            guard eventFlags & UInt32(kFSEventStreamEventFlagItemIsFile) != 0 else { continue }
            schedule(path: paths[index], delay: 4)
        }

        guard !recoveryReasons.isEmpty else { return }
        let reason = recoveryReasons.sorted().joined(separator: ",")
        requestReconciliation(reason: reason, countsAsEventLoss: true)
        if requiresStreamRebuild {
            requestStreamRebuild(reason: reason)
        }
    }

    private func requestStreamRebuild(reason: String) {
        guard !streamRebuildScheduled else { return }
        streamRebuildScheduled = true
        eventQueue.async { [weak self] in
            guard let self else { return }
            self.stopEventStream()
            do {
                try self.startEventStream()
                self.streamRebuildScheduled = false
                self.appendEvent(ProtectionEvent(
                    id: UUID(),
                    timestamp: Date(),
                    path: self.watchedPaths.first ?? "/",
                    result: "recovery",
                    signature: nil,
                    message: "File system watcher reinitialized (\(reason))."
                ))
            } catch {
                self.streamRebuildScheduled = false
                self.appendEvent(ProtectionEvent(
                    id: UUID(),
                    timestamp: Date(),
                    path: self.watchedPaths.first ?? "/",
                    result: "error",
                    signature: nil,
                    message: "The file system watcher could not be reinitialized: \(error.localizedDescription)"
                ))
                self.eventQueue.asyncAfter(deadline: .now() + 5) { [weak self] in
                    guard let self, self.isServiceRunning else { return }
                    self.requestStreamRebuild(reason: "retry-after-\(reason)")
                }
            }
        }
    }

    private var isServiceRunning: Bool {
        stateLock.lock()
        defer { stateLock.unlock() }
        return isRunning
    }

    private func requestReconciliation(reason: String, countsAsEventLoss: Bool) {
        if countsAsEventLoss {
            stateLock.lock()
            eventLossCount += 1
            stateLock.unlock()
        }

        guard !reconciliationScheduled else {
            if countsAsEventLoss {
                let existing = reconciliationFollowUpReason.map { $0 + "," } ?? ""
                reconciliationFollowUpReason = String((existing + reason).prefix(512))
            }
            writeStatus()
            return
        }
        reconciliationScheduled = true
        stateLock.lock()
        reconciliationActive = true
        reconciliationReason = reason
        reconciliationQueuedCount = 0
        stateLock.unlock()
        writeStatus()
        appendEvent(ProtectionEvent(
            id: UUID(),
            timestamp: Date(),
            path: watchedPaths.first ?? "/",
            result: "recovery",
            signature: nil,
            message: reason == "startup"
                ? "Startup recovery scan started."
                : "File system event loss detected; limited recovery scan started (\(reason))."
        ))

        reconciliationQueue.async { [weak self] in
            guard let self else { return }
            let candidates = self.boundedRecentFiles()
            self.eventQueue.async { [weak self] in
                guard let self else { return }
                for path in candidates {
                    self.schedule(path: path, delay: 0.1)
                }
                self.reconciliationScheduled = false
                self.stateLock.lock()
                self.reconciliationActive = false
                self.reconciliationReason = reason
                self.reconciliationQueuedCount = candidates.count
                self.lastReconciliationAt = Date()
                self.stateLock.unlock()
                self.writeStatus()
                self.appendEvent(ProtectionEvent(
                    id: UUID(),
                    timestamp: Date(),
                    path: self.watchedPaths.first ?? "/",
                    result: "recovery",
                    signature: nil,
                    message: "For recovery scanning, \(candidates.count) recent files queued."
                ))
                if let followUpReason = self.reconciliationFollowUpReason {
                    self.reconciliationFollowUpReason = nil
                    self.requestReconciliation(
                        reason: "coalesced-\(followUpReason)",
                        countsAsEventLoss: false
                    )
                }
            }
        }
    }

    private func boundedRecentFiles() -> [String] {
        let resourceKeys: Set<URLResourceKey> = [
            .isDirectoryKey,
            .isRegularFileKey,
            .isSymbolicLinkKey,
            .contentModificationDateKey
        ]
        let cutoff = Date().addingTimeInterval(-7 * 24 * 60 * 60)
        let deadline = Date().addingTimeInterval(8)
        let totalLimit = 4_000
        var candidates: [String] = []
        var seen = Set<String>()

        for rootPath in watchedPaths where candidates.count < totalLimit && Date() < deadline {
            let rootURL = URL(fileURLWithPath: rootPath, isDirectory: true)
            let perRootLimit = rootPath == "/Volumes" ? 1_000 : 1_500
            let rootDepth = rootURL.standardizedFileURL.pathComponents.count
            var rootCount = 0
            guard let enumerator = fileManager.enumerator(
                at: rootURL,
                includingPropertiesForKeys: Array(resourceKeys),
                options: [],
                errorHandler: { _, _ in true }
            ) else { continue }

            while let entry = enumerator.nextObject() as? URL,
                  candidates.count < totalLimit,
                  rootCount < perRootLimit,
                  Date() < deadline {
                let standardized = entry.standardizedFileURL
                let depth = standardized.pathComponents.count - rootDepth
                if depth > 12 {
                    enumerator.skipDescendants()
                    continue
                }
                guard shouldConsider(path: standardized.path),
                      let values = try? standardized.resourceValues(forKeys: resourceKeys) else {
                    continue
                }
                if values.isDirectory == true { continue }
                guard values.isRegularFile == true,
                      values.isSymbolicLink != true,
                      (values.contentModificationDate ?? .distantPast) >= cutoff,
                      seen.insert(standardized.path).inserted else { continue }
                candidates.append(standardized.path)
                rootCount += 1
            }
        }
        return candidates
    }

    private func schedule(path: String, delay: TimeInterval) {
        guard shouldConsider(path: path) else { return }
        pendingWork[path]?.cancel()

        let pathExtension = URL(fileURLWithPath: path).pathExtension.lowercased()
        let effectiveDelay = delayedExtensions.contains(pathExtension) ? max(delay, 15) : delay

        let item = DispatchWorkItem { [weak self] in
            guard let self else { return }
            self.pendingWork[path] = nil
            self.enqueueScan(path: path)
        }
        pendingWork[path] = item
        eventQueue.asyncAfter(deadline: .now() + effectiveDelay, execute: item)
    }

    private func enqueueScan(path: String) {
        guard !queuedScanPaths.contains(path) else { return }
        queuedScanPaths.append(path)
        drainScanQueue()
    }

    private func drainScanQueue() {
        while activeScanPaths.count < 2, !queuedScanPaths.isEmpty {
            let path = queuedScanPaths.removeFirst()
            guard !activeScanPaths.contains(path) else { continue }
            activeScanPaths.insert(path)
            scanQueue.async { [weak self] in
                guard let self else { return }
                self.process(path: path)
                self.eventQueue.async { [weak self] in
                    guard let self else { return }
                    self.activeScanPaths.remove(path)
                    self.drainScanQueue()
                }
            }
        }
    }

    private func shouldConsider(path: String) -> Bool {
        let standardized = NSString(string: path).standardizingPath
        let excludedRoots = [applicationDirectory.path, logDirectory.path, runtimeDirectory.path]
        guard !excludedRoots.contains(where: { standardized == $0 || standardized.hasPrefix($0 + "/") }) else {
            return false
        }

        let url = URL(fileURLWithPath: standardized)
        guard !url.pathComponents.contains(where: ignoredComponents.contains) else { return false }
        // Browsers often download into a temporary directory such as
        // "image.iso.download". Do not inspect its metadata or partial payload
        // until the browser atomically publishes the completed file.
        guard !url.pathComponents.contains(where: {
            delayedExtensions.contains(URL(fileURLWithPath: $0).pathExtension.lowercased())
        }) else { return false }
        guard !onDemandOnlyExtensions.contains(url.pathExtension.lowercased()) else { return false }
        return true
    }

    private func process(path: String) {
        guard shouldConsider(path: path) else { return }
        guard let fingerprint = waitUntilStable(path: path) else { return }
        guard recentFingerprint(for: path) != fingerprint else {
            clearRetry(for: path)
            return
        }

        let allowedScanSeconds = realtimeScanDeadline(for: fingerprint.size)
        let result = runClamdscan(path: path, maximumDuration: allowedScanSeconds)
        switch result.exitCode {
        case 0:
            resetTimedOutStreak()
            guard currentFingerprint(path: path) == fingerprint else {
                eventQueue.async { [weak self] in self?.schedule(path: path, delay: 1.5) }
                return
            }
            remember(fingerprint: fingerprint, for: path)
            clearRetry(for: path)
            recordScan(path: path, result: "clean", daemonConnected: true)
            appendEvent(ProtectionEvent(
                id: UUID(),
                timestamp: Date(),
                path: path,
                result: "clean",
                signature: nil,
                message: "No threat found."
            ))
        case 1:
            clearRetry(for: path)
            let signature = parseSignature(from: result.output) ?? "Detected by ClamAV"

            guard let currentIdentity = currentFingerprint(path: path) else {
                // Another protection layer may already have moved the file.
                return
            }
            guard currentIdentity == fingerprint else {
                eventQueue.async { [weak self] in self?.schedule(path: path, delay: 1.5) }
                return
            }

            do {
                switch try quarantine(
                    path: path,
                    signature: signature,
                    expectedIdentity: fingerprint
                ) {
                case .quarantined:
                    recordScan(path: path, result: "infected", daemonConnected: true, foundThreat: true)
                    appendEvent(ProtectionEvent(
                        id: UUID(),
                        timestamp: Date(),
                        path: path,
                        result: "infected",
                        signature: signature,
                        message: "Threat automatically quarantined."
                    ))
                    notify(
                        title: "ClamAV: Threat quarantined",
                        message: "\(URL(fileURLWithPath: path).lastPathComponent) — \(signature)"
                    )
                case .sourceMissing:
                    // Another layer using the shared lock, such as VirusTotal, won.
                    // Do not log or report the same event as an error.
                    return
                case .sourceChanged:
                    eventQueue.async { [weak self] in self?.schedule(path: path, delay: 1.5) }
                    return
                }
            } catch {
                recordScan(path: path, result: "error", daemonConnected: true)
                appendEvent(ProtectionEvent(
                    id: UUID(),
                    timestamp: Date(),
                    path: path,
                    result: "error",
                    signature: signature,
                    message: "Threat found but could not be quarantined: \(error.localizedDescription)"
                ))
                notify(
                    title: "ClamAV: Action required",
                    message: "Threat found but quarantine failed."
                )
            }
        case 124:
            // A malformed or unusually complex archive must never keep the
            // real-time queue and a CPU core busy indefinitely. It remains on
            // disk for an on-demand scan, but this event is not retried. clamd
            // can continue a scan after its client has exited, so repeated
            // timeouts recover that engine while isolated timeouts avoid an
            // unnecessary global restart.
            remember(fingerprint: fingerprint, for: path)
            clearRetry(for: path)
            let restartDaemon = shouldRestartDaemonAfterTimedOutScan()
            if restartDaemon {
                restartDaemonAfterTimedOutScan()
            }
            recordScan(path: path, result: "skipped", daemonConnected: true)
            appendEvent(ProtectionEvent(
                id: UUID(),
                timestamp: Date(),
                path: path,
                result: "skipped",
                signature: nil,
                message: restartDaemon
                    ? "The \(Int(allowedScanSeconds))-second real-time scan limit was exceeded for this file; the queue was released and the ClamAV engine was safely restarted. You can scan the file manually."
                    : "The \(Int(allowedScanSeconds))-second real-time scan limit was exceeded for this file; the queue was released. The ClamAV engine will be repaired automatically if stalls recur. You can scan the file manually."
            ))
        default:
            recordScan(path: path, result: "error", daemonConnected: false)
            appendEvent(ProtectionEvent(
                id: UUID(),
                timestamp: Date(),
                path: path,
                result: "error",
                signature: nil,
                message: compactError(from: result.output)
            ))
            retry(path: path)
        }
    }

    private func waitUntilStable(path: String) -> FileFingerprint? {
        var previous: FileFingerprint?
        var stableSamples = 0

        for _ in 0..<4 {
            guard let current = currentFingerprint(path: path) else { return nil }
            if current == previous {
                stableSamples += 1
                if stableSamples >= 2 { return current }
            } else {
                stableSamples = 0
            }
            previous = current
            Thread.sleep(forTimeInterval: 1)
        }

        eventQueue.async { [weak self] in self?.schedule(path: path, delay: 5) }
        return nil
    }

    private func currentFingerprint(path: String) -> FileFingerprint? {
        fileFingerprint(at: URL(fileURLWithPath: path))
    }

    private func realtimeScanDeadline(for fileSize: Int64) -> TimeInterval {
        // Give larger files proportionally longer, but bounded, time. This is
        // 20 seconds for small files and adds one second per MiB, up to 165 s.
        let mebibytes = max(0, Double(fileSize) / 1_048_576)
        return min(165, max(20, 15 + ceil(mebibytes)))
    }

    private func runClamdscan(path: String, maximumDuration: TimeInterval) -> ScanResult {
        let process = Process()
        let output = Pipe()
        let readHandle = output.fileHandleForReading
        let writeHandle = output.fileHandleForWriting
        defer { try? readHandle.close() }
        process.executableURL = URL(fileURLWithPath: clamdscanPath)
        process.arguments = [
            "--config-file=\(clamdConfigURL.path)",
            "--wait",
            "--infected",
            "--no-summary",
            path
        ]
        process.standardOutput = output
        process.standardError = output

        do {
            try process.run()
            // The child inherited its own writer. Closing our copy prevents a
            // descriptor from accumulating on long-running live protection.
            try? writeHandle.close()
            let deadline = Date().addingTimeInterval(maximumDuration)
            while process.isRunning && Date() < deadline {
                Thread.sleep(forTimeInterval: 0.2)
            }
            let timedOut = process.isRunning
            if timedOut {
                process.terminate()
            }
            process.waitUntilExit()
            let data = readHandle.readDataToEndOfFile()
            let text = String(data: data, encoding: .utf8) ?? ""
            return ScanResult(
                exitCode: timedOut ? 124 : process.terminationStatus,
                output: timedOut ? "Live scan timed out." : text
            )
        } catch {
            return ScanResult(exitCode: 127, output: error.localizedDescription)
        }
    }

    private func parseSignature(from output: String) -> String? {
        for line in output.split(separator: "\n") {
            let text = String(line)
            guard text.hasSuffix(" FOUND"),
                  let separator = text.range(of: ": ", options: .backwards) else { continue }
            let end = text.index(text.endIndex, offsetBy: -" FOUND".count)
            return String(text[separator.upperBound..<end])
        }
        return nil
    }

    private func quarantine(
        path: String,
        signature: String,
        expectedIdentity: FileFingerprint
    ) throws -> QuarantineOutcome {
        guard let quarantineCoordinator else {
            throw CoordinationError(operation: "lock not prepared", code: EINVAL)
        }

        return try quarantineCoordinator.withExclusiveLock {
            // Repeat the identity check after acquiring the lock so ClamAV and
            // VirusTotal cannot move the same source simultaneously.
            guard let lockedIdentity = currentFingerprint(path: path) else {
                return .sourceMissing
            }
            guard lockedIdentity == expectedIdentity else {
                return .sourceChanged
            }

            try preparePrivateDirectory(quarantineDirectory)
            let crossesVolumes = expectedIdentity.device != (try directoryDevice(at: quarantineDirectory))
            let expectedDigest: [UInt8]
            do {
                expectedDigest = try streamingSHA256(at: URL(fileURLWithPath: path))
            } catch TransferIntegrityError.sourceChanged {
                return .sourceChanged
            }
            guard currentFingerprint(path: path) == expectedIdentity else {
                return .sourceChanged
            }

            let id = UUID()
            let originalURL = URL(fileURLWithPath: path)
            let storedFileName = id.uuidString + "-" + originalURL.lastPathComponent
            let storedURL = quarantineDirectory.appendingPathComponent(storedFileName)
            let metadataURL = quarantineDirectory.appendingPathComponent(id.uuidString + ".json")
            let stagingURL = crossesVolumes
                ? originalURL.deletingLastPathComponent()
                    .appendingPathComponent(
                        ".clamav-quarantine-\(id.uuidString).stage-dir",
                        isDirectory: true
                    )
                    .appendingPathComponent("payload")
                : nil
            let temporaryStoredFileName = crossesVolumes
                ? ".\(id.uuidString).payload.tmp"
                : nil
            let temporaryStoredURL = temporaryStoredFileName.map {
                quarantineDirectory.appendingPathComponent($0)
            }
            let digestString = hexadecimalDigest(expectedDigest)
            let preparingMetadata = QuarantineMetadata(
                id: id,
                originalPath: path,
                storedFileName: storedFileName,
                signature: signature,
                quarantinedAt: Date(),
                state: "preparing",
                sha256: digestString,
                fileSize: expectedIdentity.size,
                stagingPath: stagingURL?.path,
                temporaryStoredFileName: temporaryStoredFileName,
                restoreMode: nil,
                restoreTemporaryPath: nil,
                restoreTemporaryDevice: nil,
                restoreTemporaryInode: nil
            )
            let readyMetadata = QuarantineMetadata(
                id: id,
                originalPath: path,
                storedFileName: storedFileName,
                signature: signature,
                quarantinedAt: preparingMetadata.quarantinedAt,
                state: "ready",
                sha256: digestString,
                fileSize: expectedIdentity.size,
                stagingPath: nil,
                temporaryStoredFileName: nil,
                restoreMode: nil,
                restoreTemporaryPath: nil,
                restoreTemporaryDevice: nil,
                restoreTemporaryInode: nil
            )
            let preparingMetadataData = try JSONEncoder().encode(preparingMetadata)
            let readyMetadataData = try JSONEncoder().encode(readyMetadata)

            // Prepare metadata atomically before moving. Any subsequent permission or
            // restore error cannot leave an invisible orphan destination.
            do {
                try securelyPublishMetadata(preparingMetadataData, at: metadataURL)
            } catch {
                try? fileManager.removeItem(at: metadataURL)
                throw error
            }

            guard currentFingerprint(path: path) == expectedIdentity else {
                try? fileManager.removeItem(at: metadataURL)
                return .sourceChanged
            }

            if crossesVolumes {
                guard let stagingURL, let temporaryStoredURL else {
                    try? fileManager.removeItem(at: metadataURL)
                    throw TransferIntegrityError.destinationMismatch
                }

                let copyOutcome: VerifiedCopyOutcome
                do {
                    copyOutcome = try verifiedCrossVolumeCopy(
                        originalURL: originalURL,
                        stagingURL: stagingURL,
                        temporaryStoredURL: temporaryStoredURL,
                        storedURL: storedURL,
                        expectedIdentity: expectedIdentity,
                        expectedDigest: expectedDigest,
                        fileManager: fileManager
                    )
                } catch let transferError {
                    let destinationRemoved = try removeFailedDestination(
                        storedURL: storedURL,
                        metadataURL: metadataURL,
                        metadataData: preparingMetadataData,
                        fileManager: fileManager
                    )
                    let temporaryRemoved = try removeFailedDestination(
                        storedURL: temporaryStoredURL,
                        metadataURL: metadataURL,
                        metadataData: preparingMetadataData,
                        fileManager: fileManager
                    )
                    guard destinationRemoved, temporaryRemoved else { throw transferError }
                    try? fileManager.removeItem(at: metadataURL)
                    // After the cross-volume helper claims the source under a staging name,
                    // originalURL may refer to a new user file. It is unsafe to inspect
                    // or modify that path here.
                    throw transferError
                }

                switch copyOutcome {
                case .completed:
                    break
                case .sourceMissing, .sourceChanged:
                    let destinationRemoved = try removeFailedDestination(
                        storedURL: storedURL,
                        metadataURL: metadataURL,
                        metadataData: preparingMetadataData,
                        fileManager: fileManager
                    )
                    let temporaryRemoved = try removeFailedDestination(
                        storedURL: temporaryStoredURL,
                        metadataURL: metadataURL,
                        metadataData: preparingMetadataData,
                        fileManager: fileManager
                    )
                    guard destinationRemoved, temporaryRemoved else {
                        throw TransferIntegrityError.sourceChanged
                    }
                    try? fileManager.removeItem(at: metadataURL)
                    return copyOutcome == .sourceMissing ? .sourceMissing : .sourceChanged
                }
            } else {
                do {
                    try renameExclusively(from: originalURL, to: storedURL)
                    guard let storedIdentity = fileFingerprint(at: storedURL),
                          sameVolumeIdentityMatches(storedIdentity, expected: expectedIdentity) else {
                        throw TransferIntegrityError.destinationMismatch
                    }
                } catch let transferError {
                    if fileManager.fileExists(atPath: storedURL.path) {
                        let restored = try restorePayloadOrPublishMetadata(
                            originalURL: originalURL,
                            storedURL: storedURL,
                            metadataURL: metadataURL,
                            metadataData: preparingMetadataData,
                            fileManager: fileManager
                        )
                        if restored { throw transferError }

                        // A payload that cannot be restored remains visible through its metadata.
                        throw transferError
                    }

                    try? fileManager.removeItem(at: metadataURL)
                    guard let currentIdentity = currentFingerprint(path: path) else {
                        return .sourceMissing
                    }
                    guard currentIdentity == expectedIdentity else {
                        return .sourceChanged
                    }
                    throw transferError
                }
            }

            do {
                try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: storedURL.path)
                try securelyPublishMetadata(readyMetadataData, at: metadataURL)
            } catch let finalizationError {
                let restored = try restorePayloadOrPublishMetadata(
                    originalURL: originalURL,
                    storedURL: storedURL,
                    metadataURL: metadataURL,
                    metadataData: readyMetadataData,
                    fileManager: fileManager
                )
                if restored { throw finalizationError }

                // Restore failed, but the payload and secure metadata remain in quarantine
                // and can be recovered by Threat Center.
                return .quarantined
            }
            return .quarantined
        }
    }

    private func recordScan(
        path: String,
        result: String,
        daemonConnected: Bool,
        foundThreat: Bool = false
    ) {
        stateLock.lock()
        scannedCount += 1
        if foundThreat { threatCount += 1 }
        lastPath = path
        lastResult = result
        self.daemonConnected = daemonConnected
        stateLock.unlock()
        writeStatus()
    }

    private func remember(fingerprint: FileFingerprint, for path: String) {
        fingerprintLock.lock()
        defer { fingerprintLock.unlock() }
        recentFingerprints[path] = fingerprint
        recentFingerprintOrder.removeAll(where: { $0 == path })
        recentFingerprintOrder.append(path)
        if recentFingerprintOrder.count > 5_000 {
            let removed = recentFingerprintOrder.removeFirst()
            recentFingerprints.removeValue(forKey: removed)
        }
    }

    private func recentFingerprint(for path: String) -> FileFingerprint? {
        fingerprintLock.lock()
        defer { fingerprintLock.unlock() }
        return recentFingerprints[path]
    }

    private func resetTimedOutStreak() {
        stateLock.lock()
        consecutiveTimedOutScans = 0
        stateLock.unlock()
    }

    private func shouldRestartDaemonAfterTimedOutScan() -> Bool {
        stateLock.lock()
        defer { stateLock.unlock() }
        consecutiveTimedOutScans += 1
        let cooldownExpired = lastTimedOutDaemonRestartAt.map {
            Date().timeIntervalSince($0) >= 15 * 60
        } ?? true
        guard consecutiveTimedOutScans >= 2, cooldownExpired else { return false }
        consecutiveTimedOutScans = 0
        lastTimedOutDaemonRestartAt = Date()
        return true
    }

    private func retry(path: String) {
        eventQueue.async { [weak self] in
            guard let self else { return }
            let count = (self.retryCounts[path] ?? 0) + 1
            self.retryCounts[path] = count
            guard count <= 6 else {
                self.retryCounts.removeValue(forKey: path)
                return
            }
            self.schedule(path: path, delay: min(Double(count) * 5, 30))
        }
    }

    private func clearRetry(for path: String) {
        eventQueue.async { [weak self] in self?.retryCounts.removeValue(forKey: path) }
    }

    private func startHeartbeat() {
        let timer = DispatchSource.makeTimerSource(queue: heartbeatQueue)
        timer.schedule(deadline: .now() + 30, repeating: 30)
        var heartbeatTick = 0
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            heartbeatTick += 1
            if heartbeatTick == 1 || heartbeatTick % 4 == 0 {
                self.refreshDaemonConnection()
            }
            self.writeStatus()
        }
        heartbeatTimer = timer
        timer.resume()
    }

    private func refreshDaemonConnection() {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: clamdscanPath)
        process.arguments = ["--config-file=\(clamdConfigURL.path)", "--ping=1:1"]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice

        let connected: Bool
        do {
            try process.run()
            process.waitUntilExit()
            connected = process.terminationStatus == 0
        } catch {
            connected = false
        }

        stateLock.lock()
        daemonConnected = connected
        stateLock.unlock()
    }

    private func restartDaemonAfterTimedOutScan() {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["kickstart", "-k", "gui/\(getuid())/com.local.clamav.daemon"]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            // The next heartbeat will report a disconnected daemon and normal
            // launchd KeepAlive recovery still applies.
        }
    }

    private func writeStatus() {
        stateLock.lock()
        let snapshot = ProtectionStatus(
            running: isRunning,
            startedAt: startedAt,
            heartbeatAt: Date(),
            watchedPaths: watchedPaths,
            scannedCount: scannedCount,
            threatCount: threatCount,
            lastPath: lastPath,
            lastResult: lastResult,
            daemonConnected: daemonConnected,
            reconciliationActive: reconciliationActive,
            reconciliationReason: reconciliationReason,
            reconciliationQueuedCount: reconciliationQueuedCount,
            lastReconciliationAt: lastReconciliationAt,
            eventLossCount: eventLossCount
        )
        stateLock.unlock()

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        do {
            let data = try encoder.encode(snapshot)
            try data.write(to: statusURL, options: .atomic)
            try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: statusURL.path)
        } catch {
            FileHandle.standardError.write(Data("Could not write status file: \(error)\n".utf8))
        }
    }

    private func appendEvent(_ event: ProtectionEvent) {
        eventLogLock.lock()
        defer { eventLogLock.unlock() }
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        guard var data = try? encoder.encode(event) else { return }
        data.append(0x0A)

        do {
            try rotateEventsIfNeeded(adding: data.count)
            if !fileManager.fileExists(atPath: eventsURL.path) {
                try data.write(to: eventsURL, options: .atomic)
            } else {
                let handle = try FileHandle(forWritingTo: eventsURL)
                try handle.seekToEnd()
                try handle.write(contentsOf: data)
                try handle.close()
            }
            try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: eventsURL.path)
        } catch {
            FileHandle.standardError.write(Data("Could not write event log: \(error)\n".utf8))
        }
    }

    private func rotateEventsIfNeeded(adding byteCount: Int) throws {
        let attributes = try? fileManager.attributesOfItem(atPath: eventsURL.path)
        let currentSize = (attributes?[.size] as? NSNumber)?.intValue ?? 0
        guard currentSize + byteCount > 10 * 1_024 * 1_024 else { return }

        let archiveURL = eventsURL.appendingPathExtension("1")
        if fileManager.fileExists(atPath: archiveURL.path) {
            try fileManager.removeItem(at: archiveURL)
        }
        try fileManager.moveItem(at: eventsURL, to: archiveURL)
        try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: archiveURL.path)
    }

    private func compactError(from output: String) -> String {
        let compact = output
            .split(whereSeparator: \ .isNewline)
            .prefix(3)
            .joined(separator: " ")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return compact.isEmpty ? "ClamAV scan could not be completed." : compact
    }

    private func notify(title: String, message: String) {
        let process = Process()
        let input = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-", title, message]
        process.standardInput = input
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            let script = """
            on run argv
                display notification (item 2 of argv) with title (item 1 of argv) sound name "Basso"
            end run
            """
            try input.fileHandleForWriting.write(contentsOf: Data(script.utf8))
            try input.fileHandleForWriting.close()
            process.waitUntilExit()
        } catch {
            try? input.fileHandleForWriting.close()
        }
    }
}

private enum ProtectionError: LocalizedError {
    case missingClamdscan
    case noWatchedPaths
    case streamCreationFailed
    case streamStartFailed

    var errorDescription: String? {
        switch self {
        case .missingClamdscan:
            return "clamdscan not found. ClamAV installation missing."
        case .noWatchedPaths:
            return "No accessible folders found to watch."
        case .streamCreationFailed:
            return "Failed to create file system tracker."
        case .streamStartFailed:
            return "Failed to initialize file system tracker."
        }
    }
}

#if COORDINATION_LOCK_TEST
private func runVerifiedTransferTests(in parentDirectory: URL) throws {
    let testDirectory = parentDirectory.appendingPathComponent("verified-transfer", isDirectory: true)
    try FileManager.default.createDirectory(
        at: testDirectory,
        withIntermediateDirectories: false,
        attributes: [.posixPermissions: 0o700]
    )

    let originalData = Data(repeating: 0x41, count: 2_200_000)
    let changedData = Data(repeating: 0x42, count: originalData.count)

    // Same-volume model: inode/generation identity must survive rename.
    let sameSource = testDirectory.appendingPathComponent("same-source.bin")
    let sameStored = testDirectory.appendingPathComponent("same-stored.bin")
    try originalData.write(to: sameSource)
    guard let sameExpected = fileFingerprint(at: sameSource) else {
        throw CoordinationError(operation: "same-volume test identity", code: EIO)
    }
    try FileManager.default.moveItem(at: sameSource, to: sameStored)
    guard let sameResult = fileFingerprint(at: sameStored),
          sameVolumeIdentityMatches(sameResult, expected: sameExpected) else {
        throw CoordinationError(operation: "same-volume inode test", code: EIO)
    }

    // Exercise the cross-volume path on the test disk: after hash verification,
    // only the verified source may be deleted.
    let cleanSource = testDirectory.appendingPathComponent("cross-clean-source.bin")
    let cleanStored = testDirectory.appendingPathComponent("cross-clean-stored.bin")
    try originalData.write(to: cleanSource)
    guard let cleanIdentity = fileFingerprint(at: cleanSource) else {
        throw CoordinationError(operation: "cross-volume test identity", code: EIO)
    }
    let cleanDigest = try streamingSHA256(at: cleanSource)
    let cleanOutcome = try verifiedCrossVolumeCopy(
        originalURL: cleanSource,
        storedURL: cleanStored,
        expectedIdentity: cleanIdentity,
        expectedDigest: cleanDigest
    )
    guard cleanOutcome == .completed,
          !FileManager.default.fileExists(atPath: cleanSource.path),
          try streamingSHA256(at: cleanStored) == cleanDigest else {
        throw CoordinationError(operation: "cross-volume clean copy test", code: EIO)
    }

    // If the user creates a new inode at the original path after claiming,
    // the new file must remain; only the random staging entry may be deleted.
    let replacedSource = testDirectory.appendingPathComponent("cross-replaced-source.bin")
    let replacedStored = testDirectory.appendingPathComponent("cross-replaced-stored.bin")
    try originalData.write(to: replacedSource)
    guard let replacedIdentity = fileFingerprint(at: replacedSource) else {
        throw CoordinationError(operation: "replacement test identity", code: EIO)
    }
    let replacedDigest = try streamingSHA256(at: replacedSource)
    let replacedOutcome = try verifiedCrossVolumeCopy(
        originalURL: replacedSource,
        storedURL: replacedStored,
        expectedIdentity: replacedIdentity,
        expectedDigest: replacedDigest,
        beforeStagingDeletion: { _ in
            try changedData.write(to: replacedSource, options: .withoutOverwriting)
        }
    )
    guard replacedOutcome == .completed,
          (try Data(contentsOf: replacedSource)) == changedData,
          try streamingSHA256(at: replacedStored) == replacedDigest else {
        throw CoordinationError(operation: "path replacement race test", code: EIO)
    }

    // If the claimed inode changes after copying, staging must be restored
    // and the unverified destination must be removable.
    let changedSource = testDirectory.appendingPathComponent("cross-mutated-source.bin")
    let changedStored = testDirectory.appendingPathComponent("cross-mutated-stored.bin")
    let changedMetadata = testDirectory.appendingPathComponent("cross-mutated.json")
    let changedMetadataData = Data("{\"case\":\"staging-mutated\"}".utf8)
    try originalData.write(to: changedSource)
    try securelyPublishMetadata(changedMetadataData, at: changedMetadata)
    guard let changedIdentity = fileFingerprint(at: changedSource) else {
        throw CoordinationError(operation: "staging mutation test identity", code: EIO)
    }
    let changedExpectedDigest = try streamingSHA256(at: changedSource)
    let changedOutcome = try verifiedCrossVolumeCopy(
        originalURL: changedSource,
        storedURL: changedStored,
        expectedIdentity: changedIdentity,
        expectedDigest: changedExpectedDigest,
        beforeStagingDeletion: { stagingURL in
            let handle = try FileHandle(forWritingTo: stagingURL)
            defer { try? handle.close() }
            try handle.seek(toOffset: 0)
            try handle.write(contentsOf: changedData)
            try handle.truncate(atOffset: UInt64(changedData.count))
            try handle.synchronize()
        }
    )
    guard changedOutcome == .sourceChanged,
          (try Data(contentsOf: changedSource)) == changedData,
          try removeFailedDestination(
              storedURL: changedStored,
              metadataURL: changedMetadata,
              metadataData: changedMetadataData
          ) else {
        throw CoordinationError(operation: "staging mutation recovery test", code: EIO)
    }
    try? FileManager.default.removeItem(at: changedMetadata)

    // If the destination copy is corrupted, the hash must differ and the source must remain.
    let corruptSource = testDirectory.appendingPathComponent("cross-corrupt-source.bin")
    let corruptStored = testDirectory.appendingPathComponent("cross-corrupt-stored.bin")
    let corruptMetadata = testDirectory.appendingPathComponent("cross-corrupt.json")
    let corruptMetadataData = Data("{\"case\":\"destination-corrupt\"}".utf8)
    try originalData.write(to: corruptSource)
    try securelyPublishMetadata(corruptMetadataData, at: corruptMetadata)
    guard let corruptIdentity = fileFingerprint(at: corruptSource) else {
        throw CoordinationError(operation: "destination test identity", code: EIO)
    }
    let corruptDigest = try streamingSHA256(at: corruptSource)
    do {
        _ = try verifiedCrossVolumeCopy(
            originalURL: corruptSource,
            storedURL: corruptStored,
            expectedIdentity: corruptIdentity,
            expectedDigest: corruptDigest,
            afterCopy: { temporaryURL in
                let handle = try FileHandle(forWritingTo: temporaryURL)
                defer { try? handle.close() }
                try handle.seek(toOffset: 0)
                try handle.write(contentsOf: Data([0x7A]))
                try handle.synchronize()
            }
        )
        throw CoordinationError(operation: "corrupt destination was accepted", code: EIO)
    } catch TransferIntegrityError.destinationMismatch {
        // Expected safe rejection.
    }
    guard FileManager.default.fileExists(atPath: corruptSource.path),
          try removeFailedDestination(
              storedURL: corruptStored,
              metadataURL: corruptMetadata,
              metadataData: corruptMetadataData
          ) else {
        throw CoordinationError(operation: "corrupt destination cleanup test", code: EIO)
    }
    try? FileManager.default.removeItem(at: corruptMetadata)
}

private func runExternalVerifiedTransferTests(
    externalRoot: URL,
    quarantineTestDirectory: URL
) throws {
    let fileManager = FileManager.default
    let externalTestDirectory = externalRoot.appendingPathComponent(
        "ClamAV-Realtime-Test-\(UUID().uuidString)",
        isDirectory: true
    )
    try fileManager.createDirectory(
        at: externalTestDirectory,
        withIntermediateDirectories: false,
        attributes: [.posixPermissions: 0o700]
    )
    defer { try? fileManager.removeItem(at: externalTestDirectory) }

    let originalData = Data(repeating: 0x51, count: 2_200_000)
    let replacementData = Data(repeating: 0x52, count: originalData.count)

    func transfer(name: String, replaceOriginal: Bool) throws {
        let sourceURL = externalTestDirectory.appendingPathComponent("\(name)-source.bin")
        let storedURL = quarantineTestDirectory.appendingPathComponent("\(name)-stored.bin")
        let temporaryURL = quarantineTestDirectory.appendingPathComponent(".\(name).payload.tmp")
        let stagingURL = externalTestDirectory
            .appendingPathComponent(
                ".clamav-quarantine-\(UUID().uuidString).stage-dir",
                isDirectory: true
            )
            .appendingPathComponent("payload")
        try originalData.write(to: sourceURL)
        guard let identity = fileFingerprint(at: sourceURL) else {
            throw CoordinationError(operation: "exFAT source ID", code: EIO)
        }
        let digest = try streamingSHA256(at: sourceURL)
        let outcome = try verifiedCrossVolumeCopy(
            originalURL: sourceURL,
            stagingURL: stagingURL,
            temporaryStoredURL: temporaryURL,
            storedURL: storedURL,
            expectedIdentity: identity,
            expectedDigest: digest,
            beforeStagingDeletion: replaceOriginal ? { _ in
                try replacementData.write(to: sourceURL, options: .withoutOverwriting)
            } : nil
        )
        guard outcome == .completed,
              try streamingSHA256(at: storedURL) == digest,
              !pathEntryExists(at: stagingURL),
              !pathEntryExists(at: temporaryURL) else {
            throw CoordinationError(operation: "exFAT verified transfer", code: EIO)
        }
        if replaceOriginal {
            guard try Data(contentsOf: sourceURL) == replacementData else {
                throw CoordinationError(operation: "exFAT replacement protection", code: EIO)
            }
        } else if pathEntryExists(at: sourceURL) {
            throw CoordinationError(operation: "exFAT source cleanup", code: EIO)
        }
    }

    try transfer(name: "exfat-clean", replaceOriginal: false)
    try transfer(name: "exfat-replaced", replaceOriginal: true)
}

private func runQuarantineRecoveryTest(in parentDirectory: URL) throws {
    let testDirectory = parentDirectory.appendingPathComponent("recovery", isDirectory: true)
    try FileManager.default.createDirectory(
        at: testDirectory,
        withIntermediateDirectories: false,
        attributes: [.posixPermissions: 0o700]
    )

    let restoredOriginal = testDirectory.appendingPathComponent("restored-original.bin")
    let restoredPayload = testDirectory.appendingPathComponent("restored-payload.bin")
    let restoredMetadata = testDirectory.appendingPathComponent("restored.json")
    let restoredMetadataData = Data("{\"case\":\"restore\"}".utf8)
    try Data("payload-a".utf8).write(to: restoredPayload)
    try securelyPublishMetadata(restoredMetadataData, at: restoredMetadata)

    let didRestore = try restorePayloadOrPublishMetadata(
        originalURL: restoredOriginal,
        storedURL: restoredPayload,
        metadataURL: restoredMetadata,
        metadataData: restoredMetadataData
    )
    guard didRestore,
          FileManager.default.fileExists(atPath: restoredOriginal.path),
          !FileManager.default.fileExists(atPath: restoredPayload.path),
          !FileManager.default.fileExists(atPath: restoredMetadata.path) else {
        throw CoordinationError(operation: "restore test", code: EIO)
    }

    let occupiedOriginal = testDirectory.appendingPathComponent("occupied-original", isDirectory: true)
    let retainedPayload = testDirectory.appendingPathComponent("retained-payload.bin")
    let publishedMetadata = testDirectory.appendingPathComponent("published.json")
    let publishedMetadataData = Data("{\"case\":\"publish\"}".utf8)
    try FileManager.default.createDirectory(at: occupiedOriginal, withIntermediateDirectories: false)
    try Data("payload-b".utf8).write(to: retainedPayload)

    let didUnexpectedlyRestore = try restorePayloadOrPublishMetadata(
        originalURL: occupiedOriginal,
        storedURL: retainedPayload,
        metadataURL: publishedMetadata,
        metadataData: publishedMetadataData
    )

    var payloadInfo = stat()
    var metadataInfo = stat()
    guard !didUnexpectedlyRestore,
          FileManager.default.fileExists(atPath: retainedPayload.path),
          (try Data(contentsOf: publishedMetadata)) == publishedMetadataData,
          retainedPayload.path.withCString({ Darwin.lstat($0, &payloadInfo) }) == 0,
          publishedMetadata.path.withCString({ Darwin.lstat($0, &metadataInfo) }) == 0,
          payloadInfo.st_mode & mode_t(0o777) == mode_t(0o600),
          metadataInfo.st_mode & mode_t(0o777) == mode_t(0o600) else {
        throw CoordinationError(operation: "metadata recovery test", code: EIO)
    }
}

private func runCoordinationLockTest() -> Int32 {
    let testDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent("ClamAV-Coordination-Test-\(UUID().uuidString)", isDirectory: true)
    let lockURL = testDirectory.appendingPathComponent("quarantine.lock")
    let holderReady = DispatchSemaphore(value: 0)
    let releaseHolder = DispatchSemaphore(value: 0)
    let holderDone = DispatchSemaphore(value: 0)
    let contenderEntered = DispatchSemaphore(value: 0)
    let contenderDone = DispatchSemaphore(value: 0)

    defer { try? FileManager.default.removeItem(at: testDirectory) }
    defer {
        releaseHolder.signal()
        _ = holderDone.wait(timeout: .now() + 6)
        _ = contenderDone.wait(timeout: .now() + 6)
    }

    do {
        let holder = try QuarantineCoordinator(directoryURL: testDirectory, lockURL: lockURL)
        let contender = try QuarantineCoordinator(directoryURL: testDirectory, lockURL: lockURL)

        DispatchQueue.global(qos: .utility).async {
            defer { holderDone.signal() }
            try? holder.withExclusiveLock {
                holderReady.signal()
                _ = releaseHolder.wait(timeout: .now() + 5)
            }
        }

        guard holderReady.wait(timeout: .now() + 2) == .success else {
            FileHandle.standardError.write(Data("TEST ERROR: could not acquire the first lock.\n".utf8))
            return 1
        }

        DispatchQueue.global(qos: .utility).async {
            defer { contenderDone.signal() }
            _ = try? contender.withExclusiveLock {
                contenderEntered.signal()
            }
        }

        guard contenderEntered.wait(timeout: .now() + .milliseconds(250)) == .timedOut else {
            FileHandle.standardError.write(Data("TEST ERROR: second process entered the critical section while locked.\n".utf8))
            return 1
        }

        releaseHolder.signal()
        guard contenderEntered.wait(timeout: .now() + 2) == .success else {
            FileHandle.standardError.write(Data("TEST ERROR: no progress after lock release.\n".utf8))
            return 1
        }

        var directoryInfo = stat()
        var lockInfo = stat()
        guard testDirectory.path.withCString({ Darwin.lstat($0, &directoryInfo) }) == 0,
              lockURL.path.withCString({ Darwin.lstat($0, &lockInfo) }) == 0,
              directoryInfo.st_mode & mode_t(0o777) == mode_t(0o700),
              lockInfo.st_mode & mode_t(0o777) == mode_t(0o600),
              lockInfo.st_mode & S_IFMT == S_IFREG,
              lockInfo.st_uid == getuid() else {
            FileHandle.standardError.write(Data("TEST ERROR: lock path or permissions are unsafe.\n".utf8))
            return 1
        }

        try runQuarantineRecoveryTest(in: testDirectory)
        try runVerifiedTransferTests(in: testDirectory)
        if let externalRootPath = ProcessInfo.processInfo.environment["CLAMAV_EXTERNAL_TEST_ROOT"] {
            try runExternalVerifiedTransferTests(
                externalRoot: URL(fileURLWithPath: externalRootPath, isDirectory: true),
                quarantineTestDirectory: testDirectory
            )
        }

        print("TEST OK: lock, restore, inode and cross-volume SHA-256 mutation paths are safe.")
        return 0
    } catch {
        FileHandle.standardError.write(Data("TEST ERROR: \(error.localizedDescription)\n".utf8))
        return 1
    }
}

exit(runCoordinationLockTest())
#else
do {
    let protection = try RealtimeProtection()
    try protection.start()

    signal(SIGTERM, SIG_IGN)
    signal(SIGINT, SIG_IGN)
    let terminationSource = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
    let interruptSource = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
    let stop: (String) -> Void = { reason in
        FileHandle.standardError.write(Data("ClamAV live protection stopped: \(reason).\n".utf8))
        protection.stop()
        exit(EXIT_SUCCESS)
    }
    terminationSource.setEventHandler { stop("SIGTERM") }
    interruptSource.setEventHandler { stop("SIGINT") }
    terminationSource.resume()
    interruptSource.resume()
    RunLoop.main.run()
} catch {
    FileHandle.standardError.write(Data("ClamAV live protection could not start: \(error.localizedDescription)\n".utf8))
    exit(EXIT_FAILURE)
}
#endif
