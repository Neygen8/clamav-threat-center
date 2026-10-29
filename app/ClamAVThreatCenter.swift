import AppKit
import Combine
import CryptoKit
import Darwin
import Foundation
import SwiftUI

// Darwin's Swift overlay also defines a `flock` structure, so bind the BSD
// advisory-lock function explicitly. This is the same lock used by Python's
// `fcntl.flock` and the realtime protection engine.
@_silgen_name("flock")
private func threatCenterAdvisoryFlock(_ descriptor: Int32, _ operation: Int32) -> Int32

struct ThreatOccurrence: Identifiable {
    let id = UUID()
    let path: String
    let signature: String
    let date: Date
    let logURL: URL
}

struct ThreatSummary: Identifiable {
    var id: String { path + "\u{0}" + signature }
    let path: String
    let signature: String
    let lastSeen: Date
    let detectionCount: Int
    let logURL: URL
    let exists: Bool
}

struct ScanRecord: Identifiable {
    let id = UUID()
    let name: String
    let date: Date
    let scannedFiles: Int
    let infectedFiles: Int
    let warningCount: Int
    let logURL: URL

    var source: String {
        name.hasPrefix("selection-") ? "Right-click scan" : "Automatic scan"
    }

    var statusText: String {
        if infectedFiles > 0 { return "Tehdit bulundu" }
        if warningCount > 0 { return "Warning" }
        return "Temiz"
    }

    var statusColor: Color {
        if infectedFiles > 0 { return .red }
        if warningCount > 0 { return .orange }
        return .green
    }
}

struct ScanProgressStatus: Decodable {
    let id: String
    let running: Bool
    let phase: String
    let title: String
    let source: String
    let startedAt: Date
    let heartbeatAt: Date
    let finishedAt: Date?
    let targetPaths: [String]
    let totalFiles: Int
    let scannedFiles: Int
    let totalBytes: Int64
    let scannedBytes: Int64
    let infectedFiles: Int
    let errorCount: Int
    let excludedCount: Int?
    let currentPath: String?
    let estimatedSecondsRemaining: Int?
    let filesPerSecond: Double
    let percent: Double?
    let message: String
    let resultCode: Int?

    var isLegacy: Bool { phase == "legacy" }

    static func legacy(startedAt: Date, title: String) -> ScanProgressStatus {
        ScanProgressStatus(
            id: "legacy-active-scan",
            running: true,
            phase: "legacy",
            title: title,
            source: "legacy",
            startedAt: startedAt,
            heartbeatAt: Date(),
            finishedAt: nil,
            targetPaths: [],
            totalFiles: 0,
            scannedFiles: 0,
            totalBytes: 0,
            scannedBytes: 0,
            infectedFiles: 0,
            errorCount: 0,
            excludedCount: nil,
            currentPath: nil,
            estimatedSecondsRemaining: nil,
            filesPerSecond: 0,
            percent: nil,
            message: "This scan started before progress tracking was added.",
            resultCode: nil
        )
    }
}

struct QuarantineMetadata: Codable {
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

    var effectiveState: String { state ?? "ready" }
}

struct QuarantineItem: Identifiable {
    let metadata: QuarantineMetadata
    let metadataURL: URL
    let fileURL: URL

    var id: UUID { metadata.id }
    var fileName: String { URL(fileURLWithPath: metadata.originalPath).lastPathComponent }
    var exists: Bool { FileManager.default.fileExists(atPath: fileURL.path) }
    var isPreparing: Bool { metadata.effectiveState != "ready" }
    var isActionable: Bool { metadata.effectiveState == "ready" && exists }
}

struct RealtimeProtectionStatus: Decodable {
    let running: Bool
    let startedAt: Date
    let heartbeatAt: Date
    let watchedPaths: [String]
    let scannedCount: Int
    let threatCount: Int
    let lastPath: String?
    let lastResult: String?
    let daemonConnected: Bool
    let reconciliationActive: Bool?
    let reconciliationReason: String?
    let reconciliationQueuedCount: Int?
    let lastReconciliationAt: Date?
    let eventLossCount: Int?
}

struct RealtimeProtectionEvent: Decodable, Identifiable {
    let id: UUID
    let timestamp: Date
    let path: String
    let result: String
    let signature: String?
    let message: String

    var fileName: String {
        let name = URL(fileURLWithPath: path).lastPathComponent
        return name.isEmpty ? path : name
    }

    var resultText: String {
        switch result {
        case "clean": return "Temiz"
        case "infected": return "Threat quarantined"
        case "error": return "Scan failed"
        case "skipped": return "Skipped"
        case "recovery": return "Recovery scan"
        default: return "Kontrol edildi"
        }
    }

    var resultColor: Color {
        switch result {
        case "clean": return .green
        case "infected": return .red
        case "error": return .orange
        case "recovery": return .blue
        default: return .secondary
        }
    }

    var resultIcon: String {
        switch result {
        case "clean": return "checkmark.circle.fill"
        case "infected": return "exclamationmark.shield.fill"
        case "error": return "exclamationmark.circle.fill"
        case "recovery": return "arrow.clockwise.circle.fill"
        default: return "minus.circle.fill"
        }
    }
}

struct VirusTotalServiceStatus: Decodable {
    let running: Bool
    let startedAt: Date
    let heartbeatAt: Date
    let watchedPaths: [String]
    let checkedCount: Int
    let uploadedCount: Int
    let threatCount: Int
    let quarantinedCount: Int
    let queueDepth: Int
    let autoUploadUnknown: Bool
    let autoUploadQuarantine: Bool
    let apiKeyConfigured: Bool
    let lastPath: String?
    let lastResult: String?
    let lastError: String?

    private enum CodingKeys: String, CodingKey {
        case running, startedAt, heartbeatAt, watchedPaths, checkedCount
        case uploadedCount, threatCount, quarantinedCount, queueDepth
        case autoUploadUnknown, autoUploadQuarantine, apiKeyConfigured, lastPath, lastResult, lastError
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        running = try values.decodeIfPresent(Bool.self, forKey: .running) ?? false
        startedAt = try values.decodeIfPresent(Date.self, forKey: .startedAt) ?? .distantPast
        heartbeatAt = try values.decodeIfPresent(Date.self, forKey: .heartbeatAt) ?? .distantPast
        watchedPaths = try values.decodeIfPresent([String].self, forKey: .watchedPaths) ?? []
        checkedCount = try values.decodeIfPresent(Int.self, forKey: .checkedCount) ?? 0
        uploadedCount = try values.decodeIfPresent(Int.self, forKey: .uploadedCount) ?? 0
        threatCount = try values.decodeIfPresent(Int.self, forKey: .threatCount) ?? 0
        quarantinedCount = try values.decodeIfPresent(Int.self, forKey: .quarantinedCount) ?? 0
        queueDepth = try values.decodeIfPresent(Int.self, forKey: .queueDepth) ?? 0
        autoUploadUnknown = try values.decodeIfPresent(Bool.self, forKey: .autoUploadUnknown) ?? false
        autoUploadQuarantine = try values.decodeIfPresent(Bool.self, forKey: .autoUploadQuarantine) ?? false
        apiKeyConfigured = try values.decodeIfPresent(Bool.self, forKey: .apiKeyConfigured) ?? false
        lastPath = try values.decodeIfPresent(String.self, forKey: .lastPath)
        lastResult = try values.decodeIfPresent(String.self, forKey: .lastResult)
        lastError = try values.decodeIfPresent(String.self, forKey: .lastError)
    }
}

struct VirusTotalResult: Decodable, Identifiable {
    let id: String
    let timestamp: Date
    let path: String
    let sha256: String
    let status: String
    let malicious: Int
    let suspicious: Int
    let harmless: Int
    let undetected: Int
    let uploaded: Bool
    let quarantinedTo: String?
    let reportURL: String?
    let sourceDomains: [String]
    let errorMessage: String?
    let source: String?
    let quarantineID: String?
    let alreadyQuarantined: Bool

    private enum CodingKeys: String, CodingKey {
        case id, timestamp, time, path, file, sha256, status
        case malicious, suspicious, harmless, undetected, harmlessOrUndetected = "harmless_or_undetected"
        case uploaded, quarantinedTo, quarantinedToLegacy = "quarantined_to"
        case reportURL, url, sourceDomains, sourceDomainsLegacy = "download_source_domains"
        case errorMessage, error, source, quarantineID, alreadyQuarantined
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        timestamp = try values.decodeIfPresent(Date.self, forKey: .timestamp)
            ?? values.decodeIfPresent(Date.self, forKey: .time)
            ?? .distantPast
        path = try values.decodeIfPresent(String.self, forKey: .path)
            ?? values.decodeIfPresent(String.self, forKey: .file)
            ?? ""
        sha256 = try values.decodeIfPresent(String.self, forKey: .sha256) ?? ""
        malicious = try values.decodeIfPresent(Int.self, forKey: .malicious) ?? 0
        suspicious = try values.decodeIfPresent(Int.self, forKey: .suspicious) ?? 0
        let combinedClean = try values.decodeIfPresent(Int.self, forKey: .harmlessOrUndetected) ?? 0
        harmless = try values.decodeIfPresent(Int.self, forKey: .harmless) ?? combinedClean
        undetected = try values.decodeIfPresent(Int.self, forKey: .undetected) ?? 0
        uploaded = try values.decodeIfPresent(Bool.self, forKey: .uploaded) ?? false
        quarantinedTo = try values.decodeIfPresent(String.self, forKey: .quarantinedTo)
            ?? values.decodeIfPresent(String.self, forKey: .quarantinedToLegacy)
        reportURL = try values.decodeIfPresent(String.self, forKey: .reportURL)
            ?? values.decodeIfPresent(String.self, forKey: .url)
        sourceDomains = try values.decodeIfPresent([String].self, forKey: .sourceDomains)
            ?? values.decodeIfPresent([String].self, forKey: .sourceDomainsLegacy)
            ?? []
        errorMessage = try values.decodeIfPresent(String.self, forKey: .errorMessage)
            ?? values.decodeIfPresent(String.self, forKey: .error)
        source = try values.decodeIfPresent(String.self, forKey: .source)
        quarantineID = try values.decodeIfPresent(String.self, forKey: .quarantineID)
        alreadyQuarantined = try values.decodeIfPresent(Bool.self, forKey: .alreadyQuarantined) ?? false
        let decodedStatus = try values.decodeIfPresent(String.self, forKey: .status)
        if let decodedStatus {
            status = decodedStatus
        } else if malicious > 0 {
            status = "known-malicious"
        } else if suspicious > 0 {
            status = "known-warning"
        } else {
            status = "known-clean"
        }
        id = try values.decodeIfPresent(String.self, forKey: .id)
            ?? "\(timestamp.timeIntervalSinceReferenceDate)|\(sha256)|\(path)|\(status)"
    }

    var fileName: String {
        let name = URL(fileURLWithPath: path).lastPathComponent
        return name.isEmpty ? "Dosya" : name
    }

    var riskCount: Int { malicious + suspicious }

    var isUnknown: Bool {
        status == "unknown" || status.hasPrefix("bilinmiyor")
    }

    var statusText: String {
        switch status {
        case "known-clean", "uploaded-clean", "clean": return "Temiz"
        case "known-warning", "uploaded-warning", "warning", "inceleme-gerekli-tekil-uyarı": return "Review needed"
        case "known-malicious", "uploaded-malicious", "malicious", "quarantined": return "Tehdit bulundu"
        case "unknown", "bilinmiyor-yüklenmedi-gizlilik": return "Unknown to VirusTotal"
        case "queued", "kuyrukta", "tarayıcı-kuyruğunda": return "Queued"
        case "scanning", "taranıyor": return "Checking"
        case "retrying", "tarama-yeniden-denenecek": return "Otomatik yeniden denenecek"
        case "error", "tarama-başarısız": return "Check failed"
        default:
            if status.hasPrefix("karantina-hatası") { return "Could not move to quarantine" }
            return status.replacingOccurrences(of: "-", with: " ")
        }
    }

    var statusColor: Color {
        if riskCount > 0 || status.contains("malicious") || status == "quarantined" { return .red }
        if isUnknown || status.contains("warning") || status.contains("hata") || status == "error" || status == "retrying" { return .orange }
        if status.contains("clean") { return .green }
        return .secondary
    }

    var statusIcon: String {
        if statusColor == .red { return "exclamationmark.shield.fill" }
        if statusColor == .orange { return "exclamationmark.circle.fill" }
        if statusColor == .green { return "checkmark.circle.fill" }
        return "clock.fill"
    }
}

struct VirusTotalUploadRequest: Identifiable {
    let id = UUID()
    let fileURL: URL
    let sha256: String
}

private enum SecureQuarantineError: LocalizedError {
    case unsafeStorage
    case lockBusy
    case lockUnavailable
    case sourceMissing
    case sourceChanged
    case metadataPreparationFailed
    case fileSecuredButNeedsAttention
    case incompleteOperation
    case restorePreScanThreatFound
    case restorePreScanIncomplete

    var errorDescription: String? {
        switch self {
        case .unsafeStorage:
            return "Karantina alanının güvenliği doğrulanamadı. Otomasyonu yeniden kur."
        case .lockBusy:
            return "Başka bir güvenlik bileşeni şu anda karantina işlemi yapıyor. Birkaç saniye sonra yeniden dene."
        case .lockUnavailable:
            return "Ortak karantina kilidi açılamadı. Otomasyonu yeniden kur."
        case .sourceMissing:
            return "Dosya artık belirtilen konumda bulunmuyor."
        case .sourceChanged:
            return "Dosya işlem sırasında değiştiği için karantinaya alınmadı. Yeniden tarayıp tekrar dene."
        case .metadataPreparationFailed:
            return "Karantina kaydı güvenli biçimde hazırlanamadı."
        case .fileSecuredButNeedsAttention:
            return "Dosya özgün konumuna döndürülemedi; Tehdit Merkezi'nde görünen güvenli karantinada tutuluyor."
        case .incompleteOperation:
            return "Karantina işlemi tamamlanmamış durumda. Canlı korumanın kurtarma işlemini bitirmesini bekle."
        case .restorePreScanThreatFound:
            return "Geri yükleme öncesi tekrar tarandı ve tehdit bulundu."
        case .restorePreScanIncomplete:
            return "Geri yükleme öncesi tarama tamamlanamadı; dosya karantinada tutuldu."
        }
    }
}

private struct QuarantineSourceIdentity: Equatable {
    let device: UInt64
    let inode: UInt64
    let generation: UInt64
    let size: Int64
    let modificationSeconds: Int64
    let modificationNanoseconds: Int64
    let statusChangeSeconds: Int64
    let statusChangeNanoseconds: Int64
}

private struct QuarantineFilesystemError: LocalizedError {
    let code: Int32

    var errorDescription: String? {
        "Güvenli atomik yeniden adlandırma başarısız: \(String(cString: strerror(code))) (\(code))"
    }
}

private enum QuarantineStagingRecovery {
    case restored
    case preserved
    case missing
}

enum ProtectionLayerHealth: Sendable {
    case active
    case attention
    case missing
    case checking
}

struct ProtectionLayerStatus: Identifiable, Sendable {
    let id: String
    let name: String
    let icon: String
    let statusText: String
    let detail: String
    let health: ProtectionLayerHealth

    static let checkingItems: [ProtectionLayerStatus] = [
        ProtectionLayerStatus(id: "gatekeeper", name: "Uygulama denetimi", icon: "checkmark.seal.fill", statusText: "Checking", detail: "İndirilen uygulamaların güvenilirliğini denetler.", health: .checking),
        ProtectionLayerStatus(id: "firewall", name: "Güvenlik duvarı", icon: "network.badge.shield.half.filled", statusText: "Checking", detail: "İstenmeyen gelen bağlantıları sınırlar.", health: .checking),
        ProtectionLayerStatus(id: "filevault", name: "Disk şifreleme", icon: "lock.fill", statusText: "Checking", detail: "Mac'teki verileri parola ile korur.", health: .checking),
        ProtectionLayerStatus(id: "lulu", name: "LuLu", icon: "arrow.up.right.circle.fill", statusText: "Checking", detail: "Uygulamaların dışarıya bağlantılarını denetler.", health: .checking),
        ProtectionLayerStatus(id: "santa", name: "Santa", icon: "hand.raised.square.fill", statusText: "Checking", detail: "Güvenilmeyen programların çalışmasını sınırlar.", health: .checking),
        ProtectionLayerStatus(id: "blockblock", name: "BlockBlock", icon: "bolt.shield.fill", statusText: "Checking", detail: "Programların kendini kalıcı hâle getirmesini izler.", health: .checking),
        ProtectionLayerStatus(id: "ransomwhere", name: "RansomWhere?", icon: "lock.shield.fill", statusText: "Checking", detail: "Şüpheli toplu dosya şifreleme davranışını izler.", health: .checking)
    ]
}

private func realtimeJSONDecoder() -> JSONDecoder {
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .custom { decoder in
        let container = try decoder.singleValueContainer()
        let value = try container.decode(String.self)

        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = fractional.date(from: value) {
            return date
        }

        let standard = ISO8601DateFormatter()
        standard.formatOptions = [.withInternetDateTime]
        if let date = standard.date(from: value) {
            return date
        }

        throw DecodingError.dataCorruptedError(
            in: container,
            debugDescription: "Geçersiz canlı koruma tarihi: \(value)"
        )
    }
    return decoder
}

private func readTailLines(from url: URL, maximumBytes: Int) -> [String] {
    guard let handle = try? FileHandle(forReadingFrom: url) else { return [] }
    defer { try? handle.close() }

    let attributes = (try? FileManager.default.attributesOfItem(atPath: url.path))?[.size] as? NSNumber
    let fileSize = Int64(attributes?.intValue ?? 0)
    let start = max(Int64(0), fileSize - Int64(maximumBytes))
    do {
        try handle.seek(toOffset: UInt64(start))
        let data = try handle.readToEnd() ?? Data()
        var lines = String(data: data, encoding: .utf8)?
            .split(separator: "\n", omittingEmptySubsequences: true)
            .map(String.init) ?? []
        if start > 0, !lines.isEmpty {
            lines.removeFirst()
        }
        return lines
    } catch {
        return []
    }
}

private struct DashboardSnapshot: @unchecked Sendable {
    let threats: [ThreatSummary]
    let scans: [ScanRecord]
    let newestKnownViruses: Int?
    let newestEngineVersion: String?
    let quarantineItems: [QuarantineItem]
    let realtimeStatus: RealtimeProtectionStatus?
    let realtimeEvents: [RealtimeProtectionEvent]
    let scanProgressStatus: ScanProgressStatus?
    let virusTotalStatus: VirusTotalServiceStatus?
    let virusTotalResults: [VirusTotalResult]
}

@MainActor
final class ThreatStore: ObservableObject {
    @Published var threats: [ThreatSummary] = []
    @Published var scans: [ScanRecord] = []
    @Published var engineVersion = "—"
    @Published var signatureCount = "—"
    @Published var lastRefresh = Date()
    @Published var quarantineItems: [QuarantineItem] = []
    @Published var isCommandRunning = false
    @Published var activeCommand = ""
    @Published var commandResult = "Henüz manuel komut çalıştırılmadı."
    @Published var scanProgressStatus: ScanProgressStatus?
    @Published var realtimeStatus: RealtimeProtectionStatus?
    @Published var realtimeEvents: [RealtimeProtectionEvent] = []
    @Published var isRestartingProtection = false
    @Published var protectionCommandResult = ""
    @Published var protectionLayers = ProtectionLayerStatus.checkingItems
    @Published var isCheckingProtectionLayers = false
    @Published var virusTotalStatus: VirusTotalServiceStatus?
    @Published var virusTotalResults: [VirusTotalResult] = []
    @Published var isVirusTotalManualScanRunning = false
    @Published var virusTotalManualMessage = "Bir dosya seçerek önce yalnızca hash bilgisini VirusTotal'da sorgulayabilirsin."
    @Published var pendingVirusTotalUpload: VirusTotalUploadRequest?
    @Published var isRestartingClamAVDaemon = false
    @Published var isRestartingVirusTotal = false
    @Published var ownedServiceMessages: [String: String] = [:]
    @Published var clamAVDaemonResponding: Bool?
    private var refreshTimer: AnyCancellable?
    private var scanProgressTimer: AnyCancellable?
    private var isRefreshing = false
    private var isRefreshingScanProgress = false

    nonisolated private let logDirectory = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Logs/ClamAV-Automation", isDirectory: true)
    nonisolated private let automationDirectory = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Application Support/ClamAV-Automation", isDirectory: true)

    private var scriptsDirectory: URL {
        automationDirectory.appendingPathComponent("scripts", isDirectory: true)
    }

    nonisolated private var quarantineDirectory: URL {
        automationDirectory.appendingPathComponent("Quarantine", isDirectory: true)
    }

    nonisolated private var realtimeStatusURL: URL {
        automationDirectory.appendingPathComponent("realtime-status.json")
    }

    nonisolated private var scanProgressStatusURL: URL {
        automationDirectory.appendingPathComponent("scan-progress.json")
    }

    nonisolated private var realtimeEventsURL: URL {
        logDirectory.appendingPathComponent("realtime-events.jsonl")
    }

    nonisolated private var virusTotalStatusURL: URL {
        automationDirectory.appendingPathComponent("virustotal-status.json")
    }

    nonisolated private var virusTotalResultsURL: URL {
        logDirectory.appendingPathComponent("virustotal-results.jsonl")
    }

    private var virusTotalScriptURL: URL {
        scriptsDirectory.appendingPathComponent("virustotal-download-watcher.py")
    }

    var isRealtimeProtectionActive: Bool {
        guard let status = realtimeStatus,
              status.running,
              status.daemonConnected else { return false }
        return abs(status.heartbeatAt.timeIntervalSinceNow) < 90
    }

    var isClamAVDaemonReady: Bool {
        clamAVDaemonResponding ?? (realtimeStatus?.daemonConnected == true)
    }

    var isVirusTotalActive: Bool {
        guard let status = virusTotalStatus, status.running else { return false }
        return abs(status.heartbeatAt.timeIntervalSinceNow) < 90
    }

    var isAnyScanRunning: Bool {
        isCommandRunning || scanProgressStatus?.running == true
    }

    init() {
        refresh()
        refreshTimer = Timer.publish(every: 60, on: .main, in: .common)
            .autoconnect()
            .sink { [weak self] _ in
                self?.refresh()
            }
        scanProgressTimer = Timer.publish(every: 5, on: .main, in: .common)
            .autoconnect()
            .sink { [weak self] _ in
                self?.refreshScanProgress()
            }
    }

    private func refreshScanProgress() {
        guard !isRefreshingScanProgress else { return }
        isRefreshingScanProgress = true
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            let status = self.loadScanProgressSnapshot()
            DispatchQueue.main.async {
                self.isRefreshingScanProgress = false
                self.scanProgressStatus = status
            }
        }
    }

    func refresh() {
        guard !isRefreshing else { return }
        isRefreshing = true
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self else { return }
            let snapshot = self.loadDashboardSnapshot()
            DispatchQueue.main.async {
                self.isRefreshing = false
                self.apply(snapshot)
                self.refreshProtectionLayers()
                self.lastRefresh = Date()
            }
        }
    }

    nonisolated private func loadDashboardSnapshot() -> DashboardSnapshot {
        let keys: [URLResourceKey] = [.contentModificationDateKey, .isRegularFileKey]
        let urls = (try? FileManager.default.contentsOfDirectory(
            at: logDirectory,
            includingPropertiesForKeys: keys,
            options: [.skipsHiddenFiles]
        )) ?? []

        var occurrences: [ThreatOccurrence] = []
        var records: [ScanRecord] = []
        var newestKnownViruses: Int?
        var newestKnownVirusesDate = Date.distantPast
        var newestEngineVersion: String?

        for url in urls where isScanLog(url) {
            guard let contents = try? String(contentsOf: url, encoding: .utf8) else { continue }
            let values = try? url.resourceValues(forKeys: Set(keys))
            let modified = values?.contentModificationDate ?? Date.distantPast
            let scanDate = parseDate(in: contents) ?? modified
            let scannedFiles = parseInteger(label: "Scanned files:", in: contents) ?? 0
            let infectedFiles = parseInteger(label: "Infected files:", in: contents) ?? 0
            let warningCount = contents.components(separatedBy: "WARNING:").count - 1

            if let known = parseInteger(label: "Known viruses:", in: contents), modified > newestKnownVirusesDate {
                newestKnownViruses = known
                newestKnownVirusesDate = modified
                newestEngineVersion = parseString(label: "Engine version:", in: contents)
            }

            records.append(ScanRecord(
                name: url.lastPathComponent,
                date: scanDate,
                scannedFiles: scannedFiles,
                infectedFiles: infectedFiles,
                warningCount: warningCount,
                logURL: url
            ))

            for line in contents.split(separator: "\n") {
                let text = String(line)
                guard text.hasSuffix(" FOUND"), let separator = text.range(of: ": ", options: .backwards) else { continue }
                let path = String(text[..<separator.lowerBound])
                let signatureStart = separator.upperBound
                let signatureEnd = text.index(text.endIndex, offsetBy: -" FOUND".count)
                let signature = String(text[signatureStart..<signatureEnd])
                occurrences.append(ThreatOccurrence(
                    path: path,
                    signature: signature,
                    date: scanDate,
                    logURL: url
                ))
            }
        }

        let loadedThreats = Dictionary(grouping: occurrences, by: { $0.path + "\u{0}" + $0.signature })
            .compactMap { _, items -> ThreatSummary? in
                guard let latest = items.max(by: { $0.date < $1.date }) else { return nil }
                return ThreatSummary(
                    path: latest.path,
                    signature: latest.signature,
                    lastSeen: latest.date,
                    detectionCount: items.count,
                    logURL: latest.logURL,
                    exists: FileManager.default.fileExists(atPath: latest.path)
                )
            }
            .sorted { $0.lastSeen > $1.lastSeen }

        let quarantine = loadQuarantineSnapshot()
        let realtime = loadRealtimeProtectionSnapshot()
        let scanProgress = loadScanProgressSnapshot()
        let virusTotal = loadVirusTotalSnapshot()
        return DashboardSnapshot(
            threats: loadedThreats,
            scans: records.sorted { $0.date > $1.date },
            newestKnownViruses: newestKnownViruses,
            newestEngineVersion: newestEngineVersion,
            quarantineItems: quarantine,
            realtimeStatus: realtime.status,
            realtimeEvents: realtime.events,
            scanProgressStatus: scanProgress,
            virusTotalStatus: virusTotal.status,
            virusTotalResults: virusTotal.results
        )
    }

    private func apply(_ snapshot: DashboardSnapshot) {
        threats = snapshot.threats
        scans = snapshot.scans
        signatureCount = snapshot.newestKnownViruses.map { $0.formatted() } ?? "—"
        engineVersion = snapshot.newestEngineVersion ?? "Bilinmiyor"
        quarantineItems = snapshot.quarantineItems
        realtimeStatus = snapshot.realtimeStatus
        realtimeEvents = snapshot.realtimeEvents
        scanProgressStatus = snapshot.scanProgressStatus
        virusTotalStatus = snapshot.virusTotalStatus
        virusTotalResults = snapshot.virusTotalResults
    }

    func restartRealtimeProtection() {
        restartOwnedService(label: "com.local.clamav.realtime", displayName: "Live protection")
    }

    func restartClamAVDaemon() {
        restartOwnedService(label: "com.local.clamav.daemon", displayName: "ClamAV tarama motoru")
    }

    func restartVirusTotalService() {
        restartOwnedService(label: "com.local.clamav.virustotal", displayName: "VirusTotal protection")
    }

    func ownedServiceMessage(for label: String) -> String? {
        ownedServiceMessages[label]
    }

    private func restartOwnedService(label: String, displayName: String) {
        let allowedLabels = Set([
            "com.local.clamav.daemon",
            "com.local.clamav.realtime",
            "com.local.clamav.virustotal"
        ])
        guard allowedLabels.contains(label), !isOwnedServiceRestarting(label) else { return }

        let process = Process()
        let output = Pipe()
        let readHandle = output.fileHandleForReading
        let writeHandle = output.fileHandleForWriting
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["kickstart", "-k", "gui/\(getuid())/\(label)"]
        process.standardOutput = output
        process.standardError = output

        setOwnedServiceRestarting(label, true)
        let startingMessage = "\(displayName) yeniden başlatılıyor…"
        ownedServiceMessages[label] = startingMessage
        if label == "com.local.clamav.realtime" { protectionCommandResult = startingMessage }

        do {
            try process.run()
            try? writeHandle.close()
        } catch {
            setOwnedServiceRestarting(label, false)
            let message = "\(displayName) yeniden başlatılamadı. Otomasyonu yeniden kurmayı dene."
            ownedServiceMessages[label] = message
            if label == "com.local.clamav.realtime" { protectionCommandResult = message }
            return
        }

        process.terminationHandler = { [weak self] finished in
            let data = readHandle.readDataToEndOfFile()
            try? readHandle.close()
            _ = data
            Task { @MainActor in
                guard let self else { return }
                self.setOwnedServiceRestarting(label, false)
                let message = finished.terminationStatus == 0
                    ? "\(displayName) yeniden başlatıldı. Durum birkaç saniye içinde güncellenecek."
                    : "\(displayName) yeniden başlatılamadı. Otomasyonu yeniden kurmayı dene."
                self.ownedServiceMessages[label] = message
                if label == "com.local.clamav.realtime" { self.protectionCommandResult = message }
                self.refresh()
            }
        }
    }

    private func isOwnedServiceRestarting(_ label: String) -> Bool {
        switch label {
        case "com.local.clamav.daemon": return isRestartingClamAVDaemon
        case "com.local.clamav.realtime": return isRestartingProtection
        case "com.local.clamav.virustotal": return isRestartingVirusTotal
        default: return false
        }
    }

    private func setOwnedServiceRestarting(_ label: String, _ value: Bool) {
        switch label {
        case "com.local.clamav.daemon": isRestartingClamAVDaemon = value
        case "com.local.clamav.realtime": isRestartingProtection = value
        case "com.local.clamav.virustotal": isRestartingVirusTotal = value
        default: break
        }
    }

    func refreshProtectionLayers() {
        guard !isCheckingProtectionLayers else { return }
        isCheckingProtectionLayers = true

        Task.detached(priority: .utility) {
            let results = Self.inspectProtectionLayers()
            let daemonResponding = Self.inspectClamAVDaemon()
            await MainActor.run { [weak self] in
                guard let self else { return }
                self.protectionLayers = results
                self.clamAVDaemonResponding = daemonResponding
                self.isCheckingProtectionLayers = false
            }
        }
    }

    func runQuickScan() {
        runCommand(
            title: "Hızlı tarama",
            executable: scriptsDirectory.appendingPathComponent("scan-clamav.sh"),
            arguments: [],
            successMessage: "Hızlı tarama tamamlandı; tehdit bulunmadı."
        )
    }

    func chooseAndScan() {
        let panel = NSOpenPanel()
        panel.title = "ClamAV ile taranacak öğeleri seç"
        panel.prompt = "Start Scan"
        panel.canChooseFiles = true
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = true
        panel.resolvesAliases = true
        panel.begin { [weak self] response in
            guard response == .OK, let self else { return }
            self.runCommand(
                title: "Seçili öğe taraması",
                executable: self.scriptsDirectory.appendingPathComponent("scan-selection.sh"),
                arguments: panel.urls.map(\.path),
                successMessage: "Seçili öğeler tarandı; tehdit bulunmadı."
            )
        }
    }

    func runFullScan() {
        let home = FileManager.default.homeDirectoryForCurrentUser
        let names = ["Desktop", "Downloads", "Documents", "Movies", "Music", "Pictures"]
        let paths = names
            .map { home.appendingPathComponent($0, isDirectory: true) }
            .filter { FileManager.default.fileExists(atPath: $0.path) }
            .map(\.path)
        runCommand(
            title: "Kapsamlı tarama",
            executable: scriptsDirectory.appendingPathComponent("scan-selection.sh"),
            arguments: paths,
            successMessage: "Kapsamlı tarama tamamlandı; tehdit bulunmadı."
        )
    }

    func updateSignatures() {
        runCommand(
            title: "Virüs imzalarını güncelleme",
            executable: scriptsDirectory.appendingPathComponent("update-clamav.sh"),
            arguments: [],
            successMessage: "Virüs imzaları başarıyla güncellendi."
        )
    }

    func quarantine(_ threat: ThreatSummary) async -> String? {
        guard threat.exists else { return SecureQuarantineError.sourceMissing.localizedDescription }
        let originalURL = URL(fileURLWithPath: threat.path)
        let signature = threat.signature
        let automationDirectory = automationDirectory
        let quarantineDirectory = quarantineDirectory
        let message = await Task.detached(priority: .utility) {
            do {
                try Self.securelyQuarantine(
                    originalURL: originalURL,
                    signature: signature,
                    automationDirectory: automationDirectory,
                    quarantineDirectory: quarantineDirectory
                )
                return nil as String?
            } catch let error as SecureQuarantineError {
                return error.localizedDescription
            } catch {
                return "Karantina işlemi güvenli biçimde tamamlanamadı. Lütfen yeniden dene."
            }
        }.value
        refresh()
        return message
    }

    func restore(_ item: QuarantineItem) async -> String? {
        guard item.isActionable else {
            return item.isPreparing
                ? SecureQuarantineError.incompleteOperation.localizedDescription
                : "Karantinadaki dosya bulunamadı."
        }
        let metadataURL = item.metadataURL
        let expectedID = item.id
        let automationDirectory = automationDirectory
        let quarantineDirectory = quarantineDirectory
        let message = await Task.detached(priority: .utility) {
            do {
                try Self.securelyRestore(
                    metadataURL: metadataURL,
                    expectedID: expectedID,
                    automationDirectory: automationDirectory,
                    quarantineDirectory: quarantineDirectory
                )
                return nil as String?
            } catch {
                return "Geri yükleme başarısız: \(error.localizedDescription)"
            }
        }.value
        refresh()
        return message
    }

    func permanentlyDelete(_ item: QuarantineItem) async -> String? {
        guard item.isActionable else {
            return item.isPreparing
                ? SecureQuarantineError.incompleteOperation.localizedDescription
                : "Karantinadaki dosya bulunamadı."
        }
        let metadataURL = item.metadataURL
        let expectedID = item.id
        let automationDirectory = automationDirectory
        let quarantineDirectory = quarantineDirectory
        let message = await Task.detached(priority: .utility) {
            do {
                try Self.securelyDeleteQuarantineItem(
                    metadataURL: metadataURL,
                    expectedID: expectedID,
                    automationDirectory: automationDirectory,
                    quarantineDirectory: quarantineDirectory
                )
                return nil as String?
            } catch {
                return "Kalıcı silme başarısız: \(error.localizedDescription)"
            }
        }.value
        refresh()
        return message
    }

    private func runCommand(title: String, executable: URL, arguments: [String], successMessage: String) {
        guard !isAnyScanRunning else {
            commandResult = "Önce çalışan komutun tamamlanmasını bekle."
            return
        }
        guard FileManager.default.isExecutableFile(atPath: executable.path) else {
            commandResult = "Komut dosyası bulunamadı. Otomasyonu yeniden kur."
            return
        }

        let process = Process()
        let output = Pipe()
        let readHandle = output.fileHandleForReading
        let writeHandle = output.fileHandleForWriting
        process.executableURL = executable
        process.arguments = arguments
        process.standardOutput = output
        process.standardError = output

        isCommandRunning = true
        activeCommand = title
        commandResult = "\(title) başlatıldı…"

        do {
            try process.run()
            try? writeHandle.close()
        } catch {
            isCommandRunning = false
            commandResult = "Başlatılamadı: \(error.localizedDescription)"
            return
        }

        process.terminationHandler = { [weak self] finished in
            let status = finished.terminationStatus
            let data = readHandle.readDataToEndOfFile()
            try? readHandle.close()
            let outputText = String(data: data, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            Task { @MainActor in
                guard let self else { return }
                self.isCommandRunning = false
                self.activeCommand = ""
                switch status {
                case 0:
                    self.commandResult = successMessage
                case 1:
                    self.commandResult = "\(title) tamamlandı; tehdit bulundu. Tehditler bölümünü kontrol et."
                case 75:
                    self.commandResult = "Başka bir tarama zaten çalışıyor."
                default:
                    self.commandResult = outputText.isEmpty
                        ? "\(title) tamamlanamadı (kod \(status))."
                        : outputText
                }
                self.refresh()
            }
        }
    }

    private nonisolated static func securelyQuarantine(
        originalURL: URL,
        signature: String,
        automationDirectory: URL,
        quarantineDirectory: URL
    ) throws {
        let coordinationDirectory = automationDirectory
            .appendingPathComponent("coordination", isDirectory: true)
        let lockURL = coordinationDirectory.appendingPathComponent("quarantine.lock")

        try ensurePrivateDirectory(automationDirectory)
        try ensurePrivateDirectory(coordinationDirectory)
        let lockDescriptor = try openAndLockQuarantineFile(lockURL)
        defer {
            _ = threatCenterAdvisoryFlock(lockDescriptor, LOCK_UN)
            Darwin.close(lockDescriptor)
        }

        // Re-check only after obtaining the shared lock. The realtime and
        // VirusTotal services use this same lock before moving a source file.
        let sourceIdentity = try quarantineSourceIdentity(at: originalURL)
        try ensurePrivateDirectory(quarantineDirectory)
        let quarantineDevice = try directoryDevice(at: quarantineDirectory)
        let crossesVolumes = sourceIdentity.device != quarantineDevice
        let expectedDigest = try sha256Digest(at: originalURL)
        guard try quarantineSourceIdentity(at: originalURL) == sourceIdentity else {
            throw SecureQuarantineError.sourceChanged
        }

        let fileManager = FileManager.default
        let id = UUID()
        let storedName = id.uuidString + "-" + originalURL.lastPathComponent
        let storedURL = quarantineDirectory.appendingPathComponent(storedName)
        let metadataURL = quarantineDirectory.appendingPathComponent(id.uuidString + ".json")
        let temporaryMetadataURL = quarantineDirectory
            .appendingPathComponent(".\(id.uuidString).json.tmp")
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
            originalPath: originalURL.path,
            storedFileName: storedName,
            signature: signature,
            quarantinedAt: Date(),
            state: "preparing",
            sha256: digestString,
            fileSize: sourceIdentity.size,
            stagingPath: stagingURL?.path,
            temporaryStoredFileName: temporaryStoredFileName,
            restoreMode: nil,
            restoreTemporaryPath: nil,
            restoreTemporaryDevice: nil,
            restoreTemporaryInode: nil
        )
        let readyMetadata = QuarantineMetadata(
            id: id,
            originalPath: originalURL.path,
            storedFileName: storedName,
            signature: signature,
            quarantinedAt: preparingMetadata.quarantinedAt,
            state: "ready",
            sha256: digestString,
            fileSize: sourceIdentity.size,
            stagingPath: nil,
            temporaryStoredFileName: nil,
            restoreMode: nil,
            restoreTemporaryPath: nil,
            restoreTemporaryDevice: nil,
            restoreTemporaryInode: nil
        )

        let preparingMetadataData: Data
        let readyMetadataData: Data
        do {
            preparingMetadataData = try JSONEncoder().encode(preparingMetadata)
            readyMetadataData = try JSONEncoder().encode(readyMetadata)
            try writePrivateTemporaryFile(preparingMetadataData, to: temporaryMetadataURL)
            try finalizePreparedMetadata(
                temporaryMetadataURL,
                at: metadataURL,
                expectedData: preparingMetadataData
            )
        } catch {
            try? fileManager.removeItem(at: temporaryMetadataURL)
            throw SecureQuarantineError.metadataPreparationFailed
        }
        defer { try? fileManager.removeItem(at: temporaryMetadataURL) }

        var payloadValidated = false
        do {
            guard try quarantineSourceIdentity(at: originalURL) == sourceIdentity else {
                throw SecureQuarantineError.sourceChanged
            }
            if crossesVolumes {
                guard let stagingURL, let temporaryStoredURL else {
                    throw SecureQuarantineError.unsafeStorage
                }
                try transferCrossVolumePayload(
                    originalURL: originalURL,
                    stagingURL: stagingURL,
                    temporaryStoredURL: temporaryStoredURL,
                    storedURL: storedURL,
                    expectedIdentity: sourceIdentity,
                    expectedDigest: expectedDigest
                )
            } else {
                try renameExclusively(from: originalURL, to: storedURL)
                let storedIdentity = try quarantineSourceIdentity(at: storedURL)
                guard storedIdentity.device == sourceIdentity.device,
                      storedIdentity.inode == sourceIdentity.inode,
                      storedIdentity.generation == sourceIdentity.generation,
                      storedIdentity.size == sourceIdentity.size,
                      storedIdentity.modificationSeconds == sourceIdentity.modificationSeconds,
                      storedIdentity.modificationNanoseconds == sourceIdentity.modificationNanoseconds,
                      try sha256Digest(at: storedURL) == expectedDigest else {
                    throw SecureQuarantineError.sourceChanged
                }
            }
            payloadValidated = true
            try secureRegularFile(at: storedURL, requireSingleLink: false)
            try publishMetadataAtomically(readyMetadataData, at: metadataURL)
        } catch let operationError {
            if crossesVolumes {
                if let stagingURL {
                    _ = recoverStagedPayload(stagingURL: stagingURL, originalURL: originalURL)
                }
                if let temporaryStoredURL, pathEntryExists(at: temporaryStoredURL) {
                    try? fileManager.removeItem(at: temporaryStoredURL)
                }
            }

            if payloadValidated, pathEntryExists(at: storedURL) {
                let recovered = recoverQuarantinePayload(
                    originalURL: originalURL,
                    storedURL: storedURL
                )
                if recovered {
                    removeMetadataIfMatching(readyMetadataData, at: metadataURL)
                    removeMetadataIfMatching(preparingMetadataData, at: metadataURL)
                    throw operationError
                }

                try? secureRegularFile(at: storedURL, requireSingleLink: false)
                do {
                    try publishMetadataAtomically(readyMetadataData, at: metadataURL)
                } catch {
                    try publishRecoveryMetadata(
                        readyMetadataData,
                        preparedURL: temporaryMetadataURL,
                        preferredURL: metadataURL,
                        quarantineDirectory: quarantineDirectory,
                        id: id
                    )
                    removeMetadataIfMatching(preparingMetadataData, at: metadataURL)
                }
                throw SecureQuarantineError.fileSecuredButNeedsAttention
            }

            if pathEntryExists(at: storedURL) {
                if crossesVolumes {
                    try? fileManager.removeItem(at: storedURL)
                } else if recoverQuarantinePayload(originalURL: originalURL, storedURL: storedURL) {
                    // Same-volume claim was restored without overwriting a new path.
                }
            }

            let hasRetainedArtifact = pathEntryExists(at: storedURL)
                || temporaryStoredURL.map { pathEntryExists(at: $0) } ?? false
                || stagingURL.map { pathEntryExists(at: $0) } ?? false
            if hasRetainedArtifact {
                try publishRecoveryMetadata(
                    preparingMetadataData,
                    preparedURL: temporaryMetadataURL,
                    preferredURL: metadataURL,
                    quarantineDirectory: quarantineDirectory,
                    id: id
                )
                throw SecureQuarantineError.incompleteOperation
            }

            removeMetadataIfMatching(preparingMetadataData, at: metadataURL)
            throw operationError
        }
    }

    private nonisolated static func renameExclusively(
        from sourceURL: URL,
        to destinationURL: URL
    ) throws {
        let result = sourceURL.path.withCString { sourcePath in
            destinationURL.path.withCString { destinationPath in
                Darwin.renamex_np(sourcePath, destinationPath, UInt32(RENAME_EXCL))
            }
        }
        guard result == 0 else { throw QuarantineFilesystemError(code: errno) }
    }

    private nonisolated static func pathEntryExists(at url: URL) -> Bool {
        var info = stat()
        return url.path.withCString { Darwin.lstat($0, &info) } == 0
    }

    private nonisolated static func isPrivateStagingContainer(
        _ directoryURL: URL,
        for originalURL: URL
    ) -> Bool {
        let name = directoryURL.lastPathComponent
        return directoryURL.deletingLastPathComponent().standardizedFileURL
            == originalURL.deletingLastPathComponent().standardizedFileURL
            && name.hasPrefix(".clamav-quarantine-")
            && name.hasSuffix(".stage-dir")
    }

    private nonisolated static func validatedPrivateStagingContainer(
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
            return info.st_nlink == 1 || info.st_nlink == 2 || info.st_nlink == 3
        }
        return info.st_nlink == 1 || info.st_nlink == 2
    }

    private nonisolated static func cleanupPrivateStagingContainer(
        for stagingURL: URL,
        originalURL: URL
    ) {
        let containerURL = stagingURL.deletingLastPathComponent()
        guard stagingURL.lastPathComponent == "payload",
              validatedPrivateStagingContainer(
                  containerURL,
                  for: originalURL,
                  containsPayload: false
              ),
              !pathEntryExists(at: stagingURL) else { return }
        _ = containerURL.path.withCString { Darwin.rmdir($0) }
    }

    private nonisolated static func claimSource(
        originalURL: URL,
        stagingURL: URL
    ) throws {
        let originalParent = originalURL.deletingLastPathComponent().standardizedFileURL
        let stagingParent = stagingURL.deletingLastPathComponent().standardizedFileURL
        if originalParent == stagingParent {
            try renameExclusively(from: originalURL, to: stagingURL)
            return
        }

        guard stagingURL.lastPathComponent == "payload",
              isPrivateStagingContainer(stagingParent, for: originalURL),
              stagingParent.path.withCString({ Darwin.mkdir($0, mode_t(S_IRWXU)) }) == 0 else {
            throw QuarantineFilesystemError(code: errno)
        }
        guard stagingParent.path.withCString({ Darwin.chmod($0, mode_t(S_IRWXU)) }) == 0,
              validatedPrivateStagingContainer(
                  stagingParent,
                  for: originalURL,
                  containsPayload: false
              ),
              !pathEntryExists(at: stagingURL) else {
            cleanupPrivateStagingContainer(for: stagingURL, originalURL: originalURL)
            throw SecureQuarantineError.unsafeStorage
        }
        let result = originalURL.path.withCString { sourcePath in
            stagingURL.path.withCString { destinationPath in
                Darwin.rename(sourcePath, destinationPath)
            }
        }
        guard result == 0 else {
            let errorCode = errno
            cleanupPrivateStagingContainer(for: stagingURL, originalURL: originalURL)
            throw QuarantineFilesystemError(code: errorCode)
        }
        guard validatedPrivateStagingContainer(
            stagingParent,
            for: originalURL,
            containsPayload: true
        ) else {
            throw SecureQuarantineError.incompleteOperation
        }
    }

    private nonisolated static func sameVolumeIdentityMatches(
        _ identity: QuarantineSourceIdentity,
        expected: QuarantineSourceIdentity
    ) -> Bool {
        identity.device == expected.device
            && identity.inode == expected.inode
            && identity.generation == expected.generation
            && identity.size == expected.size
            && identity.modificationSeconds == expected.modificationSeconds
            && identity.modificationNanoseconds == expected.modificationNanoseconds
    }

    private nonisolated static func ownedSingleLinkIdentity(
        at url: URL
    ) -> QuarantineSourceIdentity? {
        var info = stat()
        guard url.path.withCString({ Darwin.lstat($0, &info) }) == 0,
              info.st_mode & S_IFMT == S_IFREG,
              info.st_uid == getuid(),
              info.st_nlink == 1 else { return nil }
        return quarantineSourceIdentity(from: info)
    }

    private nonisolated static func recoverStagedPayload(
        stagingURL: URL,
        originalURL: URL
    ) -> QuarantineStagingRecovery {
        guard pathEntryExists(at: stagingURL) else { return .missing }
        do {
            try renameExclusively(from: stagingURL, to: originalURL)
            cleanupPrivateStagingContainer(for: stagingURL, originalURL: originalURL)
            return .restored
        } catch {
            return pathEntryExists(at: stagingURL) ? .preserved : .missing
        }
    }

    private nonisolated static func transferCrossVolumePayload(
        originalURL: URL,
        stagingURL: URL,
        temporaryStoredURL: URL,
        storedURL: URL,
        expectedIdentity: QuarantineSourceIdentity,
        expectedDigest: [UInt8],
        beforeStagingDeletion: ((URL) throws -> Void)? = nil
    ) throws {
        do {
            try claimSource(originalURL: originalURL, stagingURL: stagingURL)
        } catch let error as QuarantineFilesystemError where error.code == ENOENT {
            throw SecureQuarantineError.sourceMissing
        } catch {
            guard let currentIdentity = try? quarantineSourceIdentity(at: originalURL),
                  currentIdentity == expectedIdentity else {
                throw SecureQuarantineError.sourceChanged
            }
            throw error
        }

        func recoverThenThrow(_ error: Error) throws -> Never {
            switch recoverStagedPayload(stagingURL: stagingURL, originalURL: originalURL) {
            case .restored, .missing:
                throw error
            case .preserved:
                throw SecureQuarantineError.incompleteOperation
            }
        }

        do {
            guard let claimedIdentity = ownedSingleLinkIdentity(at: stagingURL),
                  sameVolumeIdentityMatches(claimedIdentity, expected: expectedIdentity),
                  try sha256Digest(at: stagingURL) == expectedDigest else {
                try recoverThenThrow(SecureQuarantineError.sourceChanged)
            }

            try FileManager.default.copyItem(at: stagingURL, to: temporaryStoredURL)
            guard let temporaryIdentity = try? quarantineSourceIdentity(at: temporaryStoredURL),
                  temporaryIdentity.size == expectedIdentity.size,
                  try sha256Digest(at: temporaryStoredURL) == expectedDigest else {
                try recoverThenThrow(SecureQuarantineError.sourceChanged)
            }
            try renameExclusively(from: temporaryStoredURL, to: storedURL)

            try beforeStagingDeletion?(stagingURL)

            guard let finalStagingIdentity = ownedSingleLinkIdentity(at: stagingURL),
                  sameVolumeIdentityMatches(finalStagingIdentity, expected: expectedIdentity),
                  try sha256Digest(at: stagingURL) == expectedDigest else {
                try recoverThenThrow(SecureQuarantineError.sourceChanged)
            }
            do {
                try FileManager.default.removeItem(at: stagingURL)
                cleanupPrivateStagingContainer(for: stagingURL, originalURL: originalURL)
            } catch {
                guard !pathEntryExists(at: stagingURL) else {
                    try recoverThenThrow(error)
                }
            }
        } catch {
            if pathEntryExists(at: stagingURL) {
                try recoverThenThrow(error)
            }
            throw error
        }
    }

    private nonisolated static func publishMetadataAtomically(_ data: Data, at url: URL) throws {
        do {
            try data.write(to: url, options: .atomic)
            try secureRegularFile(at: url, requireSingleLink: true)
            guard (try? Data(contentsOf: url)) == data else {
                throw SecureQuarantineError.metadataPreparationFailed
            }
        } catch let error as SecureQuarantineError {
            throw error
        } catch {
            throw SecureQuarantineError.metadataPreparationFailed
        }
    }

    private nonisolated static func quarantineChildURL(
        named name: String,
        in quarantineDirectory: URL
    ) throws -> URL {
        guard !name.isEmpty,
              name != ".",
              name != "..",
              !name.contains("/") else {
            throw SecureQuarantineError.unsafeStorage
        }
        let candidate = quarantineDirectory.appendingPathComponent(name)
        guard candidate.deletingLastPathComponent().standardizedFileURL
            == quarantineDirectory.standardizedFileURL else {
            throw SecureQuarantineError.unsafeStorage
        }
        return candidate
    }

    private nonisolated static func loadAndValidateReadyMetadata(
        metadataURL: URL,
        expectedID: UUID,
        quarantineDirectory: URL
    ) throws -> (
        metadata: QuarantineMetadata,
        storedURL: URL,
        identity: QuarantineSourceIdentity,
        digest: [UInt8]
    ) {
        let firstData = try Data(contentsOf: metadataURL)
        try secureRegularFile(at: metadataURL, requireSingleLink: true)
        guard (try? Data(contentsOf: metadataURL)) == firstData,
              var metadata = try? JSONDecoder().decode(QuarantineMetadata.self, from: firstData),
              metadata.id == expectedID,
              metadata.effectiveState == "ready" else {
            throw SecureQuarantineError.incompleteOperation
        }

        let storedURL = try quarantineChildURL(
            named: metadata.storedFileName,
            in: quarantineDirectory
        )
        try secureRegularFile(at: storedURL, requireSingleLink: true)
        let identity = try quarantineSourceIdentity(at: storedURL)
        let digest = try sha256Digest(at: storedURL)
        let digestString = hexadecimalDigest(digest)

        if let expectedSize = metadata.fileSize,
           let expectedHash = metadata.sha256?.lowercased() {
            guard expectedSize == identity.size,
                  expectedHash.count == 64,
                  expectedHash.allSatisfy({ $0.isHexDigit }),
                  expectedHash == digestString else {
                throw SecureQuarantineError.sourceChanged
            }
        } else {
            // Legacy records without integrity fields are upgraded under the
            // shared lock before any restore/delete action becomes possible.
            metadata = QuarantineMetadata(
                id: metadata.id,
                originalPath: metadata.originalPath,
                storedFileName: metadata.storedFileName,
                signature: metadata.signature,
                quarantinedAt: metadata.quarantinedAt,
                state: "ready",
                sha256: digestString,
                fileSize: identity.size,
                stagingPath: nil,
                temporaryStoredFileName: nil,
                restoreMode: nil,
                restoreTemporaryPath: nil,
                restoreTemporaryDevice: nil,
                restoreTemporaryInode: nil
            )
            try publishMetadataAtomically(try JSONEncoder().encode(metadata), at: metadataURL)
        }
        guard try quarantineSourceIdentity(at: storedURL) == identity else {
            throw SecureQuarantineError.sourceChanged
        }
        return (metadata, storedURL, identity, digest)
    }

    private nonisolated static func nextRestoreDestination(for originalURL: URL) -> URL {
        guard pathEntryExists(at: originalURL) else { return originalURL }
        let parent = originalURL.deletingLastPathComponent()
        let baseName = originalURL.deletingPathExtension().lastPathComponent
        let pathExtension = originalURL.pathExtension
        for _ in 0..<16 {
            var candidate = parent.appendingPathComponent(
                "\(baseName)-geri-yuklendi-\(UUID().uuidString)"
            )
            if !pathExtension.isEmpty {
                candidate.appendPathExtension(pathExtension)
            }
            if !pathEntryExists(at: candidate) { return candidate }
        }
        return parent.appendingPathComponent("ClamAV-Geri-Yuklendi-\(UUID().uuidString).bin")
    }

    private nonisolated static func createPrivateRestoreTemporary(
        at url: URL,
        expectedSize: Int64 = 0
    ) throws -> (descriptor: Int32, device: UInt64, inode: UInt64) {
        guard expectedSize >= 0 else { throw SecureQuarantineError.unsafeStorage }
        let descriptor = url.path.withCString {
            Darwin.open(
                $0,
                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                mode_t(S_IRUSR | S_IWUSR)
            )
        }
        guard descriptor >= 0 else { throw SecureQuarantineError.unsafeStorage }

        var info = stat()
        guard Darwin.fstat(descriptor, &info) == 0,
              info.st_mode & S_IFMT == S_IFREG,
              info.st_uid == getuid(),
              info.st_nlink == 1,
              Darwin.fchmod(descriptor, mode_t(S_IRUSR | S_IWUSR)) == 0,
              Darwin.ftruncate(descriptor, off_t(expectedSize)) == 0,
              Darwin.lseek(descriptor, 0, SEEK_SET) == 0,
              Darwin.fstat(descriptor, &info) == 0 else {
            Darwin.close(descriptor)
            throw SecureQuarantineError.unsafeStorage
        }
        var pathInfo = stat()
        guard url.path.withCString({ Darwin.lstat($0, &pathInfo) }) == 0,
              pathInfo.st_mode & S_IFMT == S_IFREG,
              pathInfo.st_uid == getuid(),
              pathInfo.st_nlink == 1,
              info.st_dev == pathInfo.st_dev,
              info.st_ino == pathInfo.st_ino,
              Int64(info.st_size) == expectedSize,
              Int64(pathInfo.st_size) == expectedSize else {
            Darwin.close(descriptor)
            throw SecureQuarantineError.unsafeStorage
        }
        return (descriptor, UInt64(info.st_dev), UInt64(info.st_ino))
    }

    private nonisolated static func supportsExclusiveRename(in directoryURL: URL) throws -> Bool {
        let probeID = UUID().uuidString
        let sourceURL = directoryURL.appendingPathComponent(".clamav-rename-probe-\(probeID).src")
        let destinationURL = directoryURL.appendingPathComponent(".clamav-rename-probe-\(probeID).dst")
        let opened = try createPrivateRestoreTemporary(at: sourceURL)
        Darwin.close(opened.descriptor)
        defer {
            try? FileManager.default.removeItem(at: sourceURL)
            try? FileManager.default.removeItem(at: destinationURL)
        }
        do {
            try renameExclusively(from: sourceURL, to: destinationURL)
            return true
        } catch let error as QuarantineFilesystemError
            where error.code == ENOTSUP || error.code == EINVAL || error.code == ENOTTY {
            return false
        }
    }

    private nonisolated static func copyValidatedPayload(
        from sourceURL: URL,
        expectedIdentity: QuarantineSourceIdentity,
        expectedDigest: [UInt8],
        to destinationDescriptor: Int32
    ) throws -> QuarantineSourceIdentity {
        let sourceDescriptor = sourceURL.path.withCString {
            Darwin.open($0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        }
        guard sourceDescriptor >= 0 else { throw SecureQuarantineError.sourceChanged }
        defer { Darwin.close(sourceDescriptor) }

        var sourceBefore = stat()
        guard Darwin.fstat(sourceDescriptor, &sourceBefore) == 0,
              quarantineSourceIdentity(from: sourceBefore) == expectedIdentity else {
            throw SecureQuarantineError.sourceChanged
        }

        var hasher = SHA256()
        var buffer = [UInt8](repeating: 0, count: 1_048_576)
        while true {
            let readCount = buffer.withUnsafeMutableBytes { bytes -> Int in
                guard let baseAddress = bytes.baseAddress else { return 0 }
                return Darwin.read(sourceDescriptor, baseAddress, bytes.count)
            }
            if readCount < 0 {
                if errno == EINTR { continue }
                throw SecureQuarantineError.sourceChanged
            }
            if readCount == 0 { break }
            hasher.update(data: Data(buffer[0..<readCount]))
            var written = 0
            while written < readCount {
                let writeCount = buffer.withUnsafeBytes { bytes -> Int in
                    guard let baseAddress = bytes.baseAddress else { return -1 }
                    return Darwin.write(
                        destinationDescriptor,
                        baseAddress.advanced(by: written),
                        readCount - written
                    )
                }
                if writeCount < 0 {
                    if errno == EINTR { continue }
                    throw SecureQuarantineError.unsafeStorage
                }
                guard writeCount > 0 else { throw SecureQuarantineError.unsafeStorage }
                written += writeCount
            }
        }
        guard Array(hasher.finalize()) == expectedDigest,
              Darwin.fsync(destinationDescriptor) == 0 else {
            throw SecureQuarantineError.sourceChanged
        }

        var sourceAfter = stat()
        var destinationAfter = stat()
        guard Darwin.fstat(sourceDescriptor, &sourceAfter) == 0,
              Darwin.fstat(destinationDescriptor, &destinationAfter) == 0,
              quarantineSourceIdentity(from: sourceAfter) == expectedIdentity,
              try quarantineSourceIdentity(at: sourceURL) == expectedIdentity,
              destinationAfter.st_mode & S_IFMT == S_IFREG,
              destinationAfter.st_uid == getuid(),
              destinationAfter.st_nlink == 1,
              Int64(destinationAfter.st_size) == expectedIdentity.size else {
            throw SecureQuarantineError.sourceChanged
        }
        return quarantineSourceIdentity(from: destinationAfter)
    }

    private nonisolated static func safeRestoreTemporaryURL(
        from metadata: QuarantineMetadata
    ) -> URL? {
        guard let path = metadata.restoreTemporaryPath else { return nil }
        let candidate = URL(fileURLWithPath: path).standardizedFileURL
        let destinationParent = URL(fileURLWithPath: metadata.originalPath)
            .deletingLastPathComponent().standardizedFileURL
        let name = candidate.lastPathComponent
        let hiddenTemporary = candidate.deletingLastPathComponent() == destinationParent
            && name.hasPrefix(".clamav-restore-")
            && name.hasSuffix(".tmp")
        let directExclusiveTarget = candidate
            == URL(fileURLWithPath: metadata.originalPath).standardizedFileURL
        switch metadata.restoreMode {
        case "directExclusive":
            guard directExclusiveTarget else { return nil }
        case "sameVolumeRename":
            guard directExclusiveTarget else { return nil }
        case "hiddenTemporary":
            guard hiddenTemporary else { return nil }
        case nil:
            // Legacy records only ever used canonical hidden temporaries. A
            // direct path without an explicit mode must never be treated as a
            // disposable temporary file.
            guard hiddenTemporary else { return nil }
        default:
            return nil
        }
        return candidate
    }

    private nonisolated static func recordedRestoreIdentityMatches(
        _ url: URL,
        metadata: QuarantineMetadata
    ) -> Bool {
        var info = stat()
        guard let expectedDevice = metadata.restoreTemporaryDevice,
              let expectedInode = metadata.restoreTemporaryInode,
              url.path.withCString({ Darwin.lstat($0, &info) }) == 0,
              info.st_mode & S_IFMT == S_IFREG,
              info.st_uid == getuid(),
              info.st_nlink == 1 else { return false }
        return UInt64(info.st_dev) == expectedDevice && UInt64(info.st_ino) == expectedInode
    }

    private nonisolated static func removeOwnedRestoreTemporary(
        _ url: URL,
        metadata: QuarantineMetadata
    ) -> Bool {
        guard let expectedDevice = metadata.restoreTemporaryDevice,
              let expectedInode = metadata.restoreTemporaryInode,
              recordedRestoreIdentityMatches(url, metadata: metadata) else { return false }
        let cleanupURL = url.deletingLastPathComponent().appendingPathComponent(
            ".clamav-restore-cleanup-\(UUID().uuidString).tmp"
        )
        do {
            try renameExclusively(from: url, to: cleanupURL)
            let claimed = try quarantineSourceIdentity(at: cleanupURL)
            guard claimed.device == expectedDevice,
                  claimed.inode == expectedInode else {
                _ = try? renameExclusively(from: cleanupURL, to: url)
                return false
            }
            try FileManager.default.removeItem(at: cleanupURL)
            return !pathEntryExists(at: cleanupURL)
        } catch {
            guard let filesystemError = error as? QuarantineFilesystemError,
                  filesystemError.code == ENOTSUP
                    || filesystemError.code == EINVAL
                    || filesystemError.code == ENOTTY else { return false }
        }

        // exFAT does not provide a no-clobber rename primitive. A path-based
        // fallback could move or delete a replacement created after the inode
        // check. Preserve the tracked output and restorePreparing metadata;
        // the dashboard keeps the transaction disabled instead of risking a
        // user file.
        return false
    }

    private nonisolated static func readyMetadata(
        from metadata: QuarantineMetadata,
        hash: String,
        size: Int64
    ) -> QuarantineMetadata {
        QuarantineMetadata(
            id: metadata.id,
            originalPath: metadata.originalPath,
            storedFileName: metadata.storedFileName,
            signature: metadata.signature,
            quarantinedAt: metadata.quarantinedAt,
            state: "ready",
            sha256: hash,
            fileSize: size,
            stagingPath: nil,
            temporaryStoredFileName: nil,
            restoreMode: nil,
            restoreTemporaryPath: nil,
            restoreTemporaryDevice: nil,
            restoreTemporaryInode: nil
        )
    }

    @discardableResult
    private nonisolated static func recoverRestoreTransactionsLocked(
        quarantineDirectory: URL
    ) -> Set<UUID> {
        let fileManager = FileManager.default
        let decoder = JSONDecoder()
        let records = ((try? fileManager.contentsOfDirectory(
            at: quarantineDirectory,
            includingPropertiesForKeys: nil,
            options: [.skipsHiddenFiles]
        )) ?? [])
        .filter { $0.pathExtension == "json" }
        .sorted { $0.path < $1.path }
        .compactMap { url -> (URL, QuarantineMetadata)? in
            guard let data = try? Data(contentsOf: url),
                  let metadata = try? decoder.decode(QuarantineMetadata.self, from: data),
                  metadata.state == "restorePreparing" else { return nil }
            return (url, metadata)
        }
        .sorted {
            if $0.1.quarantinedAt != $1.1.quarantinedAt {
                return $0.1.quarantinedAt < $1.1.quarantinedAt
            }
            return $0.0.path < $1.0.path
        }
        .prefix(64)

        var remainingBytes: Int64 = 512 * 1_024 * 1_024
        var finalizedIDs = Set<UUID>()
        var validationCache: [String: (QuarantineSourceIdentity, String)] = [:]
        func payloadMatches(_ url: URL, size: Int64, hash: String) -> Bool {
            guard size >= 0,
                  let identity = try? quarantineSourceIdentity(at: url),
                  identity.size == size else { return false }
            if let cached = validationCache[url.path], cached.0 == identity {
                return cached.1 == hash
            }
            guard remainingBytes >= size else { return false }
            remainingBytes -= size
            guard let digest = try? hexadecimalDigest(sha256Digest(at: url)),
                  (try? quarantineSourceIdentity(at: url)) == identity else { return false }
            validationCache[url.path] = (identity, digest)
            return digest == hash
        }

        for (metadataURL, metadata) in records {
            guard remainingBytes > 0,
                  let hash = metadata.sha256?.lowercased(),
                  hash.count == 64,
                  let size = metadata.fileSize,
                  let storedURL = try? quarantineChildURL(
                      named: metadata.storedFileName,
                      in: quarantineDirectory
                  ) else { continue }
            let deletionStagingURL = metadata.temporaryStoredFileName.flatMap {
                try? quarantineChildURL(named: $0, in: quarantineDirectory)
            }
            let externalTemporaryURL = safeRestoreTemporaryURL(from: metadata)
            if metadata.restoreTemporaryPath != nil, externalTemporaryURL == nil { continue }
            var storedValid = payloadMatches(storedURL, size: size, hash: hash)
            var deletionValid = deletionStagingURL.map {
                payloadMatches($0, size: size, hash: hash)
            } ?? false

            let destinationURL = URL(fileURLWithPath: metadata.originalPath).standardizedFileURL
            let isDirectOutput = metadata.restoreMode == "directExclusive"
                || metadata.restoreMode == "sameVolumeRename"
            let publishedHiddenOutput = !isDirectOutput
                && !pathEntryExists(at: externalTemporaryURL ?? destinationURL)
                && recordedRestoreIdentityMatches(destinationURL, metadata: metadata)
            let finalOutputURL: URL? = isDirectOutput
                ? externalTemporaryURL
                : (publishedHiddenOutput ? destinationURL : nil)

            func outputIsValid(_ outputURL: URL) -> Bool {
                recordedRestoreIdentityMatches(outputURL, metadata: metadata)
                    && payloadMatches(outputURL, size: size, hash: hash)
            }

            func finalizeRestoredOutput(_ outputURL: URL) -> Bool {
                guard outputIsValid(outputURL) else { return false }
                if storedValid {
                    guard let deletionStagingURL,
                          !pathEntryExists(at: deletionStagingURL) else { return false }
                    do {
                        try renameExclusively(from: storedURL, to: deletionStagingURL)
                    } catch {
                        return false
                    }
                    storedValid = false
                    deletionValid = payloadMatches(deletionStagingURL, size: size, hash: hash)
                }
                if let deletionStagingURL, pathEntryExists(at: deletionStagingURL) {
                    guard deletionValid, outputIsValid(outputURL) else {
                        if !pathEntryExists(at: storedURL) {
                            _ = try? renameExclusively(from: deletionStagingURL, to: storedURL)
                        }
                        return false
                    }
                    do {
                        try fileManager.removeItem(at: deletionStagingURL)
                    } catch {
                        return false
                    }
                    guard !pathEntryExists(at: deletionStagingURL), outputIsValid(outputURL) else {
                        return false
                    }
                }
                guard !pathEntryExists(at: storedURL),
                      deletionStagingURL.map({ !pathEntryExists(at: $0) }) ?? true,
                      outputIsValid(outputURL) else { return false }
                do {
                    try fileManager.removeItem(at: metadataURL)
                    guard !pathEntryExists(at: metadataURL) else { return false }
                    finalizedIDs.insert(metadata.id)
                    return true
                } catch {
                    return false
                }
            }

            // A direct O_EXCL target or same-volume atomic rename is the
            // restored file, not a disposable temporary. If its exact recorded
            // inode and content are complete, finish without unlinking it.
            if let finalOutputURL, outputIsValid(finalOutputURL) {
                _ = finalizeRestoredOutput(finalOutputURL)
                continue
            }

            if isDirectOutput {
                guard let directURL = externalTemporaryURL else { continue }
                if pathEntryExists(at: directURL) {
                    // Only an exact partial inode may be claimed and removed.
                    // A replacement or any ambiguous state is preserved with
                    // restorePreparing metadata and disabled UI actions.
                    guard storedValid,
                          recordedRestoreIdentityMatches(directURL, metadata: metadata),
                          removeOwnedRestoreTemporary(directURL, metadata: metadata) else {
                        continue
                    }
                } else {
                    guard storedValid else { continue }
                }
                let ready = readyMetadata(from: metadata, hash: hash, size: size)
                try? publishMetadataAtomically(try JSONEncoder().encode(ready), at: metadataURL)
                continue
            }

            // Hidden temporaries are disposable only when their exact recorded
            // inode is still at the canonical hidden path.
            if let externalTemporaryURL, pathEntryExists(at: externalTemporaryURL) {
                guard removeOwnedRestoreTemporary(externalTemporaryURL, metadata: metadata) else {
                    continue
                }
            }

            if !storedValid, deletionValid, let deletionStagingURL {
                do {
                    try renameExclusively(from: deletionStagingURL, to: storedURL)
                    storedValid = payloadMatches(storedURL, size: size, hash: hash)
                } catch {
                    continue
                }
            }

            if storedValid {
                if deletionValid, let deletionStagingURL, pathEntryExists(at: deletionStagingURL) {
                    try? fileManager.removeItem(at: deletionStagingURL)
                    guard !pathEntryExists(at: deletionStagingURL) else { continue }
                }
                let ready = readyMetadata(from: metadata, hash: hash, size: size)
                try? publishMetadataAtomically(try JSONEncoder().encode(ready), at: metadataURL)
                continue
            }

            let noQuarantinePayload = !pathEntryExists(at: storedURL)
                && (deletionStagingURL.map { !pathEntryExists(at: $0) } ?? true)
            if noQuarantinePayload, outputIsValid(destinationURL) {
                try? fileManager.removeItem(at: metadataURL)
                if !pathEntryExists(at: metadataURL) { finalizedIDs.insert(metadata.id) }
            }
        }
        return finalizedIDs
    }

    private nonisolated static func securelyRestore(
        metadataURL: URL,
        expectedID: UUID,
        automationDirectory: URL,
        quarantineDirectory: URL,
        afterSameVolumeRename: ((URL) throws -> Void)? = nil,
        afterRestoreTemporaryCopy: ((URL) throws -> Void)? = nil,
        beforeQuarantineSourceDeletion: ((URL) throws -> Void)? = nil
    ) throws {
        let coordinationDirectory = automationDirectory
            .appendingPathComponent("coordination", isDirectory: true)
        try ensurePrivateDirectory(automationDirectory)
        try ensurePrivateDirectory(coordinationDirectory)
        try ensurePrivateDirectory(quarantineDirectory)
        let lockDescriptor = try openAndLockQuarantineFile(
            coordinationDirectory.appendingPathComponent("quarantine.lock")
        )
        defer {
            _ = threatCenterAdvisoryFlock(lockDescriptor, LOCK_UN)
            Darwin.close(lockDescriptor)
        }

        let recoveredRestores = recoverRestoreTransactionsLocked(
            quarantineDirectory: quarantineDirectory
        )
        if recoveredRestores.contains(expectedID), !pathEntryExists(at: metadataURL) {
            return
        }

        let validated = try loadAndValidateReadyMetadata(
            metadataURL: metadataURL,
            expectedID: expectedID,
            quarantineDirectory: quarantineDirectory
        )
        try verifyRestorePayload(at: validated.storedURL, automationDirectory: automationDirectory)
        let originalURL = URL(fileURLWithPath: validated.metadata.originalPath)
        let destinationURL = nextRestoreDestination(for: originalURL)
        let destinationDirectory = destinationURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(
            at: destinationDirectory,
            withIntermediateDirectories: true
        )
        let destinationDevice = try directoryDevice(at: destinationDirectory)
        let crossesVolumes = destinationDevice != validated.identity.device
        let deletionStagingName = ".\(validated.metadata.id.uuidString).restore-source.tmp"
        let digestString = hexadecimalDigest(validated.digest)

        if !crossesVolumes {
            let transactionMetadata = QuarantineMetadata(
                id: validated.metadata.id,
                originalPath: destinationURL.path,
                storedFileName: validated.metadata.storedFileName,
                signature: validated.metadata.signature,
                quarantinedAt: validated.metadata.quarantinedAt,
                state: "restorePreparing",
                sha256: digestString,
                fileSize: validated.identity.size,
                stagingPath: nil,
                temporaryStoredFileName: nil,
                restoreMode: "sameVolumeRename",
                restoreTemporaryPath: destinationURL.path,
                restoreTemporaryDevice: validated.identity.device,
                restoreTemporaryInode: validated.identity.inode
            )
            try publishMetadataAtomically(try JSONEncoder().encode(transactionMetadata), at: metadataURL)
            try renameExclusively(from: validated.storedURL, to: destinationURL)
            guard let restoredIdentity = try? quarantineSourceIdentity(at: destinationURL),
                  sameVolumeIdentityMatches(restoredIdentity, expected: validated.identity),
                  try sha256Digest(at: destinationURL) == validated.digest else {
                throw SecureQuarantineError.sourceChanged
            }
            try afterSameVolumeRename?(destinationURL)
            try FileManager.default.removeItem(at: metadataURL)
            return
        }

        let usesAtomicPublication = try supportsExclusiveRename(in: destinationDirectory)
        let restoreOutputURL = usesAtomicPublication
            ? destinationDirectory.appendingPathComponent(
                ".clamav-restore-\(UUID().uuidString).tmp"
            )
            : destinationURL
        let openedTemporary = try createPrivateRestoreTemporary(
            at: restoreOutputURL,
            expectedSize: validated.identity.size
        )
        var destinationDescriptor: Int32? = openedTemporary.descriptor
        defer {
            if let destinationDescriptor { Darwin.close(destinationDescriptor) }
        }
        let transactionMetadata = QuarantineMetadata(
            id: validated.metadata.id,
            originalPath: destinationURL.path,
            storedFileName: validated.metadata.storedFileName,
            signature: validated.metadata.signature,
            quarantinedAt: validated.metadata.quarantinedAt,
            state: "restorePreparing",
            sha256: digestString,
            fileSize: validated.identity.size,
            stagingPath: nil,
            temporaryStoredFileName: deletionStagingName,
            restoreMode: usesAtomicPublication ? "hiddenTemporary" : "directExclusive",
            restoreTemporaryPath: restoreOutputURL.path,
            restoreTemporaryDevice: openedTemporary.device,
            restoreTemporaryInode: openedTemporary.inode
        )
        do {
            try publishMetadataAtomically(try JSONEncoder().encode(transactionMetadata), at: metadataURL)
        } catch {
            Darwin.close(openedTemporary.descriptor)
            destinationDescriptor = nil
            _ = removeOwnedRestoreTemporary(restoreOutputURL, metadata: transactionMetadata)
            throw error
        }
        let copiedIdentity = try copyValidatedPayload(
            from: validated.storedURL,
            expectedIdentity: validated.identity,
            expectedDigest: validated.digest,
            to: openedTemporary.descriptor
        )
        Darwin.close(openedTemporary.descriptor)
        destinationDescriptor = nil
        try afterRestoreTemporaryCopy?(restoreOutputURL)
        guard let temporaryPathIdentity = try? quarantineSourceIdentity(at: restoreOutputURL),
              sameVolumeIdentityMatches(temporaryPathIdentity, expected: copiedIdentity),
              try sha256Digest(at: restoreOutputURL) == validated.digest else {
            throw SecureQuarantineError.sourceChanged
        }
        if usesAtomicPublication {
            try renameExclusively(from: restoreOutputURL, to: destinationURL)
        }
        guard let publishedDestinationIdentity = try? quarantineSourceIdentity(at: destinationURL),
              sameVolumeIdentityMatches(publishedDestinationIdentity, expected: copiedIdentity),
              try sha256Digest(at: destinationURL) == validated.digest else {
            throw SecureQuarantineError.sourceChanged
        }

        try beforeQuarantineSourceDeletion?(destinationURL)
        guard let finalDestinationIdentity = try? quarantineSourceIdentity(at: destinationURL),
              sameVolumeIdentityMatches(finalDestinationIdentity, expected: publishedDestinationIdentity),
              try sha256Digest(at: destinationURL) == validated.digest,
              try quarantineSourceIdentity(at: validated.storedURL) == validated.identity,
              try sha256Digest(at: validated.storedURL) == validated.digest else {
            throw SecureQuarantineError.sourceChanged
        }

        let deletionStagingURL = try quarantineChildURL(
            named: deletionStagingName,
            in: quarantineDirectory
        )
        try renameExclusively(from: validated.storedURL, to: deletionStagingURL)
        guard let deletionIdentity = try? quarantineSourceIdentity(at: deletionStagingURL),
              sameVolumeIdentityMatches(deletionIdentity, expected: validated.identity),
              try sha256Digest(at: deletionStagingURL) == validated.digest else {
            _ = try? renameExclusively(from: deletionStagingURL, to: validated.storedURL)
            throw SecureQuarantineError.sourceChanged
        }
        guard let deletionSafeDestinationIdentity = try? quarantineSourceIdentity(at: destinationURL),
              sameVolumeIdentityMatches(
                  deletionSafeDestinationIdentity,
                  expected: publishedDestinationIdentity
              ),
              try sha256Digest(at: destinationURL) == validated.digest else {
            _ = try? renameExclusively(from: deletionStagingURL, to: validated.storedURL)
            throw SecureQuarantineError.sourceChanged
        }
        try FileManager.default.removeItem(at: deletionStagingURL)
        try FileManager.default.removeItem(at: metadataURL)
    }

    private nonisolated static func securelyDeleteQuarantineItem(
        metadataURL: URL,
        expectedID: UUID,
        automationDirectory: URL,
        quarantineDirectory: URL
    ) throws {
        let coordinationDirectory = automationDirectory
            .appendingPathComponent("coordination", isDirectory: true)
        try ensurePrivateDirectory(automationDirectory)
        try ensurePrivateDirectory(coordinationDirectory)
        try ensurePrivateDirectory(quarantineDirectory)
        let lockDescriptor = try openAndLockQuarantineFile(
            coordinationDirectory.appendingPathComponent("quarantine.lock")
        )
        defer {
            _ = threatCenterAdvisoryFlock(lockDescriptor, LOCK_UN)
            Darwin.close(lockDescriptor)
        }

        recoverRestoreTransactionsLocked(quarantineDirectory: quarantineDirectory)
        let validated = try loadAndValidateReadyMetadata(
            metadataURL: metadataURL,
            expectedID: expectedID,
            quarantineDirectory: quarantineDirectory
        )
        let deletionStagingName = ".\(validated.metadata.id.uuidString).delete.tmp"
        let deletionStagingURL = try quarantineChildURL(
            named: deletionStagingName,
            in: quarantineDirectory
        )
        let transactionMetadata = QuarantineMetadata(
            id: validated.metadata.id,
            originalPath: validated.metadata.originalPath,
            storedFileName: validated.metadata.storedFileName,
            signature: validated.metadata.signature,
            quarantinedAt: validated.metadata.quarantinedAt,
            state: "preparing",
            sha256: hexadecimalDigest(validated.digest),
            fileSize: validated.identity.size,
            stagingPath: nil,
            temporaryStoredFileName: deletionStagingName,
            restoreMode: nil,
            restoreTemporaryPath: nil,
            restoreTemporaryDevice: nil,
            restoreTemporaryInode: nil
        )
        try publishMetadataAtomically(try JSONEncoder().encode(transactionMetadata), at: metadataURL)
        try renameExclusively(from: validated.storedURL, to: deletionStagingURL)
        guard let deletionIdentity = try? quarantineSourceIdentity(at: deletionStagingURL),
              sameVolumeIdentityMatches(deletionIdentity, expected: validated.identity),
              try sha256Digest(at: deletionStagingURL) == validated.digest else {
            _ = try? renameExclusively(from: deletionStagingURL, to: validated.storedURL)
            throw SecureQuarantineError.sourceChanged
        }
        try FileManager.default.removeItem(at: deletionStagingURL)
        try FileManager.default.removeItem(at: metadataURL)
    }

    private nonisolated static func ensurePrivateDirectory(_ url: URL) throws {
        do {
            try FileManager.default.createDirectory(
                at: url,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
        } catch {
            throw SecureQuarantineError.unsafeStorage
        }

        var info = stat()
        let status = url.path.withCString { Darwin.lstat($0, &info) }
        guard status == 0,
              info.st_mode & S_IFMT == S_IFDIR,
              info.st_uid == getuid() else {
            throw SecureQuarantineError.unsafeStorage
        }
        guard url.path.withCString({ Darwin.chmod($0, mode_t(S_IRWXU)) }) == 0 else {
            throw SecureQuarantineError.unsafeStorage
        }
    }

    private nonisolated static func openAndLockQuarantineFile(_ lockURL: URL) throws -> Int32 {
        let descriptor = lockURL.path.withCString {
            Darwin.open(
                $0,
                O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW,
                mode_t(S_IRUSR | S_IWUSR)
            )
        }
        guard descriptor >= 0 else { throw SecureQuarantineError.lockUnavailable }

        do {
            try validateLockFile(descriptor: descriptor, url: lockURL)
            guard Darwin.fchmod(descriptor, mode_t(S_IRUSR | S_IWUSR)) == 0 else {
                throw SecureQuarantineError.lockUnavailable
            }

            while threatCenterAdvisoryFlock(descriptor, LOCK_EX | LOCK_NB) != 0 {
                let errorCode = errno
                if errorCode == EINTR { continue }
                if errorCode == EWOULDBLOCK || errorCode == EAGAIN {
                    throw SecureQuarantineError.lockBusy
                }
                throw SecureQuarantineError.lockUnavailable
            }

            do {
                // A same-user process could replace the pathname after open.
                // Confirm every participant still reaches this exact inode.
                try validateLockFile(descriptor: descriptor, url: lockURL)
            } catch {
                _ = threatCenterAdvisoryFlock(descriptor, LOCK_UN)
                throw error
            }
            return descriptor
        } catch {
            Darwin.close(descriptor)
            throw error
        }
    }

    private nonisolated static func validateLockFile(descriptor: Int32, url: URL) throws {
        var descriptorInfo = stat()
        var pathInfo = stat()
        guard Darwin.fstat(descriptor, &descriptorInfo) == 0,
              url.path.withCString({ Darwin.lstat($0, &pathInfo) }) == 0,
              descriptorInfo.st_mode & S_IFMT == S_IFREG,
              pathInfo.st_mode & S_IFMT == S_IFREG,
              descriptorInfo.st_uid == getuid(),
              pathInfo.st_uid == getuid(),
              descriptorInfo.st_nlink == 1,
              pathInfo.st_nlink == 1,
              descriptorInfo.st_dev == pathInfo.st_dev,
              descriptorInfo.st_ino == pathInfo.st_ino else {
            throw SecureQuarantineError.lockUnavailable
        }
    }

    private nonisolated static func quarantineSourceIdentity(
        at url: URL
    ) throws -> QuarantineSourceIdentity {
        var info = stat()
        let status = url.path.withCString { Darwin.lstat($0, &info) }
        guard status == 0 else { throw SecureQuarantineError.sourceMissing }
        guard info.st_mode & S_IFMT == S_IFREG,
              info.st_uid == getuid() else {
            throw SecureQuarantineError.unsafeStorage
        }
        return quarantineSourceIdentity(from: info)
    }

    private nonisolated static func quarantineSourceIdentity(
        from info: stat
    ) -> QuarantineSourceIdentity {
        QuarantineSourceIdentity(
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

    private nonisolated static func directoryDevice(at url: URL) throws -> UInt64 {
        var info = stat()
        let status = url.path.withCString { Darwin.lstat($0, &info) }
        guard status == 0,
              info.st_mode & S_IFMT == S_IFDIR,
              info.st_uid == getuid() else {
            throw SecureQuarantineError.unsafeStorage
        }
        return UInt64(info.st_dev)
    }

    private nonisolated static func sha256Digest(at url: URL) throws -> [UInt8] {
        let descriptor = url.path.withCString {
            Darwin.open($0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        }
        guard descriptor >= 0 else { throw SecureQuarantineError.sourceChanged }
        defer { Darwin.close(descriptor) }

        var before = stat()
        guard Darwin.fstat(descriptor, &before) == 0,
              before.st_mode & S_IFMT == S_IFREG,
              before.st_uid == getuid() else {
            throw SecureQuarantineError.sourceChanged
        }
        let beforeIdentity = quarantineSourceIdentity(from: before)

        var hasher = SHA256()
        var buffer = [UInt8](repeating: 0, count: 1_048_576)
        while true {
            let readCount = buffer.withUnsafeMutableBytes { bytes -> Int in
                guard let baseAddress = bytes.baseAddress else { return 0 }
                return Darwin.read(descriptor, baseAddress, bytes.count)
            }
            if readCount < 0 {
                if errno == EINTR { continue }
                throw SecureQuarantineError.sourceChanged
            }
            if readCount == 0 { break }
            hasher.update(data: Data(buffer[0..<readCount]))
        }

        var after = stat()
        guard Darwin.fstat(descriptor, &after) == 0 else {
            throw SecureQuarantineError.sourceChanged
        }
        let afterIdentity = quarantineSourceIdentity(from: after)
        guard beforeIdentity == afterIdentity,
              try quarantineSourceIdentity(at: url) == afterIdentity else {
            throw SecureQuarantineError.sourceChanged
        }
        return Array(hasher.finalize())
    }

    private nonisolated static func hexadecimalDigest(_ digest: [UInt8]) -> String {
        digest.map { String(format: "%02x", $0) }.joined()
    }

    private nonisolated static func writePrivateTemporaryFile(_ data: Data, to url: URL) throws {
        let descriptor = url.path.withCString {
            Darwin.open(
                $0,
                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                mode_t(S_IRUSR | S_IWUSR)
            )
        }
        guard descriptor >= 0 else { throw SecureQuarantineError.metadataPreparationFailed }
        defer { Darwin.close(descriptor) }

        var info = stat()
        guard Darwin.fstat(descriptor, &info) == 0,
              info.st_mode & S_IFMT == S_IFREG,
              info.st_uid == getuid(),
              info.st_nlink == 1,
              Darwin.fchmod(descriptor, mode_t(S_IRUSR | S_IWUSR)) == 0 else {
            throw SecureQuarantineError.metadataPreparationFailed
        }

        try data.withUnsafeBytes { bytes in
            guard let baseAddress = bytes.baseAddress else { return }
            var written = 0
            while written < bytes.count {
                let result = Darwin.write(
                    descriptor,
                    baseAddress.advanced(by: written),
                    bytes.count - written
                )
                if result < 0 {
                    if errno == EINTR { continue }
                    throw SecureQuarantineError.metadataPreparationFailed
                }
                guard result > 0 else { throw SecureQuarantineError.metadataPreparationFailed }
                written += result
            }
        }
        guard Darwin.fsync(descriptor) == 0 else {
            throw SecureQuarantineError.metadataPreparationFailed
        }
    }

    private nonisolated static func secureRegularFile(
        at url: URL,
        requireSingleLink: Bool
    ) throws {
        let descriptor = url.path.withCString {
            Darwin.open($0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        }
        guard descriptor >= 0 else { throw SecureQuarantineError.unsafeStorage }
        defer { Darwin.close(descriptor) }

        var descriptorInfo = stat()
        var pathInfo = stat()
        guard Darwin.fstat(descriptor, &descriptorInfo) == 0,
              url.path.withCString({ Darwin.lstat($0, &pathInfo) }) == 0,
              descriptorInfo.st_mode & S_IFMT == S_IFREG,
              pathInfo.st_mode & S_IFMT == S_IFREG,
              descriptorInfo.st_uid == getuid(),
              pathInfo.st_uid == getuid(),
              descriptorInfo.st_dev == pathInfo.st_dev,
              descriptorInfo.st_ino == pathInfo.st_ino,
              (!requireSingleLink || (descriptorInfo.st_nlink == 1 && pathInfo.st_nlink == 1)),
              Darwin.fchmod(descriptor, mode_t(S_IRUSR | S_IWUSR)) == 0 else {
            throw SecureQuarantineError.unsafeStorage
        }
    }

    private nonisolated static func finalizePreparedMetadata(
        _ preparedURL: URL,
        at metadataURL: URL,
        expectedData: Data
    ) throws {
        try FileManager.default.moveItem(at: preparedURL, to: metadataURL)
        try secureRegularFile(at: metadataURL, requireSingleLink: true)
        guard (try? Data(contentsOf: metadataURL)) == expectedData else {
            throw SecureQuarantineError.metadataPreparationFailed
        }
    }

    private nonisolated static func recoverQuarantinePayload(
        originalURL: URL,
        storedURL: URL
    ) -> Bool {
        // Cross-volume FileManager.move fallback could copy/delete across a
        // replaced path. Recovery is therefore only an atomic same-volume rename.
        guard let storedIdentity = try? quarantineSourceIdentity(at: storedURL),
              let originalDirectoryDevice = try? directoryDevice(
                  at: originalURL.deletingLastPathComponent()
              ),
              storedIdentity.device == originalDirectoryDevice else { return false }
        do {
            try renameExclusively(from: storedURL, to: originalURL)
            return pathEntryExists(at: originalURL) && !pathEntryExists(at: storedURL)
        } catch {
            return false
        }
    }

    private nonisolated static func removeMetadataIfMatching(_ data: Data, at url: URL) {
        guard (try? Data(contentsOf: url)) == data else { return }
        try? FileManager.default.removeItem(at: url)
    }

    private nonisolated static func publishRecoveryMetadata(
        _ data: Data,
        preparedURL: URL,
        preferredURL: URL,
        quarantineDirectory: URL,
        id: UUID
    ) throws {
        if (try? Data(contentsOf: preferredURL)) == data {
            do {
                try secureRegularFile(at: preferredURL, requireSingleLink: true)
                return
            } catch {
                // Publish a fresh private record below if this visible path was
                // replaced or cannot be secured.
            }
        }

        if FileManager.default.fileExists(atPath: preparedURL.path) {
            do {
                try FileManager.default.moveItem(at: preparedURL, to: preferredURL)
                try secureRegularFile(at: preferredURL, requireSingleLink: true)
                return
            } catch {
                // A colliding or replaced preferred path must not hide the
                // retained payload; publish under a fresh visible filename.
            }
        }

        let recoveryID = UUID()
        let recoveryURL = quarantineDirectory
            .appendingPathComponent("recovered-\(id.uuidString)-\(recoveryID.uuidString).json")
        let recoveryTemporaryURL = quarantineDirectory
            .appendingPathComponent(".\(recoveryID.uuidString).recovery.tmp")
        defer { try? FileManager.default.removeItem(at: recoveryTemporaryURL) }

        if FileManager.default.fileExists(atPath: preparedURL.path) {
            try FileManager.default.moveItem(at: preparedURL, to: recoveryURL)
        } else {
            try writePrivateTemporaryFile(data, to: recoveryTemporaryURL)
            try FileManager.default.moveItem(at: recoveryTemporaryURL, to: recoveryURL)
        }
        try secureRegularFile(at: recoveryURL, requireSingleLink: true)
        guard (try? Data(contentsOf: recoveryURL)) == data else {
            throw SecureQuarantineError.metadataPreparationFailed
        }
    }

    nonisolated private func loadQuarantineSnapshot() -> [QuarantineItem] {
        try? FileManager.default.createDirectory(
            at: quarantineDirectory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let files = (try? FileManager.default.contentsOfDirectory(
            at: quarantineDirectory,
            includingPropertiesForKeys: nil,
            options: [.skipsHiddenFiles]
        )) ?? []
        let decoder = JSONDecoder()
        return files
            .filter { $0.pathExtension == "json" }
            .compactMap { metadataURL in
                guard let data = try? Data(contentsOf: metadataURL),
                      let metadata = try? decoder.decode(QuarantineMetadata.self, from: data) else { return nil }
                return QuarantineItem(
                    metadata: metadata,
                    metadataURL: metadataURL,
                    fileURL: quarantineDirectory.appendingPathComponent(metadata.storedFileName)
                )
            }
            .sorted { $0.metadata.quarantinedAt > $1.metadata.quarantinedAt }
    }

    nonisolated private func loadRealtimeProtectionSnapshot() -> (
        status: RealtimeProtectionStatus?,
        events: [RealtimeProtectionEvent]
    ) {
        let decoder = realtimeJSONDecoder()

        let status = (try? Data(contentsOf: realtimeStatusURL))
            .flatMap { try? decoder.decode(RealtimeProtectionStatus.self, from: $0) }
        let events = readTailLines(from: realtimeEventsURL, maximumBytes: 256 * 1_024)
            .compactMap { line in
                line.data(using: .utf8).flatMap { try? decoder.decode(RealtimeProtectionEvent.self, from: $0) }
            }
            .sorted { $0.timestamp > $1.timestamp }
            .prefix(100)
            .map { $0 }
        return (status, events)
    }

    nonisolated private func loadVirusTotalSnapshot() -> (
        status: VirusTotalServiceStatus?,
        results: [VirusTotalResult]
    ) {
        let decoder = realtimeJSONDecoder()
        let status = (try? Data(contentsOf: virusTotalStatusURL))
            .flatMap { try? decoder.decode(VirusTotalServiceStatus.self, from: $0) }
        let results = readTailLines(from: virusTotalResultsURL, maximumBytes: 512 * 1_024)
            .compactMap { line in
                line.data(using: .utf8).flatMap { try? decoder.decode(VirusTotalResult.self, from: $0) }
            }
            .sorted { $0.timestamp > $1.timestamp }
            .prefix(200)
            .map { $0 }
        return (status, results)
    }

    func chooseVirusTotalFile() {
        guard !isVirusTotalManualScanRunning else { return }
        let panel = NSOpenPanel()
        panel.title = "VirusTotal'da hash sorgusu yapılacak dosyayı seç"
        panel.prompt = "Hash Sorgula"
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.resolvesAliases = true
        panel.begin { [weak self] response in
            guard response == .OK, let file = panel.url, let self else { return }
            self.runVirusTotalFile(file, hashOnly: true, forceUpload: false)
            }
    }

    nonisolated private func loadScanProgressSnapshot() -> ScanProgressStatus? {
        let decoder = realtimeJSONDecoder()
        let decoded = (try? Data(contentsOf: scanProgressStatusURL))
            .flatMap { try? decoder.decode(ScanProgressStatus.self, from: $0) }
        let lockURL = automationDirectory.appendingPathComponent("scan.lock", isDirectory: true)
        let lockExists = FileManager.default.fileExists(atPath: lockURL.path)

        if decoded?.running == true, lockExists {
            return decoded
        }
        guard lockExists else {
            return decoded?.running == false ? decoded : nil
        }

        let keys: [URLResourceKey] = [.contentModificationDateKey, .isRegularFileKey]
        let candidates = ((try? FileManager.default.contentsOfDirectory(
            at: logDirectory,
            includingPropertiesForKeys: keys,
            options: [.skipsHiddenFiles]
        )) ?? [])
            .filter(isScanLog)
            .sorted {
                let left = (try? $0.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
                let right = (try? $1.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
                return left > right
            }

        for url in candidates.prefix(5) {
            guard let contents = try? String(contentsOf: url, encoding: .utf8),
                  !contents.contains("Bitiş:") else { continue }
            let start = parseLegacyScanStart(in: contents)
                ?? (try? url.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate)
                ?? Date()
            return .legacy(
                startedAt: start,
                title: url.lastPathComponent.hasPrefix("selection-") ? "Devam eden seçili öğe taraması" : "Devam eden otomatik tarama"
            )
        }
        return .legacy(startedAt: Date(), title: "Devam eden ClamAV taraması")
    }

    nonisolated private func parseLegacyScanStart(in text: String) -> Date? {
        guard let line = text.split(separator: "\n").first(where: { $0.hasPrefix("Başlangıç:") }) else { return nil }
        let value = line.dropFirst("Başlangıç:".count).trimmingCharacters(in: .whitespaces)
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = .current
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return formatter.date(from: value)
    }

    func confirmVirusTotalUpload() {
        guard let request = pendingVirusTotalUpload else { return }
        pendingVirusTotalUpload = nil
        guard FileManager.default.fileExists(atPath: request.fileURL.path) else {
            virusTotalManualMessage = "Dosya artık belirtilen konumda bulunmuyor."
            return
        }
        runVirusTotalFile(
            request.fileURL,
            hashOnly: false,
            forceUpload: true,
            expectedSHA256: request.sha256
        )
    }

    func cancelVirusTotalUpload() {
        pendingVirusTotalUpload = nil
        virusTotalManualMessage = "Dosya VirusTotal'a yüklenmedi."
    }

    private func runVirusTotalFile(
        _ file: URL,
        hashOnly: Bool,
        forceUpload: Bool,
        expectedSHA256: String? = nil
    ) {
        guard FileManager.default.isReadableFile(atPath: file.path) else {
            virusTotalManualMessage = "Seçilen dosya okunamıyor."
            return
        }
        guard FileManager.default.fileExists(atPath: virusTotalScriptURL.path) else {
            virusTotalManualMessage = "VirusTotal tarama bileşeni bulunamadı. Otomasyonu yeniden kur."
            return
        }
        guard let python = Self.compatiblePythonURL() else {
            virusTotalManualMessage = "Uyumlu Python bulunamadı. VirusTotal bileşenini yeniden kur."
            return
        }
        if forceUpload && (expectedSHA256?.isEmpty ?? true) {
            virusTotalManualMessage = "Dosyanın güvenli hash doğrulaması yapılamadı; yükleme başlatılmadı."
            return
        }

        let process = Process()
        let output = Pipe()
        let readHandle = output.fileHandleForReading
        let writeHandle = output.fileHandleForWriting
        process.executableURL = python
        var arguments = [virusTotalScriptURL.path, "--file", file.path]
        if hashOnly { arguments.append("--hash-only") }
        if forceUpload {
            arguments.append("--force-upload")
            arguments.append(contentsOf: ["--expected-sha256", expectedSHA256 ?? ""])
        }
        process.arguments = arguments
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice

        isVirusTotalManualScanRunning = true
        virusTotalManualMessage = hashOnly
            ? "Dosyanın hash bilgisi VirusTotal'da sorgulanıyor…"
            : "Dosya VirusTotal'a yükleniyor ve analiz ediliyor…"

        do {
            try process.run()
            try? writeHandle.close()
        } catch {
            isVirusTotalManualScanRunning = false
            virusTotalManualMessage = "VirusTotal sorgusu başlatılamadı."
            return
        }

        DispatchQueue.global(qos: .utility).async { [weak self] in
            let data = readHandle.readDataToEndOfFile()
            try? readHandle.close()
            process.waitUntilExit()
            Task { @MainActor in
                guard let self else { return }
                self.isVirusTotalManualScanRunning = false
                guard let result = self.decodeVirusTotalProcessOutput(data) else {
                    self.virusTotalManualMessage = "VirusTotal sorgusu tamamlanamadı. Servis durumunu kontrol et."
                    return
                }

                if process.terminationStatus != 0 || result.status == "error" {
                    self.virusTotalManualMessage = result.errorMessage ?? "VirusTotal sorgusu tamamlanamadı. Servis durumunu kontrol et."
                    self.refresh()
                    return
                }

                if hashOnly && result.isUnknown {
                    guard !result.sha256.isEmpty else {
                        self.virusTotalManualMessage = "Dosyanın hash bilgisi doğrulanamadı; yükleme onayı sunulmadı."
                        return
                    }
                    self.pendingVirusTotalUpload = VirusTotalUploadRequest(fileURL: file, sha256: result.sha256)
                    self.virusTotalManualMessage = "Bu dosya VirusTotal'da bilinmiyor. Onay verirsen analiz için bir kopyası yüklenecek."
                } else {
                    self.virusTotalManualMessage = self.manualVirusTotalMessage(for: result)
                    self.refresh()
                }
            }
        }
    }

    private func decodeVirusTotalProcessOutput(_ data: Data) -> VirusTotalResult? {
        let decoder = realtimeJSONDecoder()
        if let result = try? decoder.decode(VirusTotalResult.self, from: data),
           isUsableVirusTotalResult(result) {
            return result
        }
        guard let text = String(data: data, encoding: .utf8) else { return nil }
        for line in text.split(separator: "\n").reversed() {
            guard let lineData = String(line).data(using: .utf8),
                  let result = try? decoder.decode(VirusTotalResult.self, from: lineData),
                  isUsableVirusTotalResult(result) else { continue }
            return result
        }
        return nil
    }

    private func isUsableVirusTotalResult(_ result: VirusTotalResult) -> Bool {
        !result.path.isEmpty || !result.sha256.isEmpty || result.errorMessage != nil
    }

    private func manualVirusTotalMessage(for result: VirusTotalResult) -> String {
        if result.riskCount > 0 {
            if result.quarantinedTo != nil {
                return "\(result.fileName) için \(result.riskCount) uyarı bulundu ve dosya karantinaya taşındı."
            }
            return "\(result.fileName) için \(result.riskCount) güvenlik motoru uyarı verdi."
        }
        if result.isUnknown {
            return "Dosya VirusTotal'da hâlâ bilinmiyor; yükleme sonucu daha sonra görünebilir."
        }
        return "\(result.fileName) için VirusTotal'da tehdit uyarısı bulunmadı."
    }

    private nonisolated static func compatiblePythonURL() -> URL? {
        let candidates = [
            "/Library/Frameworks/Python.framework/Versions/3.12/bin/python3",
            "/Library/Frameworks/Python.framework/Versions/3.14/bin/python3",
            "/opt/homebrew/bin/python3",
            "/usr/local/bin/python3"
        ]
        for path in candidates where FileManager.default.isExecutableFile(atPath: path) {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: path)
            process.arguments = ["-c", "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)"]
            process.standardOutput = FileHandle.nullDevice
            process.standardError = FileHandle.nullDevice
            do {
                try process.run()
                process.waitUntilExit()
                if process.terminationStatus == 0 { return URL(fileURLWithPath: path) }
            } catch {
                continue
            }
        }
        return nil
    }

    func openVirusTotalReport(_ result: VirusTotalResult) {
        guard let text = result.reportURL, let url = URL(string: text) else { return }
        NSWorkspace.shared.open(url)
    }

    func canOpenProtectionApp(_ id: String) -> Bool {
        protectionAppURL(for: id) != nil
    }

    func openProtectionApp(_ id: String) {
        guard let url = protectionAppURL(for: id) else { return }
        NSWorkspace.shared.openApplication(at: url, configuration: NSWorkspace.OpenConfiguration())
    }

    private func protectionAppURL(for id: String) -> URL? {
        let candidates: [String]
        switch id {
        case "lulu": candidates = ["/Applications/LuLu.app"]
        case "santa": candidates = ["/Applications/Santa.app"]
        case "blockblock": candidates = [
            "/Applications/BlockBlock Helper.app",
            "/Applications/BlockBlock.app"
        ]
        case "ransomwhere": candidates = [
            "/Applications/RansomWhere Helper.app",
            "/Applications/RansomWhere.app"
        ]
        default: return nil
        }
        guard let path = candidates.first(where: { FileManager.default.fileExists(atPath: $0) }) else { return nil }
        return URL(fileURLWithPath: path, isDirectory: true)
    }

    func reveal(_ threat: ThreatSummary) {
        if threat.exists {
            NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: threat.path)])
        } else {
            NSWorkspace.shared.activateFileViewerSelecting([threat.logURL])
        }
    }

    func openLog(_ url: URL) {
        NSWorkspace.shared.open(url)
    }

    func openLogDirectory() {
        NSWorkspace.shared.open(logDirectory)
    }

    nonisolated private func isScanLog(_ url: URL) -> Bool {
        let name = url.lastPathComponent
        return url.pathExtension == "log" && (name.hasPrefix("scan-20") || name.hasPrefix("selection-20"))
    }

    nonisolated private func parseInteger(label: String, in text: String) -> Int? {
        guard let line = text.split(separator: "\n").first(where: { $0.hasPrefix(label) }) else { return nil }
        return Int(line.dropFirst(label.count).trimmingCharacters(in: .whitespaces))
    }

    nonisolated private func parseString(label: String, in text: String) -> String? {
        guard let line = text.split(separator: "\n").first(where: { $0.hasPrefix(label) }) else { return nil }
        return line.dropFirst(label.count).trimmingCharacters(in: .whitespaces)
    }

    nonisolated private func parseDate(in text: String) -> Date? {
        guard let line = text.split(separator: "\n").first(where: { $0.hasPrefix("Start Date:") }) else { return nil }
        let value = line.dropFirst("Start Date:".count).trimmingCharacters(in: .whitespaces)
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy:MM:dd HH:mm:ss"
        return formatter.date(from: value)
    }

    private nonisolated static func inspectProtectionLayers() -> [ProtectionLayerStatus] {
        let gatekeeperResult = runReadOnly("/usr/sbin/spctl", ["--status"])
        let gatekeeperOutput = gatekeeperResult.output.lowercased()
        let gatekeeper: ProtectionLayerStatus
        if gatekeeperOutput.contains("disabled") {
            gatekeeper = settingLayer(
                id: "gatekeeper", name: "Uygulama denetimi", icon: "checkmark.seal.fill",
                status: "Off", detail: "İndirilen uygulamaların güvenilirliği şu anda denetlenmiyor.", health: .attention
            )
        } else if gatekeeperOutput.contains("enabled") {
            gatekeeper = settingLayer(
                id: "gatekeeper", name: "Uygulama denetimi", icon: "checkmark.seal.fill",
                status: "On", detail: "İndirilen uygulamaların güvenilirliği denetleniyor.", health: .active
            )
        } else {
            gatekeeper = settingLayer(
                id: "gatekeeper", name: "Uygulama denetimi", icon: "checkmark.seal.fill",
                status: "Durum okunamadı", detail: "Bu korumanın durumunu Sistem Ayarları'ndan kontrol et.", health: .attention
            )
        }

        let firewallOutput = runReadOnly(
            "/usr/libexec/ApplicationFirewall/socketfilterfw", ["--getglobalstate"]
        ).output.lowercased()
        let firewallOn = firewallOutput.contains("enabled") || firewallOutput.contains("state = 1") || firewallOutput.contains("state = 2")
        let firewall = settingLayer(
            id: "firewall", name: "Güvenlik duvarı", icon: "network.badge.shield.half.filled",
            status: firewallOn ? "On" : "Off",
            detail: firewallOn ? "İstenmeyen gelen bağlantılar sınırlandırılıyor." : "Gelen bağlantı koruması şu anda kapalı.",
            health: firewallOn ? .active : .attention
        )

        let fileVaultOutput = runReadOnly("/usr/bin/fdesetup", ["status"]).output.lowercased()
        let fileVaultOn = fileVaultOutput.contains("filevault is on")
        let fileVault = settingLayer(
            id: "filevault", name: "Disk şifreleme", icon: "lock.fill",
            status: fileVaultOn ? "On" : "Off",
            detail: fileVaultOn ? "Mac'teki veriler disk şifreleme ile korunuyor." : "Diskteki veriler şu anda şifreleme ile korunmuyor.",
            health: fileVaultOn ? .active : .attention
        )

        let processList = runReadOnly("/bin/ps", ["-axo", "comm=,args="]).output.lowercased()
        let extensions = runReadOnly("/usr/bin/systemextensionsctl", ["list"]).output.lowercased()
        let fileManager = FileManager.default

        let luluInstalled = fileManager.fileExists(atPath: "/Applications/LuLu.app")
            || extensions.contains("objective-see") && extensions.contains("lulu")
        let luluActive = processList.contains("lulu") || extensionIsActive(extensions, matching: "lulu")
        let lulu = toolLayer(
            id: "lulu", name: "LuLu", icon: "arrow.up.right.circle.fill",
            installed: luluInstalled, active: luluActive,
            activeDetail: "Uygulamaların dışarıya bağlantıları denetleniyor.",
            inactiveDetail: "Dış bağlantı koruması kurulu ancak çalışmıyor.",
            missingDetail: "Dış bağlantı koruması henüz kurulu değil."
        )

        let santaCLIPaths = [
            "/Applications/Santa.app/Contents/MacOS/santactl",
            "/usr/local/bin/santactl",
            "/opt/homebrew/bin/santactl"
        ]
        let santaCLI = santaCLIPaths.first(where: { fileManager.isExecutableFile(atPath: $0) })
        let santaStatusResult = santaCLI.map { runReadOnly($0, ["status"]) }
        let santaResponds = santaStatusResult?.status == 0
        let santaInstalled = santaCLI != nil
            || fileManager.fileExists(atPath: "/Applications/Santa.app")
            || extensions.contains("santa")
        let santaActive = processList.contains("santad")
            || processList.contains("santa.daemon")
        let santa: ProtectionLayerStatus
        if santaActive, santaResponds,
           let mode = santaMode(from: santaStatusResult?.output ?? "") {
            switch mode {
            case "monitor":
                santa = settingLayer(
                    id: "santa", name: "Santa", icon: "hand.raised.square.fill",
                    status: "Sessiz izleme",
                    detail: "Bilinmeyen programlara izin verir ve olayları kaydeder; bozuk imzalar engellenir.",
                    health: .active
                )
            case "standalone":
                santa = settingLayer(
                    id: "santa", name: "Santa", icon: "hand.raised.square.fill",
                    status: "Onay isteyen mod",
                    detail: "Bilinmeyen programlar için kullanıcı kararı ister ve olayları kaydeder.",
                    health: .active
                )
            case "lockdown":
                santa = settingLayer(
                    id: "santa", name: "Santa", icon: "hand.raised.square.fill",
                    status: "Sıkı engelleme",
                    detail: "Yalnız izin verilen programların çalışmasına izin verir; bilinmeyen programları engeller.",
                    health: .active
                )
            default:
                santa = toolLayer(
                    id: "santa", name: "Santa", icon: "hand.raised.square.fill",
                    installed: santaInstalled, active: santaActive,
                    activeDetail: "Programlar çalıştırılmadan önce güvenlik denetiminden geçiyor.",
                    inactiveDetail: "Çalıştırma denetimi kurulu ancak yanıt vermiyor.",
                    missingDetail: "Program çalıştırma denetimi henüz kurulu değil."
                )
            }
        } else {
            santa = toolLayer(
                id: "santa", name: "Santa", icon: "hand.raised.square.fill",
                installed: santaInstalled, active: santaActive,
                activeDetail: "Programlar çalıştırılmadan önce güvenlik denetiminden geçiyor.",
                inactiveDetail: "Çalıştırma denetimi kurulu ancak yanıt vermiyor.",
                missingDetail: "Program çalıştırma denetimi henüz kurulu değil."
            )
        }

        let blockBlockInstalled = fileManager.fileExists(atPath: "/Applications/BlockBlock Helper.app")
            || fileManager.fileExists(atPath: "/Applications/BlockBlock.app")
            || fileManager.fileExists(atPath: "/Library/Objective-See/BlockBlock")
            || extensions.contains("blockblock")
        let blockBlockActive = processList.contains("blockblock")
            || extensionIsActive(extensions, matching: "blockblock")
        let blockBlock = toolLayer(
            id: "blockblock", name: "BlockBlock", icon: "bolt.shield.fill",
            installed: blockBlockInstalled, active: blockBlockActive,
            activeDetail: "Şüpheli kalıcılık girişimleri izleniyor.",
            inactiveDetail: "Kalıcılık koruması kurulu ancak çalışmıyor.",
            missingDetail: "Kalıcılık koruması henüz kurulu değil."
        )

        let ransomWhereInstalled = fileManager.fileExists(atPath: "/Applications/RansomWhere Helper.app")
            || fileManager.fileExists(atPath: "/Applications/RansomWhere.app")
            || fileManager.fileExists(atPath: "/Library/Objective-See/RansomWhere")
            || processList.contains("ransomwhere")
        let ransomWhereActive = processList.contains("ransomwhere")
        let ransomWhere = toolLayer(
            id: "ransomwhere", name: "RansomWhere?", icon: "lock.shield.fill",
            installed: ransomWhereInstalled, active: ransomWhereActive,
            activeDetail: "Şüpheli toplu dosya şifreleme davranışı izleniyor.",
            inactiveDetail: "Fidye yazılımı koruması kurulu ancak çalışmıyor.",
            missingDetail: "Fidye yazılımı davranış koruması henüz kurulu değil."
        )

        return [gatekeeper, firewall, fileVault, lulu, santa, blockBlock, ransomWhere]
    }

    private nonisolated static func inspectClamAVDaemon() -> Bool {
        let fileManager = FileManager.default
        let candidates = ["/opt/homebrew/bin/clamdscan", "/usr/local/bin/clamdscan"]
        guard let executable = candidates.first(where: { fileManager.isExecutableFile(atPath: $0) }) else {
            return false
        }
        let config = fileManager.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/ClamAV-Automation/clamd.conf").path
        guard fileManager.fileExists(atPath: config) else { return false }
        return runReadOnly(executable, ["--config-file=\(config)", "--ping=1:1"]).status == 0
    }

    private nonisolated static func runReadOnly(_ executable: String, _ arguments: [String]) -> (status: Int32, output: String) {
        let process = Process()
        let output = Pipe()
        let readHandle = output.fileHandleForReading
        let writeHandle = output.fileHandleForWriting
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.standardOutput = output
        process.standardError = output

        do {
            try process.run()
            try? writeHandle.close()
            let data = readHandle.readDataToEndOfFile()
            try? readHandle.close()
            process.waitUntilExit()
            return (
                process.terminationStatus,
                String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            )
        } catch {
            return (-1, "")
        }
    }

    private nonisolated static func verifyRestorePayload(at payloadURL: URL, automationDirectory: URL) throws {
        let fileManager = FileManager.default
        let candidates = ["/opt/homebrew/bin/clamdscan", "/usr/local/bin/clamdscan"]
        guard let executable = candidates.first(where: { fileManager.isExecutableFile(atPath: $0) }) else {
            throw SecureQuarantineError.restorePreScanIncomplete
        }
        let configURL = automationDirectory.appendingPathComponent("clamd.conf")
        guard fileManager.fileExists(atPath: configURL.path) else {
            throw SecureQuarantineError.restorePreScanIncomplete
        }
        let result = runReadOnly(executable, [
            "--config-file=\(configURL.path)",
            payloadURL.path
        ])
        if result.status == 0 { return }
        if result.status == 1 { throw SecureQuarantineError.restorePreScanThreatFound }
        throw SecureQuarantineError.restorePreScanIncomplete
    }

    private nonisolated static func extensionIsActive(_ output: String, matching name: String) -> Bool {
        output.split(separator: "\n").contains { line in
            let text = line.lowercased()
            return text.contains(name.lowercased())
                && (text.contains("activated enabled") || text.hasPrefix("*\t*"))
        }
    }

    private nonisolated static func santaMode(from output: String) -> String? {
        for line in output.split(separator: "\n") {
            let parts = line.split(separator: "|", maxSplits: 1, omittingEmptySubsequences: false)
            guard parts.count == 2,
                  parts[0].trimmingCharacters(in: .whitespacesAndNewlines)
                    .caseInsensitiveCompare("Mode") == .orderedSame else { continue }
            return parts[1]
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .lowercased()
        }
        return nil
    }

    private nonisolated static func settingLayer(
        id: String,
        name: String,
        icon: String,
        status: String,
        detail: String,
        health: ProtectionLayerHealth
    ) -> ProtectionLayerStatus {
        ProtectionLayerStatus(
            id: id,
            name: name,
            icon: icon,
            statusText: status,
            detail: detail,
            health: health
        )
    }

    private nonisolated static func toolLayer(
        id: String,
        name: String,
        icon: String,
        installed: Bool,
        active: Bool,
        activeDetail: String,
        inactiveDetail: String,
        missingDetail: String
    ) -> ProtectionLayerStatus {
        if active {
            return settingLayer(id: id, name: name, icon: icon, status: "Running", detail: activeDetail, health: .active)
        }
        if installed {
            return settingLayer(id: id, name: name, icon: icon, status: "Inactive", detail: inactiveDetail, health: .attention)
        }
        return settingLayer(id: id, name: name, icon: icon, status: "Not installed", detail: missingDetail, health: .missing)
    }

#if QUARANTINE_TRANSACTION_TEST
    nonisolated static func runQuarantineTransactionTests() -> Int32 {
        let fileManager = FileManager.default
        let root = fileManager.temporaryDirectory.appendingPathComponent(
            "ClamAV-Threat-Center-Test-\(UUID().uuidString)",
            isDirectory: true
        )
        defer { try? fileManager.removeItem(at: root) }

        do {
            try fileManager.createDirectory(
                at: root,
                withIntermediateDirectories: false,
                attributes: [.posixPermissions: 0o700]
            )
            let automationDirectory = root.appendingPathComponent("automation", isDirectory: true)
            let quarantineDirectory = automationDirectory.appendingPathComponent("Quarantine", isDirectory: true)
            let originalData = Data(repeating: 0x41, count: 2_200_000)
            let replacementData = Data(repeating: 0x42, count: originalData.count)

            // Cross-volume helper path replacement race: original path is
            // recreated after copy, and must survive deletion of owned staging.
            let raceSource = root.appendingPathComponent("race-source.bin")
            let raceStaging = root.appendingPathComponent(".clamav-quarantine-race.stage")
            let raceTemporary = root.appendingPathComponent(".race.payload.tmp")
            let raceStored = root.appendingPathComponent("race-stored.bin")
            try originalData.write(to: raceSource)
            let raceIdentity = try quarantineSourceIdentity(at: raceSource)
            let raceDigest = try sha256Digest(at: raceSource)
            try transferCrossVolumePayload(
                originalURL: raceSource,
                stagingURL: raceStaging,
                temporaryStoredURL: raceTemporary,
                storedURL: raceStored,
                expectedIdentity: raceIdentity,
                expectedDigest: raceDigest,
                beforeStagingDeletion: { _ in
                    try replacementData.write(to: raceSource, options: .withoutOverwriting)
                }
            )
            guard try Data(contentsOf: raceSource) == replacementData,
                  try Data(contentsOf: raceStored) == originalData,
                  !pathEntryExists(at: raceStaging),
                  !pathEntryExists(at: raceTemporary) else {
                throw SecureQuarantineError.sourceChanged
            }

            // A completed manual quarantine must publish ready + size + SHA-256.
            let restoreSource = root.appendingPathComponent("restore-source.bin")
            try originalData.write(to: restoreSource)
            try securelyQuarantine(
                originalURL: restoreSource,
                signature: "Test.Signature",
                automationDirectory: automationDirectory,
                quarantineDirectory: quarantineDirectory
            )
            let restoreMetadataURL = try fileManager.contentsOfDirectory(
                at: quarantineDirectory,
                includingPropertiesForKeys: nil,
                options: [.skipsHiddenFiles]
            ).first { $0.pathExtension == "json" }
            guard let restoreMetadataURL else { throw SecureQuarantineError.metadataPreparationFailed }
            let readyData = try Data(contentsOf: restoreMetadataURL)
            let readyMetadata = try JSONDecoder().decode(QuarantineMetadata.self, from: readyData)
            guard readyMetadata.effectiveState == "ready",
                  readyMetadata.sha256 == hexadecimalDigest(raceDigest),
                  readyMetadata.fileSize == Int64(originalData.count) else {
                throw SecureQuarantineError.metadataPreparationFailed
            }

            // Preparing records are visible but never actionable.
            let preparingMetadata = QuarantineMetadata(
                id: readyMetadata.id,
                originalPath: readyMetadata.originalPath,
                storedFileName: readyMetadata.storedFileName,
                signature: readyMetadata.signature,
                quarantinedAt: readyMetadata.quarantinedAt,
                state: "preparing",
                sha256: readyMetadata.sha256,
                fileSize: readyMetadata.fileSize,
                stagingPath: nil,
                temporaryStoredFileName: nil,
                restoreMode: nil,
                restoreTemporaryPath: nil,
                restoreTemporaryDevice: nil,
                restoreTemporaryInode: nil
            )
            try publishMetadataAtomically(
                try JSONEncoder().encode(preparingMetadata),
                at: restoreMetadataURL
            )
            do {
                try securelyRestore(
                    metadataURL: restoreMetadataURL,
                    expectedID: readyMetadata.id,
                    automationDirectory: automationDirectory,
                    quarantineDirectory: quarantineDirectory
                )
                throw SecureQuarantineError.sourceChanged
            } catch SecureQuarantineError.incompleteOperation {
                // Expected safe rejection.
            }

            try publishMetadataAtomically(readyData, at: restoreMetadataURL)
            try securelyRestore(
                metadataURL: restoreMetadataURL,
                expectedID: readyMetadata.id,
                automationDirectory: automationDirectory,
                quarantineDirectory: quarantineDirectory
            )
            guard try Data(contentsOf: restoreSource) == originalData,
                  !pathEntryExists(at: restoreMetadataURL) else {
                throw SecureQuarantineError.sourceChanged
            }

            // Same-volume rename is atomic, but a crash can occur after the
            // payload reaches its final path and before metadata is removed.
            // Recovery must recognize the recorded inode/hash and preserve the
            // sole restored copy while finalizing the transaction.
            let sameCrashSource = root.appendingPathComponent("same-volume-crash.bin")
            try originalData.write(to: sameCrashSource)
            try securelyQuarantine(
                originalURL: sameCrashSource,
                signature: "Test.SameVolumeCrash",
                automationDirectory: automationDirectory,
                quarantineDirectory: quarantineDirectory
            )
            let sameCrashMetadataURL = try fileManager.contentsOfDirectory(
                at: quarantineDirectory,
                includingPropertiesForKeys: nil,
                options: [.skipsHiddenFiles]
            ).first { $0.pathExtension == "json" }
            guard let sameCrashMetadataURL else {
                throw SecureQuarantineError.metadataPreparationFailed
            }
            let sameCrashReady = try JSONDecoder().decode(
                QuarantineMetadata.self,
                from: Data(contentsOf: sameCrashMetadataURL)
            )
            do {
                try securelyRestore(
                    metadataURL: sameCrashMetadataURL,
                    expectedID: sameCrashReady.id,
                    automationDirectory: automationDirectory,
                    quarantineDirectory: quarantineDirectory,
                    afterSameVolumeRename: { _ in
                        throw SecureQuarantineError.incompleteOperation
                    }
                )
                throw SecureQuarantineError.sourceChanged
            } catch SecureQuarantineError.incompleteOperation {
                // Expected simulated process/power interruption.
            }
            let sameCrashPreparing = try JSONDecoder().decode(
                QuarantineMetadata.self,
                from: Data(contentsOf: sameCrashMetadataURL)
            )
            let sameCrashStoredURL = quarantineDirectory.appendingPathComponent(
                sameCrashPreparing.storedFileName
            )
            guard sameCrashPreparing.effectiveState == "restorePreparing",
                  sameCrashPreparing.restoreMode == "sameVolumeRename",
                  sameCrashPreparing.restoreTemporaryPath == sameCrashSource.path,
                  try Data(contentsOf: sameCrashSource) == originalData,
                  !pathEntryExists(at: sameCrashStoredURL) else {
                throw SecureQuarantineError.sourceChanged
            }
            try securelyRestore(
                metadataURL: sameCrashMetadataURL,
                expectedID: sameCrashReady.id,
                automationDirectory: automationDirectory,
                quarantineDirectory: quarantineDirectory
            )
            guard try Data(contentsOf: sameCrashSource) == originalData,
                  !pathEntryExists(at: sameCrashMetadataURL) else {
                throw SecureQuarantineError.sourceChanged
            }

            // Delete verifies integrity under the lock before claiming payload.
            let deleteSource = root.appendingPathComponent("delete-source.bin")
            try originalData.write(to: deleteSource)
            try securelyQuarantine(
                originalURL: deleteSource,
                signature: "Test.Delete",
                automationDirectory: automationDirectory,
                quarantineDirectory: quarantineDirectory
            )
            let deleteMetadataURL = try fileManager.contentsOfDirectory(
                at: quarantineDirectory,
                includingPropertiesForKeys: nil,
                options: [.skipsHiddenFiles]
            ).first { $0.pathExtension == "json" }
            guard let deleteMetadataURL else { throw SecureQuarantineError.metadataPreparationFailed }
            let deleteMetadata = try JSONDecoder().decode(
                QuarantineMetadata.self,
                from: Data(contentsOf: deleteMetadataURL)
            )
            let deleteStoredURL = quarantineDirectory.appendingPathComponent(deleteMetadata.storedFileName)
            try securelyDeleteQuarantineItem(
                metadataURL: deleteMetadataURL,
                expectedID: deleteMetadata.id,
                automationDirectory: automationDirectory,
                quarantineDirectory: quarantineDirectory
            )
            guard !pathEntryExists(at: deleteStoredURL),
                  !pathEntryExists(at: deleteMetadataURL) else {
                throw SecureQuarantineError.sourceChanged
            }

            // A ready record whose payload no longer matches its stored digest
            // cannot be restored.
            let tamperSource = root.appendingPathComponent("tamper-source.bin")
            try originalData.write(to: tamperSource)
            try securelyQuarantine(
                originalURL: tamperSource,
                signature: "Test.Tamper",
                automationDirectory: automationDirectory,
                quarantineDirectory: quarantineDirectory
            )
            let tamperMetadataURL = try fileManager.contentsOfDirectory(
                at: quarantineDirectory,
                includingPropertiesForKeys: nil,
                options: [.skipsHiddenFiles]
            ).first { $0.pathExtension == "json" }
            guard let tamperMetadataURL else { throw SecureQuarantineError.metadataPreparationFailed }
            let tamperMetadata = try JSONDecoder().decode(
                QuarantineMetadata.self,
                from: Data(contentsOf: tamperMetadataURL)
            )
            let tamperStoredURL = quarantineDirectory.appendingPathComponent(tamperMetadata.storedFileName)
            try replacementData.write(to: tamperStoredURL, options: .atomic)
            do {
                try securelyRestore(
                    metadataURL: tamperMetadataURL,
                    expectedID: tamperMetadata.id,
                    automationDirectory: automationDirectory,
                    quarantineDirectory: quarantineDirectory
                )
                throw SecureQuarantineError.sourceChanged
            } catch SecureQuarantineError.sourceChanged {
                // Expected safe rejection.
            }
            guard pathEntryExists(at: tamperStoredURL),
                  pathEntryExists(at: tamperMetadataURL) else {
                throw SecureQuarantineError.sourceChanged
            }

            if let externalRootPath = ProcessInfo.processInfo.environment["CLAMAV_EXTERNAL_TEST_ROOT"] {
                let externalRoot = URL(fileURLWithPath: externalRootPath, isDirectory: true)
                    .standardizedFileURL
                let externalTestDirectory = externalRoot.appendingPathComponent(
                    "ClamAV-Restore-Test-\(UUID().uuidString)",
                    isDirectory: true
                )
                try fileManager.createDirectory(
                    at: externalTestDirectory,
                    withIntermediateDirectories: false,
                    attributes: [.posixPermissions: 0o700]
                )
                defer { try? fileManager.removeItem(at: externalTestDirectory) }

                func metadataRecord(for originalURL: URL) throws -> (URL, QuarantineMetadata) {
                    for metadataURL in try fileManager.contentsOfDirectory(
                        at: quarantineDirectory,
                        includingPropertiesForKeys: nil,
                        options: [.skipsHiddenFiles]
                    ) where metadataURL.pathExtension == "json" {
                        guard let metadata = try? JSONDecoder().decode(
                            QuarantineMetadata.self,
                            from: Data(contentsOf: metadataURL)
                        ) else { continue }
                        if metadata.originalPath == originalURL.path {
                            return (metadataURL, metadata)
                        }
                    }
                    throw SecureQuarantineError.metadataPreparationFailed
                }

                // Simulated SIGKILL point: copied external temp remains tracked
                // by path+inode and the next locked operation rolls it back.
                print("TEST INFO: exFAT crash recovery")
                let crashSource = externalTestDirectory.appendingPathComponent("restore-crash.bin")
                try originalData.write(to: crashSource)
                try securelyQuarantine(
                    originalURL: crashSource,
                    signature: "Test.RestoreCrash",
                    automationDirectory: automationDirectory,
                    quarantineDirectory: quarantineDirectory
                )
                print("TEST INFO: exFAT quarantine ready")
                let (crashMetadataURL, crashReady) = try metadataRecord(for: crashSource)
                var crashTemporaryURL: URL?
                do {
                    try securelyRestore(
                        metadataURL: crashMetadataURL,
                        expectedID: crashReady.id,
                        automationDirectory: automationDirectory,
                        quarantineDirectory: quarantineDirectory,
                        afterRestoreTemporaryCopy: { temporaryURL in
                            crashTemporaryURL = temporaryURL
                            throw SecureQuarantineError.incompleteOperation
                        }
                    )
                    throw SecureQuarantineError.sourceChanged
                } catch SecureQuarantineError.incompleteOperation {
                    // Expected simulated interruption.
                }
                print("TEST INFO: exFAT interruption recorded")
                let crashPreparing = try JSONDecoder().decode(
                    QuarantineMetadata.self,
                    from: Data(contentsOf: crashMetadataURL)
                )
                guard crashPreparing.effectiveState == "restorePreparing",
                      crashPreparing.restoreTemporaryPath == crashTemporaryURL?.path,
                      crashTemporaryURL.map({ pathEntryExists(at: $0) }) == true else {
                    throw SecureQuarantineError.incompleteOperation
                }
#if QUARANTINE_TRANSACTION_TEST
                if let crashTemporaryURL,
                   let outputIdentity = try? quarantineSourceIdentity(at: crashTemporaryURL) {
                    let debugMode = crashPreparing.restoreMode ?? "nil"
                    let debugDigest = (try? hexadecimalDigest(
                        sha256Digest(at: crashTemporaryURL)
                    )) ?? "error"
                    print(
                        "TEST DEBUG: mode=\(debugMode) "
                            + "recorded=\(crashPreparing.restoreTemporaryDevice ?? 0):"
                            + "\(crashPreparing.restoreTemporaryInode ?? 0) actual="
                            + "\(outputIdentity.device):\(outputIdentity.inode) size="
                            + "\(outputIdentity.size) sha="
                            + debugDigest
                    )
                }
#endif
                try securelyRestore(
                    metadataURL: crashMetadataURL,
                    expectedID: crashReady.id,
                    automationDirectory: automationDirectory,
                    quarantineDirectory: quarantineDirectory
                )
                print("TEST INFO: exFAT resumed")
                let restoredOutputPreserved = crashPreparing.restoreMode == "directExclusive"
                    ? crashTemporaryURL.map({ pathEntryExists(at: $0) }) == true
                    : crashTemporaryURL.map({ !pathEntryExists(at: $0) }) == true
                guard try Data(contentsOf: crashSource) == originalData,
                      restoredOutputPreserved,
                      !pathEntryExists(at: crashMetadataURL) else {
                    throw SecureQuarantineError.sourceChanged
                }

                // Replace the published user destination immediately before
                // quarantine-source deletion. The replacement must survive and
                // the verified quarantine payload must remain available.
                print("TEST INFO: exFAT destination replacement")
                let replacementSource = externalTestDirectory
                    .appendingPathComponent("restore-replacement.bin")
                try originalData.write(to: replacementSource)
                try securelyQuarantine(
                    originalURL: replacementSource,
                    signature: "Test.RestoreReplacement",
                    automationDirectory: automationDirectory,
                    quarantineDirectory: quarantineDirectory
                )
                let (replacementMetadataURL, replacementReady) = try metadataRecord(
                    for: replacementSource
                )
                let replacementStoredURL = quarantineDirectory.appendingPathComponent(
                    replacementReady.storedFileName
                )
                let displacedDestination = externalTestDirectory.appendingPathComponent(
                    "restore-displaced-\(UUID().uuidString).bin"
                )
                do {
                    try securelyRestore(
                        metadataURL: replacementMetadataURL,
                        expectedID: replacementReady.id,
                        automationDirectory: automationDirectory,
                        quarantineDirectory: quarantineDirectory,
                        beforeQuarantineSourceDeletion: { destinationURL in
                            let renameResult = destinationURL.path.withCString { sourcePath in
                                displacedDestination.path.withCString { destinationPath in
                                    Darwin.rename(sourcePath, destinationPath)
                                }
                            }
                            guard renameResult == 0 else {
                                throw SecureQuarantineError.sourceChanged
                            }
                            try replacementData.write(
                                to: destinationURL,
                                options: .withoutOverwriting
                            )
                        }
                    )
                    throw SecureQuarantineError.sourceChanged
                } catch SecureQuarantineError.sourceChanged {
                    // Expected safe rejection.
                }
                recoverRestoreTransactionsLocked(quarantineDirectory: quarantineDirectory)
                let replacementRolledBack = try JSONDecoder().decode(
                    QuarantineMetadata.self,
                    from: Data(contentsOf: replacementMetadataURL)
                )
                guard try Data(contentsOf: replacementSource) == replacementData,
                      try Data(contentsOf: displacedDestination) == originalData,
                      pathEntryExists(at: replacementStoredURL),
                      replacementRolledBack.effectiveState == "restorePreparing" else {
                    throw SecureQuarantineError.sourceChanged
                }
            }

            print("TEST OK: app staging race, metadata state, restore ve delete bütünlük kontrolleri güvenli.")
            return 0
        } catch {
            FileHandle.standardError.write(Data("TEST HATA: \(error.localizedDescription)\n".utf8))
            return 1
        }
    }
#endif

}

enum SidebarItem: String, CaseIterable, Identifiable {
    case overview = "Kontrol Paneli"
    case protection = "Live Protection"
    case virusTotal = "VirusTotal"
    case commands = "Komut Merkezi"
    case threats = "Tehditler"
    case quarantine = "Karantina"
    case scans = "Taramalar"

    var id: String { rawValue }

    var icon: String {
        switch self {
        case .overview: return "square.grid.2x2.fill"
        case .protection: return "shield.checkered"
        case .virusTotal: return "network.badge.shield.half.filled"
        case .commands: return "play.circle.fill"
        case .threats: return "exclamationmark.triangle.fill"
        case .quarantine: return "lock.shield.fill"
        case .scans: return "clock.arrow.circlepath"
        }
    }
}

private struct SecurityPageHeader: View {
    let title: String
    let subtitle: String
    let icon: String
    let tint: Color

    var body: some View {
        HStack(alignment: .center, spacing: 14) {
            Image(systemName: icon)
                .font(.system(size: 25, weight: .semibold))
                .foregroundStyle(tint)
                .frame(width: 42, height: 42)
                .background(tint.opacity(0.12), in: RoundedRectangle(cornerRadius: 8))

            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(.system(size: 27, weight: .bold))
                Text(subtitle)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
        .accessibilityElement(children: .combine)
    }
}

private struct SecuritySectionHeader<Accessory: View>: View {
    let title: String
    let subtitle: String?
    let accessory: Accessory

    init(
        _ title: String,
        subtitle: String? = nil,
        @ViewBuilder accessory: () -> Accessory = { EmptyView() }
    ) {
        self.title = title
        self.subtitle = subtitle
        self.accessory = accessory()
    }

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.title3.bold())
                if let subtitle {
                    Text(subtitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Spacer()
            accessory
        }
    }
}

private struct SidebarItemRow: View {
    let item: SidebarItem
    let badge: Int?

    var body: some View {
        HStack(spacing: 9) {
            Image(systemName: item.icon)
                .frame(width: 18)
                .foregroundStyle(item == .overview ? Color.accentColor : .secondary)
            Text(item.rawValue)
            Spacer(minLength: 4)
            if let badge, badge > 0 {
                Text(badge.formatted())
                    .font(.caption2.bold().monospacedDigit())
                    .foregroundStyle(item == .threats ? Color.white : Color.secondary)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(
                        item == .threats ? Color.red : Color.secondary.opacity(0.16),
                        in: Capsule()
                    )
            }
        }
        .tag(item)
    }
}

private extension View {
    func securityCardBackground(accent: Color = .clear, emphasized: Bool = false) -> some View {
        background(
            emphasized ? accent.opacity(0.10) : Color.primary.opacity(0.035),
            in: RoundedRectangle(cornerRadius: 8)
        )
        .overlay {
            RoundedRectangle(cornerRadius: 8)
                .stroke(
                    emphasized ? accent.opacity(0.28) : Color.primary.opacity(0.08),
                    lineWidth: 1
                )
        }
    }
}

private enum MenuServiceHealth {
    case ready
    case attention
    case checking

    var symbol: String {
        switch self {
        case .ready: return "checkmark.circle.fill"
        case .attention: return "exclamationmark.circle.fill"
        case .checking: return "clock.fill"
        }
    }

    var color: Color {
        switch self {
        case .ready: return .green
        case .attention: return .orange
        case .checking: return .secondary
        }
    }
}

private struct MenuServiceSummary {
    let name: String
    let state: String
    let health: MenuServiceHealth
}

private struct MenuServiceStatusLabel: View {
    let summary: MenuServiceSummary

    var body: some View {
        Label {
            Text("\(summary.name): \(summary.state)")
        } icon: {
            Image(systemName: summary.health.symbol)
                .foregroundStyle(summary.health.color)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(summary.name), \(summary.state)")
    }
}

private struct ThreatCenterMenuBarView: View {
    @ObservedObject var store: ThreatStore
    @Environment(\.openWindow) private var openWindow

    private var daemonSummary: MenuServiceSummary {
        if store.clamAVDaemonResponding == true || store.realtimeStatus?.daemonConnected == true {
            return MenuServiceSummary(name: "ClamAV engine", state: "Ready", health: .ready)
        }
        if store.clamAVDaemonResponding != nil || store.realtimeStatus != nil {
            return MenuServiceSummary(name: "ClamAV engine", state: "Not responding", health: .attention)
        }
        return MenuServiceSummary(name: "ClamAV engine", state: "Checking", health: .checking)
    }

    private var realtimeSummary: MenuServiceSummary {
        guard store.realtimeStatus != nil else {
            return MenuServiceSummary(name: "Live protection", state: "Checking", health: .checking)
        }
        return store.isRealtimeProtectionActive
            ? MenuServiceSummary(name: "Live protection", state: "Running", health: .ready)
            : MenuServiceSummary(name: "Live protection", state: "Not responding", health: .attention)
    }

    private var virusTotalSummary: MenuServiceSummary {
        guard let status = store.virusTotalStatus else {
            return MenuServiceSummary(name: "VirusTotal", state: "Checking", health: .checking)
        }
        if !status.apiKeyConfigured {
            return MenuServiceSummary(name: "VirusTotal", state: "API key required", health: .attention)
        }
        return store.isVirusTotalActive
            ? MenuServiceSummary(name: "VirusTotal", state: "Running", health: .ready)
            : MenuServiceSummary(name: "VirusTotal", state: "Not responding", health: .attention)
    }

    private var scanSummary: MenuServiceSummary? {
        guard let progress = store.scanProgressStatus, progress.running else { return nil }
        if progress.phase == "counting" {
            return MenuServiceSummary(name: "Scan", state: "Counting files", health: .checking)
        }
        if let percent = progress.percent, progress.phase == "scanning" {
            return MenuServiceSummary(name: "Scan", state: "%\(Int(percent.rounded(.down))) tamamlandı", health: .checking)
        }
        return MenuServiceSummary(name: "Scan", state: "Running", health: .checking)
    }

    var body: some View {
        MenuServiceStatusLabel(summary: daemonSummary)
        MenuServiceStatusLabel(summary: realtimeSummary)
        MenuServiceStatusLabel(summary: virusTotalSummary)
        if let scanSummary {
            MenuServiceStatusLabel(summary: scanSummary)
        }

        Divider()

        Button {
            openControlPanel()
        } label: {
            Label("Open Dashboard", systemImage: "macwindow")
        }

        Button {
            store.refresh()
        } label: {
            Label("Refresh Status", systemImage: "arrow.clockwise")
        }

        Menu {
            Button {
                store.restartClamAVDaemon()
            } label: {
                Label(
                    store.isRestartingClamAVDaemon ? "Starting ClamAV engine" : "Restart ClamAV Engine",
                    systemImage: "gearshape.2.fill"
                )
            }
            .disabled(store.isRestartingClamAVDaemon)

            Button {
                store.restartRealtimeProtection()
            } label: {
                Label(
                    store.isRestartingProtection ? "Starting live protection" : "Restart Live Protection",
                    systemImage: "shield.checkered"
                )
            }
            .disabled(store.isRestartingProtection)

            Button {
                store.restartVirusTotalService()
            } label: {
                Label(
                    store.isRestartingVirusTotal ? "Starting VirusTotal" : "Restart VirusTotal",
                    systemImage: "network.badge.shield.half.filled"
                )
            }
            .disabled(store.isRestartingVirusTotal)
        } label: {
            Label("Restart Services", systemImage: "arrow.clockwise.circle")
        }

        Divider()

        Button {
            NSApplication.shared.terminate(nil)
        } label: {
            Label("Quit Interface — protection continues", systemImage: "rectangle.portrait.and.arrow.right")
        }
        .keyboardShortcut("q")
        .help("Closes the Threat Center interface; ClamAV and VirusTotal services continue running.")
    }

    private func openControlPanel() {
        openWindow(id: "control-panel")
        DispatchQueue.main.async {
            NSApplication.shared.activate(ignoringOtherApps: true)
            bringExistingControlPanelToFront()
        }
    }
}

@MainActor
@discardableResult
private func bringExistingControlPanelToFront() -> Bool {
    let application = NSApplication.shared
    let windows = application.windows.filter { $0.canBecomeMain && !($0 is NSPanel) }
    let window = windows.first(where: {
        $0.title == "ClamAV Tehdit Merkezi" || $0.title == "Tehdit Merkezi"
    }) ?? windows.first
    guard let window else { return false }
    if window.isMiniaturized { window.deminiaturize(nil) }
    window.makeKeyAndOrderFront(nil)
    return true
}

struct ContentView: View {
    @ObservedObject var store: ThreatStore
    @State private var selection: SidebarItem? = .overview

    var body: some View {
        NavigationSplitView {
            List(selection: $selection) {
                Section("GENEL") {
                    SidebarItemRow(item: .overview, badge: nil)
                }
                Section("KORUMA") {
                    SidebarItemRow(item: .protection, badge: nil)
                    SidebarItemRow(item: .virusTotal, badge: nil)
                }
                Section("ACTIONS") {
                    SidebarItemRow(item: .commands, badge: nil)
                    SidebarItemRow(item: .scans, badge: nil)
                }
                Section("KAYITLAR") {
                    SidebarItemRow(item: .threats, badge: store.threats.filter(\.exists).count)
                    SidebarItemRow(item: .quarantine, badge: store.quarantineItems.count)
                }
            }
            .listStyle(.sidebar)
            .navigationTitle("Tehdit Merkezi")
            .navigationSplitViewColumnWidth(min: 205, ideal: 225)
            .safeAreaInset(edge: .bottom) {
                HStack(spacing: 9) {
                    Circle()
                        .fill(store.isRealtimeProtectionActive ? Color.green : Color.orange)
                        .frame(width: 8, height: 8)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(store.isRealtimeProtectionActive ? "Koruma aktif" : "Dikkat gerekiyor")
                            .font(.caption.bold())
                        Text("Son güncelleme \(store.lastRefresh.formatted(date: .omitted, time: .shortened))")
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                    }
                    Spacer()
                }
                .padding(12)
                .background(.bar)
            }
        } detail: {
            Group {
                switch selection ?? .overview {
                case .overview: OverviewView(store: store, selection: $selection)
                case .protection: LiveProtectionView(store: store)
                case .virusTotal: VirusTotalView(store: store)
                case .commands: CommandCenterView(store: store)
                case .threats: ThreatsView(store: store)
                case .quarantine: QuarantineView(store: store)
                case .scans: ScansView(store: store)
                }
            }
            .toolbar {
                ToolbarItemGroup {
                    Button {
                        store.openLogDirectory()
                    } label: {
                        Image(systemName: "folder")
                    }
                    .help("Open scan logs in Finder")
                    Button {
                        store.refresh()
                    } label: {
                        Image(systemName: "arrow.clockwise")
                    }
                    .keyboardShortcut("r", modifiers: .command)
                    .help("Refresh all statuses")
                }
            }
        }
        .frame(minWidth: 980, minHeight: 680)
    }
}

struct OverviewView: View {
    @ObservedObject var store: ThreatStore
    @Binding var selection: SidebarItem?

    private var activeThreats: [ThreatSummary] { store.threats.filter(\.exists) }
    private var latestScan: ScanRecord? { store.scans.first }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                SecurityPageHeader(
                    title: "Security Dashboard",
                    subtitle: "Shows the current status of your protection.",
                    icon: "shield.lefthalf.filled",
                    tint: bannerColor
                )

                statusBanner

                SecuritySectionHeader("Protection services", subtitle: "Core scanning and monitoring components")

                LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible()), GridItem(.flexible())], spacing: 12) {
                    DashboardServiceCard(
                        title: "ClamAV tarama motoru",
                        status: store.isClamAVDaemonReady ? "Ready" : "Not responding",
                        detail: "Checks file contents against local virus signatures.",
                        icon: "gearshape.2.fill",
                        color: store.isClamAVDaemonReady ? .green : .orange,
                        isRestarting: store.isRestartingClamAVDaemon,
                        message: store.ownedServiceMessage(for: "com.local.clamav.daemon"),
                        restart: store.restartClamAVDaemon
                    )
                    DashboardServiceCard(
                        title: "ClamAV live protection",
                        status: store.isRealtimeProtectionActive ? "Running" : "Not responding",
                        detail: "Automatically checks new and changed files.",
                        icon: "shield.checkered",
                        color: store.isRealtimeProtectionActive ? .green : .orange,
                        isRestarting: store.isRestartingProtection,
                        message: store.ownedServiceMessage(for: "com.local.clamav.realtime"),
                        restart: store.restartRealtimeProtection
                    )
                    DashboardServiceCard(
                        title: "VirusTotal protection",
                        status: virusTotalServiceStatus,
                        detail: virusTotalServiceDetail,
                        icon: "network.badge.shield.half.filled",
                        color: virusTotalServiceColor,
                        isRestarting: store.isRestartingVirusTotal,
                        message: store.ownedServiceMessage(for: "com.local.clamav.virustotal"),
                        restart: store.restartVirusTotalService
                    )
                }

                LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 12), count: 4), spacing: 12) {
                    MetricCard(
                        title: "Live protection",
                        value: store.isRealtimeProtectionActive ? "On" : "Off",
                        icon: store.isRealtimeProtectionActive ? "checkmark.shield.fill" : "shield.slash.fill",
                        color: store.isRealtimeProtectionActive ? .green : .orange
                    )
                    MetricCard(
                        title: "Aktif tehdit",
                        value: activeThreats.count.formatted(),
                        icon: "exclamationmark.shield.fill",
                        color: activeThreats.isEmpty ? .green : .red
                    )
                    MetricCard(
                        title: "Monitored location",
                        value: store.realtimeStatus?.watchedPaths.count.formatted() ?? "—",
                        icon: "folder.badge.gearshape",
                        color: .indigo
                    )
                    MetricCard(
                        title: "Son tarama",
                        value: latestScan.map { $0.date.formatted(date: .omitted, time: .shortened) } ?? "—",
                        icon: "clock.fill",
                        color: .blue
                    )
                }

                SecuritySectionHeader("Protection layers", subtitle: "Apple security and additional behavior protection") {
                    if store.isCheckingProtectionLayers {
                        ProgressView().controlSize(.small)
                        Text("Checking")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }

                LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 12) {
                    ForEach(store.protectionLayers) { layer in
                        ProtectionLayerCard(
                            layer: layer,
                            openApp: store.canOpenProtectionApp(layer.id)
                                ? { store.openProtectionApp(layer.id) }
                                : nil
                        )
                    }
                }

                SecuritySectionHeader("Son tehditler") {
                    Button("View All") { selection = .threats }
                        .buttonStyle(.link)
                }

                if activeThreats.isEmpty {
                    Label("No malicious files were found in completed scans.", systemImage: "checkmark.shield.fill")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .padding(12)
                        .securityCardBackground(accent: .green, emphasized: true)
                } else {
                    VStack(spacing: 10) {
                        ForEach(store.threats.prefix(3)) { threat in
                            ThreatRow(threat: threat) { store.reveal(threat) }
                        }
                    }
                }

                Text("ClamAV \(store.engineVersion) • Son yenileme \(store.lastRefresh.formatted(date: .omitted, time: .standard))")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }
            .padding(28)
        }
    }

    private var statusBanner: some View {
        HStack(spacing: 14) {
            Image(systemName: bannerIcon)
                .font(.system(size: 29, weight: .semibold))
                .foregroundStyle(bannerColor)
                .frame(width: 46, height: 46)
                .background(bannerColor.opacity(0.12), in: RoundedRectangle(cornerRadius: 8))
            VStack(alignment: .leading, spacing: 3) {
                Text(bannerTitle)
                    .font(.title3.bold())
                Text(bannerMessage)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if !activeThreats.isEmpty {
                Button("Review") { selection = .threats }
                    .buttonStyle(.borderedProminent)
                    .tint(.red)
            } else if !store.isRealtimeProtectionActive {
                Button("Review Live Protection") { selection = .protection }
                    .buttonStyle(.borderedProminent)
                    .tint(.orange)
            }
        }
        .padding(16)
        .securityCardBackground(accent: bannerColor, emphasized: true)
    }

    private var bannerColor: Color {
        if !activeThreats.isEmpty { return .red }
        return store.isRealtimeProtectionActive ? .green : .orange
    }

    private var bannerIcon: String {
        if !activeThreats.isEmpty { return "exclamationmark.shield.fill" }
        return store.isRealtimeProtectionActive ? "checkmark.shield.fill" : "shield.slash.fill"
    }

    private var bannerTitle: String {
        if !activeThreats.isEmpty { return "Dikkat gerektiren tehdit var" }
        return store.isRealtimeProtectionActive ? "Canlı koruma açık" : "Canlı koruma çalışmıyor"
    }

    private var bannerMessage: String {
        if !activeThreats.isEmpty {
            return "\(activeThreats.count) tehdit dosyası hâlâ bilgisayarda bulunuyor."
        }
        if store.isRealtimeProtectionActive {
            return "Yeni ve değişen dosyalar otomatik olarak kontrol ediliyor."
        }
        if store.realtimeStatus == nil {
            return "Koruma henüz durum bilgisi göndermedi. Canlı Koruma bölümünü kontrol et."
        }
        return "Koruma bir süredir yanıt vermiyor. Yeniden başlatmayı deneyebilirsin."
    }

    private var virusTotalServiceStatus: String {
        if store.virusTotalStatus?.apiKeyConfigured == false { return "API key required" }
        return store.isVirusTotalActive ? "Running" : "Not responding"
    }

    private var virusTotalServiceDetail: String {
        if store.virusTotalStatus?.apiKeyConfigured == false {
            return "Hash sorguları için VirusTotal API anahtarı bekleniyor."
        }
        if store.virusTotalStatus?.lastResult == "retrying" {
            return "Geçici erişim sorunu var; bekleyen dosyalar otomatik olarak yeniden denenecek."
        }
        return "İndirilen dosyaların hash bilgisini ikinci görüş olarak kontrol eder."
    }

    private var virusTotalServiceColor: Color {
        store.isVirusTotalActive && store.virusTotalStatus?.apiKeyConfigured == true ? .green : .orange
    }
}

struct DashboardServiceCard: View {
    let title: String
    let status: String
    let detail: String
    let icon: String
    let color: Color
    let isRestarting: Bool
    let message: String?
    let restart: () -> Void

    private var isReady: Bool {
        status == "Running" || status == "Ready"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 9) {
            HStack(spacing: 10) {
                Image(systemName: icon)
                    .font(.system(size: 19, weight: .semibold))
                    .foregroundStyle(color)
                    .frame(width: 36, height: 36)
                    .background(color.opacity(0.11), in: RoundedRectangle(cornerRadius: 8))
                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .font(.subheadline.bold())
                    Text(status)
                        .font(.caption.bold())
                        .foregroundStyle(color)
                }
                Spacer()
                Image(systemName: isReady ? "checkmark.circle.fill" : "exclamationmark.circle.fill")
                    .foregroundStyle(color)
            }
            Text(detail)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if let message, !message.isEmpty {
                Text(message)
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                    .lineLimit(2)
            }
            Button(action: restart) {
                if isRestarting {
                    HStack(spacing: 5) {
                        ProgressView().controlSize(.small)
                        Text("Starting").font(.caption)
                    }
                } else {
                    Label("Yeniden başlat", systemImage: "arrow.clockwise")
                        .font(.caption)
                }
            }
            .buttonStyle(.link)
            .disabled(isRestarting)
        }
        .frame(maxWidth: .infinity, minHeight: 154, alignment: .topLeading)
        .padding(14)
        .securityCardBackground(accent: color, emphasized: !isReady)
    }
}

private enum RealtimeEventFilter: String, CaseIterable, Identifiable {
    case all = "Tümü"
    case clean = "Temiz"
    case threats = "Tehdit"
    case problems = "Sorun"

    var id: String { rawValue }

    func matches(_ event: RealtimeProtectionEvent) -> Bool {
        switch self {
        case .all:
            return true
        case .clean:
            return event.result == "clean"
        case .threats:
            return event.result == "infected"
        case .problems:
            return ["error", "skipped", "recovery"].contains(event.result)
        }
    }
}

struct LiveProtectionView: View {
    @ObservedObject var store: ThreatStore
    @State private var searchText = ""
    @State private var eventFilter: RealtimeEventFilter = .all

    private var filteredEvents: [RealtimeProtectionEvent] {
        let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return store.realtimeEvents.filter { event in
            guard eventFilter.matches(event) else { return false }
            guard !query.isEmpty else { return true }
            return event.fileName.lowercased().contains(query)
                || event.path.lowercased().contains(query)
                || (event.signature ?? "").lowercased().contains(query)
                || event.message.lowercased().contains(query)
        }
    }

    private var statusColor: Color {
        store.isRealtimeProtectionActive ? .green : .orange
    }

    private var statusIcon: String {
        store.isRealtimeProtectionActive ? "checkmark.shield.fill" : "shield.slash.fill"
    }

    private var statusTitle: String {
        store.isRealtimeProtectionActive ? "Canlı koruma açık" : "Canlı koruma yanıt vermiyor"
    }

    private var statusDetail: String {
        guard let status = store.realtimeStatus else {
            return "Koruma henüz durum bilgisi göndermedi. Yeniden başlatmayı deneyebilirsin."
        }
        if !status.running {
            return "Dosya izleme hizmeti şu anda çalışmıyor."
        }
        if !status.daemonConnected {
            return "Dosyalar izleniyor ancak tarama motoruna ulaşılamıyor."
        }
        if !store.isRealtimeProtectionActive {
            return "Koruma bir süredir yeni durum bilgisi göndermedi."
        }
        return "Yeni veya değişen dosyalar kaydedildikleri anda otomatik olarak kontrol ediliyor."
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                HStack(alignment: .top) {
                    SecurityPageHeader(
                        title: "Live Protection",
                        subtitle: "Yeni dosyaları kontrol eder ve bulunan tehditleri güvenli alana taşır.",
                        icon: "shield.checkered",
                        tint: statusColor
                    )
                    Button {
                        store.refresh()
                    } label: {
                        Label("Yenile", systemImage: "arrow.clockwise")
                    }
                    .buttonStyle(.bordered)

                    Button {
                        store.restartRealtimeProtection()
                    } label: {
                        if store.isRestartingProtection {
                            HStack(spacing: 7) {
                                ProgressView().controlSize(.small)
                                Text("Starting")
                            }
                        } else {
                            Label("Restart", systemImage: "power")
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(statusColor)
                    .disabled(store.isRestartingProtection)
                }

                HStack(spacing: 14) {
                    Image(systemName: statusIcon)
                        .font(.system(size: 28, weight: .semibold))
                        .foregroundStyle(statusColor)
                        .frame(width: 46, height: 46)
                        .background(statusColor.opacity(0.11), in: RoundedRectangle(cornerRadius: 8))
                    VStack(alignment: .leading, spacing: 4) {
                        Text(statusTitle).font(.headline)
                        Text(statusDetail)
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                        if let heartbeat = store.realtimeStatus?.heartbeatAt {
                            Text("Son haber: \(relativeText(for: heartbeat))")
                                .font(.caption)
                                .foregroundStyle(.tertiary)
                        }
                    }
                    Spacer()
                }
                .padding(15)
                .securityCardBackground(accent: statusColor, emphasized: true)

                if store.realtimeStatus?.reconciliationActive == true {
                    HStack(spacing: 10) {
                        ProgressView().controlSize(.small)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Telafi taraması sürüyor").font(.subheadline.bold())
                            Text("Servis kapalıyken veya olay akışı kesilirken kaçmış olabilecek yakın tarihli dosyalar sıraya alınıyor.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(12)
                    .background(Color.orange.opacity(0.10), in: RoundedRectangle(cornerRadius: 8))
                } else if let lossCount = store.realtimeStatus?.eventLossCount, lossCount > 0 {
                    Label(
                        "Bu oturumda \(lossCount) olay akışı kesintisi algılandı; son telafide \(store.realtimeStatus?.reconciliationQueuedCount ?? 0) dosya sıraya alındı.",
                        systemImage: "arrow.clockwise.circle.fill"
                    )
                    .font(.subheadline)
                    .foregroundStyle(.blue)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(12)
                    .background(Color.blue.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
                }

                if !store.protectionCommandResult.isEmpty {
                    Label(store.protectionCommandResult, systemImage: "info.circle.fill")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(12)
                        .background(Color.blue.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
                }

                LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 12), count: 4), spacing: 12) {
                    MetricCard(
                        title: "Bu oturumda taranan",
                        value: store.realtimeStatus?.scannedCount.formatted() ?? "—",
                        icon: "doc.text.magnifyingglass",
                        color: .blue
                    )
                    MetricCard(
                        title: "Yakalanan tehdit",
                        value: store.realtimeStatus?.threatCount.formatted() ?? "—",
                        icon: "exclamationmark.shield.fill",
                        color: (store.realtimeStatus?.threatCount ?? 0) > 0 ? .red : .green
                    )
                    MetricCard(
                        title: "Monitored location",
                        value: store.realtimeStatus?.watchedPaths.count.formatted() ?? "—",
                        icon: "folder.badge.gearshape",
                        color: .indigo
                    )
                    MetricCard(
                        title: "Tarama motoru",
                        value: store.realtimeStatus?.daemonConnected == true ? "Ready" : "Bağlantı yok",
                        icon: "gearshape.2.fill",
                        color: store.realtimeStatus?.daemonConnected == true ? .green : .orange
                    )
                }

                watchedLocations

                SecuritySectionHeader("Protection layers", subtitle: "Mac'in yerleşik güvenliği ve ek koruma araçları") {
                    if store.isCheckingProtectionLayers {
                        ProgressView().controlSize(.small)
                        Text("Checking")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }

                LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 12) {
                    ForEach(store.protectionLayers) { layer in
                        ProtectionLayerCard(layer: layer)
                    }
                }

                SecuritySectionHeader("Live events", subtitle: "Filter recent records by file name, path or signature") {
                    Text("Up to 50 records")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                HStack(spacing: 10) {
                    Image(systemName: "magnifyingglass")
                        .foregroundStyle(.secondary)
                    TextField("Dosya, yol veya imza ara", text: $searchText)
                        .textFieldStyle(.plain)
                    if !searchText.isEmpty {
                        Button {
                            searchText = ""
                        } label: {
                            Image(systemName: "xmark.circle.fill")
                                .foregroundStyle(.secondary)
                        }
                        .buttonStyle(.plain)
                    }
                    Divider()
                    Picker("Event type", selection: $eventFilter) {
                        ForEach(RealtimeEventFilter.allCases) { filter in
                            Text(filter.rawValue).tag(filter)
                        }
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                    .frame(width: 330)
                }
                .padding(.horizontal, 12)
                .frame(height: 38)
                .securityCardBackground()

                if filteredEvents.isEmpty {
                    EmptyState(
                        icon: "checkmark.shield.fill",
                        title: store.realtimeEvents.isEmpty ? "No events yet" : "No matching events",
                        message: store.realtimeEvents.isEmpty
                            ? "Results appear here when a new file is checked."
                            : "Change the search or event filter and try again."
                    )
                } else {
                    LazyVStack(spacing: 8) {
                        ForEach(filteredEvents.prefix(50)) { event in
                            RealtimeEventRow(event: event)
                        }
                    }
                }

                Text("Live protection checks files after they are saved to disk. Quarantined files appear in Quarantine.")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }
            .padding(28)
        }
    }

    private var watchedLocations: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Monitored locations")
                .font(.headline)

            if let paths = store.realtimeStatus?.watchedPaths, !paths.isEmpty {
                ForEach(paths, id: \.self) { path in
                    HStack(spacing: 12) {
                        Image(systemName: path == "/Volumes" ? "externaldrive.fill" : "folder.fill")
                            .foregroundStyle(.blue)
                            .frame(width: 24)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(locationName(for: path)).font(.subheadline.bold())
                            Text(path)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                        Spacer()
                        Image(systemName: "eye.fill")
                            .foregroundStyle(.green)
                    }
                }
            } else {
                Text("Monitored locations are not available yet.")
                    .foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .securityCardBackground(accent: .blue)
    }

    private func locationName(for path: String) -> String {
        if path == "/Volumes" { return "USB ve harici diskler" }
        switch URL(fileURLWithPath: path).lastPathComponent {
        case "Desktop": return "Desktop"
        case "Downloads": return "Downloads"
        case "Documents": return "Belgeler"
        default:
            let name = URL(fileURLWithPath: path).lastPathComponent
            return name.isEmpty ? path : name
        }
    }

    private func relativeText(for date: Date) -> String {
        let formatter = RelativeDateTimeFormatter()
        formatter.locale = Locale(identifier: "tr_TR")
        formatter.unitsStyle = .full
        return formatter.localizedString(for: date, relativeTo: Date())
    }
}

struct VirusTotalView: View {
    @ObservedObject var store: ThreatStore

    private var statusColor: Color {
        store.isVirusTotalActive && store.virusTotalStatus?.apiKeyConfigured == true ? .green : .orange
    }

    private var statusTitle: String {
        guard let status = store.virusTotalStatus else { return "VirusTotal durumu bekleniyor" }
        if !status.apiKeyConfigured { return "VirusTotal API key required" }
        return store.isVirusTotalActive ? "VirusTotal protection is running" : "VirusTotal protection is not responding"
    }

    private var statusDetail: String {
        guard let status = store.virusTotalStatus else {
            return "No status has been received from the background service yet."
        }
        if !status.apiKeyConfigured {
            return "Add a VirusTotal API key to the local configuration to check hashes."
        }
        if status.lastResult == "retrying" {
            return "VirusTotal is currently unavailable; queued files will be retried automatically."
        }
        if status.lastError != nil {
            return "The last check failed; the service can be restarted."
        }
        return store.isVirusTotalActive
            ? "Downloaded file hashes and quarantined files are automatically checked for a second opinion."
            : "The service has not reported its status recently."
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                HStack(alignment: .top) {
                    SecurityPageHeader(
                        title: "VirusTotal",
                        subtitle: "Cloud-based second opinions, privacy controls and recent file results.",
                        icon: "network.badge.shield.half.filled",
                        tint: statusColor
                    )
                    Button {
                        store.refresh()
                    } label: {
                        Label("Yenile", systemImage: "arrow.clockwise")
                    }
                    .buttonStyle(.bordered)
                    Button {
                        store.restartVirusTotalService()
                    } label: {
                        if store.isRestartingVirusTotal {
                            HStack(spacing: 7) {
                                ProgressView().controlSize(.small)
                                Text("Starting")
                            }
                        } else {
                            Label("Restart", systemImage: "power")
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(statusColor)
                    .disabled(store.isRestartingVirusTotal)
                }

                HStack(spacing: 14) {
                    Image(systemName: store.isVirusTotalActive ? "checkmark.shield.fill" : "network.slash")
                        .font(.system(size: 28, weight: .semibold))
                        .foregroundStyle(statusColor)
                        .frame(width: 46, height: 46)
                        .background(statusColor.opacity(0.11), in: RoundedRectangle(cornerRadius: 8))
                    VStack(alignment: .leading, spacing: 4) {
                        Text(statusTitle).font(.headline)
                        Text(statusDetail)
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                        if let heartbeat = store.virusTotalStatus?.heartbeatAt,
                           heartbeat != .distantPast {
                            Text("Son haber: \(relativeText(for: heartbeat))")
                                .font(.caption)
                                .foregroundStyle(.tertiary)
                        }
                    }
                    Spacer()
                }
                .padding(15)
                .securityCardBackground(accent: statusColor, emphasized: true)

                if let message = store.ownedServiceMessage(for: "com.local.clamav.virustotal") {
                    Label(message, systemImage: "info.circle.fill")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(12)
                        .background(Color.blue.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
                }

                LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 12), count: 4), spacing: 12) {
                    MetricCard(
                        title: "Kontrol edilen",
                        value: store.virusTotalStatus?.checkedCount.formatted() ?? "—",
                        icon: "number.circle.fill",
                        color: .blue
                    )
                    MetricCard(
                        title: "Uploaded",
                        value: store.virusTotalStatus?.uploadedCount.formatted() ?? "—",
                        icon: "icloud.and.arrow.up.fill",
                        color: .indigo
                    )
                    MetricCard(
                        title: "Threat warning",
                        value: store.virusTotalStatus?.threatCount.formatted() ?? "—",
                        icon: "exclamationmark.shield.fill",
                        color: (store.virusTotalStatus?.threatCount ?? 0) > 0 ? .red : .green
                    )
                    MetricCard(
                        title: "Bekleyen",
                        value: store.virusTotalStatus?.queueDepth.formatted() ?? "—",
                        icon: "clock.badge.fill",
                        color: (store.virusTotalStatus?.queueDepth ?? 0) > 0 ? .orange : .green
                    )
                }

                privacyCard
                manualScanCard

                SecuritySectionHeader("Recent VirusTotal results") {
                    Text("Son \(min(store.virusTotalResults.count, 50)) kayıt")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                if store.virusTotalResults.isEmpty {
                    EmptyState(
                        icon: "network.badge.shield.half.filled",
                        title: "No VirusTotal results yet",
                        message: "Results appear here when a download or manual hash lookup completes."
                    )
                } else {
                    LazyVStack(spacing: 10) {
                        ForEach(store.virusTotalResults.prefix(50)) { result in
                            VirusTotalResultRow(result: result) {
                                store.openVirusTotalReport(result)
                            }
                        }
                    }
                }

                Text(store.virusTotalStatus?.autoUploadQuarantine == true
                     ? "Karantinadaki dosyaların önce SHA-256 değeri sorgulanır; VirusTotal'da bilinmiyorsa dosyanın bir kopyası otomatik gönderilir. Normal indirilen bilinmeyen dosyalar otomatik yüklenmez."
                     : "Hash sorgusu dosyanın kendisini göndermez. Karantina dahil hiçbir dosya otomatik yüklenmez; yalnız açıkça onaylarsan dosya gönderilir.")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }
            .padding(28)
        }
        .confirmationDialog(
            "Upload file to VirusTotal?",
            isPresented: Binding(
                get: { store.pendingVirusTotalUpload != nil },
                set: { if !$0, store.pendingVirusTotalUpload != nil { store.cancelVirusTotalUpload() } }
            ),
            titleVisibility: .visible
        ) {
            Button("Agree and Upload") { store.confirmVirusTotalUpload() }
            Button("Cancel", role: .cancel) { store.cancelVirusTotalUpload() }
        } message: {
            Text("VirusTotal does not recognize this file. Uploading sends a copy for analysis under the service’s sharing rules.")
        }
    }

    private var privacyCard: some View {
        let hasStatus = store.virusTotalStatus != nil
        let automatic = store.virusTotalStatus?.autoUploadQuarantine == true
        let color: Color = hasStatus ? (automatic ? .orange : .green) : .blue
        return HStack(spacing: 14) {
            Image(systemName: hasStatus ? (automatic ? "exclamationmark.lock.fill" : "hand.raised.fill") : "clock.fill")
                .font(.system(size: 27))
                .foregroundStyle(color)
                .frame(width: 34)
            VStack(alignment: .leading, spacing: 4) {
                Text(hasStatus ? (automatic ? "Automatic quarantine analysis enabled" : "Privacy mode enabled") : "Waiting for privacy status")
                    .font(.headline)
                Text(!hasStatus
                     ? "The automatic upload setting appears here when service status is available."
                     : automatic
                        ? "Quarantined files are checked by hash first; unknown files are uploaded automatically. Other unknown files require approval."
                        : "Unknown files, including quarantined files, are not uploaded automatically. Manual uploads require approval.")
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Label(
                !hasStatus ? "Waiting for status" : store.virusTotalStatus?.apiKeyConfigured == true ? "API key configured" : "No API key",
                systemImage: !hasStatus ? "clock.fill" : store.virusTotalStatus?.apiKeyConfigured == true ? "key.fill" : "key.slash.fill"
            )
            .font(.caption.bold())
            .foregroundStyle(!hasStatus ? .blue : store.virusTotalStatus?.apiKeyConfigured == true ? .green : .orange)
        }
        .padding(16)
        .securityCardBackground(accent: color, emphasized: automatic)
    }

    private var manualScanCard: some View {
        HStack(spacing: 15) {
            Image(systemName: "doc.text.magnifyingglass")
                .font(.system(size: 28))
                .foregroundStyle(.blue)
                .frame(width: 36)
            VStack(alignment: .leading, spacing: 4) {
                Text("Check file with VirusTotal")
                    .font(.headline)
                Text(store.virusTotalManualMessage)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button {
                store.chooseVirusTotalFile()
            } label: {
                if store.isVirusTotalManualScanRunning {
                    HStack(spacing: 7) {
                        ProgressView().controlSize(.small)
                        Text("Checking")
                    }
                } else {
                    Label("Choose File", systemImage: "doc.badge.plus")
                }
            }
            .buttonStyle(.borderedProminent)
            .disabled(store.isVirusTotalManualScanRunning || store.virusTotalStatus?.apiKeyConfigured == false)
        }
        .padding(16)
        .securityCardBackground(accent: .blue)
    }

    private func relativeText(for date: Date) -> String {
        let formatter = RelativeDateTimeFormatter()
        formatter.locale = Locale(identifier: "tr_TR")
        formatter.unitsStyle = .full
        return formatter.localizedString(for: date, relativeTo: Date())
    }
}

struct VirusTotalResultRow: View {
    let result: VirusTotalResult
    let openReport: () -> Void

    var body: some View {
        HStack(spacing: 13) {
            Image(systemName: result.statusIcon)
                .font(.system(size: 23))
                .foregroundStyle(result.statusColor)
                .frame(width: 30)
            VStack(alignment: .leading, spacing: 4) {
                Text(result.fileName).font(.headline)
                HStack(spacing: 7) {
                    Text(result.statusText)
                        .font(.subheadline.bold())
                        .foregroundStyle(result.statusColor)
                    if result.riskCount > 0 {
                        Text("• \(result.malicious) zararlı, \(result.suspicious) şüpheli")
                            .font(.subheadline)
                            .foregroundStyle(.red)
                    }
                    if result.uploaded {
                        Label("Uploaded", systemImage: "icloud.and.arrow.up.fill")
                            .font(.caption)
                            .foregroundStyle(.indigo)
                    }
                    if result.quarantinedTo != nil {
                        Label("Karantinada", systemImage: "lock.shield.fill")
                            .font(.caption)
                            .foregroundStyle(.orange)
                    }
                    if result.source == "quarantine-auto" {
                        Label("Karantinadan otomatik", systemImage: "arrow.triangle.2.circlepath")
                            .font(.caption)
                            .foregroundStyle(.blue)
                    }
                }
                Text(result.path)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                if let errorMessage = result.errorMessage, !errorMessage.isEmpty {
                    Text(errorMessage)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.tail)
                }
                if !result.sha256.isEmpty {
                    Text("SHA-256: \(result.sha256.prefix(22))…")
                        .font(.caption2.monospaced())
                        .foregroundStyle(.tertiary)
                }
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 7) {
                if result.timestamp != .distantPast {
                    Text(result.timestamp.formatted(date: .abbreviated, time: .shortened))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                if result.reportURL != nil {
                    Button("Open Report", action: openReport)
                        .buttonStyle(.bordered)
                }
            }
        }
        .padding(14)
        .securityCardBackground(accent: result.statusColor, emphasized: result.riskCount > 0)
    }
}

struct ProtectionLayerCard: View {
    let layer: ProtectionLayerStatus
    var openApp: (() -> Void)? = nil

    private var color: Color {
        switch layer.health {
        case .active: return .green
        case .attention: return .orange
        case .missing: return .secondary
        case .checking: return .blue
        }
    }

    private var badgeIcon: String {
        switch layer.health {
        case .active: return "checkmark.circle.fill"
        case .attention: return "exclamationmark.circle.fill"
        case .missing: return "minus.circle.fill"
        case .checking: return "clock.fill"
        }
    }

    var body: some View {
        HStack(alignment: .top, spacing: 11) {
            Image(systemName: layer.icon)
                .font(.system(size: 20, weight: .semibold))
                .foregroundStyle(color)
                .frame(width: 34, height: 34)
                .background(color.opacity(0.10), in: RoundedRectangle(cornerRadius: 8))
            VStack(alignment: .leading, spacing: 3) {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text(layer.name).font(.subheadline.bold())
                    Spacer()
                    Label(layer.statusText, systemImage: badgeIcon)
                        .font(.caption.bold())
                        .foregroundStyle(color)
                }
                Text(layer.detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if let openApp {
                    Button("Open Application", action: openApp)
                        .font(.caption)
                        .buttonStyle(.link)
                }
            }
        }
        .frame(maxWidth: .infinity, minHeight: 68, alignment: .topLeading)
        .padding(12)
        .securityCardBackground(accent: color, emphasized: layer.health != .active)
    }
}

struct RealtimeEventRow: View {
    let event: RealtimeProtectionEvent

    var body: some View {
        HStack(spacing: 11) {
            Image(systemName: event.resultIcon)
                .font(.system(size: 19, weight: .semibold))
                .foregroundStyle(event.resultColor)
                .frame(width: 32, height: 32)
                .background(event.resultColor.opacity(0.10), in: RoundedRectangle(cornerRadius: 8))
            VStack(alignment: .leading, spacing: 2) {
                Text(event.fileName).font(.subheadline.bold())
                HStack(spacing: 5) {
                    Text(event.resultText)
                        .font(.caption.bold())
                        .foregroundStyle(event.resultColor)
                    if let signature = event.signature, !signature.isEmpty {
                        Text("• \(signature)")
                            .font(.caption.monospaced())
                            .foregroundStyle(.red)
                    }
                }
                Text(event.path)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 2) {
                Text(event.timestamp.formatted(date: .abbreviated, time: .shortened))
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                Text(event.message)
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                    .lineLimit(1)
                    .frame(maxWidth: 180, alignment: .trailing)
            }
        }
        .padding(11)
        .securityCardBackground(accent: event.resultColor, emphasized: event.result == "infected")
    }
}

struct ThreatsView: View {
    @ObservedObject var store: ThreatStore
    @State private var searchText = ""
    @State private var pendingQuarantine: ThreatSummary?
    @State private var operationMessage: String?
    @State private var isOperationRunning = false

    private var filteredThreats: [ThreatSummary] {
        let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !query.isEmpty else { return store.threats }
        return store.threats.filter {
            $0.path.lowercased().contains(query) || $0.signature.lowercased().contains(query)
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            SecurityPageHeader(
                title: "Tehditler",
                subtitle: "Files detected by ClamAV; no files are deleted automatically.",
                icon: "exclamationmark.triangle.fill",
                tint: .red
            )

            if !store.threats.isEmpty {
                HStack(spacing: 8) {
                    Image(systemName: "magnifyingglass")
                        .foregroundStyle(.secondary)
                    TextField("Dosya yolu veya imza ara", text: $searchText)
                        .textFieldStyle(.plain)
                    if !searchText.isEmpty {
                        Button {
                            searchText = ""
                        } label: {
                            Image(systemName: "xmark.circle.fill")
                                .foregroundStyle(.secondary)
                        }
                        .buttonStyle(.plain)
                    }
                }
                .padding(.horizontal, 12)
                .frame(height: 38)
                .securityCardBackground()
            }

            if filteredThreats.isEmpty {
                EmptyState(
                    icon: "checkmark.shield.fill",
                    title: store.threats.isEmpty ? "No threats found" : "No matching threats",
                    message: store.threats.isEmpty
                        ? "No threats were recorded in scan logs."
                        : "Aramaya dosya yolu veya imza yazarak tekrar bak."
                )
            } else {
                ScrollView {
                    LazyVStack(spacing: 8) {
                        ForEach(filteredThreats) { threat in
                            ThreatRow(
                                threat: threat,
                                reveal: { store.reveal(threat) },
                                quarantine: threat.exists && !isOperationRunning
                                    ? { pendingQuarantine = threat }
                                    : nil
                            )
                        }
                    }
                }
            }
        }
        .padding(28)
        .confirmationDialog(
            "Move this file to quarantine?",
            isPresented: Binding(
                get: { pendingQuarantine != nil },
                set: { if !$0 { pendingQuarantine = nil } }
            ),
            titleVisibility: .visible
        ) {
            Button("Karantinaya Al") {
                if let threat = pendingQuarantine {
                    isOperationRunning = true
                    Task {
                        operationMessage = await store.quarantine(threat)
                            ?? "The file was moved to quarantine."
                        isOperationRunning = false
                    }
                }
                pendingQuarantine = nil
            }
            .disabled(isOperationRunning)
            Button("Cancel", role: .cancel) { pendingQuarantine = nil }
        } message: {
            Text("The file will be moved from its original location and can be restored from Quarantine.")
        }
        .alert("ClamAV", isPresented: Binding(
            get: { operationMessage != nil },
            set: { if !$0 { operationMessage = nil } }
        )) {
            Button("Tamam") { operationMessage = nil }
        } message: {
            Text(operationMessage ?? "")
        }
    }
}

struct ThreatRow: View {
    let threat: ThreatSummary
    let reveal: () -> Void
    var quarantine: (() -> Void)? = nil

    var body: some View {
        HStack(spacing: 14) {
            Image(systemName: threat.exists ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                .font(.system(size: 25))
                .foregroundStyle(threat.exists ? .red : .green)
                .frame(width: 34)
            VStack(alignment: .leading, spacing: 5) {
                Text(URL(fileURLWithPath: threat.path).lastPathComponent)
                    .font(.headline)
                Text(threat.signature)
                    .font(.subheadline.monospaced())
                    .foregroundStyle(.red)
                Text(threat.path)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 5) {
                Text(threat.exists ? "File exists" : "File removed")
                    .font(.caption.bold())
                    .foregroundStyle(threat.exists ? .red : .green)
                Text("Son görülme: \(threat.lastSeen.formatted(date: .abbreviated, time: .shortened))")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text("\(threat.detectionCount) kez bulundu")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            VStack(spacing: 7) {
                Button("Show in Finder", action: reveal)
                    .buttonStyle(.bordered)
                if let quarantine {
                    Button("Karantinaya Al", action: quarantine)
                        .buttonStyle(.borderedProminent)
                        .tint(.orange)
                }
            }
        }
        .padding(16)
        .securityCardBackground(accent: threat.exists ? .red : .green, emphasized: threat.exists)
    }
}

struct ActiveScanProgressCard: View {
    let status: ScanProgressStatus

    private var fraction: Double? {
        guard status.phase == "scanning", let percent = status.percent else { return nil }
        return min(1, max(0, percent / 100))
    }

    private var phaseText: String {
        switch status.phase {
        case "counting": return "Counting files"
        case "scanning": return "Scan in progress"
        case "legacy": return "Previous scan in progress"
        default: return status.message
        }
    }

    private var elapsedText: String {
        "Geçen: \(formatDuration(max(0, Int(Date().timeIntervalSince(status.startedAt)))))"
    }

    private var remainingText: String {
        if status.isLegacy { return "Time remaining: unavailable for this scan" }
        if status.phase == "counting" { return "Time remaining: calculated after counting" }
        guard let remaining = status.estimatedSecondsRemaining else { return "Calculating time remaining…" }
        if remaining <= 5 { return "Almost finished" }
        return "Tahmini kalan: \(formatDuration(remaining))"
    }

    private var countText: String? {
        guard status.totalFiles > 0 else { return nil }
        return "\(status.scannedFiles.formatted()) / \(status.totalFiles.formatted()) dosya"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 12) {
                Image(systemName: "doc.text.magnifyingglass")
                    .font(.system(size: 28))
                    .foregroundStyle(.blue)
                VStack(alignment: .leading, spacing: 3) {
                    Text(status.title).font(.headline)
                    Text(phaseText).font(.subheadline).foregroundStyle(.secondary)
                }
                Spacer()
                if let percent = status.percent, status.phase == "scanning" {
                    Text("%\(Int(percent.rounded(.down)))")
                        .font(.title2.bold().monospacedDigit())
                        .foregroundStyle(.blue)
                } else {
                    ProgressView().controlSize(.small)
                }
            }

            if let fraction {
                ProgressView(value: fraction)
                    .progressViewStyle(.linear)
                    .tint(.blue)
            } else {
                ProgressView()
                    .progressViewStyle(.linear)
                    .tint(.blue)
            }

            HStack {
                if let countText { Text(countText) }
                Text(elapsedText)
                Spacer()
                Text(remainingText)
            }
            .font(.caption.monospacedDigit())
            .foregroundStyle(.secondary)

            if status.infectedFiles > 0 || status.errorCount > 0 {
                HStack(spacing: 12) {
                    if status.infectedFiles > 0 {
                        Label("\(status.infectedFiles) tehdit", systemImage: "exclamationmark.shield.fill")
                            .foregroundStyle(.red)
                    }
                    if status.errorCount > 0 {
                        Label("\(status.errorCount) erişim uyarısı", systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                    }
                }
                .font(.caption.bold())
            }

            if let excluded = status.excludedCount, excluded > 0 {
                Label("\(excluded.formatted()) yinelenen veya gereksiz klasör atlandı", systemImage: "bolt.fill")
                    .font(.caption)
                    .foregroundStyle(.green)
            }

            if let path = status.currentPath, !path.isEmpty {
                Text("Şu anda: \(path)")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            } else if status.isLegacy {
                Text("New scans automatically show file count, progress and time remaining.")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }
        }
        .padding(16)
        .securityCardBackground(accent: .blue, emphasized: true)
    }

    private func formatDuration(_ seconds: Int) -> String {
        let days = seconds / 86_400
        let hours = (seconds % 86_400) / 3_600
        let minutes = (seconds % 3_600) / 60
        if days > 0 { return "\(days) gün \(hours) sa" }
        if hours > 0 { return "\(hours) sa \(minutes) dk" }
        if minutes > 0 { return "\(minutes) dk" }
        return "\(max(0, seconds)) sn"
    }
}

struct CommandCenterView: View {
    @ObservedObject var store: ThreatStore
    @State private var confirmFullScan = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                SecurityPageHeader(
                    title: "Komut Merkezi",
                    subtitle: "Run ClamAV scans and updates.",
                    icon: "play.circle.fill",
                    tint: .blue
                )

                if let progress = store.scanProgressStatus, progress.running {
                    ActiveScanProgressCard(status: progress)
                } else if store.isCommandRunning {
                    ProgressView("\(store.activeCommand) başlatılıyor…")
                        .padding(16)
                }

                LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 14) {
                    CommandActionCard(
                        icon: "bolt.shield.fill",
                        color: .blue,
                        title: "Quick Scan",
                        detail: "Scan the Desktop and Downloads folders.",
                        buttonTitle: "Start Scan",
                        disabled: store.isAnyScanRunning,
                        action: store.runQuickScan
                    )
                    CommandActionCard(
                        icon: "doc.badge.magnifyingglass",
                        color: .indigo,
                        title: "Scan File or Folder",
                        detail: "Choose the items you want to scan.",
                        buttonTitle: "Choose Items",
                        disabled: store.isAnyScanRunning,
                        action: store.chooseAndScan
                    )
                    CommandActionCard(
                        icon: "externaldrive.badge.checkmark",
                        color: .orange,
                        title: "Full Scan",
                        detail: "Scan documents, media, Desktop and Downloads.",
                        buttonTitle: "Start Full Scan",
                        disabled: store.isAnyScanRunning,
                        action: { confirmFullScan = true }
                    )
                    CommandActionCard(
                        icon: "arrow.triangle.2.circlepath.circle.fill",
                        color: .purple,
                        title: "Update Virus Signatures",
                        detail: "Update the ClamAV threat database now.",
                        buttonTitle: "Update Now",
                        disabled: store.isAnyScanRunning,
                        action: store.updateSignatures
                    )
                }

                VStack(alignment: .leading, spacing: 8) {
                    Label("Son komut sonucu", systemImage: "terminal.fill")
                        .font(.headline)
                    Text(store.commandResult)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(16)
                .securityCardBackground(accent: .blue)

                Text("Only one scan runs at a time. Files containing threats are not automatically deleted; they can be quarantined from the Threats section.")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }
            .padding(28)
        }
        .confirmationDialog(
            "Start a full scan?",
            isPresented: $confirmFullScan,
            titleVisibility: .visible
        ) {
            Button("Start Scan") { store.runFullScan() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This may take a long time if there are many files.")
        }
    }
}

struct CommandActionCard: View {
    let icon: String
    let color: Color
    let title: String
    let detail: String
    let buttonTitle: String
    let disabled: Bool
    let action: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Image(systemName: icon)
                .font(.system(size: 28))
                .foregroundStyle(color)
            VStack(alignment: .leading, spacing: 5) {
                Text(title).font(.headline)
                Text(detail)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 4)
            Button(buttonTitle, action: action)
                .buttonStyle(.borderedProminent)
                .tint(color)
                .disabled(disabled)
        }
        .frame(maxWidth: .infinity, minHeight: 142, alignment: .leading)
        .padding(15)
        .securityCardBackground(accent: color)
    }
}

struct QuarantineView: View {
    @ObservedObject var store: ThreatStore
    @State private var searchText = ""
    @State private var pendingRestore: QuarantineItem?
    @State private var pendingDelete: QuarantineItem?
    @State private var operationMessage: String?
    @State private var isOperationRunning = false

    private var filteredQuarantineItems: [QuarantineItem] {
        let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !query.isEmpty else { return store.quarantineItems }
        return store.quarantineItems.filter {
            $0.fileName.lowercased().contains(query)
                || $0.metadata.originalPath.lowercased().contains(query)
                || $0.metadata.signature.lowercased().contains(query)
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            SecurityPageHeader(
                title: "Karantina",
                subtitle: "Isolated files are kept here so they cannot be executed.",
                icon: "lock.shield.fill",
                tint: .orange
            )

            if !store.quarantineItems.isEmpty {
                HStack(spacing: 8) {
                    Image(systemName: "magnifyingglass")
                        .foregroundStyle(.secondary)
                    TextField("Dosya, konum veya imza ara", text: $searchText)
                        .textFieldStyle(.plain)
                    if !searchText.isEmpty {
                        Button {
                            searchText = ""
                        } label: {
                            Image(systemName: "xmark.circle.fill")
                                .foregroundStyle(.secondary)
                        }
                        .buttonStyle(.plain)
                    }
                }
                .padding(.horizontal, 12)
                .frame(height: 38)
                .securityCardBackground()
            }

            if filteredQuarantineItems.isEmpty {
                EmptyState(
                    icon: "lock.shield.fill",
                    title: store.quarantineItems.isEmpty ? "Quarantine is empty" : "No matching records",
                    message: store.quarantineItems.isEmpty
                        ? "No files have been quarantined yet."
                        : "Aramaya dosya, konum veya imza yazarak tekrar bak."
                )
            } else {
                ScrollView {
                    LazyVStack(spacing: 8) {
                        ForEach(filteredQuarantineItems) { item in
                            HStack(spacing: 14) {
                                Image(systemName: "lock.shield.fill")
                                    .font(.system(size: 25))
                                    .foregroundStyle(.orange)
                                    .frame(width: 34)
                                VStack(alignment: .leading, spacing: 5) {
                                    Text(item.fileName).font(.headline)
                                    Text(item.metadata.signature)
                                        .font(.subheadline.monospaced())
                                        .foregroundStyle(.orange)
                                    if item.isPreparing {
                                        Label("Operation finishing; actions are temporarily locked", systemImage: "clock.badge.exclamationmark")
                                            .font(.caption)
                                            .foregroundStyle(.orange)
                                    }
                                    Text("Özgün konum: \(item.metadata.originalPath)")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                        .lineLimit(1)
                                        .truncationMode(.middle)
                                }
                                Spacer()
                                VStack(alignment: .trailing, spacing: 7) {
                                    Text(item.metadata.quarantinedAt.formatted(date: .abbreviated, time: .shortened))
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                    HStack(spacing: 7) {
                                        Button("Restore") { pendingRestore = item }
                                            .buttonStyle(.bordered)
                                        Button("Delete Permanently", role: .destructive) { pendingDelete = item }
                                            .buttonStyle(.bordered)
                                    }
                                    .disabled(!item.isActionable || isOperationRunning)
                                }
                            }
                            .padding(16)
                            .securityCardBackground(accent: .orange, emphasized: item.isPreparing)
                        }
                    }
                }
            }
        }
        .padding(28)
        .confirmationDialog(
            "Restore this file?",
            isPresented: Binding(
                get: { pendingRestore != nil },
                set: { if !$0 { pendingRestore = nil } }
            ),
            titleVisibility: .visible
        ) {
            Button("Restore") {
                if let item = pendingRestore {
                    isOperationRunning = true
                    Task {
                        operationMessage = await store.restore(item)
                            ?? "The file was restored to its original location."
                        isOperationRunning = false
                    }
                }
                pendingRestore = nil
            }
            .disabled(isOperationRunning)
            Button("Cancel", role: .cancel) { pendingRestore = nil }
        } message: {
            Text("The file is rescanned with current signatures first. If a threat is detected, it remains in quarantine.")
        }
        .confirmationDialog(
            "Permanently delete this file?",
            isPresented: Binding(
                get: { pendingDelete != nil },
                set: { if !$0 { pendingDelete = nil } }
            ),
            titleVisibility: .visible
        ) {
            Button("Delete Permanently", role: .destructive) {
                if let item = pendingDelete {
                    isOperationRunning = true
                    Task {
                        operationMessage = await store.permanentlyDelete(item)
                            ?? "The file was permanently deleted from quarantine."
                        isOperationRunning = false
                    }
                }
                pendingDelete = nil
            }
            .disabled(isOperationRunning)
            Button("Cancel", role: .cancel) { pendingDelete = nil }
        } message: {
            Text("This cannot be undone. Only the verified quarantined payload is deleted.")
        }
        .alert("ClamAV", isPresented: Binding(
            get: { operationMessage != nil },
            set: { if !$0 { operationMessage = nil } }
        )) {
            Button("Tamam") { operationMessage = nil }
        } message: {
            Text(operationMessage ?? "")
        }
    }
}

struct ScansView: View {
    @ObservedObject var store: ThreatStore

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            SecurityPageHeader(
                title: "Scan History",
                subtitle: "Recent automatic and right-click scan results.",
                icon: "clock.arrow.circlepath",
                tint: .indigo
            )

            if let progress = store.scanProgressStatus, progress.running {
                ActiveScanProgressCard(status: progress)
            }

            Table(store.scans) {
                TableColumn("Durum") { scan in
                    Label(scan.statusText, systemImage: scan.infectedFiles > 0 ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                        .foregroundStyle(scan.statusColor)
                }
                .width(min: 130, ideal: 150)

                TableColumn("Tarih") { scan in
                    Text(scan.date.formatted(date: .abbreviated, time: .shortened))
                }
                .width(min: 145, ideal: 170)

                TableColumn("Type") { scan in Text(scan.source) }
                    .width(min: 130, ideal: 160)

                TableColumn("Taranan") { scan in Text(scan.scannedFiles.formatted()) }
                    .width(min: 80, ideal: 90)

                TableColumn("Tehdit") { scan in Text(scan.infectedFiles.formatted()) }
                    .width(min: 65, ideal: 75)

                TableColumn("Log") { scan in
                    Button("Open") { store.openLog(scan.logURL) }
                        .buttonStyle(.link)
                }
                .width(55)
            }
        }
        .padding(28)
    }
}

struct MetricCard: View {
    let title: String
    let value: String
    let icon: String
    let color: Color

    var body: some View {
        HStack(spacing: 11) {
            Image(systemName: icon)
                .font(.system(size: 18, weight: .semibold))
                .foregroundStyle(color)
                .frame(width: 34, height: 34)
                .background(color.opacity(0.10), in: RoundedRectangle(cornerRadius: 8))
            VStack(alignment: .leading, spacing: 1) {
                Text(value)
                    .font(.headline.monospacedDigit())
                    .lineLimit(1)
                    .minimumScaleFactor(0.65)
                Text(title)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, minHeight: 66, alignment: .leading)
        .padding(11)
        .securityCardBackground(accent: color)
    }
}

struct EmptyState: View {
    let icon: String
    let title: String
    let message: String

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .font(.system(size: 24))
                .foregroundStyle(.secondary)
                .frame(width: 38, height: 38)
                .background(Color.secondary.opacity(0.10), in: RoundedRectangle(cornerRadius: 8))
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.subheadline.bold())
                Text(message)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
        .frame(maxWidth: .infinity)
        .padding(14)
        .securityCardBackground()
    }
}

#if QUARANTINE_TRANSACTION_TEST
@main
struct QuarantineTransactionTestRunner {
    static func main() {
        exit(ThreatStore.runQuarantineTransactionTests())
    }
}
#else
private final class ThreatCenterApplicationDelegate: NSObject, NSApplicationDelegate {
    private var startsInMenuBarOnly = false

    func applicationWillFinishLaunching(_ notification: Notification) {
        startsInMenuBarOnly = ProcessInfo.processInfo.arguments.contains("--menu-bar-only")
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        guard startsInMenuBarOnly else { return }
        DispatchQueue.main.async {
            for window in NSApplication.shared.windows where window.canBecomeMain {
                window.orderOut(nil)
            }
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    func applicationShouldHandleReopen(
        _ sender: NSApplication,
        hasVisibleWindows flag: Bool
    ) -> Bool {
        guard !flag else { return true }
        sender.activate(ignoringOtherApps: true)
        return !bringExistingControlPanelToFront()
    }
}

@main
struct ClamAVThreatCenterApp: App {
    @NSApplicationDelegateAdaptor(ThreatCenterApplicationDelegate.self) private var appDelegate
    @StateObject private var store = ThreatStore()

    private var hasActiveThreat: Bool {
        store.threats.contains(where: \.exists)
    }

    private var hasServiceWarning: Bool {
        let daemonKnown = store.clamAVDaemonResponding != nil || store.realtimeStatus != nil
        let daemonWarning = daemonKnown && !store.isClamAVDaemonReady
        let realtimeWarning = store.realtimeStatus != nil && !store.isRealtimeProtectionActive
        let virusTotalWarning = store.virusTotalStatus != nil
            && (!store.isVirusTotalActive || store.virusTotalStatus?.apiKeyConfigured != true)
        return daemonWarning || realtimeWarning || virusTotalWarning
    }

    private var isCheckingServices: Bool {
        let daemonKnown = store.clamAVDaemonResponding != nil || store.realtimeStatus != nil
        return !daemonKnown || store.realtimeStatus == nil || store.virusTotalStatus == nil
    }

    private var menuBarSymbol: String {
        if hasActiveThreat { return "exclamationmark.shield.fill" }
        if hasServiceWarning { return "shield.lefthalf.filled" }
        if isCheckingServices { return "shield" }
        return "shield.fill"
    }

    private var menuBarColor: Color {
        if hasActiveThreat { return .red }
        if hasServiceWarning { return .orange }
        if isCheckingServices { return .secondary }
        return .primary
    }

    private var menuBarAccessibilityLabel: String {
        if hasActiveThreat { return "ClamAV Tehdit Merkezi, ilgilenilmesi gereken tehdit var" }
        if hasServiceWarning { return "ClamAV Threat Center: a protection service is not responding" }
        if isCheckingServices { return "ClamAV Threat Center: checking protection status" }
        return "ClamAV Threat Center: protection services are running"
    }

    var body: some Scene {
        Window("ClamAV Tehdit Merkezi", id: "control-panel") {
            ContentView(store: store)
        }
        .windowStyle(.titleBar)
        .defaultSize(width: 1180, height: 780)

        MenuBarExtra {
            ThreatCenterMenuBarView(store: store)
        } label: {
            Image(systemName: menuBarSymbol)
                .foregroundStyle(menuBarColor)
                .accessibilityLabel(menuBarAccessibilityLabel)
                .help(menuBarAccessibilityLabel)
        }
        .menuBarExtraStyle(.menu)

        Settings {
            VStack(alignment: .leading, spacing: 8) {
                Text("ClamAV Tehdit Merkezi").font(.headline)
                Text("Scan logs are kept for 30 days.")
                    .foregroundStyle(.secondary)
            }
            .padding(24)
            .frame(width: 360)
        }
    }
}
#endif
