#define TGLEDP_CLASSIFY_TESTING 1
#include "kern_tgl_edp_classify.hpp"
#include "kern_tgl_edp_lifecycle.hpp"
#include <cassert>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <vector>

using namespace TGLEDP;
using namespace TGLEDPClassify;

struct Descriptor {
    uint16_t type {};
    uint8_t dvo {};
    uint8_t ddc {};
    uint8_t aux {};
    uint8_t flags {};
    uint8_t capabilities {};
};

static void put16(std::vector<uint8_t> &bytes, size_t at, uint16_t value) {
    assert(at + 2 <= bytes.size());
    bytes[at] = static_cast<uint8_t>(value);
    bytes[at + 1] = static_cast<uint8_t>(value >> 8);
}

static void put32(std::vector<uint8_t> &bytes, size_t at, uint32_t value) {
    put16(bytes, at, static_cast<uint16_t>(value));
    put16(bytes, at + 2, static_cast<uint16_t>(value >> 16));
}

static void checksum(std::vector<uint8_t> &bytes) {
    bytes[26] = 0;
    uint8_t sum = 0;
    for (auto byte : bytes) sum = static_cast<uint8_t>(sum + byte);
    bytes[26] = static_cast<uint8_t>(0U - sum);
}

static std::vector<uint8_t> makeVBT(const std::vector<Descriptor> &descriptors) {
    constexpr size_t slots = XELP::PortCount;
    constexpr size_t childBytes = 5 + 39 * slots;
    std::vector<uint8_t> bytes(48 + 22 + 3 + childBytes, 0);
    memcpy(bytes.data(), "$VBT", 4);
    put16(bytes, 20, 100);
    put16(bytes, 22, 48);
    put16(bytes, 24, static_cast<uint16_t>(bytes.size()));
    put32(bytes, 28, 48);
    memcpy(bytes.data() + 48, "BIOS_DATA_BLOCK ", 16);
    put16(bytes, 64, 237);
    put16(bytes, 66, 22);
    put16(bytes, 68, static_cast<uint16_t>(bytes.size() - 48));
    bytes[70] = 2;
    put16(bytes, 71, static_cast<uint16_t>(childBytes));
    bytes[77] = 39;
    assert(descriptors.size() <= slots);
    for (size_t i = 0; i < descriptors.size(); ++i) {
        const size_t child = 78 + 39 * i;
        const auto &descriptor = descriptors[i];
        put16(bytes, child + 2, descriptor.type);
        bytes[child + 16] = descriptor.dvo;
        bytes[child + 19] = descriptor.ddc;
        bytes[child + 23] = descriptor.flags;
        bytes[child + 25] = descriptor.aux;
        bytes[child + 33] = descriptor.capabilities;
    }
    checksum(bytes);
    return bytes;
}

static std::vector<uint8_t> malformedTail(const std::vector<uint8_t> &source) {
    auto bytes = source;
    // BDB block 58 claims 674 payload bytes; 673 remain in the BDB extent.
    bytes.push_back(58);
    bytes.push_back(0xA2);
    bytes.push_back(0x02);
    bytes.resize(bytes.size() + 673, 0);
    put16(bytes, 24, static_cast<uint16_t>(bytes.size()));
    put16(bytes, 68, static_cast<uint16_t>(bytes.size() - 48));
    checksum(bytes);
    return bytes;
}

static GPUFacts validGPU() {
    return {XELP::identify(0x9A408086U, 1), RequiredNativeProbeABI, RequiredGPUCapabilities};
}

static FirmwareAnalysis trustedSyntheticFirmware(const std::vector<uint8_t> &bytes) {
    const auto origin = TestEvidenceAuthority::syntheticFirmwareOrigin();
    return analyzeFirmware(bytes.data(), bytes.size(), origin);
}

static void attachOwnership(RouteEvidence &route, ResourceOwner owner = ResourceOwner::KnownFree,
                            ConnectionState connection = ConnectionState::Connected) {
    route.connection = connection;
    route.ownershipSnapshotComplete = true;
    route.exclusiveOwnershipValidated = true;
    route.ddiOwner = owner;
    route.phyOwner = owner;
    route.auxOwner = owner;
    route.evidenceValidated = true; // Compatibility field; the proof is authoritative.
    TestEvidenceAuthority::authorize(route);
}

static RoutingSnapshot snapshotFrom(const FirmwareAnalysis &analysis) {
    RoutingSnapshot snapshot;
    snapshot.complete = true;
    snapshot.count = analysis.candidateCount;
    assert(snapshot.count <= MaxRouteClaims);
    for (size_t i = 0; i < snapshot.count; ++i) {
        snapshot.routes[i] = analysis.candidates[i].route;
        attachOwnership(snapshot.routes[i]);
    }
    return snapshot;
}

static ClassificationResult runClassification(const FirmwareAnalysis &firmware, const GPUFacts &gpu,
                                              RoutingSnapshot snapshot) {
    TestEvidenceAuthority::authorizeSnapshot(snapshot);
    return TGLEDPClassify::classify(firmware, gpu, snapshot);
}

static FirmwareAnalysis internalFirmware() {
    return analyzeFirmware(nullptr, 0);
}

static RouteEvidence internalRoute(const FirmwareAnalysis &analysis) {
    assert(analysis.candidateCount == 1);
    assert(analysis.candidates[0].connector == ConnectorClass::InternalEDP);
    auto route = analysis.candidates[0].route;
    attachOwnership(route);
    return route;
}

static void testFirmwareValidation() {
    const auto bytes = makeVBT({{0x70D6, 10, 3, 0x40, 0, 0}});
    const auto valid = analyzeFirmware(bytes.data(), bytes.size());
    assert(valid.validation.status == FirmwareStatus::StrictlyValid);
    assert(valid.validation.headerValid && valid.validation.declaredLengthValid);
    assert(valid.validation.bdbBoundsValid && valid.validation.fullBDBStreamValid);
    assert(valid.validation.bdbVersionCompatible && valid.validation.childLayoutCompatible);
    assert(valid.validation.childTableValid && valid.validation.checksumValid);
    assert(valid.validation.connectorMetadataValid && valid.validation.wholeImageValidated);
    // Bytes that merely pass strict validation remain diagnostic without an
    // authorized native firmware origin.
    assert(!valid.validation.sourceAuthorized && !valid.validation.runtimeTrusted);
    assert(valid.candidates[0].route.source == EvidenceSource::DiagnosticVBT);
    auto diagnosticSnapshot = snapshotFrom(valid);
    auto diagnosticResult = runClassification(valid, validGPU(), diagnosticSnapshot);
    assert(diagnosticResult.detected && diagnosticResult.structurallyQualified);
    assert(!diagnosticResult.runtimeAdmissible && diagnosticResult.reason == Reason::DiagnosticOnly);
    assert(valid.candidateCount == 1 && valid.candidates[0].detected);
    assert(valid.candidates[0].connector == ConnectorClass::InternalEDP);
    assert(valid.candidates[0].route.ddi == DDI::A && valid.candidates[0].route.phy == 0);
    assert(valid.candidates[0].route.aux == AUX::A && valid.candidates[0].route.phyKind == PHYKind::Combo);
    assert(valid.candidates[0].structurallyQualified && !valid.candidates[0].runtimeAdmissible);

    const auto trustedValid = trustedSyntheticFirmware(bytes);
    assert(trustedValid.validation.runtimeTrusted && trustedValid.validation.sourceAuthorized);
    RoutingSnapshot incompleteTrust;
    incompleteTrust.complete = true;
    incompleteTrust.count = 1;
    incompleteTrust.routes[0] = trustedValid.candidates[0].route;
    incompleteTrust.routes[0].connection = ConnectionState::Connected;
    TestEvidenceAuthority::authorize(incompleteTrust.routes[0]);
    auto incompleteResult = runClassification(trustedValid, validGPU(), incompleteTrust);
    assert(incompleteResult.structurallyQualified && !incompleteResult.runtimeAdmissible);
    assert(incompleteResult.reason == Reason::OwnershipUnknown);
    incompleteTrust.authorization = {};
    assert(TGLEDP::qualifyConnector(qualifyGPU(validGPU()), incompleteTrust, 0).rejection ==
           Rejection::OwnershipUnknown);

    auto badChecksum = bytes;
    badChecksum.back() ^= 1;
    const auto checksumFailure = analyzeFirmware(badChecksum.data(), badChecksum.size());
    assert(!checksumFailure.validation.checksumValid);
    assert(checksumFailure.validation.fullBDBStreamValid && checksumFailure.validation.childTableValid);
    assert(checksumFailure.candidateCount == 1 && checksumFailure.candidates[0].detected);
    assert(checksumFailure.candidates[0].structurallyQualified);
    auto snapshot = snapshotFrom(checksumFailure);
    auto decision = runClassification(checksumFailure, validGPU(), snapshot);
    assert(decision.detected && decision.structurallyQualified && !decision.runtimeAdmissible);
    assert(decision.reason == Reason::DiagnosticOnly);

    const auto badTail = malformedTail(bytes);
    // The existing HDMI/DP parser remains unchanged; P004's stricter eDP
    // validator continues through the entire BDB stream after General Defs.
    assert(XELP::VBT::parse(badTail.data(), badTail.size(), XELP::Family::TigerLake).valid());
    const auto tailFailure = analyzeFirmware(badTail.data(), badTail.size());
    assert(tailFailure.validation.checksumValid);
    assert(!tailFailure.validation.fullBDBStreamValid);
    assert(tailFailure.validation.childTableValid && tailFailure.validation.connectorMetadataValid);
    assert(tailFailure.validation.malformedBlockId == 58);
    assert(tailFailure.validation.malformedBlockClaimedBytes == 674);
    assert(tailFailure.validation.malformedBlockAvailableBytes == 673);
    assert(tailFailure.candidateCount == 1 && tailFailure.candidates[0].structurallyQualified);
    snapshot = snapshotFrom(tailFailure);
    decision = runClassification(tailFailure, validGPU(), snapshot);
    assert(decision.detected && decision.structurallyQualified && !decision.runtimeAdmissible);
    assert(decision.reason == Reason::DiagnosticOnly);

    for (size_t length = 0; length < bytes.size(); ++length) {
        const auto truncated = analyzeFirmware(bytes.data(), length);
        assert(!truncated.validation.runtimeTrusted);
    }
    assert(analyzeFirmware(bytes.data(), 47).validation.status == FirmwareStatus::HeaderInvalid);

    auto wrongStride = bytes;
    wrongStride[77] = 38;
    checksum(wrongStride);
    const auto strideFailure = analyzeFirmware(wrongStride.data(), wrongStride.size());
    assert(strideFailure.validation.checksumValid);
    assert(!strideFailure.validation.childLayoutCompatible && !strideFailure.validation.childTableValid);
    assert(strideFailure.validation.status == FirmwareStatus::ChildLayoutInvalid);

    auto wrongVersion = bytes;
    put16(wrongVersion, 64, 257);
    checksum(wrongVersion);
    const auto versionFailure = analyzeFirmware(wrongVersion.data(), wrongVersion.size());
    assert(versionFailure.validation.checksumValid && !versionFailure.validation.bdbVersionCompatible);
    assert(versionFailure.validation.status == FirmwareStatus::BDBVersionUnsupported);
    assert(!versionFailure.validation.runtimeTrusted);

    auto overlapping = bytes;
    put16(overlapping, 71, 0xFFFF);
    put16(overlapping, 68, static_cast<uint16_t>(overlapping.size() - 48));
    checksum(overlapping);
    const auto overlapFailure = analyzeFirmware(overlapping.data(), overlapping.size());
    assert(overlapFailure.validation.checksumValid && !overlapFailure.validation.fullBDBStreamValid);
    assert(overlapFailure.validation.malformedBlockId == 2);
    assert(!overlapFailure.validation.runtimeTrusted);
}

static void testConnectorClassification() {
    const auto internal = makeVBT({{0x70D6, 10, 3, 0x40, 0, 0}});
    auto analysis = trustedSyntheticFirmware(internal);
    auto snapshot = snapshotFrom(analysis);
    auto result = runClassification(analysis, validGPU(), snapshot);
    assert(result.detected && result.structurallyQualified && result.runtimeAdmissible);
    assert(result.connector == ConnectorClass::InternalEDP && result.stage == Stage::RuntimeAdmissible);
    assert(result.connectorDecision.ddi == DDI::A && result.connectorDecision.aux == AUX::A);

    const auto hdmiBytes = makeVBT({{0x60D2, 0, 1, 0, 0, 0}});
    const auto hdmi = analyzeFirmware(hdmiBytes.data(), hdmiBytes.size());
    assert(hdmi.candidateCount == 1 && hdmi.candidates[0].connector == ConnectorClass::FixedHDMI);
    snapshot = snapshotFrom(hdmi);
    result = runClassification(hdmi, validGPU(), snapshot);
    assert(!result.runtimeAdmissible && !result.detected && result.reason == Reason::NoInternalPanel);

    const auto mixedBytes = makeVBT({
        {0x70D6, 10, 3, 0x40, 0, 0},
        {0x60D2, 7, 2, 0, 0, 0}
    });
    const auto mixed = trustedSyntheticFirmware(mixedBytes);
    assert(mixed.candidateCount == 2);
    assert(mixed.candidates[0].connector == ConnectorClass::InternalEDP);
    assert(mixed.candidates[1].connector == ConnectorClass::FixedHDMI);
    snapshot = snapshotFrom(mixed);
    result = runClassification(mixed, validGPU(), snapshot);
    assert(result.runtimeAdmissible && result.routeCount == 2);
    assert(result.routes[1].connector == ConnectorClass::FixedHDMI);

    const auto externalBytes = makeVBT({
        {0x70D6, 10, 3, 0x40, 0, 0},
        {0x60D6, 7, 2, 0x50, 0xC0, 0}
    });
    const auto external = trustedSyntheticFirmware(externalBytes);
    assert(external.candidates[1].connector == ConnectorClass::ExternalDisplayPort);
    snapshot = snapshotFrom(external);
    result = runClassification(external, validGPU(), snapshot);
    assert(result.runtimeAdmissible && result.routeCount == 2);
    assert(result.routes[1].connector == ConnectorClass::ExternalDisplayPort);

    // Type-C physical DDI D and capability bits are classified as a Type-C
    // path, while the existing VBT DP-mode candidate remains available.
    const auto typeCBytes = makeVBT({{0x60D6, 9, 4, 0x40, 0xC0, 1}});
    const auto typeC = analyzeFirmware(typeCBytes.data(), typeCBytes.size());
    assert(typeC.candidateCount == 1);
    assert(typeC.candidates[0].connector == ConnectorClass::TypeCCapableDisplayPath);
    assert(typeC.candidates[0].route.ddi == DDI::D && typeC.candidates[0].route.phyKind == PHYKind::TypeC);
    assert(typeC.candidates[0].route.typeCCapable);
    const auto nativeTypeC = XELP::VBT::parse(typeCBytes.data(), typeCBytes.size(), XELP::Family::TigerLake);
    assert(nativeTypeC.valid() && nativeTypeC.tglDPCandidates(0x1F8) == (1U << 3));

    const auto duplicateDDIBytes = makeVBT({
        {0x70D6, 10, 3, 0x40, 0, 0},
        {0x60D6, 10, 2, 0x50, 0xC0, 0}
    });
    const auto duplicateDDI = analyzeFirmware(duplicateDDIBytes.data(), duplicateDDIBytes.size());
    assert(duplicateDDI.descriptorConflict && !duplicateDDI.validation.connectorMetadataValid);
    snapshot = snapshotFrom(duplicateDDI);
    result = runClassification(duplicateDDI, validGPU(), snapshot);
    assert(result.conflict && !result.runtimeAdmissible);
    assert(result.reason == Reason::ConnectorMetadataInvalid || result.reason == Reason::DuplicateDDI);

    const auto twoInternalBytes = makeVBT({
        {0x70D6, 10, 3, 0x40, 0, 0},
        {0x70D6, 7, 2, 0x50, 0, 0}
    });
    const auto twoInternal = analyzeFirmware(twoInternalBytes.data(), twoInternalBytes.size());
    snapshot = snapshotFrom(twoInternal);
    result = runClassification(twoInternal, validGPU(), snapshot);
    assert(result.conflict && !result.runtimeAdmissible);
    assert(result.reason == Reason::AmbiguousInternalRoutes);

    const auto duplicateAUXBytes = makeVBT({
        {0x70D6, 10, 3, 0x40, 0, 0},
        {0x60D6, 7, 2, 0x40, 0xC0, 0}
    });
    const auto duplicateAUX = analyzeFirmware(duplicateAUXBytes.data(), duplicateAUXBytes.size());
    assert(duplicateAUX.duplicateAUX && !duplicateAUX.validation.connectorMetadataValid);
    snapshot = snapshotFrom(duplicateAUX);
    result = runClassification(duplicateAUX, validGPU(), snapshot);
    assert(result.conflict && !result.runtimeAdmissible && result.reason == Reason::DuplicateAUX);

    // DDI D cannot be relabeled Combo. The classifier reports the contradiction
    // and P003 independently rejects it at the final gate.
    snapshot = {};
    snapshot.complete = true;
    snapshot.count = 1;
    snapshot.routes[0] = internalRoute(analysis);
    snapshot.routes[0].ddi = DDI::D;
    snapshot.routes[0].phyKind = PHYKind::Combo;
    snapshot.routes[0].phy = 0;
    TestEvidenceAuthority::authorize(snapshot.routes[0]);
    const auto noFirmware = internalFirmware();
    result = runClassification(noFirmware, validGPU(), snapshot);
    assert(!result.structurallyQualified && !result.runtimeAdmissible);
    assert(result.routes[0].reason == Reason::TypeCComboMismatch);
    assert(result.connectorDecision.rejection == Rejection::TypeCPhy);

    snapshot = {};
    snapshot.complete = true;
    snapshot.count = 1;
    snapshot.routes[0] = internalRoute(analysis);
    snapshot.routes[0].panelPresent = false;
    TestEvidenceAuthority::authorize(snapshot.routes[0]);
    result = runClassification(noFirmware, validGPU(), snapshot);
    assert(!result.runtimeAdmissible && result.reason == Reason::PanelEvidenceMissing);
    assert(result.connectorDecision.rejection == Rejection::PanelAbsent);
}

static void testTrustAndOwnership() {
    const auto bytes = makeVBT({{0x70D6, 10, 3, 0x40, 0, 0}});
    const auto analysis = trustedSyntheticFirmware(bytes);
    const auto noFirmware = internalFirmware();
    auto route = internalRoute(analysis);
    route.source = EvidenceSource::LinuxObservation;
    route.firmwareDerived = false;
    route.firmware = {};
    route.evidenceValidated = true;
    TestEvidenceAuthority::authorize(route);
    RoutingSnapshot snapshot;
    snapshot.complete = true;
    snapshot.count = 1;
    snapshot.routes[0] = route;
    auto result = runClassification(noFirmware, validGPU(), snapshot);
    assert(result.structurallyQualified && !result.runtimeAdmissible);
    assert(result.reason == Reason::UntrustedEvidence);

    route = internalRoute(analysis);
    route.connection = ConnectionState::Unknown;
    TestEvidenceAuthority::authorize(route);
    snapshot.routes[0] = route;
    result = runClassification(noFirmware, validGPU(), snapshot);
    assert(!result.runtimeAdmissible && result.reason == Reason::PanelPresenceUnknown);

    route = internalRoute(analysis);
    route.connection = ConnectionState::Disconnected;
    TestEvidenceAuthority::authorize(route);
    snapshot.routes[0] = route;
    result = runClassification(noFirmware, validGPU(), snapshot);
    assert(!result.runtimeAdmissible && result.connectorDecision.rejection == Rejection::PanelAbsent);

    route = internalRoute(analysis);
    route.active = false;
    route.connection = ConnectionState::Disconnected;
    TestEvidenceAuthority::authorize(route);
    snapshot.routes[0] = route;
    result = runClassification(noFirmware, validGPU(), snapshot);
    assert(result.detected && !result.runtimeAdmissible);
    assert(result.reason == Reason::ConnectorAbsent && result.gpuDecision.admitted());

    // A disconnected external connector still has explicit ownership. It is
    // never treated as free because active/connected is false.
    const auto withExternalBytes = makeVBT({
        {0x70D6, 10, 3, 0x40, 0, 0},
        {0x60D6, 7, 2, 0x50, 0xC0, 0}
    });
    const auto withExternal = trustedSyntheticFirmware(withExternalBytes);
    snapshot = snapshotFrom(withExternal);
    snapshot.routes[1].active = false;
    snapshot.routes[1].connection = ConnectionState::Disconnected;
    snapshot.routes[1].ddiOwner = ResourceOwner::Unknown;
    snapshot.routes[1].phyOwner = ResourceOwner::Unknown;
    snapshot.routes[1].auxOwner = ResourceOwner::Unknown;
    TestEvidenceAuthority::authorize(snapshot.routes[1]);
    result = runClassification(withExternal, validGPU(), snapshot);
    assert(!result.runtimeAdmissible && result.reason == Reason::OwnershipUnknown);
    snapshot.routes[1].ddiOwner = ResourceOwner::KnownFree;
    snapshot.routes[1].phyOwner = ResourceOwner::KnownFree;
    snapshot.routes[1].auxOwner = ResourceOwner::KnownFree;
    TestEvidenceAuthority::authorize(snapshot.routes[1]);
    result = runClassification(withExternal, validGPU(), snapshot);
    assert(result.runtimeAdmissible);

    // Evidence flags alone cannot mint authorization, and any edit after
    // authorization invalidates the route-bound proof.
    route = internalRoute(analysis);
    route.source = EvidenceSource::ValidatedBoardRecord;
    route.firmwareDerived = false;
    route.firmware = {};
    route.evidenceValidated = true;
    route.authorization = {};
    snapshot = {};
    snapshot.complete = true;
    snapshot.count = 1;
    snapshot.routes[0] = route;
    result = runClassification(noFirmware, validGPU(), snapshot);
    assert(!result.runtimeAdmissible && result.reason == Reason::UntrustedEvidence);

    route = internalRoute(analysis);
    route.typeCCapable = true; // Do not refresh proof.
    snapshot.routes[0] = route;
    result = runClassification(noFirmware, validGPU(), snapshot);
    assert(!result.runtimeAdmissible && result.reason == Reason::UntrustedEvidence);

    route = internalRoute(analysis);
    route.ddiOwner = ResourceOwner::NativeDonor;
    route.phyOwner = ResourceOwner::NativeDonor;
    route.auxOwner = ResourceOwner::NativeDonor;
    route.donorBindingCompatible = false;
    TestEvidenceAuthority::authorize(route);
    snapshot.routes[0] = route;
    result = runClassification(noFirmware, validGPU(), snapshot);
    assert(!result.runtimeAdmissible && result.connectorDecision.rejection == Rejection::DonorBindingConflict);

    route = internalRoute(analysis);
    route.ddiOwner = ResourceOwner::ExternalDisplay;
    route.phyOwner = ResourceOwner::ExternalDisplay;
    route.auxOwner = ResourceOwner::ExternalDisplay;
    TestEvidenceAuthority::authorize(route);
    snapshot.routes[0] = route;
    result = runClassification(noFirmware, validGPU(), snapshot);
    assert(!result.runtimeAdmissible && result.reason == Reason::OwnershipConflict);

    // Conflicting same-port records and a duplicate PHY are rejected before
    // the selected route can pass P003.
    const auto matching = trustedSyntheticFirmware(withExternalBytes);
    snapshot = snapshotFrom(matching);
    snapshot.routes[1].ddi = DDI::A;
    snapshot.routes[1].phy = 0;
    TestEvidenceAuthority::authorize(snapshot.routes[1]);
    result = runClassification(matching, validGPU(), snapshot);
    assert(result.conflict && !result.runtimeAdmissible);
    assert(result.reason == Reason::DuplicateDDI);

    snapshot = snapshotFrom(matching);
    snapshot.routes[1].phy = 0;
    TestEvidenceAuthority::authorize(snapshot.routes[1]);
    result = runClassification(matching, validGPU(), snapshot);
    assert(result.conflict && !result.runtimeAdmissible);
    assert(result.reason == Reason::DuplicatePHY || result.reason == Reason::PhysicalPairMismatch ||
           result.reason == Reason::ContradictoryEvidence);

    snapshot = snapshotFrom(matching);
    snapshot.complete = false;
    result = runClassification(matching, validGPU(), snapshot);
    assert(!result.structurallyQualified && !result.runtimeAdmissible);
    assert(result.reason == Reason::IncompleteSnapshot);
}

static void testProvenanceConflictsAndGPU() {
    const auto strictBytes = makeVBT({{0x70D6, 10, 3, 0x40, 0, 0}});
    const auto strict = trustedSyntheticFirmware(strictBytes);
    auto snapshot = snapshotFrom(strict);
    snapshot.routes[0].source = EvidenceSource::AuthorizedNativeReadout;
    snapshot.routes[0].firmwareDerived = false;
    snapshot.routes[0].firmware = {};
    snapshot.routes[0].ddi = DDI::B;
    snapshot.routes[0].phy = 1;
    snapshot.routes[0].aux = AUX::B;
    TestEvidenceAuthority::authorize(snapshot.routes[0]);
    auto result = runClassification(strict, validGPU(), snapshot);
    assert(result.conflict && !result.runtimeAdmissible);
    assert(result.reason == Reason::ContradictoryEvidence);

    // A bounded external firmware descriptor cannot be silently relabeled as
    // an internal panel by a conflicting native claim.
    const auto markedExternalBytes = makeVBT({{0x60D6, 10, 3, 0x40, 0xC0, 0}});
    const auto markedExternal = trustedSyntheticFirmware(markedExternalBytes);
    assert(markedExternal.candidates[0].connector == ConnectorClass::ExternalDisplayPort);
    snapshot = snapshotFrom(markedExternal);
    snapshot.routes[0].connector = Connector::InternalDP;
    snapshot.routes[0].role = Role::InternalPanel;
    snapshot.routes[0].panelPresent = true;
    TestEvidenceAuthority::authorize(snapshot.routes[0]);
    result = runClassification(markedExternal, validGPU(), snapshot);
    assert(result.conflict && !result.runtimeAdmissible);
    assert(result.reason == Reason::ContradictoryEvidence);

    const auto internal = makeVBT({{0x70D6, 10, 3, 0x40, 0, 0}});
    const auto analysis = trustedSyntheticFirmware(internal);
    snapshot = snapshotFrom(analysis);
    auto spoofed = validGPU();
    spoofed.profile = XELP::identify(0xDEAD8086U, 1, 0x9A408086U);
    result = runClassification(analysis, spoofed, snapshot);
    assert(!result.runtimeAdmissible && result.gpuDecision.rejection == Rejection::PhysicalIdentity);

    auto incompatibleABI = validGPU();
    incompatibleABI.nativeProbeABI = RequiredNativeProbeABI - 1;
    result = runClassification(analysis, incompatibleABI, snapshot);
    assert(!result.runtimeAdmissible && result.gpuDecision.rejection == Rejection::NativeABI);
    assert(result.reason == Reason::NativeABIRejected);

    auto alderLakeN = validGPU();
    alderLakeN.profile = XELP::identify(0x46D18086U, 0);
    result = runClassification(analysis, alderLakeN, snapshot);
    assert(!result.runtimeAdmissible && result.gpuDecision.rejection == Rejection::WrongFamily);
}

static void testP003BoundaryAndExistingDisplayBehavior() {
    const auto bytes = makeVBT({
        {0x70D6, 10, 3, 0x50, 0, 0},
        {0x60D2, 7, 2, 0, 0, 0},
        {0x60D6, 9, 4, 0x40, 0xC0, 0}
    });
    const auto analysis = trustedSyntheticFirmware(bytes);
    assert(analysis.candidateCount == 3);
    assert(analysis.candidates[0].connector == ConnectorClass::InternalEDP);
    assert(analysis.candidates[1].connector == ConnectorClass::FixedHDMI);
    assert(analysis.candidates[2].connector == ConnectorClass::TypeCCapableDisplayPath);
    const auto existing = XELP::VBT::parse(bytes.data(), bytes.size(), XELP::Family::TigerLake);
    assert(existing.valid());
    assert(existing.hdmi(3).valid && existing.hdmi(3).hdmi == (1U << 1));
    assert(existing.tglDPCandidates(0x1F8) == (1U << 3));

    auto snapshot = snapshotFrom(analysis);
    const auto result = runClassification(analysis, validGPU(), snapshot);
    assert(result.runtimeAdmissible);

    // Classification never creates or advances a lifecycle Session.
    Session session;
    assert(session.state == State::Unbound);
    (void)runClassification(analysis, validGPU(), snapshot);
    assert(session.state == State::Unbound);

    const auto forgedBytes = makeVBT({{0x70D6, 10, 3, 0x40, 0, 0}});
    const auto forgedAnalysis = trustedSyntheticFirmware(forgedBytes);
    snapshot = snapshotFrom(forgedAnalysis);
    snapshot.routes[0].evidenceValidated = false;
    TestEvidenceAuthority::authorize(snapshot.routes[0]);
    // The value is intentionally not used as an admission predicate. Clearing
    // the compatibility bit leaves the independent proof valid.
    assert(runClassification(forgedAnalysis, validGPU(), snapshot).runtimeAdmissible);

    snapshot.routes[0].authorization = {};
    snapshot.routes[0].evidenceValidated = true;
    const auto unproved = runClassification(forgedAnalysis, validGPU(), snapshot);
    assert(!unproved.runtimeAdmissible && unproved.reason == Reason::UntrustedEvidence);
}

static void testBoundedMutationSweep() {
    auto bytes = makeVBT({{0x70D6, 10, 3, 0x40, 0, 0}});
    for (size_t length = 0; length <= bytes.size(); ++length)
        (void)analyzeFirmware(bytes.data(), length);
    uint32_t seed = 0xC004FC1A;
    for (unsigned i = 0; i < 4000; ++i) {
        auto mutated = bytes;
        seed = seed * 1664525U + 1013904223U;
        const size_t offset = seed % mutated.size();
        mutated[offset] ^= static_cast<uint8_t>(seed >> 24);
        checksum(mutated);
        (void)analyzeFirmware(mutated.data(), mutated.size());
    }

    const auto firmware = trustedSyntheticFirmware(bytes);
    auto snapshot = snapshotFrom(firmware);
    auto oversizedFirmware = firmware;
    oversizedFirmware.candidateCount = MaxCandidates + 1;
    auto result = runClassification(oversizedFirmware, validGPU(), snapshot);
    assert(result.conflict && !result.runtimeAdmissible);
    auto oversizedSnapshot = snapshot;
    oversizedSnapshot.count = MaxRouteClaims + 1;
    result = runClassification(firmware, validGPU(), oversizedSnapshot);
    assert(!result.runtimeAdmissible && result.reason == Reason::IncompleteSnapshot);
    puts("PASS P004: bounded strict VBT classification, trust separation, TGL DDI/PHY/AUX topology, conflicts, P003 gate and display regressions");
}

static const char *statusName(FirmwareStatus status) {
    switch (status) {
        case FirmwareStatus::Missing: return "missing";
        case FirmwareStatus::HeaderInvalid: return "header-invalid";
        case FirmwareStatus::DeclaredLengthInvalid: return "declared-length-invalid";
        case FirmwareStatus::BDBBoundsInvalid: return "bdb-bounds-invalid";
        case FirmwareStatus::BDBVersionUnsupported: return "bdb-version-unsupported";
        case FirmwareStatus::ChecksumInvalid: return "checksum-invalid";
        case FirmwareStatus::BDBStreamMalformed: return "bdb-stream-malformed";
        case FirmwareStatus::ChildLayoutInvalid: return "child-layout-invalid";
        case FirmwareStatus::ConnectorMetadataInvalid: return "connector-metadata-invalid";
        case FirmwareStatus::StrictlyValid: return "content-valid";
    }
    return "unknown";
}

static const char *connectorName(ConnectorClass connector) {
    switch (connector) {
        case ConnectorClass::InternalEDP: return "internal-edp";
        case ConnectorClass::ExternalDisplayPort: return "external-dp";
        case ConnectorClass::FixedHDMI: return "fixed-hdmi";
        case ConnectorClass::TypeCCapableDisplayPath: return "type-c-capable";
        case ConnectorClass::UnsupportedOrUnknown: return "unsupported-unknown";
        case ConnectorClass::ConflictingOrAmbiguous: return "conflict-ambiguous";
    }
    return "unknown";
}

static int replayVBT(const char *path) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) return 2;
    stream.seekg(0, std::ios::end);
    const auto end = stream.tellg();
    if (end < 0 || end > 1024 * 1024) return 2;
    stream.seekg(0, std::ios::beg);
    std::vector<uint8_t> bytes(static_cast<size_t>(end));
    if (!bytes.empty()) stream.read(reinterpret_cast<char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!stream && !bytes.empty()) return 2;
    const auto analysis = analyzeFirmware(bytes.data(), bytes.size());
    printf("OFFLINE replay: status=%s supplied=%zu declared=%zu header=%zu bdb-offset=%zu bdb-version=%u bdb-header=%zu bdb-bytes=%zu general-definitions=%zu child-stride=%u child-slots=%u descriptors=%u checksum=%s remainder=0x%02x bdb-stream=%s child-table=%s malformed-block=%u overrun=%zu\n",
        statusName(analysis.validation.status), analysis.validation.suppliedBytes,
        analysis.validation.declaredBytes, analysis.validation.headerBytes, analysis.validation.bdbOffset,
        analysis.validation.bdbVersion, analysis.validation.bdbHeaderBytes, analysis.validation.bdbBytes,
        analysis.validation.generalDefinitionsBytes, analysis.validation.childStride,
        analysis.validation.childSlots, analysis.validation.populatedDescriptors,
        analysis.validation.checksumValid ? "valid" : "rejected",
        static_cast<unsigned>(analysis.validation.checksumRemainder),
        analysis.validation.fullBDBStreamValid ? "valid" : "malformed",
        analysis.validation.childTableValid ? "valid" : "invalid",
        static_cast<unsigned>(analysis.validation.malformedBlockId),
        analysis.validation.malformedBlockClaimedBytes > analysis.validation.malformedBlockAvailableBytes ?
            analysis.validation.malformedBlockClaimedBytes - analysis.validation.malformedBlockAvailableBytes : 0U);
    for (size_t i = 0; i < analysis.candidateCount; ++i) {
        const auto &candidate = analysis.candidates[i];
        printf("candidate: class=%s ddi=%u dvo=0x%02x phy-kind=%u phy=%u aux-code=0x%02x structural=%s source=%u\n",
            connectorName(candidate.connector), static_cast<unsigned>(candidate.route.ddi),
            candidate.dvoCode, static_cast<unsigned>(candidate.route.phyKind),
            static_cast<unsigned>(candidate.route.phy),
            candidate.auxCode, candidate.structurallyQualified ? "yes" : "no",
            static_cast<unsigned>(candidate.route.source));
    }
    printf("runtime=not-admitted\n");
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 3 && !strcmp(argv[1], "--replay-vbt")) return replayVBT(argv[2]);
    if (argc != 1) return 64;

    testFirmwareValidation();
    testConnectorClassification();
    testTrustAndOwnership();
    testProvenanceConflictsAndGPU();
    testP003BoundaryAndExistingDisplayBehavior();
    testBoundedMutationSweep();
    return 0;
}
