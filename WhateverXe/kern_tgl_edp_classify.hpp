// Pure Tiger Lake connector classification and strict eDP VBT validation.
// This layer prepares evidence for P003; it never touches display hardware or
// advances the P003 lifecycle.
#ifndef KERN_TGL_EDP_CLASSIFY_HPP
#define KERN_TGL_EDP_CLASSIFY_HPP

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "kern_tgl_edp_contract.hpp"
#include "kern_vbt.hpp"

namespace TGLEDPClassify {

constexpr size_t MaxCandidates = TGLEDP::MaxRouteClaims;

enum class ConnectorClass : uint8_t {
    InternalEDP,
    ExternalDisplayPort,
    FixedHDMI,
    TypeCCapableDisplayPath,
    UnsupportedOrUnknown,
    ConflictingOrAmbiguous
};

enum class Stage : uint8_t { Unknown, Detected, StructurallyQualified, RuntimeAdmissible, Rejected, Conflict };

enum class Reason : uint8_t {
    None,
    NoInternalPanel,
    FirmwareRouteMissing,
    HeaderInvalid,
    DeclaredLengthInvalid,
    BDBBoundsInvalid,
    ChecksumInvalid,
    BDBStreamMalformed,
    BDBVersionUnsupported,
    ChildLayoutInvalid,
    ConnectorMetadataInvalid,
    UnsupportedDDI,
    TypeCComboMismatch,
    PhysicalPairMismatch,
    AUXUnknown,
    TransportMismatch,
    PanelEvidenceMissing,
    PanelPresenceUnknown,
    IncompleteSnapshot,
    OwnershipUnknown,
    OwnershipConflict,
    DuplicateDDI,
    DuplicatePHY,
    DuplicateAUX,
    DuplicateResource,
    AmbiguousInternalRoutes,
    ContradictoryEvidence,
    DiagnosticOnly,
    UntrustedEvidence,
    GPURejected,
    NativeABIRejected,
    BackendUnavailable,
    DonorBindingConflict,
    ConnectorAbsent
};

enum class FirmwareStatus : uint8_t {
    Missing,
    HeaderInvalid,
    DeclaredLengthInvalid,
    BDBBoundsInvalid,
    BDBVersionUnsupported,
    ChecksumInvalid,
    BDBStreamMalformed,
    ChildLayoutInvalid,
    ConnectorMetadataInvalid,
    StrictlyValid
};

struct FirmwareValidation {
    FirmwareStatus status {FirmwareStatus::Missing};
    bool headerValid {};
    bool declaredLengthValid {};
    bool bdbBoundsValid {};
    bool fullBDBStreamValid {};
    bool bdbVersionCompatible {};
    bool childLayoutCompatible {};
    bool childTableValid {};
    bool checksumValid {};
    bool connectorMetadataValid {};
    bool wholeImageValidated {};
    bool sourceAuthorized {};
    bool runtimeTrusted {};
    bool diagnosticOnly {true};
    uint32_t bdbVersion {};
    size_t suppliedBytes {};
    size_t declaredBytes {};
    size_t headerBytes {};
    size_t bdbOffset {};
    size_t bdbHeaderBytes {};
    size_t bdbBytes {};
    size_t generalDefinitionsBytes {};
    uint32_t childStride {};
    uint32_t childSlots {};
    uint32_t populatedDescriptors {};
    uint8_t checksumRemainder {};
    uint8_t malformedBlockId {};
    size_t malformedBlockOffset {};
    size_t malformedBlockClaimedBytes {};
    size_t malformedBlockAvailableBytes {};
};

class FirmwareOriginProof {
    // No production acquisition source is registered by P004. Normal callers
    // can validate bytes but only obtain diagnostic routes; a future native
    // reader must add an explicit private minting path after provenance checks.
    bool authorizedNativeSource_ {};

    explicit FirmwareOriginProof(bool authorized) : authorizedNativeSource_(authorized) {}
    friend class FirmwareValidator;
#if defined(TGLEDP_CLASSIFY_TESTING)
    friend class TestEvidenceAuthority;
#endif

public:
    FirmwareOriginProof() = default;
    bool valid() const { return authorizedNativeSource_; }
};

struct FirmwareCandidate {
    ConnectorClass connector {ConnectorClass::UnsupportedOrUnknown};
    Stage stage {Stage::Unknown};
    Reason reason {Reason::None};
    bool detected {};
    bool structurallyQualified {};
    bool runtimeAdmissible {}; // Firmware alone never satisfies P003 ownership.
    uint8_t descriptorIndex {};
    uint32_t dvoCode {};
    uint32_t auxCode {};
    TGLEDP::RouteEvidence route;
};

struct FirmwareAnalysis {
    FirmwareValidation validation;
    bool duplicateGeneralDefinitions {};
    bool descriptorConflict {};
    bool duplicateDDI {};
    bool duplicatePHY {};
    bool duplicateAUX {};
    size_t candidateCount {};
    FirmwareCandidate candidates[MaxCandidates] {};
};

class FirmwareValidator {
    static void authorize(TGLEDP::RouteEvidence &route) {
        route.authorization = TGLEDP::EvidenceAuthorization(static_cast<const TGLEDP::RouteFacts &>(route));
    }

public:
    static FirmwareAnalysis analyze(const void *data, size_t length, const FirmwareOriginProof &origin);
};

struct RouteClassification {
    ConnectorClass connector {ConnectorClass::UnsupportedOrUnknown};
    Stage stage {Stage::Unknown};
    Reason reason {Reason::None};
    bool detected {};
    bool structurallyQualified {};
    bool runtimeAdmissible {};
};

struct ClassificationResult {
    ConnectorClass connector {ConnectorClass::UnsupportedOrUnknown};
    Stage stage {Stage::Unknown};
    Reason reason {Reason::None};
    bool detected {};
    bool structurallyQualified {};
    bool runtimeAdmissible {};
    bool conflict {};
    size_t internalRouteIndex {MaxCandidates};
    size_t routeCount {};
    RouteClassification routes[MaxCandidates] {};
    TGLEDP::Decision gpuDecision {TGLEDP::Rejection::GPUProfile};
    TGLEDP::ConnectorDecision connectorDecision;
};

inline TGLEDP::AUX decodeAUX(uint32_t encoded) {
    if (encoded < 0x40 || encoded > 0xB0 || (encoded & 0x0FU)) return TGLEDP::AUX::Unknown;
    return static_cast<TGLEDP::AUX>((encoded >> 4) - 3U);
}

inline TGLEDP::DDI decodeTGLDDI(uint32_t dvo) {
    const auto physical = XELP::VBT::ddi(XELP::Family::TigerLake, dvo);
    if (physical >= XELP::PortCount) return TGLEDP::DDI::Unknown;
    return static_cast<TGLEDP::DDI>(physical);
}

inline bool internalType(uint32_t type) { return (type & 0x1000U) != 0; }
inline bool dpType(uint32_t type) { return (type & 0x4U) != 0; }

inline ConnectorClass classifyDescriptor(const XELP::VBT::Port &port, TGLEDP::DDI ddi) {
    if (internalType(port.type) && dpType(port.type)) return ConnectorClass::InternalEDP;
    if (TGLEDP::typeCDDI(ddi) || (port.capabilities & 3U))
        return ConnectorClass::TypeCCapableDisplayPath;
    if (!TGLEDP::knownDDI(ddi)) return ConnectorClass::UnsupportedOrUnknown;
    if (port.fixedTMDS()) return ConnectorClass::FixedHDMI;
    if (port.dp()) return ConnectorClass::ExternalDisplayPort;
    return ConnectorClass::UnsupportedOrUnknown;
}

inline Reason topologyReason(const TGLEDP::RouteEvidence &route, ConnectorClass connector) {
    if (!TGLEDP::knownDDI(route.ddi)) return Reason::UnsupportedDDI;
    if (TGLEDP::typeCDDI(route.ddi) && connector == ConnectorClass::InternalEDP)
        return Reason::TypeCComboMismatch;
    if (!TGLEDP::validPhysicalPair(route)) {
        if ((TGLEDP::comboDDI(route.ddi) && route.phyKind == TGLEDP::PHYKind::TypeC) ||
            (TGLEDP::typeCDDI(route.ddi) && route.phyKind == TGLEDP::PHYKind::Combo))
            return Reason::TypeCComboMismatch;
        return Reason::PhysicalPairMismatch;
    }
    if (connector == ConnectorClass::InternalEDP && !TGLEDP::comboDDI(route.ddi))
        return Reason::TypeCComboMismatch;
    if (connector == ConnectorClass::InternalEDP && !route.displayPortSupported)
        return Reason::TransportMismatch;
    if (connector == ConnectorClass::InternalEDP && !route.panelPresent)
        return Reason::PanelEvidenceMissing;
    if (route.displayPortSupported && !TGLEDP::knownAUX(route.aux)) return Reason::AUXUnknown;
    if (connector == ConnectorClass::FixedHDMI && route.displayPortSupported)
        return Reason::TransportMismatch;
    return Reason::None;
}

inline FirmwareAnalysis FirmwareValidator::analyze(const void *data, size_t length,
                                                   const FirmwareOriginProof &origin) {
    FirmwareAnalysis result;
    auto &v = result.validation;
    v.suppliedBytes = length;
    if (!data || !length) return result;

    const auto p = static_cast<const uint8_t *>(data);
    if (length < 48 || memcmp(p, "$VBT", 4) != 0) {
        v.status = FirmwareStatus::HeaderInvalid;
        return result;
    }
    const size_t headerBytes = XELP::VBT::u16(p + 22);
    const size_t declaredBytes = XELP::VBT::u16(p + 24);
    const size_t bdbOffset = XELP::VBT::u32(p + 28);
    v.declaredBytes = declaredBytes;
    v.headerBytes = headerBytes;
    v.bdbOffset = bdbOffset;
    v.headerValid = headerBytes >= 48;
    v.declaredLengthValid = v.headerValid && declaredBytes >= headerBytes && declaredBytes <= length;
    if (!v.headerValid) {
        v.status = FirmwareStatus::HeaderInvalid;
        return result;
    }
    if (!v.declaredLengthValid) {
        v.status = FirmwareStatus::DeclaredLengthInvalid;
        return result;
    }
    for (size_t i = 0; i < declaredBytes; ++i) v.checksumRemainder = static_cast<uint8_t>(v.checksumRemainder + p[i]);
    v.checksumValid = v.checksumRemainder == 0;

    if (bdbOffset < headerBytes || bdbOffset > declaredBytes || declaredBytes - bdbOffset < 22) {
        v.status = FirmwareStatus::BDBBoundsInvalid;
        return result;
    }
    const auto bdb = p + bdbOffset;
    const size_t bdbHeaderBytes = XELP::VBT::u16(bdb + 18);
    const size_t bdbBytes = XELP::VBT::u16(bdb + 20);
    v.bdbBytes = bdbBytes;
    v.bdbHeaderBytes = bdbHeaderBytes;
    v.bdbVersion = XELP::VBT::u16(bdb + 16);
    if (memcmp(bdb, "BIOS_DATA_BLOCK ", 16) != 0 || bdbHeaderBytes < 22 ||
        bdbBytes < bdbHeaderBytes || bdbBytes > declaredBytes - bdbOffset) {
        v.status = FirmwareStatus::BDBBoundsInvalid;
        return result;
    }
    v.bdbBoundsValid = true;
    v.bdbVersionCompatible = v.bdbVersion >= 216 && v.bdbVersion <= 256;

    const uint8_t *generalDefinitions = nullptr;
    size_t generalDefinitionsBytes = 0;
    const size_t streamEnd = bdbBytes;
    size_t at = bdbHeaderBytes;
    bool streamValid = true;
    while (at < streamEnd) {
        const size_t remaining = streamEnd - at;
        if (remaining < 3) {
            streamValid = false;
            v.malformedBlockOffset = bdbOffset + at;
            break;
        }
        const uint8_t blockId = bdb[at];
        size_t payloadBytes = XELP::VBT::u16(bdb + at + 1);
        if (blockId == 53) { // Preserve the repository's versioned MIPI length rule.
            if (remaining < 4) {
                streamValid = false;
                v.malformedBlockId = blockId;
                v.malformedBlockOffset = bdbOffset + at;
                break;
            }
            if (bdb[at + 3] >= 3) {
                if (remaining < 8) {
                    streamValid = false;
                    v.malformedBlockId = blockId;
                    v.malformedBlockOffset = bdbOffset + at;
                    break;
                }
                payloadBytes = XELP::VBT::u32(bdb + at + 4);
                if (payloadBytes < 5) {
                    streamValid = false;
                    v.malformedBlockId = blockId;
                    v.malformedBlockOffset = bdbOffset + at;
                    break;
                }
            }
        }
        if (payloadBytes > remaining - 3) {
            streamValid = false;
            v.malformedBlockId = blockId;
            v.malformedBlockOffset = bdbOffset + at;
            v.malformedBlockClaimedBytes = payloadBytes;
            v.malformedBlockAvailableBytes = remaining - 3;
            break;
        }
        if (blockId == 2) {
            if (generalDefinitions) {
                result.duplicateGeneralDefinitions = true;
            } else {
                generalDefinitions = bdb + at + 3;
                generalDefinitionsBytes = payloadBytes;
            }
        }
        at += 3 + payloadBytes;
    }
    v.fullBDBStreamValid = streamValid && at == streamEnd;
    v.generalDefinitionsBytes = generalDefinitionsBytes;
    if (!v.bdbVersionCompatible) {
        v.status = FirmwareStatus::BDBVersionUnsupported;
        return result;
    }

    if (generalDefinitions && generalDefinitionsBytes >= 5) {
        const uint32_t stride = generalDefinitions[4];
        const size_t descriptorBytes = generalDefinitionsBytes - 5;
        v.childStride = stride;
        if (stride == 39 && descriptorBytes % stride == 0 && descriptorBytes / stride <= XELP::PortCount) {
            v.childLayoutCompatible = true;
            v.childTableValid = !result.duplicateGeneralDefinitions;
            v.childSlots = static_cast<uint32_t>(descriptorBytes / stride);
            for (size_t i = 0; i < v.childSlots; ++i) {
                const auto child = generalDefinitions + 5 + stride * i;
                const uint32_t type = XELP::VBT::u16(child + 2);
                if (!type) continue;
                ++v.populatedDescriptors;
                XELP::VBT::Port port;
                port.type = type;
                port.dvo = child[16];
                port.ddc = child[19];
                port.aux = child[25];
                port.flags = child[23];
                port.capabilities = child[33];
                const auto ddi = decodeTGLDDI(port.dvo);
                auto candidate = FirmwareCandidate{};
                candidate.connector = classifyDescriptor(port, ddi);
                candidate.descriptorIndex = static_cast<uint8_t>(i);
                candidate.dvoCode = port.dvo;
                candidate.auxCode = port.aux;
                candidate.detected = candidate.connector == ConnectorClass::InternalEDP;
                candidate.route.active = true;
                candidate.route.connector = candidate.connector == ConnectorClass::InternalEDP ?
                    TGLEDP::Connector::InternalDP :
                    (candidate.connector == ConnectorClass::FixedHDMI ? TGLEDP::Connector::HDMI :
                     ((candidate.connector == ConnectorClass::ExternalDisplayPort ||
                       candidate.connector == ConnectorClass::TypeCCapableDisplayPath) ?
                       TGLEDP::Connector::ExternalDP : TGLEDP::Connector::Unknown));
                candidate.route.role = candidate.connector == ConnectorClass::InternalEDP ?
                    TGLEDP::Role::InternalPanel :
                    (candidate.route.connector == TGLEDP::Connector::Unknown ? TGLEDP::Role::Unknown :
                     TGLEDP::Role::ExternalDisplay);
                candidate.route.ddi = ddi;
                if (TGLEDP::comboDDI(ddi)) {
                    candidate.route.phyKind = TGLEDP::PHYKind::Combo;
                    candidate.route.phy = ddi == TGLEDP::DDI::A ? 0 : 1;
                } else if (TGLEDP::typeCDDI(ddi)) {
                    candidate.route.phyKind = TGLEDP::PHYKind::TypeC;
                    candidate.route.phy = static_cast<uint8_t>(ddi) - 3U;
                }
                candidate.route.aux = decodeAUX(port.aux);
                candidate.route.source = v.checksumValid && v.fullBDBStreamValid ?
                    TGLEDP::EvidenceSource::StrictFirmware : TGLEDP::EvidenceSource::DiagnosticVBT;
                candidate.route.firmware = {v.checksumValid, v.fullBDBStreamValid,
                    v.childTableValid, false, false};
                candidate.route.firmwareDerived = true;
                candidate.route.panelPresent = candidate.connector == ConnectorClass::InternalEDP;
                candidate.route.displayPortSupported = port.dp();
                candidate.route.typeCCapable = (port.capabilities & 3U) != 0;
                candidate.route.backendCapable = candidate.connector == ConnectorClass::InternalEDP &&
                    TGLEDP::comboDDI(ddi) && candidate.route.displayPortSupported &&
                    TGLEDP::knownAUX(candidate.route.aux);
                const auto topology = topologyReason(candidate.route, candidate.connector);
                candidate.structurallyQualified = topology == Reason::None;
                candidate.stage = candidate.structurallyQualified ? Stage::StructurallyQualified : Stage::Detected;
                candidate.reason = topology;
                if (candidate.structurallyQualified &&
                    (candidate.route.source != TGLEDP::EvidenceSource::StrictFirmware || !v.checksumValid ||
                     !v.fullBDBStreamValid || !v.childTableValid))
                    candidate.reason = Reason::DiagnosticOnly;
                if (result.candidateCount < MaxCandidates)
                    result.candidates[result.candidateCount++] = candidate;
            }
            // Duplicate physical DVO claims are ambiguous even if each record
            // was individually bounded and decoded.
            for (size_t i = 0; i < result.candidateCount; ++i) {
                for (size_t j = i + 1; j < result.candidateCount; ++j) {
                    if (result.candidates[i].route.ddi != TGLEDP::DDI::Unknown &&
                        result.candidates[i].route.ddi == result.candidates[j].route.ddi) {
                        result.descriptorConflict = true;
                        result.duplicateDDI = true;
                        result.candidates[i].stage = Stage::Conflict;
                        result.candidates[j].stage = Stage::Conflict;
                        result.candidates[i].reason = Reason::DuplicateDDI;
                        result.candidates[j].reason = Reason::DuplicateDDI;
                    } else if (result.candidates[i].route.phyKind != TGLEDP::PHYKind::Unknown &&
                               result.candidates[i].route.phyKind == result.candidates[j].route.phyKind &&
                               result.candidates[i].route.phy == result.candidates[j].route.phy) {
                        result.descriptorConflict = true;
                        result.duplicatePHY = true;
                        result.candidates[i].stage = Stage::Conflict;
                        result.candidates[j].stage = Stage::Conflict;
                        result.candidates[i].reason = Reason::DuplicatePHY;
                        result.candidates[j].reason = Reason::DuplicatePHY;
                    } else if (result.candidates[i].route.displayPortSupported &&
                               result.candidates[j].route.displayPortSupported &&
                               result.candidates[i].route.aux == result.candidates[j].route.aux) {
                        result.descriptorConflict = true;
                        result.duplicateAUX = true;
                        result.candidates[i].stage = Stage::Conflict;
                        result.candidates[j].stage = Stage::Conflict;
                        result.candidates[i].reason = Reason::DuplicateAUX;
                        result.candidates[j].reason = Reason::DuplicateAUX;
                    }
                }
            }
            v.connectorMetadataValid = !result.descriptorConflict && !result.duplicateGeneralDefinitions;
        }
    }

    v.childTableValid = v.childTableValid && v.childLayoutCompatible && generalDefinitions != nullptr;
    v.wholeImageValidated = v.headerValid && v.declaredLengthValid && v.bdbBoundsValid &&
        v.bdbVersionCompatible && v.childLayoutCompatible && v.childTableValid &&
        v.fullBDBStreamValid && v.checksumValid &&
        v.connectorMetadataValid;
    v.sourceAuthorized = origin.valid();
    v.runtimeTrusted = v.wholeImageValidated && v.sourceAuthorized;
    v.diagnosticOnly = !v.runtimeTrusted;
    if (v.wholeImageValidated) v.status = FirmwareStatus::StrictlyValid;
    else if (!v.checksumValid) v.status = FirmwareStatus::ChecksumInvalid;
    else if (!v.fullBDBStreamValid) v.status = FirmwareStatus::BDBStreamMalformed;
    else if (!v.childLayoutCompatible) v.status = FirmwareStatus::ChildLayoutInvalid;
    else if (!v.childTableValid || !v.connectorMetadataValid) v.status = FirmwareStatus::ConnectorMetadataInvalid;
    else v.status = FirmwareStatus::BDBStreamMalformed;

    for (size_t i = 0; i < result.candidateCount; ++i) {
        auto &candidate = result.candidates[i];
        auto &route = candidate.route;
        route.source = v.runtimeTrusted ? TGLEDP::EvidenceSource::StrictFirmware :
            TGLEDP::EvidenceSource::DiagnosticVBT;
        route.firmware = {v.checksumValid, v.fullBDBStreamValid, v.childTableValid,
            v.wholeImageValidated, !v.runtimeTrusted};
        route.firmwareDerived = true;
        if (v.runtimeTrusted && candidate.connector != ConnectorClass::UnsupportedOrUnknown &&
            candidate.stage != Stage::Conflict)
            authorize(route);
        if (candidate.structurallyQualified && !v.runtimeTrusted && candidate.reason == Reason::None)
            candidate.reason = Reason::DiagnosticOnly;
        candidate.runtimeAdmissible = false;
    }
    return result;
}

inline FirmwareAnalysis analyzeFirmware(const void *data, size_t length) {
    return FirmwareValidator::analyze(data, length, FirmwareOriginProof{});
}

inline FirmwareAnalysis analyzeFirmware(const void *data, size_t length, const FirmwareOriginProof &origin) {
    return FirmwareValidator::analyze(data, length, origin);
}

inline ConnectorClass classifyRoute(const TGLEDP::RouteEvidence &route) {
    using namespace TGLEDP;
    if (route.connector == Connector::InternalDP) {
        return route.role == Role::InternalPanel ? ConnectorClass::InternalEDP :
            ConnectorClass::ConflictingOrAmbiguous;
    }
    if (route.connector == Connector::ExternalDP) {
        if (route.role != Role::ExternalDisplay) return ConnectorClass::ConflictingOrAmbiguous;
        return (route.typeCCapable || typeCDDI(route.ddi)) ? ConnectorClass::TypeCCapableDisplayPath :
            ConnectorClass::ExternalDisplayPort;
    }
    if (route.connector == Connector::HDMI) {
        if (route.role != Role::ExternalDisplay) return ConnectorClass::ConflictingOrAmbiguous;
        return (route.typeCCapable || typeCDDI(route.ddi)) ? ConnectorClass::TypeCCapableDisplayPath :
            ConnectorClass::FixedHDMI;
    }
    return ConnectorClass::UnsupportedOrUnknown;
}

inline Reason reasonForRejection(TGLEDP::Rejection rejection) {
    using TGLEDP::Rejection;
    switch (rejection) {
        case Rejection::None: return Reason::None;
        case Rejection::NativeABI: return Reason::NativeABIRejected;
        case Rejection::InventoryIncomplete: return Reason::IncompleteSnapshot;
        case Rejection::BackendCapability: return Reason::BackendUnavailable;
        case Rejection::DDI: return Reason::UnsupportedDDI;
        case Rejection::TypeCPhy: return Reason::TypeCComboMismatch;
        case Rejection::PHY: return Reason::PhysicalPairMismatch;
        case Rejection::AUX: return Reason::AUXUnknown;
        case Rejection::DiagnosticOnly: return Reason::DiagnosticOnly;
        case Rejection::PanelAbsent: return Reason::PanelEvidenceMissing;
        case Rejection::PanelPresenceUnknown: return Reason::PanelPresenceUnknown;
        case Rejection::OwnershipUnknown: return Reason::OwnershipUnknown;
        case Rejection::OwnershipConflict: return Reason::OwnershipConflict;
        case Rejection::AmbiguousRoute: return Reason::DuplicateResource;
        case Rejection::DonorBindingConflict: return Reason::DonorBindingConflict;
        case Rejection::UntrustedEvidence: return Reason::UntrustedEvidence;
        case Rejection::GPUProfile:
        case Rejection::PhysicalIdentity:
        case Rejection::WrongFamily:
        case Rejection::WrongDisplay:
        case Rejection::Donor:
        case Rejection::GPUCapability: return Reason::GPURejected;
        case Rejection::FirmwareChecksum: return Reason::ChecksumInvalid;
        case Rejection::FirmwareMalformed: return Reason::BDBStreamMalformed;
        case Rejection::ConnectorRole: return Reason::TransportMismatch;
        case Rejection::Transport: return Reason::TransportMismatch;
        case Rejection::RouteUnknown: return Reason::NoInternalPanel;
        case Rejection::FramebufferEvidence: return Reason::UntrustedEvidence;
    }
    return Reason::UntrustedEvidence;
}

inline ClassificationResult classify(const FirmwareAnalysis &firmware, const TGLEDP::GPUFacts &gpuFacts,
                                      const TGLEDP::RoutingSnapshot &snapshot) {
    using namespace TGLEDP;
    ClassificationResult result;
    result.routeCount = snapshot.count <= MaxCandidates ? snapshot.count : MaxCandidates;
    const size_t firmwareCount = firmware.candidateCount <= MaxCandidates ? firmware.candidateCount : MaxCandidates;
    if (firmware.candidateCount > MaxCandidates) {
        result.conflict = true;
        result.reason = Reason::ConnectorMetadataInvalid;
    }
    bool firmwareInternal = false;
    for (size_t i = 0; i < firmwareCount; ++i)
        firmwareInternal = firmwareInternal || firmware.candidates[i].connector == ConnectorClass::InternalEDP;

    size_t internalCount = 0;
    bool allRoutesStructural = snapshot.complete && snapshot.count <= MaxCandidates &&
        firmware.candidateCount <= MaxCandidates;
    for (size_t i = 0; i < result.routeCount; ++i) {
        const auto &route = snapshot.routes[i];
        auto &item = result.routes[i];
        item.connector = classifyRoute(route);
        item.detected = item.connector == ConnectorClass::InternalEDP ||
            item.connector == ConnectorClass::ExternalDisplayPort || item.connector == ConnectorClass::FixedHDMI ||
            item.connector == ConnectorClass::TypeCCapableDisplayPath;
        if (item.connector == ConnectorClass::InternalEDP) {
            result.detected = true;
            ++internalCount;
            if (route.active && result.internalRouteIndex == MaxCandidates) result.internalRouteIndex = i;
        }
        if (item.connector == ConnectorClass::ConflictingOrAmbiguous) {
            item.stage = Stage::Conflict;
            item.reason = Reason::ContradictoryEvidence;
            result.conflict = true;
            allRoutesStructural = false;
        } else {
            item.reason = topologyReason(route, item.connector);
            item.structurallyQualified = item.detected && item.reason == Reason::None;
            item.stage = item.structurallyQualified ? Stage::StructurallyQualified :
                (item.detected ? Stage::Detected : Stage::Unknown);
            if ((item.detected && !item.structurallyQualified) ||
                (route.active && item.connector == ConnectorClass::UnsupportedOrUnknown)) {
                allRoutesStructural = false;
                if (result.reason == Reason::None)
                    result.reason = item.reason == Reason::None ? Reason::ConnectorMetadataInvalid : item.reason;
            }
        }
    }
    result.detected = result.detected || firmwareInternal;

    if (firmware.descriptorConflict || firmware.duplicateGeneralDefinitions) {
        result.conflict = true;
        allRoutesStructural = false;
        result.reason = Reason::ConnectorMetadataInvalid;
    }
    if (snapshot.count > MaxCandidates || !snapshot.complete) {
        allRoutesStructural = false;
        result.reason = Reason::IncompleteSnapshot;
    }

    // Reconcile every mapped firmware connector with the complete ownership
    // snapshot. Firmware DVO and AUX values are compared independently.
    for (size_t i = 0; i < firmwareCount; ++i) {
        const auto &candidate = firmware.candidates[i];
        const auto &firmwareRoute = candidate.route;
        if (!knownDDI(firmwareRoute.ddi)) continue;
        size_t match = MaxCandidates;
        for (size_t j = 0; j < result.routeCount; ++j) {
            if (snapshot.routes[j].ddi == firmwareRoute.ddi) {
                if (match != MaxCandidates) {
                    result.conflict = true;
                    allRoutesStructural = false;
                    result.reason = Reason::DuplicateDDI;
                }
                match = j;
            }
        }
        if (match == MaxCandidates) {
            allRoutesStructural = false;
            if (candidate.connector == ConnectorClass::InternalEDP && internalCount) {
                result.conflict = true;
                result.reason = Reason::ContradictoryEvidence;
            } else if (result.reason == Reason::None) result.reason = Reason::FirmwareRouteMissing;
            continue;
        }
        const auto &observed = snapshot.routes[match];
        const auto observedClass = classifyRoute(observed);
        if (observedClass != candidate.connector || observed.phyKind != firmwareRoute.phyKind ||
            observed.phy != firmwareRoute.phy ||
            (firmwareRoute.displayPortSupported && observed.aux != firmwareRoute.aux)) {
            result.conflict = true;
            allRoutesStructural = false;
            result.reason = Reason::ContradictoryEvidence;
        }
    }

    // Any repeated physical resource claim is ambiguous, including claims by
    // disconnected ports: a connector's absence never proves its resources free.
    for (size_t i = 0; i < result.routeCount; ++i) {
        for (size_t j = i + 1; j < result.routeCount; ++j) {
            const auto &a = snapshot.routes[i];
            const auto &b = snapshot.routes[j];
            if (a.ddi == DDI::Unknown || b.ddi == DDI::Unknown) continue;
            if (a.ddi == b.ddi) {
                result.conflict = true;
                allRoutesStructural = false;
                result.reason = Reason::DuplicateDDI;
            } else if (a.phyKind == b.phyKind && a.phy == b.phy) {
                result.conflict = true;
                allRoutesStructural = false;
                result.reason = Reason::DuplicatePHY;
            } else if (a.displayPortSupported && b.displayPortSupported && a.aux == b.aux) {
                result.conflict = true;
                allRoutesStructural = false;
                result.reason = Reason::DuplicateAUX;
            }
        }
    }

    if (internalCount > 1) {
        result.conflict = true;
        allRoutesStructural = false;
        result.reason = Reason::AmbiguousInternalRoutes;
    }
    if (internalCount == 0) {
        result.connector = firmwareInternal ? ConnectorClass::InternalEDP :
            (result.routeCount == 1 ? result.routes[0].connector : ConnectorClass::UnsupportedOrUnknown);
        result.stage = result.conflict ? Stage::Conflict : (result.detected ? Stage::Detected : Stage::Unknown);
        if (result.reason == Reason::None) result.reason = firmwareInternal ? Reason::FirmwareRouteMissing : Reason::NoInternalPanel;
        result.gpuDecision = qualifyGPU(gpuFacts);
        return result;
    }
    if (result.internalRouteIndex == MaxCandidates) {
        result.conflict = result.conflict || firmwareInternal;
        result.gpuDecision = qualifyGPU(gpuFacts);
        result.stage = result.conflict ? Stage::Conflict : Stage::Detected;
        result.connector = ConnectorClass::InternalEDP;
        result.reason = Reason::ConnectorAbsent;
        return result;
    }

    result.connector = internalCount > 1 ? ConnectorClass::ConflictingOrAmbiguous : ConnectorClass::InternalEDP;
    result.gpuDecision = qualifyGPU(gpuFacts);
    if (allRoutesStructural && internalCount == 1) {
        result.structurallyQualified = true;
        result.stage = Stage::StructurallyQualified;
    } else {
        result.stage = result.conflict ? Stage::Conflict : Stage::Detected;
        if (result.reason == Reason::None) result.reason = Reason::IncompleteSnapshot;
    }
    result.connectorDecision = qualifyConnector(result.gpuDecision, snapshot, result.internalRouteIndex);
    if (result.connectorDecision.admitted() && !result.conflict && allRoutesStructural) {
        result.runtimeAdmissible = true;
        result.stage = Stage::RuntimeAdmissible;
        result.reason = Reason::None;
        for (size_t i = 0; i < result.routeCount; ++i) {
            if (result.routes[i].connector == ConnectorClass::InternalEDP) {
                result.routes[i].runtimeAdmissible = true;
                result.routes[i].stage = Stage::RuntimeAdmissible;
            }
        }
    } else if (result.reason == Reason::None) {
        result.reason = !result.gpuDecision.admitted() ? reasonForRejection(result.gpuDecision.rejection) :
            reasonForRejection(result.connectorDecision.rejection);
    }
    return result;
}

#if defined(TGLEDP_CLASSIFY_TESTING)
// Test-only authority allows deterministic synthetic contexts to exercise the
// final P003 gate. Production code has no route-minting shortcut for native or
// board evidence.
class TestEvidenceAuthority {
public:
    static FirmwareOriginProof syntheticFirmwareOrigin() {
        return FirmwareOriginProof(true);
    }

    static void authorize(TGLEDP::RouteEvidence &route) {
        route.authorization = TGLEDP::EvidenceAuthorization(static_cast<const TGLEDP::RouteFacts &>(route));
    }

    static void authorizeSnapshot(TGLEDP::RoutingSnapshot &snapshot) {
        if (snapshot.count > TGLEDP::MaxRouteClaims) return;
        TGLEDP::SnapshotFacts facts;
        facts.complete = snapshot.complete;
        facts.count = snapshot.count;
        for (size_t i = 0; i < snapshot.count; ++i)
            facts.routes[i] = static_cast<const TGLEDP::RouteFacts &>(snapshot.routes[i]);
        snapshot.authorization = TGLEDP::SnapshotAuthorization(facts);
    }
};
#endif

} // namespace TGLEDPClassify
#endif
