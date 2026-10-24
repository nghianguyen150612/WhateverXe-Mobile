// Bounded, read-only evidence model for a future Tiger Lake native route.
// This file validates copied observations only. It does not inspect pointers,
// acquire resources, or mint P004 route/snapshot authorizations.
#ifndef KERN_TGL_EDP_NATIVE_EVIDENCE_HPP
#define KERN_TGL_EDP_NATIVE_EVIDENCE_HPP

#include <stddef.h>
#include <stdint.h>

#include "kern_tgl_edp_contract.hpp"

namespace TGLEDPNative {

constexpr size_t MaxPorts = 8;       // DDI A/B and D/I; Tiger Lake has no DDI C.
constexpr size_t MaxResources = 32;  // 8 DDI + 8 PHY + 8 AUX, plus optional records.
constexpr uint32_t NativePortRecordMinimumBytes = 0x580;
constexpr uint32_t NativeFramebufferMinimumBytes = 0x4B90;
constexpr uint32_t NativePathMinimumBytes = 0x3730;
constexpr uint32_t NativePlaneMinimumBytes = 0x1C8;

enum class ObservationSource : uint8_t {
    Unknown,
    NativePortRecord,
    NativePHYReadout,
    NativeAUXReadout,
    NativeConnectorReadout,
    NativeConnectionReadout,
    NativeActivityReadout,
    NativePanelReadout,
    NativeOwnershipInventory,
    NativeFramebufferBinding,
    NativeTransportReadout,
    DiagnosticVBT,
    LinuxSysfsDiagnostic,
    SyntheticFixture
};

enum class ObjectKind : uint8_t { Unknown, Platform, PortRecord, Framebuffer, Path, Plane };
enum class ResourceKind : uint8_t { Unknown, DDI, PHY, AUX, PanelPower };
enum class PathState : uint8_t { Unknown, NoBoundPath, BoundPath };
enum class ActivityState : uint8_t { Unknown, Inactive, Active };
enum class PanelPresence : uint8_t { Unknown, Absent, Present };
enum class Transport : uint8_t { Unknown, DisplayPort, HDMI };

enum class Reason : uint8_t {
    None,
    UnsupportedGPU,
    WrongGeneration,
    DonorMismatch,
    NativeABIMismatch,
    MissingOwnerBinding,
    MissingObjectBinding,
    ObjectTooSmall,
    ObjectAssociationMismatch,
    UnsupportedDDI,
    DDIPhyMismatch,
    AUXUnknown,
    ConnectorUnknown,
    ConnectionUnknown,
    PanelPresenceUnknown,
    ContradictoryObservation,
    PathObservationUnknown,
    DuplicateDDI,
    DuplicatePHY,
    DuplicateAUX,
    DuplicateResource,
    OwnershipUnknown,
    OwnershipConflict,
    DonorBindingConflict,
    InventoryIncomplete,
    SnapshotChanged,
    StaleGeneration,
    SynchronizationMismatch,
    DiagnosticOnly,
    UnsupportedSource
};

enum class Consistency : uint8_t { Unknown, Inconsistent, Consistent };

struct NativeObjectBinding {
    ObjectKind kind {ObjectKind::Unknown};
    uint64_t ownerIdentity {};
    uint64_t objectIdentity {};
    uint64_t parentIdentity {};
    uint64_t linkedPortIdentity {};
    uint64_t observationGeneration {};
    uint32_t recordIndex {UINT32_MAX};
    uint32_t abiRevision {};
    uint32_t objectBytes {};
};

struct FramebufferAssociation {
    PathState state {PathState::Unknown};
    ObservationSource source {ObservationSource::Unknown};
    uint64_t ownerLockIdentity {};
    uint64_t observationGeneration {};
    NativeObjectBinding framebufferObject;
    NativeObjectBinding pathObject;
    NativeObjectBinding planeObject;
    // This index is diagnostic metadata only. It never identifies a DDI or
    // substitutes for any of the opaque object identities above.
    uint32_t framebufferIndex {UINT32_MAX};
    uint32_t pipe {UINT32_MAX};
    TGLEDP::DDI ddi {TGLEDP::DDI::Unknown};
    uint32_t primaryPlane {UINT32_MAX};
};

struct PortObservation {
    NativeObjectBinding portRecord;
    FramebufferAssociation framebuffer;
    TGLEDP::DDI ddi {TGLEDP::DDI::Unknown};
    TGLEDP::PHYKind phyKind {TGLEDP::PHYKind::Unknown};
    uint8_t phy {0xFF};
    TGLEDP::AUX aux {TGLEDP::AUX::Unknown};
    TGLEDP::Connector connector {TGLEDP::Connector::Unknown};
    TGLEDP::Role role {TGLEDP::Role::Unknown};
    TGLEDP::ConnectionState connection {TGLEDP::ConnectionState::Unknown};
    ActivityState activity {ActivityState::Unknown};
    PanelPresence panel {PanelPresence::Unknown};
    Transport transport {Transport::Unknown};
    uint64_t ownerLockIdentity {};
    uint64_t observationGeneration {};
    ObservationSource ddiSource {ObservationSource::Unknown};
    ObservationSource phySource {ObservationSource::Unknown};
    ObservationSource auxSource {ObservationSource::Unknown};
    ObservationSource connectorSource {ObservationSource::Unknown};
    ObservationSource connectionSource {ObservationSource::Unknown};
    ObservationSource activitySource {ObservationSource::Unknown};
    ObservationSource panelSource {ObservationSource::Unknown};
    ObservationSource transportSource {ObservationSource::Unknown};
};

struct ResourceObservation {
    ResourceKind kind {ResourceKind::Unknown};
    uint8_t index {0xFF};
    TGLEDP::PHYKind phyKind {TGLEDP::PHYKind::Unknown};
    TGLEDP::ResourceOwner owner {TGLEDP::ResourceOwner::Unknown};
    uint64_t ownerIdentity {};
    uint64_t ownerLockIdentity {};
    uint64_t observationGeneration {};
    ObservationSource source {ObservationSource::Unknown};
};

// All identities are opaque integer keys supplied by the native owner. They
// are never cast to pointers or dereferenced by this policy layer.
struct SnapshotCandidate {
    TGLEDP::GPUFacts gpu;
    uint64_t nativeOwnerIdentity {};
    uint64_t controllerIdentity {};
    uint64_t platformIdentity {};
    uint64_t generationAtStart {};
    uint64_t generationAtEnd {};
    uint64_t nativeOwnerLockIdentity {};
    size_t portCount {};
    PortObservation ports[MaxPorts] {};
    size_t resourceCount {};
    ResourceObservation resources[MaxResources] {};
};

struct ValidationResult {
    Consistency consistency {Consistency::Unknown};
    Reason reason {Reason::None};
    uint64_t generation {};
    bool inventoryComplete {};
    bool topologyConsistent {};
};

inline bool supportedDDI(TGLEDP::DDI ddi) {
    return TGLEDP::knownDDI(ddi);
}

inline uint8_t expectedPortDDI(size_t slot) {
    if (slot == 0) return static_cast<uint8_t>(TGLEDP::DDI::A);
    if (slot == 1) return static_cast<uint8_t>(TGLEDP::DDI::B);
    return static_cast<uint8_t>(TGLEDP::DDI::D) + static_cast<uint8_t>(slot - 2);
}

inline bool validResourceKey(const ResourceObservation &resource) {
    using TGLEDP::PHYKind;
    switch (resource.kind) {
        case ResourceKind::DDI:
            return resource.phyKind == PHYKind::Unknown &&
                (resource.index == static_cast<uint8_t>(TGLEDP::DDI::A) ||
                 resource.index == static_cast<uint8_t>(TGLEDP::DDI::B) ||
                 (resource.index >= static_cast<uint8_t>(TGLEDP::DDI::D) &&
                  resource.index <= static_cast<uint8_t>(TGLEDP::DDI::I)));
        case ResourceKind::PHY:
            return (resource.phyKind == PHYKind::Combo && resource.index < 2) ||
                (resource.phyKind == PHYKind::TypeC && resource.index < 6);
        case ResourceKind::AUX:
            return resource.index >= static_cast<uint8_t>(TGLEDP::AUX::A) &&
                resource.index <= static_cast<uint8_t>(TGLEDP::AUX::H) &&
                resource.phyKind == PHYKind::Unknown;
        case ResourceKind::PanelPower:
            return resource.index == 0 && resource.phyKind == PHYKind::Unknown;
        case ResourceKind::Unknown:
            return false;
    }
    return false;
}

inline bool sameResourceKey(const ResourceObservation &a, const ResourceObservation &b) {
    return a.kind == b.kind && a.index == b.index && a.phyKind == b.phyKind;
}

inline size_t countResource(const SnapshotCandidate &candidate, const ResourceObservation &key) {
    size_t count = 0;
    const auto limit = candidate.resourceCount <= MaxResources ? candidate.resourceCount : MaxResources;
    for (size_t i = 0; i < limit; ++i)
        if (sameResourceKey(candidate.resources[i], key)) ++count;
    return count;
}

inline const ResourceObservation *findResource(const SnapshotCandidate &candidate,
                                              const ResourceObservation &key) {
    const auto limit = candidate.resourceCount <= MaxResources ? candidate.resourceCount : MaxResources;
    for (size_t i = 0; i < limit; ++i)
        if (sameResourceKey(candidate.resources[i], key)) return &candidate.resources[i];
    return nullptr;
}

inline ResourceObservation resourceKey(ResourceKind kind, uint8_t index,
                                       TGLEDP::PHYKind phyKind = TGLEDP::PHYKind::Unknown) {
    ResourceObservation key;
    key.kind = kind;
    key.index = index;
    key.phyKind = phyKind;
    return key;
}

inline bool sourceAllowed(ObservationSource source) {
    return source == ObservationSource::NativePortRecord ||
        source == ObservationSource::NativePHYReadout ||
        source == ObservationSource::NativeAUXReadout ||
        source == ObservationSource::NativeConnectorReadout ||
        source == ObservationSource::NativeConnectionReadout ||
        source == ObservationSource::NativeActivityReadout ||
        source == ObservationSource::NativePanelReadout ||
        source == ObservationSource::NativeOwnershipInventory ||
        source == ObservationSource::NativeFramebufferBinding ||
        source == ObservationSource::NativeTransportReadout ||
        source == ObservationSource::SyntheticFixture;
}

inline bool sourceMatches(ObservationSource source, ObservationSource expected) {
    return source == expected || source == ObservationSource::SyntheticFixture;
}

inline bool sourceDiagnostic(ObservationSource source) {
    return source == ObservationSource::DiagnosticVBT ||
        source == ObservationSource::LinuxSysfsDiagnostic;
}

inline uint32_t expectedPHY(TGLEDP::DDI ddi, TGLEDP::PHYKind &kind) {
    if (TGLEDP::comboDDI(ddi)) {
        kind = TGLEDP::PHYKind::Combo;
        return ddi == TGLEDP::DDI::A ? 0U : 1U;
    }
    if (TGLEDP::typeCDDI(ddi)) {
        kind = TGLEDP::PHYKind::TypeC;
        return static_cast<uint32_t>(ddi) - 3U;
    }
    kind = TGLEDP::PHYKind::Unknown;
    return UINT32_MAX;
}

inline Reason validateObject(const NativeObjectBinding &object, ObjectKind expectedKind,
                             uint64_t ownerIdentity, uint64_t parentIdentity,
                             uint64_t generation, uint32_t minimumBytes,
                             uint32_t recordIndex = UINT32_MAX) {
    if (object.kind != expectedKind || !object.objectIdentity || !object.ownerIdentity ||
        !object.parentIdentity) return Reason::MissingObjectBinding;
    if (object.ownerIdentity != ownerIdentity || object.parentIdentity != parentIdentity ||
        object.observationGeneration != generation || object.abiRevision != TGLEDP::RequiredNativeProbeABI ||
        (recordIndex != UINT32_MAX && object.recordIndex != recordIndex))
        return Reason::ObjectAssociationMismatch;
    if (object.objectBytes < minimumBytes) return Reason::ObjectTooSmall;
    return Reason::None;
}

// This is a structural consistency check over bounded copied values. Source
// labels describe provenance claims; they are not proof of provenance and do
// not authorize a route. expectedGeneration must come from the current owner.
inline ValidationResult validate(const SnapshotCandidate &candidate, uint64_t expectedGeneration) {
    ValidationResult result;
    if (candidate.gpu.profile.family != XELP::Family::TigerLake) {
        result.consistency = Consistency::Inconsistent;
        result.reason = Reason::WrongGeneration;
        return result;
    }
    if (candidate.gpu.profile.donor != XELP::Donor::C004FC1A) {
        result.consistency = Consistency::Inconsistent;
        result.reason = Reason::DonorMismatch;
        return result;
    }
    if (candidate.gpu.nativeProbeABI != TGLEDP::RequiredNativeProbeABI) {
        result.consistency = Consistency::Inconsistent;
        result.reason = Reason::NativeABIMismatch;
        return result;
    }
    if (!TGLEDP::qualifyGPU(candidate.gpu).admitted()) {
        result.consistency = Consistency::Inconsistent;
        result.reason = Reason::UnsupportedGPU;
        return result;
    }
    if (!candidate.nativeOwnerIdentity || !candidate.controllerIdentity || !candidate.platformIdentity ||
        !candidate.nativeOwnerLockIdentity) {
        result.consistency = Consistency::Inconsistent;
        result.reason = Reason::MissingOwnerBinding;
        return result;
    }
    if (!candidate.generationAtStart || candidate.generationAtStart != candidate.generationAtEnd) {
        result.consistency = Consistency::Inconsistent;
        result.reason = Reason::SnapshotChanged;
        return result;
    }
    if (candidate.generationAtEnd != expectedGeneration) {
        result.consistency = Consistency::Inconsistent;
        result.reason = Reason::StaleGeneration;
        return result;
    }
    result.generation = candidate.generationAtEnd;

    if (candidate.portCount != MaxPorts || candidate.resourceCount > MaxResources ||
        candidate.resourceCount < 24) {
        result.consistency = Consistency::Inconsistent;
        result.reason = Reason::InventoryIncomplete;
        return result;
    }

    // The complete inventory is exactly DDI A/B/D-I, Combo PHY 0/1,
    // Type-C PHY 0-5, and AUX A-H. DDI C has no supported Tiger Lake record.
    for (size_t slot = 0; slot < MaxPorts; ++slot) {
        const auto ddi = expectedPortDDI(slot);
        const auto key = resourceKey(ResourceKind::DDI, ddi);
        if (countResource(candidate, key) != 1) {
            result.consistency = Consistency::Inconsistent;
            result.reason = countResource(candidate, key) > 1 ? Reason::DuplicateResource : Reason::InventoryIncomplete;
            return result;
        }
    }
    for (uint8_t phy = 0; phy < 2; ++phy) {
        const auto key = resourceKey(ResourceKind::PHY, phy, TGLEDP::PHYKind::Combo);
        if (countResource(candidate, key) != 1) {
            result.consistency = Consistency::Inconsistent;
            result.reason = countResource(candidate, key) > 1 ? Reason::DuplicateResource : Reason::InventoryIncomplete;
            return result;
        }
    }
    for (uint8_t phy = 0; phy < 6; ++phy) {
        const auto key = resourceKey(ResourceKind::PHY, phy, TGLEDP::PHYKind::TypeC);
        if (countResource(candidate, key) != 1) {
            result.consistency = Consistency::Inconsistent;
            result.reason = countResource(candidate, key) > 1 ? Reason::DuplicateResource : Reason::InventoryIncomplete;
            return result;
        }
    }
    for (uint8_t aux = static_cast<uint8_t>(TGLEDP::AUX::A);
         aux <= static_cast<uint8_t>(TGLEDP::AUX::H); ++aux) {
        const auto key = resourceKey(ResourceKind::AUX, aux);
        if (countResource(candidate, key) != 1) {
            result.consistency = Consistency::Inconsistent;
            result.reason = countResource(candidate, key) > 1 ? Reason::DuplicateResource : Reason::InventoryIncomplete;
            return result;
        }
    }
    if (candidate.resourceCount != 24 && candidate.resourceCount != 25) {
        result.consistency = Consistency::Inconsistent;
        result.reason = Reason::InventoryIncomplete;
        return result;
    }

    for (size_t i = 0; i < candidate.resourceCount; ++i) {
        const auto &resource = candidate.resources[i];
        if (!validResourceKey(resource)) {
            result.consistency = Consistency::Inconsistent;
            result.reason = Reason::UnsupportedDDI;
            return result;
        }
        if (sourceDiagnostic(resource.source)) {
            result.consistency = Consistency::Inconsistent;
            result.reason = Reason::DiagnosticOnly;
            return result;
        }
        if (!sourceAllowed(resource.source)) {
            result.consistency = Consistency::Inconsistent;
            result.reason = Reason::UnsupportedSource;
            return result;
        }
        if (!sourceMatches(resource.source, ObservationSource::NativeOwnershipInventory)) {
            result.consistency = Consistency::Inconsistent;
            result.reason = Reason::UnsupportedSource;
            return result;
        }
        if (resource.observationGeneration != result.generation) {
            result.consistency = Consistency::Inconsistent;
            result.reason = Reason::StaleGeneration;
            return result;
        }
        if (resource.ownerLockIdentity != candidate.nativeOwnerLockIdentity) {
            result.consistency = Consistency::Inconsistent;
            result.reason = Reason::SynchronizationMismatch;
            return result;
        }
        if (resource.owner == TGLEDP::ResourceOwner::Unknown) {
            result.consistency = Consistency::Inconsistent;
            result.reason = Reason::OwnershipUnknown;
            return result;
        }
        if (!TGLEDP::knownOwner(resource.owner)) {
            result.consistency = Consistency::Inconsistent;
            result.reason = Reason::OwnershipUnknown;
            return result;
        }
        if ((resource.owner == TGLEDP::ResourceOwner::KnownFree && resource.ownerIdentity) ||
            (resource.owner != TGLEDP::ResourceOwner::KnownFree && !resource.ownerIdentity)) {
            result.consistency = Consistency::Inconsistent;
            result.reason = Reason::OwnershipConflict;
            return result;
        }
        if (resource.owner == TGLEDP::ResourceOwner::NativeDonor &&
            resource.ownerIdentity != candidate.nativeOwnerIdentity) {
            result.consistency = Consistency::Inconsistent;
            result.reason = Reason::DonorBindingConflict;
            return result;
        }
        for (size_t j = 0; j < i; ++j) {
            if (sameResourceKey(resource, candidate.resources[j])) {
                result.consistency = Consistency::Inconsistent;
                result.reason = Reason::DuplicateResource;
                return result;
            }
        }
    }

    bool ddiSeen[9] {};
    bool comboPHYSeen[2] {};
    bool typeCPHYSeen[6] {};
    bool auxSeen[9] {};
    for (size_t i = 0; i < MaxPorts; ++i) {
        const auto &port = candidate.ports[i];
        if (port.ddi == TGLEDP::DDI::Unknown || !supportedDDI(port.ddi)) {
            result.consistency = Consistency::Inconsistent;
            result.reason = Reason::UnsupportedDDI;
            return result;
        }
        const auto ddiIndex = static_cast<uint8_t>(port.ddi);
        if (ddiSeen[ddiIndex]) {
            result.consistency = Consistency::Inconsistent;
            result.reason = Reason::DuplicateDDI;
            return result;
        }
        ddiSeen[ddiIndex] = true;
        if (ddiIndex != expectedPortDDI(i)) {
            result.consistency = Consistency::Inconsistent;
            result.reason = Reason::ObjectAssociationMismatch;
            return result;
        }
        if (sourceDiagnostic(port.ddiSource) || sourceDiagnostic(port.phySource) ||
            sourceDiagnostic(port.auxSource) || sourceDiagnostic(port.connectorSource) ||
            sourceDiagnostic(port.connectionSource) || sourceDiagnostic(port.activitySource) ||
            sourceDiagnostic(port.panelSource) || sourceDiagnostic(port.transportSource) ||
            sourceDiagnostic(port.framebuffer.source)) {
            result.consistency = Consistency::Inconsistent;
            result.reason = Reason::DiagnosticOnly;
            return result;
        }
        if (!sourceMatches(port.ddiSource, ObservationSource::NativePortRecord) ||
            !sourceMatches(port.phySource, ObservationSource::NativePHYReadout) ||
            !sourceMatches(port.connectorSource, ObservationSource::NativeConnectorReadout) ||
            !sourceMatches(port.connectionSource, ObservationSource::NativeConnectionReadout) ||
            !sourceMatches(port.activitySource, ObservationSource::NativeActivityReadout) ||
            !sourceMatches(port.panelSource, ObservationSource::NativePanelReadout) ||
            !sourceMatches(port.transportSource, ObservationSource::NativeTransportReadout)) {
            result.consistency = Consistency::Inconsistent;
            result.reason = Reason::UnsupportedSource;
            return result;
        }
        if (!sourceAllowed(port.auxSource) && port.aux != TGLEDP::AUX::Unknown) {
            result.consistency = Consistency::Inconsistent;
            result.reason = Reason::UnsupportedSource;
            return result;
        }
        if (port.observationGeneration != result.generation) {
            result.consistency = Consistency::Inconsistent;
            result.reason = Reason::StaleGeneration;
            return result;
        }
        if (port.ownerLockIdentity != candidate.nativeOwnerLockIdentity) {
            result.consistency = Consistency::Inconsistent;
            result.reason = Reason::SynchronizationMismatch;
            return result;
        }
        const auto objectReason = validateObject(port.portRecord, ObjectKind::PortRecord,
            candidate.nativeOwnerIdentity, candidate.platformIdentity, result.generation,
            NativePortRecordMinimumBytes, ddiIndex);
        if (objectReason != Reason::None) {
            result.consistency = Consistency::Inconsistent;
            result.reason = objectReason;
            return result;
        }
        if (port.connector == TGLEDP::Connector::Unknown || port.role == TGLEDP::Role::Unknown) {
            result.consistency = Consistency::Inconsistent;
            result.reason = Reason::ConnectorUnknown;
            return result;
        }
        if (port.connection == TGLEDP::ConnectionState::Unknown) {
            result.consistency = Consistency::Inconsistent;
            result.reason = Reason::ConnectionUnknown;
            return result;
        }
        if (port.connection != TGLEDP::ConnectionState::Connected &&
            port.connection != TGLEDP::ConnectionState::Disconnected) {
            result.consistency = Consistency::Inconsistent;
            result.reason = Reason::ConnectionUnknown;
            return result;
        }
        if (port.activity == ActivityState::Unknown) {
            result.consistency = Consistency::Inconsistent;
            result.reason = Reason::PathObservationUnknown;
            return result;
        }
        if (port.activity != ActivityState::Active && port.activity != ActivityState::Inactive) {
            result.consistency = Consistency::Inconsistent;
            result.reason = Reason::PathObservationUnknown;
            return result;
        }
        if (port.panel == PanelPresence::Unknown && port.connector == TGLEDP::Connector::InternalDP) {
            result.consistency = Consistency::Inconsistent;
            result.reason = Reason::PanelPresenceUnknown;
            return result;
        }
        if (port.panel != PanelPresence::Unknown && port.panel != PanelPresence::Present &&
            port.panel != PanelPresence::Absent) {
            result.consistency = Consistency::Inconsistent;
            result.reason = Reason::PanelPresenceUnknown;
            return result;
        }
        if (port.transport == Transport::Unknown) {
            result.consistency = Consistency::Inconsistent;
            result.reason = Reason::UnsupportedSource;
            return result;
        }
        if (port.transport != Transport::DisplayPort && port.transport != Transport::HDMI) {
            result.consistency = Consistency::Inconsistent;
            result.reason = Reason::UnsupportedSource;
            return result;
        }
        TGLEDP::PHYKind expectedKind;
        const auto expectedPHYIndex = expectedPHY(port.ddi, expectedKind);
        if (expectedPHYIndex == UINT32_MAX) {
            result.consistency = Consistency::Inconsistent;
            result.reason = Reason::DDIPhyMismatch;
            return result;
        }
        if (port.phyKind == TGLEDP::PHYKind::Combo && port.phy < 2) {
            if (comboPHYSeen[port.phy]) {
                result.consistency = Consistency::Inconsistent;
                result.reason = Reason::DuplicatePHY;
                return result;
            }
            comboPHYSeen[port.phy] = true;
        } else if (port.phyKind == TGLEDP::PHYKind::TypeC && port.phy < 6) {
            if (typeCPHYSeen[port.phy]) {
                result.consistency = Consistency::Inconsistent;
                result.reason = Reason::DuplicatePHY;
                return result;
            }
            typeCPHYSeen[port.phy] = true;
        } else {
            result.consistency = Consistency::Inconsistent;
            result.reason = Reason::DDIPhyMismatch;
            return result;
        }
        if (port.phyKind != expectedKind || port.phy != expectedPHYIndex) {
            result.consistency = Consistency::Inconsistent;
            result.reason = Reason::DDIPhyMismatch;
            return result;
        }
        if (port.transport == Transport::DisplayPort) {
            if (port.aux == TGLEDP::AUX::Unknown || !TGLEDP::knownAUX(port.aux)) {
                result.consistency = Consistency::Inconsistent;
                result.reason = Reason::AUXUnknown;
                return result;
            }
            if (!sourceMatches(port.auxSource, ObservationSource::NativeAUXReadout)) {
                result.consistency = Consistency::Inconsistent;
                result.reason = Reason::UnsupportedSource;
                return result;
            }
            const auto auxIndex = static_cast<uint8_t>(port.aux);
            if (auxSeen[auxIndex]) {
                result.consistency = Consistency::Inconsistent;
                result.reason = Reason::DuplicateAUX;
                return result;
            }
            auxSeen[auxIndex] = true;
        }
        if (port.connector == TGLEDP::Connector::InternalDP &&
            (port.role != TGLEDP::Role::InternalPanel || !TGLEDP::comboDDI(port.ddi))) {
            result.consistency = Consistency::Inconsistent;
            result.reason = Reason::UnsupportedDDI;
            return result;
        }
        if ((port.connector == TGLEDP::Connector::ExternalDP || port.connector == TGLEDP::Connector::HDMI) &&
            port.role != TGLEDP::Role::ExternalDisplay) {
            result.consistency = Consistency::Inconsistent;
            result.reason = Reason::ConnectorUnknown;
            return result;
        }
        if (port.connector != TGLEDP::Connector::InternalDP &&
            port.connector != TGLEDP::Connector::ExternalDP && port.connector != TGLEDP::Connector::HDMI) {
            result.consistency = Consistency::Inconsistent;
            result.reason = Reason::ConnectorUnknown;
            return result;
        }
        if ((port.activity == ActivityState::Active &&
             port.connection == TGLEDP::ConnectionState::Disconnected) ||
            (port.connector == TGLEDP::Connector::InternalDP &&
             port.panel == PanelPresence::Absent &&
             port.connection == TGLEDP::ConnectionState::Connected)) {
            result.consistency = Consistency::Inconsistent;
            result.reason = Reason::ContradictoryObservation;
            return result;
        }
        if (port.connector == TGLEDP::Connector::HDMI && port.transport != Transport::HDMI) {
            result.consistency = Consistency::Inconsistent;
            result.reason = Reason::ObjectAssociationMismatch;
            return result;
        }
        if (port.connector != TGLEDP::Connector::HDMI && port.transport != Transport::DisplayPort) {
            result.consistency = Consistency::Inconsistent;
            result.reason = Reason::ObjectAssociationMismatch;
            return result;
        }

        if (port.framebuffer.state == PathState::BoundPath) {
            const auto &fb = port.framebuffer;
            if (!sourceMatches(fb.source, ObservationSource::NativeFramebufferBinding)) {
                result.consistency = Consistency::Inconsistent;
                result.reason = sourceDiagnostic(fb.source) ? Reason::DiagnosticOnly : Reason::UnsupportedSource;
                return result;
            }
            const auto framebufferReason = validateObject(fb.framebufferObject, ObjectKind::Framebuffer,
                candidate.nativeOwnerIdentity, candidate.controllerIdentity, result.generation,
                NativeFramebufferMinimumBytes);
            const auto pathReason = validateObject(fb.pathObject, ObjectKind::Path,
                candidate.nativeOwnerIdentity, fb.framebufferObject.objectIdentity, result.generation,
                NativePathMinimumBytes);
            const auto planeReason = validateObject(fb.planeObject, ObjectKind::Plane,
                candidate.nativeOwnerIdentity, fb.pathObject.objectIdentity, result.generation,
                NativePlaneMinimumBytes);
            if (fb.ownerLockIdentity != candidate.nativeOwnerLockIdentity ||
                fb.observationGeneration != result.generation || fb.framebufferObject.objectIdentity ==
                    fb.pathObject.objectIdentity || fb.framebufferObject.objectIdentity ==
                    fb.planeObject.objectIdentity || fb.pathObject.objectIdentity ==
                    fb.planeObject.objectIdentity ||
                fb.pathObject.linkedPortIdentity != port.portRecord.objectIdentity ||
                framebufferReason != Reason::None || pathReason != Reason::None ||
                planeReason != Reason::None || fb.ddi != port.ddi ||
                fb.framebufferIndex >= 3 || fb.pipe >= XELP::PipeCount ||
                fb.primaryPlane != 5U * fb.pipe) {
                result.consistency = Consistency::Inconsistent;
                if (framebufferReason != Reason::None) result.reason = framebufferReason;
                else if (pathReason != Reason::None) result.reason = pathReason;
                else if (planeReason != Reason::None) result.reason = planeReason;
                else result.reason = Reason::ObjectAssociationMismatch;
                return result;
            }
        } else if (port.framebuffer.state != PathState::NoBoundPath ||
                   !sourceMatches(port.framebuffer.source, ObservationSource::NativeFramebufferBinding) ||
                   port.framebuffer.ownerLockIdentity != candidate.nativeOwnerLockIdentity ||
                   port.framebuffer.observationGeneration != result.generation) {
            result.consistency = Consistency::Inconsistent;
            result.reason = Reason::PathObservationUnknown;
            return result;
        }
        if (port.activity == ActivityState::Active && port.framebuffer.state != PathState::BoundPath) {
            result.consistency = Consistency::Inconsistent;
            result.reason = Reason::PathObservationUnknown;
            return result;
        }

        const auto ddiOwner = findResource(candidate, resourceKey(ResourceKind::DDI, ddiIndex));
        const auto phyOwner = findResource(candidate, resourceKey(ResourceKind::PHY, port.phy,
                                                                    port.phyKind));
        if (!ddiOwner || !phyOwner || ddiOwner->owner != phyOwner->owner ||
            ddiOwner->ownerIdentity != phyOwner->ownerIdentity) {
            result.consistency = Consistency::Inconsistent;
            result.reason = Reason::OwnershipConflict;
            return result;
        }
        if (port.transport == Transport::DisplayPort) {
            const auto auxOwner = findResource(candidate, resourceKey(ResourceKind::AUX,
                static_cast<uint8_t>(port.aux)));
            if (!auxOwner || auxOwner->owner != ddiOwner->owner ||
                auxOwner->ownerIdentity != ddiOwner->ownerIdentity) {
                result.consistency = Consistency::Inconsistent;
                result.reason = Reason::OwnershipConflict;
                return result;
            }
        }
        if ((port.connector == TGLEDP::Connector::InternalDP &&
             (ddiOwner->owner == TGLEDP::ResourceOwner::ExternalDisplay ||
              ddiOwner->owner == TGLEDP::ResourceOwner::InternalEDP)) ||
            (port.connector != TGLEDP::Connector::InternalDP &&
             ddiOwner->owner == TGLEDP::ResourceOwner::InternalEDP)) {
            result.consistency = Consistency::Inconsistent;
            result.reason = Reason::OwnershipConflict;
            return result;
        }
    }

    for (size_t i = 0; i < candidate.resourceCount; ++i) {
        const auto &resource = candidate.resources[i];
        if (resource.kind == ResourceKind::PanelPower) {
            if (!sourceMatches(resource.source, ObservationSource::NativeOwnershipInventory)) {
                result.consistency = Consistency::Inconsistent;
                result.reason = sourceDiagnostic(resource.source) ? Reason::DiagnosticOnly : Reason::UnsupportedSource;
                return result;
            }
        }
    }

    result.consistency = Consistency::Consistent;
    result.reason = Reason::None;
    result.inventoryComplete = true;
    result.topologyConsistent = true;
    return result;
}

} // namespace TGLEDPNative
#endif
