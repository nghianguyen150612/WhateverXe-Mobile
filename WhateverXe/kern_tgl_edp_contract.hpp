// Pure policy for a future Tiger Lake internal eDP backend.
// This contract is intentionally not included by the production runtime.
// Firmware diagnostics, Linux topology and device properties are not runtime
// route evidence; no decision here performs hardware access or changes state.
#ifndef KERN_TGL_EDP_CONTRACT_HPP
#define KERN_TGL_EDP_CONTRACT_HPP

#include <stddef.h>
#include <stdint.h>
#include "kern_xelp_platform.hpp"

namespace TGLEDP {

constexpr uint32_t RequiredNativeProbeABI = 3; // Existing immutable ProbeConfig ABI.
constexpr size_t MaxRouteClaims = 16;

enum class Rejection : uint32_t {
    None,
    GPUProfile,
    PhysicalIdentity,
    WrongFamily,
    WrongDisplay,
    Donor,
    NativeABI,
    GPUCapability,
    InventoryIncomplete,
    BackendCapability,
    RouteUnknown,
    ConnectorRole,
    Transport,
    DDI,
    TypeCPhy,
    PHY,
    AUX,
    FirmwareChecksum,
    FirmwareMalformed,
    DiagnosticOnly,
    UntrustedEvidence,
    PanelAbsent,
    OwnershipUnknown,
    OwnershipConflict,
    AmbiguousRoute,
    DonorBindingConflict,
    FramebufferEvidence
};

struct Decision {
    Rejection rejection {Rejection::None};
    bool admitted() const { return rejection == Rejection::None; }
};

enum GPUCapability : uint32_t {
    GPUXeDisplay       = 1U << 0,
    GPUDisplayPort     = 1U << 1,
    GPUAUX             = 1U << 2,
    GPUPipeTranscoder  = 1U << 3
};
constexpr uint32_t RequiredGPUCapabilities =
    GPUXeDisplay | GPUDisplayPort | GPUAUX | GPUPipeTranscoder;

struct GPUFacts {
    XELP::Profile profile;
    uint32_t nativeProbeABI {};
    uint32_t capabilities {};
};

// Physical PCI identity is checked independently of the effective selector.
// A spoofed or unknown physical device cannot inherit a Tiger Lake profile.
inline Decision qualifyGPU(const GPUFacts &facts) {
    const auto &profile = facts.profile;
    if (!profile.admitted()) return {Rejection::GPUProfile};
    if ((profile.identity & 0xFFFFU) != 0x8086U) return {Rejection::PhysicalIdentity};
    const auto physical = XELP::deviceEntry(profile.identity);
    if (!physical || physical->backend == XELP::GT::Unknown) return {Rejection::PhysicalIdentity};
    if (physical->family != XELP::Family::TigerLake || profile.family != physical->family)
        return {Rejection::WrongFamily};
    if (physical->display != XELP::Display::XeD || profile.display != physical->display)
        return {Rejection::WrongDisplay};
    if (physical->backend != profile.gt) return {Rejection::PhysicalIdentity};
    if (profile.donor != XELP::Donor::C004FC1A) return {Rejection::Donor};
    if (facts.nativeProbeABI != RequiredNativeProbeABI) return {Rejection::NativeABI};
    if ((facts.capabilities & RequiredGPUCapabilities) != RequiredGPUCapabilities)
        return {Rejection::GPUCapability};
    return {};
}

enum class DDI : uint8_t { A = 0, B = 1, C = 2, D = 3, E = 4, F = 5, G = 6, H = 7, I = 8, Unknown = 0xFF };
enum class AUX : uint8_t { A = 1, B = 2, C = 3, D = 4, E = 5, F = 6, G = 7, H = 8, Unknown = 0xFF };
enum class PHYKind : uint8_t { Unknown, Combo, TypeC, Other };
enum class Connector : uint8_t { Unknown, InternalDP, ExternalDP, HDMI };
enum class Role : uint8_t { Unknown, InternalPanel, ExternalDisplay };
enum class EvidenceSource : uint8_t {
    Unknown,
    StrictFirmware,
    AuthorizedNativeReadout,
    ValidatedBoardRecord,
    DiagnosticVBT,
    LinuxObservation,
    DeviceProperty,
    SyntheticFixture
};
enum class ResourceOwner : uint8_t { Unknown, KnownFree, NativeDonor, ExternalDisplay, InternalEDP };

struct FirmwareIntegrity {
    bool checksumValid {};
    bool fullBDBStreamValid {};
    bool childTableValid {};
    bool wholeImageValidated {};
    bool diagnosticOnly {};
};

struct RouteEvidence {
    bool active {};
    Connector connector {Connector::Unknown};
    Role role {Role::Unknown};
    DDI ddi {DDI::Unknown};
    PHYKind phyKind {PHYKind::Unknown};
    uint8_t phy {0xFF};
    AUX aux {AUX::Unknown};
    EvidenceSource source {EvidenceSource::Unknown};
    FirmwareIntegrity firmware;
    bool firmwareDerived {};
    bool evidenceValidated {};
    bool panelPresent {};
    bool displayPortSupported {};
    bool backendCapable {};
    bool ownershipSnapshotComplete {};
    bool exclusiveOwnershipValidated {};
    ResourceOwner ddiOwner {ResourceOwner::Unknown};
    ResourceOwner phyOwner {ResourceOwner::Unknown};
    ResourceOwner auxOwner {ResourceOwner::Unknown};
    bool donorBindingCompatible {};
};

struct RoutingSnapshot {
    bool complete {};
    size_t count {};
    RouteEvidence routes[MaxRouteClaims] {};
};

struct ConnectorDecision : Decision {
    DDI ddi {DDI::Unknown};
    uint8_t phy {0xFF};
    AUX aux {AUX::Unknown};
    ResourceOwner currentOwner {ResourceOwner::Unknown};
};

inline bool knownDDI(DDI ddi) {
    // Tiger Lake has Combo A/B and Type-C D..I; C is not a physical Combo DDI.
    return ddi == DDI::A || ddi == DDI::B || ddi == DDI::D || ddi == DDI::E ||
        ddi == DDI::F || ddi == DDI::G || ddi == DDI::H || ddi == DDI::I;
}

inline bool knownOwner(ResourceOwner owner) { return owner != ResourceOwner::Unknown; }

inline Decision trust(const RouteEvidence &route) {
    if (route.firmware.diagnosticOnly) return {Rejection::DiagnosticOnly};
    if (route.firmwareDerived && route.source != EvidenceSource::StrictFirmware)
        return {Rejection::UntrustedEvidence};
    if (route.source == EvidenceSource::StrictFirmware) {
        if (!route.firmware.checksumValid) return {Rejection::FirmwareChecksum};
        if (!route.firmware.fullBDBStreamValid || !route.firmware.childTableValid ||
            !route.firmware.wholeImageValidated) return {Rejection::FirmwareMalformed};
        return {};
    }
    if (route.source == EvidenceSource::AuthorizedNativeReadout ||
        route.source == EvidenceSource::ValidatedBoardRecord) {
        return route.evidenceValidated && !route.firmwareDerived ? Decision{} :
            Decision{route.firmware.diagnosticOnly ? Rejection::DiagnosticOnly : Rejection::UntrustedEvidence};
    }
    // A bounded VBT candidate, Linux observation, or property is diagnostic
    // input only. Synthetic fixtures exercise policy but are never admissible.
    return {Rejection::UntrustedEvidence};
}

inline ConnectorDecision qualifyConnector(const Decision &gpu, const RoutingSnapshot &snapshot,
                                          size_t selected) {
    ConnectorDecision out;
    if (!gpu.admitted()) { out.rejection = Rejection::GPUProfile; return out; }
    if (!snapshot.complete || snapshot.count == 0 || snapshot.count > MaxRouteClaims || selected >= snapshot.count) {
        out.rejection = Rejection::InventoryIncomplete; return out;
    }
    const auto &route = snapshot.routes[selected];
    if (!route.active || route.connector == Connector::Unknown || route.role == Role::Unknown) {
        out.rejection = Rejection::RouteUnknown; return out;
    }
    if (route.connector != Connector::InternalDP || route.role != Role::InternalPanel) {
        out.rejection = Rejection::ConnectorRole; return out;
    }
    if (!route.backendCapable) { out.rejection = Rejection::BackendCapability; return out; }
    if (!route.displayPortSupported) { out.rejection = Rejection::Transport; return out; }
    if (!knownDDI(route.ddi)) { out.rejection = Rejection::DDI; return out; }
    if (route.phyKind == PHYKind::TypeC) { out.rejection = Rejection::TypeCPhy; return out; }
    if (route.phyKind != PHYKind::Combo) {
        out.rejection = Rejection::PHY; return out;
    }
    if (route.phy == 0xFF) { out.rejection = Rejection::PHY; return out; }
    if (route.aux == AUX::Unknown) { out.rejection = Rejection::AUX; return out; }
    if (!route.panelPresent) { out.rejection = Rejection::PanelAbsent; return out; }
    if (!route.ownershipSnapshotComplete || !route.exclusiveOwnershipValidated) {
        out.rejection = Rejection::OwnershipUnknown; return out;
    }
    const auto trusted = trust(route);
    if (!trusted.admitted()) { out.rejection = trusted.rejection; return out; }
    if (!knownOwner(route.ddiOwner) || !knownOwner(route.phyOwner) || !knownOwner(route.auxOwner)) {
        out.rejection = Rejection::OwnershipUnknown; return out;
    }
    if (route.ddiOwner != route.phyOwner || route.phyOwner != route.auxOwner) {
        out.rejection = Rejection::OwnershipConflict; return out;
    }
    if (route.ddiOwner == ResourceOwner::ExternalDisplay || route.ddiOwner == ResourceOwner::InternalEDP) {
        out.rejection = Rejection::OwnershipConflict; return out;
    }
    if (route.ddiOwner == ResourceOwner::NativeDonor && !route.donorBindingCompatible) {
        out.rejection = Rejection::DonorBindingConflict; return out;
    }
    for (size_t i = 0; i < snapshot.count; ++i) {
        if (i == selected || !snapshot.routes[i].active) continue;
        const auto &other = snapshot.routes[i];
        // An active claim with incomplete coordinates makes all ownership
        // ambiguous; it is never treated as a free DDI, PHY or AUX channel.
        if (!other.ownershipSnapshotComplete || !other.exclusiveOwnershipValidated || !knownDDI(other.ddi) ||
            other.phyKind == PHYKind::Unknown || other.phy == 0xFF ||
            other.aux == AUX::Unknown || !knownOwner(other.ddiOwner) || !knownOwner(other.phyOwner) ||
            !knownOwner(other.auxOwner)) {
            out.rejection = Rejection::OwnershipUnknown; return out;
        }
        if (other.ddi == route.ddi || (other.phyKind == route.phyKind && other.phy == route.phy) ||
            other.aux == route.aux) {
            out.rejection = Rejection::AmbiguousRoute; return out;
        }
    }
    out.ddi = route.ddi;
    out.phy = route.phy;
    out.aux = route.aux;
    out.currentOwner = route.ddiOwner;
    return out;
}

enum class MemoryDisposition : uint8_t { Unknown, NativeOwned, BorrowedPinned, CopiedToNative };

struct GOPReadout {
    bool validated {};
    bool activeScanout {};
    DDI ddi {DDI::Unknown};
    uint8_t pipe {0xFF};
    uint8_t transcoder {0xFF};
    uint64_t surfaceIdentity {};
    MemoryDisposition memory {MemoryDisposition::Unknown};
};

struct NativeFramebufferReadout {
    bool bindingComplete {};
    bool donorObjectsPreserved {};
    bool noConflictingDonorBinding {};
    bool synchronizationComplete {};
    bool memoryLifetimeValidated {};
    bool copyComplete {};
    DDI ddi {DDI::Unknown};
    uint8_t pipe {0xFF};
    uint8_t transcoder {0xFF};
    uint8_t primaryPlane {0xFF};
    uintptr_t framebufferIdentity {};
    uintptr_t pathIdentity {};
    uintptr_t planeIdentity {};
    uint64_t surfaceIdentity {};
};

inline Decision validateFramebufferHandoff(const ConnectorDecision &route, const GOPReadout &gop,
                                            const NativeFramebufferReadout &native) {
    if (!route.admitted()) return {Rejection::FramebufferEvidence};
    if (!gop.validated || !gop.activeScanout || !gop.surfaceIdentity ||
        !native.bindingComplete || !native.donorObjectsPreserved ||
        !native.noConflictingDonorBinding || !native.synchronizationComplete ||
        !native.memoryLifetimeValidated || !native.framebufferIdentity ||
        !native.pathIdentity || !native.planeIdentity || !native.surfaceIdentity ||
        !knownDDI(gop.ddi) || !knownDDI(native.ddi) || gop.ddi != route.ddi || native.ddi != route.ddi ||
        gop.pipe >= XELP::PipeCount || gop.transcoder >= XELP::PipeCount ||
        native.pipe != gop.pipe || native.transcoder != gop.transcoder ||
        native.primaryPlane != 5U * native.pipe) return {Rejection::FramebufferEvidence};
    if (gop.memory == MemoryDisposition::BorrowedPinned && gop.surfaceIdentity != native.surfaceIdentity)
        return {Rejection::FramebufferEvidence};
    if (gop.memory == MemoryDisposition::CopiedToNative &&
        (!native.copyComplete || gop.surfaceIdentity == native.surfaceIdentity))
        return {Rejection::FramebufferEvidence};
    if (gop.memory == MemoryDisposition::NativeOwned && gop.surfaceIdentity != native.surfaceIdentity)
        return {Rejection::FramebufferEvidence};
    if (gop.memory == MemoryDisposition::Unknown) return {Rejection::FramebufferEvidence};
    return {};
}

struct HandoffRollbackPlan {
    bool keepGOPScanout {};
    bool preserveDonorObjects {};
    bool undoPartialBinding {};
    bool releaseOnlyBackendOwnedResources {};
};

inline HandoffRollbackPlan framebufferRollbackPlan() {
    return {true, true, true, true};
}

} // namespace TGLEDP
#endif
