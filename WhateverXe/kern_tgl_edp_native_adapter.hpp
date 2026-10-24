// CPU-only adapter from copied donor observations into P005 policy values.
// No native callback is installed here: the current donor contracts do not
// expose a complete Tiger Lake DDI/PHY/AUX ownership capture.
#ifndef KERN_TGL_EDP_NATIVE_ADAPTER_HPP
#define KERN_TGL_EDP_NATIVE_ADAPTER_HPP

#include "kern_tgl_edp_classify.hpp"
#include "kern_tgl_edp_native_evidence.hpp"
#include "kern_tgl_fb_binding.hpp"

namespace TGLEDPNative {

class NativeEvidenceAdapter {
    static TGLEDP::EvidenceSource p004Source(const PortObservation &port) {
        if (port.ddiSource == ObservationSource::DiagnosticVBT ||
            port.phySource == ObservationSource::DiagnosticVBT ||
            port.connectorSource == ObservationSource::DiagnosticVBT ||
            port.auxSource == ObservationSource::DiagnosticVBT ||
            port.connectionSource == ObservationSource::DiagnosticVBT ||
            port.activitySource == ObservationSource::DiagnosticVBT ||
            port.transportSource == ObservationSource::DiagnosticVBT)
            return TGLEDP::EvidenceSource::DiagnosticVBT;
        if (port.ddiSource == ObservationSource::LinuxSysfsDiagnostic ||
            port.phySource == ObservationSource::LinuxSysfsDiagnostic ||
            port.connectorSource == ObservationSource::LinuxSysfsDiagnostic ||
            port.auxSource == ObservationSource::LinuxSysfsDiagnostic ||
            port.connectionSource == ObservationSource::LinuxSysfsDiagnostic ||
            port.activitySource == ObservationSource::LinuxSysfsDiagnostic ||
            port.transportSource == ObservationSource::LinuxSysfsDiagnostic)
            return TGLEDP::EvidenceSource::LinuxObservation;
        if (port.ddiSource == ObservationSource::SyntheticFixture ||
            port.phySource == ObservationSource::SyntheticFixture ||
            port.connectorSource == ObservationSource::SyntheticFixture ||
            port.auxSource == ObservationSource::SyntheticFixture ||
            port.connectionSource == ObservationSource::SyntheticFixture ||
            port.activitySource == ObservationSource::SyntheticFixture ||
            port.transportSource == ObservationSource::SyntheticFixture)
            return TGLEDP::EvidenceSource::SyntheticFixture;
        if (port.ddiSource == ObservationSource::NativePortRecord &&
            port.phySource == ObservationSource::NativePHYReadout &&
            port.auxSource == ObservationSource::NativeAUXReadout &&
            port.connectorSource == ObservationSource::NativeConnectorReadout &&
            port.connectionSource == ObservationSource::NativeConnectionReadout &&
            port.activitySource == ObservationSource::NativeActivityReadout &&
            port.panelSource == ObservationSource::NativePanelReadout &&
            port.transportSource == ObservationSource::NativeTransportReadout)
            return TGLEDP::EvidenceSource::AuthorizedNativeReadout;
        return TGLEDP::EvidenceSource::Unknown;
    }

public:
    // TGLFBBinding::inspect validates the copied framebuffer/path/plane/DDI
    // relationship while its caller holds the native owner lock. Its Readout
    // intentionally contains no object identities or AUX ownership. Preserve
    // that limitation: never turn the framebuffer slot into an object ID.
    static FramebufferAssociation copyFramebufferReadout(const TGLFBBinding::Readout &readout,
                                                         uint64_t ownerIdentity,
                                                         uint64_t ownerLockIdentity,
                                                         uint64_t generation) {
        FramebufferAssociation result;
        if (readout.status != TGLFBBinding::Status::Complete) return result;
        result.state = PathState::BoundPath;
        result.source = ObservationSource::NativeFramebufferBinding;
        result.ownerLockIdentity = ownerLockIdentity;
        result.observationGeneration = generation;
        result.framebufferObject.kind = ObjectKind::Framebuffer;
        result.framebufferObject.ownerIdentity = ownerIdentity;
        result.framebufferObject.observationGeneration = generation;
        result.pathObject.kind = ObjectKind::Path;
        result.pathObject.ownerIdentity = ownerIdentity;
        result.pathObject.observationGeneration = generation;
        result.planeObject.kind = ObjectKind::Plane;
        result.planeObject.ownerIdentity = ownerIdentity;
        result.planeObject.observationGeneration = generation;
        result.framebufferIndex = readout.framebuffer;
        result.pipe = readout.pipe;
        result.ddi = readout.ddi <= static_cast<uint32_t>(TGLEDP::DDI::I) ?
            static_cast<TGLEDP::DDI>(readout.ddi) : TGLEDP::DDI::Unknown;
        result.primaryPlane = readout.plane;
        // The current Readout retains none of the object identities, parent
        // associations, or object sizes. Those fields remain unavailable; no
        // pointer or framebuffer index is used as a substitute.
        return result;
    }

    // Converts evidence values for diagnostics and P004 reconciliation only.
    // The adapter deliberately leaves snapshot.complete false and all opaque
    // authorizations default-invalid. P004 remains the only admission gate,
    // and the missing owner capture prevents this adapter from reaching it.
    static TGLEDP::RoutingSnapshot toP004Snapshot(const SnapshotCandidate &candidate) {
        TGLEDP::RoutingSnapshot result;
        result.complete = false;
        result.count = candidate.portCount <= MaxPorts ? candidate.portCount : 0;
        for (size_t i = 0; i < result.count; ++i) {
            const auto &source = candidate.ports[i];
            auto &route = result.routes[i];
            route.active = source.activity == ActivityState::Active;
            route.connection = source.connection;
            route.connector = source.connector;
            route.role = source.role;
            route.ddi = source.ddi;
            route.phyKind = source.phyKind;
            route.phy = source.phy;
            route.aux = source.aux;
            route.source = p004Source(source);
            route.evidenceValidated = false;
            route.panelPresent = source.panel == PanelPresence::Present;
            route.displayPortSupported = source.transport == Transport::DisplayPort;
            route.typeCCapable = TGLEDP::typeCDDI(source.ddi);
            route.backendCapable = false;
            route.ownershipSnapshotComplete = false;
            route.exclusiveOwnershipValidated = false;
            const auto ddiOwner = findResource(candidate, resourceKey(ResourceKind::DDI,
                static_cast<uint8_t>(source.ddi)));
            const auto phyOwner = findResource(candidate, resourceKey(ResourceKind::PHY, source.phy,
                source.phyKind));
            route.ddiOwner = ddiOwner ? ddiOwner->owner : TGLEDP::ResourceOwner::Unknown;
            route.phyOwner = phyOwner ? phyOwner->owner : TGLEDP::ResourceOwner::Unknown;
            if (source.transport == Transport::DisplayPort) {
                const auto auxOwner = findResource(candidate, resourceKey(ResourceKind::AUX,
                    static_cast<uint8_t>(source.aux)));
                route.auxOwner = auxOwner ? auxOwner->owner : TGLEDP::ResourceOwner::Unknown;
            }
            route.donorBindingCompatible = false;
            route.firmwareDerived = route.source == TGLEDP::EvidenceSource::DiagnosticVBT;
            if (route.firmwareDerived) route.firmware.diagnosticOnly = true;
            // Route and snapshot authorization objects remain default-invalid.
        }
        return result;
    }

    static ValidationResult validate(const SnapshotCandidate &candidate, uint64_t expectedGeneration) {
        return TGLEDPNative::validate(candidate, expectedGeneration);
    }
};

} // namespace TGLEDPNative
#endif
