#ifndef TEST_TGL_EDP_NATIVE_FIXTURE_HPP
#define TEST_TGL_EDP_NATIVE_FIXTURE_HPP

#include "kern_tgl_edp_native_adapter.hpp"

namespace TGLNativeFixture {

inline TGLEDPNative::SnapshotCandidate complete() {
    using namespace TGLEDP;
    using namespace TGLEDPNative;

    SnapshotCandidate candidate;
    candidate.gpu.profile = XELP::identify(0x9A498086U, 1);
    candidate.gpu.nativeProbeABI = RequiredNativeProbeABI;
    candidate.gpu.capabilities = RequiredGPUCapabilities;
    candidate.nativeOwnerIdentity = 0x101;
    candidate.controllerIdentity = 0x202;
    candidate.platformIdentity = 0x203;
    candidate.generationAtStart = 7;
    candidate.generationAtEnd = 7;
    candidate.nativeOwnerLockIdentity = 0x303;
    candidate.portCount = MaxPorts;
    candidate.resourceCount = 0;

    const uint8_t ddiValues[] {0, 1, 3, 4, 5, 6, 7, 8};
    for (const auto ddi : ddiValues) {
        auto &resource = candidate.resources[candidate.resourceCount++];
        resource.kind = ResourceKind::DDI;
        resource.index = ddi;
        resource.owner = ResourceOwner::KnownFree;
        resource.ownerLockIdentity = candidate.nativeOwnerLockIdentity;
        resource.observationGeneration = 7;
        resource.source = ObservationSource::SyntheticFixture;
    }
    for (uint8_t phy = 0; phy < 2; ++phy) {
        auto &resource = candidate.resources[candidate.resourceCount++];
        resource.kind = ResourceKind::PHY;
        resource.index = phy;
        resource.phyKind = PHYKind::Combo;
        resource.owner = ResourceOwner::KnownFree;
        resource.ownerLockIdentity = candidate.nativeOwnerLockIdentity;
        resource.observationGeneration = 7;
        resource.source = ObservationSource::SyntheticFixture;
    }
    for (uint8_t phy = 0; phy < 6; ++phy) {
        auto &resource = candidate.resources[candidate.resourceCount++];
        resource.kind = ResourceKind::PHY;
        resource.index = phy;
        resource.phyKind = PHYKind::TypeC;
        resource.owner = ResourceOwner::KnownFree;
        resource.ownerLockIdentity = candidate.nativeOwnerLockIdentity;
        resource.observationGeneration = 7;
        resource.source = ObservationSource::SyntheticFixture;
    }
    for (uint8_t aux = static_cast<uint8_t>(AUX::A); aux <= static_cast<uint8_t>(AUX::H); ++aux) {
        auto &resource = candidate.resources[candidate.resourceCount++];
        resource.kind = ResourceKind::AUX;
        resource.index = aux;
        resource.owner = ResourceOwner::KnownFree;
        resource.ownerLockIdentity = candidate.nativeOwnerLockIdentity;
        resource.observationGeneration = 7;
        resource.source = ObservationSource::SyntheticFixture;
    }

    for (size_t slot = 0; slot < MaxPorts; ++slot) {
        auto &port = candidate.ports[slot];
        const auto ddi = static_cast<DDI>(expectedPortDDI(slot));
        TGLEDP::PHYKind phyKind;
        const auto phy = expectedPHY(ddi, phyKind);
        port.ddi = ddi;
        port.phyKind = phyKind;
        port.phy = static_cast<uint8_t>(phy);
        port.aux = static_cast<AUX>(static_cast<uint8_t>(AUX::A) + static_cast<uint8_t>(slot));
        port.connector = slot == 0 ? Connector::InternalDP : Connector::ExternalDP;
        port.role = slot == 0 ? Role::InternalPanel : Role::ExternalDisplay;
        port.connection = slot == 0 ? ConnectionState::Connected : ConnectionState::Disconnected;
        port.activity = slot == 0 ? ActivityState::Active : ActivityState::Inactive;
        port.panel = slot == 0 ? PanelPresence::Present : PanelPresence::Absent;
        port.transport = Transport::DisplayPort;
        port.ownerLockIdentity = candidate.nativeOwnerLockIdentity;
        port.observationGeneration = 7;
        port.ddiSource = ObservationSource::SyntheticFixture;
        port.phySource = ObservationSource::SyntheticFixture;
        port.auxSource = ObservationSource::SyntheticFixture;
        port.connectorSource = ObservationSource::SyntheticFixture;
        port.connectionSource = ObservationSource::SyntheticFixture;
        port.activitySource = ObservationSource::SyntheticFixture;
        port.panelSource = ObservationSource::SyntheticFixture;
        port.transportSource = ObservationSource::SyntheticFixture;

        port.portRecord.kind = ObjectKind::PortRecord;
        port.portRecord.ownerIdentity = candidate.nativeOwnerIdentity;
        port.portRecord.objectIdentity = 0x1000 + slot;
        port.portRecord.parentIdentity = candidate.platformIdentity;
        port.portRecord.observationGeneration = 7;
        port.portRecord.recordIndex = static_cast<uint32_t>(ddi);
        port.portRecord.abiRevision = RequiredNativeProbeABI;
        port.portRecord.objectBytes = NativePortRecordMinimumBytes;

        if (slot == 0) {
            auto &fb = port.framebuffer;
            fb.state = PathState::BoundPath;
            fb.source = ObservationSource::SyntheticFixture;
            fb.ownerLockIdentity = candidate.nativeOwnerLockIdentity;
            fb.observationGeneration = 7;
            fb.framebufferObject.kind = ObjectKind::Framebuffer;
            fb.framebufferObject.ownerIdentity = candidate.nativeOwnerIdentity;
            fb.framebufferObject.objectIdentity = 0x2001;
            fb.framebufferObject.parentIdentity = candidate.controllerIdentity;
            fb.framebufferObject.observationGeneration = 7;
            fb.framebufferObject.abiRevision = RequiredNativeProbeABI;
            fb.framebufferObject.objectBytes = NativeFramebufferMinimumBytes;
            fb.pathObject.kind = ObjectKind::Path;
            fb.pathObject.ownerIdentity = candidate.nativeOwnerIdentity;
            fb.pathObject.objectIdentity = 0x2002;
            fb.pathObject.parentIdentity = fb.framebufferObject.objectIdentity;
            fb.pathObject.linkedPortIdentity = port.portRecord.objectIdentity;
            fb.pathObject.observationGeneration = 7;
            fb.pathObject.abiRevision = RequiredNativeProbeABI;
            fb.pathObject.objectBytes = NativePathMinimumBytes;
            fb.planeObject.kind = ObjectKind::Plane;
            fb.planeObject.ownerIdentity = candidate.nativeOwnerIdentity;
            fb.planeObject.objectIdentity = 0x2003;
            fb.planeObject.parentIdentity = fb.pathObject.objectIdentity;
            fb.planeObject.observationGeneration = 7;
            fb.planeObject.abiRevision = RequiredNativeProbeABI;
            fb.planeObject.objectBytes = NativePlaneMinimumBytes;
            fb.framebufferIndex = 0;
            fb.pipe = 0;
            fb.ddi = ddi;
            fb.primaryPlane = 0;
        } else {
            port.framebuffer.state = PathState::NoBoundPath;
            port.framebuffer.source = ObservationSource::SyntheticFixture;
            port.framebuffer.ownerLockIdentity = candidate.nativeOwnerLockIdentity;
            port.framebuffer.observationGeneration = 7;
        }
    }
    return candidate;
}

inline void useNativeSourceClaims(TGLEDPNative::SnapshotCandidate &candidate) {
    using TGLEDPNative::ObservationSource;
    for (size_t i = 0; i < candidate.resourceCount; ++i)
        candidate.resources[i].source = ObservationSource::NativeOwnershipInventory;
    for (size_t i = 0; i < candidate.portCount; ++i) {
        auto &port = candidate.ports[i];
        port.ddiSource = ObservationSource::NativePortRecord;
        port.phySource = ObservationSource::NativePHYReadout;
        port.auxSource = ObservationSource::NativeAUXReadout;
        port.connectorSource = ObservationSource::NativeConnectorReadout;
        port.connectionSource = ObservationSource::NativeConnectionReadout;
        port.activitySource = ObservationSource::NativeActivityReadout;
        port.panelSource = ObservationSource::NativePanelReadout;
        port.transportSource = ObservationSource::NativeTransportReadout;
        if (port.framebuffer.state != TGLEDPNative::PathState::Unknown)
            port.framebuffer.source = ObservationSource::NativeFramebufferBinding;
    }
}

} // namespace TGLNativeFixture
#endif
