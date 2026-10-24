#define TGLEDP_CLASSIFY_TESTING 1
#include "kern_tgl_edp_classify.hpp"
#include <cassert>
#include <cstdio>
#include <type_traits>

using namespace TGLEDP;

static GPUFacts validGPU() {
    return {XELP::identify(0x9A408086U, 1), RequiredNativeProbeABI, RequiredGPUCapabilities};
}

// Synthetic route fixture only. The A/A/A labels exercise values without
// claiming that those coordinates are a universal Tiger Lake panel route.
static RouteEvidence validRoute() {
    RouteEvidence route;
    route.active = true;
    route.connector = Connector::InternalDP;
    route.role = Role::InternalPanel;
    route.ddi = DDI::A;
    route.phyKind = PHYKind::Combo;
    route.phy = 0;
    route.aux = AUX::A;
    route.connection = ConnectionState::Connected;
    route.source = EvidenceSource::ValidatedBoardRecord;
    route.evidenceValidated = true;
    route.panelPresent = true;
    route.displayPortSupported = true;
    route.backendCapable = true;
    route.ownershipSnapshotComplete = true;
    route.exclusiveOwnershipValidated = true;
    route.ddiOwner = ResourceOwner::KnownFree;
    route.phyOwner = ResourceOwner::KnownFree;
    route.auxOwner = ResourceOwner::KnownFree;
    TGLEDPClassify::TestEvidenceAuthority::authorize(route);
    return route;
}

static RoutingSnapshot oneRoute(RouteEvidence route) {
    RoutingSnapshot snapshot;
    snapshot.complete = true;
    snapshot.count = 1;
    snapshot.routes[0] = route;
    return snapshot;
}

// Reissue the test-only proof after deliberately changing a policy fact. The
// separate untrusted-evidence assertions below bypass this helper.
static ConnectorDecision evaluate(const Decision &gpu, RoutingSnapshot snapshot, size_t selected) {
    for (size_t i = 0; i < snapshot.count && i < MaxRouteClaims; ++i)
        TGLEDPClassify::TestEvidenceAuthority::authorize(snapshot.routes[i]);
    TGLEDPClassify::TestEvidenceAuthority::authorizeSnapshot(snapshot);
    return TGLEDP::qualifyConnector(gpu, snapshot, selected);
}

int main() {
    const auto gpu = qualifyGPU(validGPU());
    assert(gpu.admitted());

    auto bad = validGPU();
    bad.nativeProbeABI = 2;
    assert(qualifyGPU(bad).rejection == Rejection::NativeABI);
    bad = validGPU();
    bad.capabilities &= ~GPUAUX;
    assert(qualifyGPU(bad).rejection == Rejection::GPUCapability);
    bad = validGPU();
    // The selector still describes a supported Tiger Lake device, but the
    // physical PCI identity is unknown and must not inherit its admission.
    bad.profile = XELP::identify(0xDEAD8086U, 1, 0x9A408086U);
    assert(bad.profile.admitted());
    assert(qualifyGPU(bad).rejection == Rejection::PhysicalIdentity);
    bad = validGPU();
    bad.profile = XELP::identify(0x46D18086U, 0);
    assert(qualifyGPU(bad).rejection == Rejection::WrongFamily);

    auto snapshot = oneRoute(validRoute());
    auto connector = evaluate(gpu, snapshot, 0);
    assert(connector.admitted() && connector.ddi == DDI::A && connector.aux == AUX::A);

    auto forged = oneRoute(validRoute());
    forged.routes[0].source = EvidenceSource::ValidatedBoardRecord;
    forged.routes[0].evidenceValidated = true;
    forged.routes[0].authorization = {};
    TGLEDPClassify::TestEvidenceAuthority::authorizeSnapshot(forged);
    assert(TGLEDP::qualifyConnector(gpu, forged, 0).rejection == Rejection::UntrustedEvidence);

    snapshot.routes[0].ddi = DDI::Unknown;
    assert(evaluate(gpu, snapshot, 0).rejection == Rejection::DDI);
    snapshot = oneRoute(validRoute());
    snapshot.complete = false;
    assert(evaluate(gpu, snapshot, 0).rejection == Rejection::InventoryIncomplete);

    snapshot = oneRoute(validRoute());
    snapshot.routes[0].connector = Connector::ExternalDP;
    snapshot.routes[0].role = Role::ExternalDisplay;
    assert(evaluate(gpu, snapshot, 0).rejection == Rejection::ConnectorRole);
    snapshot = oneRoute(validRoute());
    snapshot.routes[0].connector = Connector::HDMI;
    assert(evaluate(gpu, snapshot, 0).rejection == Rejection::ConnectorRole);

    snapshot = oneRoute(validRoute());
    snapshot.routes[0].phyKind = PHYKind::TypeC;
    assert(evaluate(gpu, snapshot, 0).rejection == Rejection::TypeCPhy);
    snapshot = oneRoute(validRoute());
    snapshot.routes[0].ddi = DDI::D;
    snapshot.routes[0].phyKind = PHYKind::Combo;
    snapshot.routes[0].phy = 0;
    assert(evaluate(gpu, snapshot, 0).rejection == Rejection::TypeCPhy);
    snapshot = oneRoute(validRoute());
    snapshot.routes[0].phy = 1;
    assert(evaluate(gpu, snapshot, 0).rejection == Rejection::PHY);
    snapshot = oneRoute(validRoute());
    snapshot.routes[0].aux = AUX::Unknown;
    assert(evaluate(gpu, snapshot, 0).rejection == Rejection::AUX);
    snapshot = oneRoute(validRoute());
    snapshot.routes[0].panelPresent = false;
    assert(evaluate(gpu, snapshot, 0).rejection == Rejection::PanelAbsent);
    snapshot = oneRoute(validRoute());
    snapshot.routes[0].backendCapable = false;
    assert(evaluate(gpu, snapshot, 0).rejection == Rejection::BackendCapability);
    snapshot = oneRoute(validRoute());
    snapshot.routes[0].ownershipSnapshotComplete = false;
    assert(evaluate(gpu, snapshot, 0).rejection == Rejection::OwnershipUnknown);
    snapshot = oneRoute(validRoute());
    snapshot.routes[0].exclusiveOwnershipValidated = false;
    assert(evaluate(gpu, snapshot, 0).rejection == Rejection::OwnershipUnknown);

    snapshot = oneRoute(validRoute());
    snapshot.routes[0].source = EvidenceSource::StrictFirmware;
    snapshot.routes[0].firmware = {false, true, true, true, false};
    assert(evaluate(gpu, snapshot, 0).rejection == Rejection::FirmwareChecksum);
    snapshot.routes[0].firmware = {true, false, true, false, false};
    assert(evaluate(gpu, snapshot, 0).rejection == Rejection::FirmwareMalformed);
    snapshot.routes[0].firmware = {true, true, false, false, false};
    assert(evaluate(gpu, snapshot, 0).rejection == Rejection::FirmwareMalformed);
    snapshot.routes[0].source = EvidenceSource::DiagnosticVBT;
    snapshot.routes[0].firmware.diagnosticOnly = true;
    assert(evaluate(gpu, snapshot, 0).rejection == Rejection::DiagnosticOnly);
    snapshot.routes[0].firmware.diagnosticOnly = false;
    snapshot.routes[0].source = EvidenceSource::LinuxObservation;
    assert(evaluate(gpu, snapshot, 0).rejection == Rejection::UntrustedEvidence);
    snapshot.routes[0].source = EvidenceSource::DeviceProperty;
    assert(evaluate(gpu, snapshot, 0).rejection == Rejection::UntrustedEvidence);
    snapshot.routes[0].source = EvidenceSource::ValidatedBoardRecord;
    snapshot.routes[0].firmwareDerived = true;
    snapshot.routes[0].firmware.diagnosticOnly = true;
    assert(evaluate(gpu, snapshot, 0).rejection == Rejection::DiagnosticOnly);
    snapshot.routes[0].firmwareDerived = false;
    assert(evaluate(gpu, snapshot, 0).rejection == Rejection::DiagnosticOnly);
    snapshot.routes[0].firmware.diagnosticOnly = false;
    snapshot.routes[0].source = EvidenceSource::SyntheticFixture;
    assert(evaluate(gpu, snapshot, 0).rejection == Rejection::UntrustedEvidence);

    snapshot = oneRoute(validRoute());
    snapshot.routes[0].ddiOwner = ResourceOwner::NativeDonor;
    snapshot.routes[0].phyOwner = ResourceOwner::NativeDonor;
    snapshot.routes[0].auxOwner = ResourceOwner::NativeDonor;
    assert(evaluate(gpu, snapshot, 0).rejection == Rejection::DonorBindingConflict);
    snapshot.routes[0].donorBindingCompatible = true;
    assert(evaluate(gpu, snapshot, 0).admitted());

    snapshot = oneRoute(validRoute());
    snapshot.count = 2;
    snapshot.routes[1] = validRoute();
    snapshot.routes[1].role = Role::ExternalDisplay;
    snapshot.routes[1].connector = Connector::ExternalDP;
    snapshot.routes[1].ddi = DDI::B;
    snapshot.routes[1].phy = 1;
    snapshot.routes[1].aux = AUX::A;
    assert(evaluate(gpu, snapshot, 0).rejection == Rejection::AmbiguousRoute);
    snapshot.routes[1].aux = AUX::B;
    snapshot.routes[1].ddi = DDI::Unknown;
    assert(evaluate(gpu, snapshot, 0).rejection == Rejection::OwnershipUnknown);

    // The firmware parser exposes facts, not an admitted eDP route type.
    static_assert(!std::is_convertible<XELP::VBT::Ports, RouteEvidence>::value,
                  "VBT facts must not implicitly become runtime eDP evidence");

    connector = evaluate(gpu, oneRoute(validRoute()), 0);
    GOPReadout gop {true, true, DDI::A, 0, 0, 0x1000, MemoryDisposition::BorrowedPinned};
    NativeFramebufferReadout native;
    native.bindingComplete = true;
    native.donorObjectsPreserved = true;
    native.noConflictingDonorBinding = true;
    native.synchronizationComplete = true;
    native.memoryLifetimeValidated = true;
    native.ddi = DDI::A;
    native.pipe = 0;
    native.transcoder = 0;
    native.primaryPlane = 0;
    native.framebufferIdentity = 0x10;
    native.pathIdentity = 0x20;
    native.planeIdentity = 0x30;
    native.surfaceIdentity = 0x1000;
    assert(validateFramebufferHandoff(connector, gop, native).admitted());
    native.pipe = 1;
    assert(!validateFramebufferHandoff(connector, gop, native).admitted());
    native.pipe = 0;
    native.noConflictingDonorBinding = false;
    assert(!validateFramebufferHandoff(connector, gop, native).admitted());
    native.noConflictingDonorBinding = true;
    gop.memory = MemoryDisposition::Unknown;
    assert(!validateFramebufferHandoff(connector, gop, native).admitted());

    const auto rollback = framebufferRollbackPlan();
    assert(rollback.keepGOPScanout && rollback.preserveDonorObjects &&
           rollback.undoPartialBinding && rollback.releaseOnlyBackendOwnedResources);
    puts("PASS: physical GPU and ABI admission, internal route trust/ownership, DDI/AUX ambiguity, VBT trust boundary, and framebuffer handoff policy");
}
