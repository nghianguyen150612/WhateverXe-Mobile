#define TGLEDP_CLASSIFY_TESTING
#include "tgl_edp_native_fixture.hpp"
#include "kern_tgl_edp_lifecycle.hpp"

#include <cassert>
#include <cstdio>

using namespace TGLEDP;
using namespace TGLEDPNative;

static unsigned checks;
#define CHECK(expression) do { assert(expression); ++checks; } while (0)

static void expect(const SnapshotCandidate &candidate, Reason reason) {
    const auto result = NativeEvidenceAdapter::validate(candidate, 7);
    CHECK(result.consistency == Consistency::Inconsistent);
    CHECK(result.reason == reason);
}

static RouteEvidence nativeRoute() {
    RouteEvidence route;
    route.active = true;
    route.connection = ConnectionState::Connected;
    route.connector = Connector::InternalDP;
    route.role = Role::InternalPanel;
    route.ddi = DDI::A;
    route.phyKind = PHYKind::Combo;
    route.phy = 0;
    route.aux = AUX::A;
    route.source = EvidenceSource::AuthorizedNativeReadout;
    route.evidenceValidated = true;
    route.panelPresent = true;
    route.displayPortSupported = true;
    route.backendCapable = true;
    route.ownershipSnapshotComplete = true;
    route.exclusiveOwnershipValidated = true;
    route.ddiOwner = ResourceOwner::KnownFree;
    route.phyOwner = ResourceOwner::KnownFree;
    route.auxOwner = ResourceOwner::KnownFree;
    return route;
}

int main() {
    auto candidate = TGLNativeFixture::complete();
    auto result = NativeEvidenceAdapter::validate(candidate, 7);
    CHECK(result.consistency == Consistency::Consistent);
    CHECK(result.reason == Reason::None);
    CHECK(result.inventoryComplete);
    CHECK(result.topologyConsistent);
    CHECK(TGLEDP::qualifyGPU(candidate.gpu).admitted());

    auto unsupported = candidate;
    unsupported.gpu.profile.identity = 0x12348086U;
    unsupported.gpu.profile.effectiveIdentity = 0x12348086U;
    expect(unsupported, Reason::UnsupportedGPU);

    auto wrongABI = candidate;
    wrongABI.gpu.nativeProbeABI = 2;
    expect(wrongABI, Reason::NativeABIMismatch);

    auto noOwner = candidate;
    noOwner.nativeOwnerIdentity = 0;
    expect(noOwner, Reason::MissingOwnerBinding);

    auto nullPort = candidate;
    nullPort.ports[0].portRecord.objectIdentity = 0;
    expect(nullPort, Reason::MissingObjectBinding);

    auto shortPort = candidate;
    shortPort.ports[0].portRecord.objectBytes = NativePortRecordMinimumBytes - 1;
    expect(shortPort, Reason::ObjectTooSmall);

    auto shortFramebuffer = candidate;
    shortFramebuffer.ports[0].framebuffer.framebufferObject.objectBytes =
        NativeFramebufferMinimumBytes - 1;
    expect(shortFramebuffer, Reason::ObjectTooSmall);

    auto badPathParent = candidate;
    ++badPathParent.ports[0].framebuffer.pathObject.parentIdentity;
    expect(badPathParent, Reason::ObjectAssociationMismatch);

    auto misassociated = candidate;
    ++misassociated.ports[0].framebuffer.pathObject.linkedPortIdentity;
    expect(misassociated, Reason::ObjectAssociationMismatch);

    auto unknownAux = candidate;
    unknownAux.ports[0].aux = AUX::Unknown;
    expect(unknownAux, Reason::AUXUnknown);

    auto inferredAux = candidate;
    inferredAux.ports[0].auxSource = ObservationSource::NativePortRecord;
    expect(inferredAux, Reason::UnsupportedSource);

    auto unknownDDI = candidate;
    unknownDDI.ports[0].ddi = DDI::Unknown;
    expect(unknownDDI, Reason::UnsupportedDDI);

    auto mismatchedPHY = candidate;
    mismatchedPHY.ports[0].phy = 1;
    expect(mismatchedPHY, Reason::DDIPhyMismatch);

    auto diagnosticVBT = candidate;
    diagnosticVBT.ports[0].ddiSource = ObservationSource::DiagnosticVBT;
    expect(diagnosticVBT, Reason::DiagnosticOnly);

    auto linuxFacts = candidate;
    linuxFacts.ports[0].auxSource = ObservationSource::LinuxSysfsDiagnostic;
    expect(linuxFacts, Reason::DiagnosticOnly);

    // The native FB readout carries a framebuffer slot, pipe, DDI and plane,
    // but does not turn that slot into an object identity or establish AUX.
    TGLFBBinding::Readout readout;
    readout.status = TGLFBBinding::Status::Complete;
    readout.framebuffer = 1;
    readout.pipe = 0;
    readout.ddi = static_cast<uint32_t>(DDI::A);
    readout.plane = 0;
    const auto fb = NativeEvidenceAdapter::copyFramebufferReadout(readout,
        candidate.nativeOwnerIdentity, candidate.nativeOwnerLockIdentity, candidate.generationAtEnd);
    CHECK(fb.state == PathState::BoundPath);
    CHECK(fb.framebufferIndex == 1);
    CHECK(fb.framebufferObject.objectIdentity == 0);
    CHECK(fb.pathObject.objectIdentity == 0);
    CHECK(fb.ddi == DDI::A);

    auto readoutWithoutIdentities = candidate;
    readoutWithoutIdentities.ports[0].framebuffer = fb;
    expect(readoutWithoutIdentities, Reason::MissingObjectBinding);

    auto boundButInactive = candidate;
    boundButInactive.ports[0].activity = ActivityState::Inactive;
    CHECK(NativeEvidenceAdapter::validate(boundButInactive, 7).consistency == Consistency::Consistent);
    CHECK(!NativeEvidenceAdapter::toP004Snapshot(boundButInactive).routes[0].active);

    // A structurally present framebuffer path cannot fill an unknown AUX.
    auto fbWithoutAux = candidate;
    fbWithoutAux.ports[0].aux = AUX::Unknown;
    fbWithoutAux.ports[0].framebuffer = fb;
    expect(fbWithoutAux, Reason::AUXUnknown);

    // Linux and VBT observations are not sources of native P004 authorization.
    const auto bridged = NativeEvidenceAdapter::toP004Snapshot(candidate);
    CHECK(!bridged.complete);
    CHECK(bridged.count == candidate.portCount);
    auto oversized = candidate;
    oversized.portCount = MaxPorts + 1;
    CHECK(NativeEvidenceAdapter::toP004Snapshot(oversized).count == 0);
    CHECK(!bridged.routes[0].authorization.authorizes(bridged.routes[0]));
    CHECK(!bridged.authorization.authorizes(bridged));
    CHECK(!bridged.routes[0].backendCapable); // No link-training or backend proof.
    CHECK(!TGLEDP::qualifyConnector(TGLEDP::qualifyGPU(candidate.gpu), bridged, 0).admitted());

    auto forgedSnapshot = bridged;
    forgedSnapshot.complete = true;
    forgedSnapshot.routes[0].evidenceValidated = true;
    forgedSnapshot.routes[0].ownershipSnapshotComplete = true;
    forgedSnapshot.routes[0].exclusiveOwnershipValidated = true;
    CHECK(TGLEDP::qualifyConnector(TGLEDP::qualifyGPU(candidate.gpu), forgedSnapshot, 0).rejection ==
        Rejection::OwnershipUnknown);

    auto forged = nativeRoute();
    CHECK(!TGLEDP::trust(forged).admitted());
    CHECK(TGLEDP::trust(forged).rejection == Rejection::UntrustedEvidence);
    TGLEDPClassify::TestEvidenceAuthority::authorize(forged);
    CHECK(TGLEDP::trust(forged).admitted());
    forged.ddi = DDI::B;
    CHECK(!TGLEDP::trust(forged).admitted()); // A copied authorization is route-bound.

    // P004 remains the final CPU-policy gate. Only its test-only authority can
    // mint the synthetic route/snapshot proofs used to exercise admission.
    RoutingSnapshot testOnlySnapshot;
    testOnlySnapshot.complete = true;
    testOnlySnapshot.count = MaxPorts;
    for (size_t i = 0; i < MaxPorts; ++i) {
        const auto &observed = candidate.ports[i];
        auto &route = testOnlySnapshot.routes[i];
        route.active = i == 0;
        route.connection = observed.connection;
        route.connector = observed.connector;
        route.role = observed.role;
        route.ddi = observed.ddi;
        route.phyKind = observed.phyKind;
        route.phy = observed.phy;
        route.aux = observed.aux;
        route.source = EvidenceSource::AuthorizedNativeReadout;
        route.evidenceValidated = true;
        route.panelPresent = i == 0;
        route.displayPortSupported = true;
        route.typeCCapable = TGLEDP::typeCDDI(route.ddi);
        route.backendCapable = true;
        route.ownershipSnapshotComplete = true;
        route.exclusiveOwnershipValidated = true;
        route.ddiOwner = ResourceOwner::KnownFree;
        route.phyOwner = ResourceOwner::KnownFree;
        route.auxOwner = ResourceOwner::KnownFree;
        TGLEDPClassify::TestEvidenceAuthority::authorize(route);
    }
    TGLEDPClassify::TestEvidenceAuthority::authorizeSnapshot(testOnlySnapshot);
    const auto classified = TGLEDPClassify::classify(TGLEDPClassify::FirmwareAnalysis{},
        candidate.gpu, testOnlySnapshot);
    CHECK(classified.runtimeAdmissible);
    CHECK(classified.stage == TGLEDPClassify::Stage::RuntimeAdmissible);
    auto changedGPU = candidate.gpu;
    changedGPU.profile.identity = 0x12348086U;
    changedGPU.profile.effectiveIdentity = 0x12348086U;
    CHECK(!TGLEDPClassify::classify(TGLEDPClassify::FirmwareAnalysis{}, changedGPU,
        testOnlySnapshot).runtimeAdmissible);
    auto editedSnapshot = testOnlySnapshot;
    editedSnapshot.routes[1].connection = ConnectionState::Connected;
    CHECK(!editedSnapshot.authorization.authorizes(editedSnapshot));
    CHECK(!TGLEDPClassify::classify(TGLEDPClassify::FirmwareAnalysis{}, candidate.gpu,
        editedSnapshot).runtimeAdmissible);

    TGLEDP::Session session;
    CHECK(session.state == TGLEDP::State::Unbound);
    CHECK(session.generation == 0);

    std::printf("tgl_edp_native_evidence: %u checks passed\n", checks);
}
