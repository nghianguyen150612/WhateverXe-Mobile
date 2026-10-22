#include "kern_tgl_edp_lifecycle.hpp"
#include <cassert>
#include <cstdio>

using namespace TGLEDP;

struct ScriptedAdapter final : HardwareAdapter {
    AdapterResult responses[13] {};
    AdapterResult execute(AdapterOperation operation, Resource) override {
        const auto index = static_cast<uint32_t>(operation);
        return index < 13 ? responses[index] : AdapterResult{};
    }
};

static GPUFacts gpuFacts() {
    return {XELP::identify(0x9A498086U, 1), RequiredNativeProbeABI, RequiredGPUCapabilities};
}

static ConnectorDecision routeDecision() {
    ConnectorDecision route;
    route.ddi = DDI::A;
    route.phy = 0;
    route.aux = AUX::A;
    return route;
}

static void observeFree(ResourceBook &book) {
    for (uint32_t i = 0; i < ResourceCount; ++i)
        assert(book.observe(static_cast<Resource>(i), ResourceOwner::KnownFree, true));
}

static void acquireInitial(Session &session, ResourceBook &book) {
    assert(acquireResource(session, book, Resource::PanelVDD, Observation::SuccessValidated));
    assert(acquireResource(session, book, Resource::AUXController, Observation::SuccessValidated));
    assert(acquireResource(session, book, Resource::PHY, Observation::SuccessValidated));
    assert(acquireResource(session, book, Resource::PLL, Observation::SuccessValidated));
    assert(acquireResource(session, book, Resource::DDITransmitter, Observation::SuccessValidated));
    assert(!acquireResource(session, book, Resource::DDITransmitter, Observation::SuccessValidated));
}

static void expectAdvanced(Session &session, ResourceBook &book, Operation operation,
                           LifecycleEvidence evidence) {
    evidence.observation = Observation::SuccessValidated;
    const auto transition = advance(session, operation, evidence, book);
    assert(transition.advanced && transition.failure == Failure::None);
}

static void bringToLinkReady(Session &session, ResourceBook &book) {
    auto identified = identify(session, qualifyGPU(gpuFacts()), book);
    assert(identified.advanced && session.state == State::Identified);
    auto qualified = qualify(session, routeDecision(), book);
    assert(qualified.advanced && session.state == State::Qualified);
    acquireInitial(session, book);
    expectAdvanced(session, book, Operation::ResourcesOwned, {});
    LifecycleEvidence evidence;
    evidence.panelPowerPrepared = true;
    expectAdvanced(session, book, Operation::PreparePanelPower, evidence);
    evidence = {};
    evidence.panelPowerOn = true;
    expectAdvanced(session, book, Operation::ConfirmPanelPower, evidence);
    evidence = {};
    evidence.panelPowerOn = true;
    evidence.auxReady = true;
    evidence.aux = AUX::A;
    expectAdvanced(session, book, Operation::ConfirmAuxReady, evidence);
    evidence = {};
    evidence.dpcdCapabilitiesValidated = true;
    evidence.edidReadable = true;
    evidence.sinkMaxLanes = 4;
    evidence.sinkMaxRate = 3;
    expectAdvanced(session, book, Operation::DiscoverSink, evidence);
    assert(session.state == State::SinkReady); // EDID and DPCD do not train a link.
    evidence = {};
    evidence.dpcdCapabilitiesValidated = true;
    evidence.linkConfigurationValidated = true;
    evidence.sinkMaxLanes = 4;
    evidence.sinkMaxRate = 3;
    evidence.selectedLanes = 2;
    evidence.selectedRate = 1;
    expectAdvanced(session, book, Operation::ConfigureLink, evidence);
    evidence = {};
    evidence.linkTrainingValidated = true;
    evidence.auxTrainingTransactionsValidated = true;
    evidence.selectedLanes = 2;
    evidence.selectedRate = 1;
    evidence.negotiatedLanes = 2;
    evidence.negotiatedRate = 1;
    expectAdvanced(session, book, Operation::TrainLink, evidence);
    assert(session.state == State::LinkReady);
}

static void cleanup(ResourceBook &book) {
    while (book.ownedMask()) {
        const auto next = book.nextRelease();
        assert(next != Resource::Count);
        assert(book.release(next, ReleaseObservation::Released));
    }
}

int main() {
    ResourceBook absentPanelBook;
    observeFree(absentPanelBook);
    Session absentPanel;
    assert(identify(absentPanel, qualifyGPU(gpuFacts()), absentPanelBook).advanced);
    auto noPanel = routeDecision();
    noPanel.rejection = Rejection::PanelAbsent;
    const auto noPanelResult = qualify(absentPanel, noPanel, absentPanelBook);
    assert(!noPanelResult.advanced && absentPanel.state == State::Failed);
    assert(absentPanel.failure == Failure::ConnectorRejected && absentPanelBook.ownedMask() == 0);

    ResourceBook unobserved;
    assert(!unobserved.acquire(Resource::PanelVDD)); // Unknown is not free.
    assert(!unobserved.release(Resource::PanelVDD, ReleaseObservation::Released));

    ResourceBook stageBook;
    observeFree(stageBook);
    Session stageSession;
    assert(identify(stageSession, qualifyGPU(gpuFacts()), stageBook).advanced);
    assert(qualify(stageSession, routeDecision(), stageBook).advanced);
    assert(!acquireResource(stageSession, stageBook, Resource::Pipe, Observation::SuccessValidated));
    assert(!acquireResource(stageSession, stageBook, Resource::PanelVDD, Observation::NoEvidence));
    assert(stageBook.owner[static_cast<uint32_t>(Resource::PanelVDD)] == ResourceOwner::Unknown);

    ResourceBook order;
    observeFree(order);
    assert(!order.acquire(Resource::PLL)); // PHY must be owned first.
    assert(order.acquire(Resource::PanelVDD));
    assert(!order.acquire(Resource::DDITransmitter));
    assert(order.acquire(Resource::PHY));
    assert(order.acquire(Resource::PLL));
    assert(order.acquire(Resource::DDITransmitter));
    assert(!order.release(Resource::PHY, ReleaseObservation::Released)); // Dependents remain.
    assert(order.nextRelease() == Resource::DDITransmitter);
    assert(order.release(Resource::DDITransmitter, ReleaseObservation::Released));
    assert(order.release(Resource::PLL, ReleaseObservation::Released));
    assert(order.release(Resource::PHY, ReleaseObservation::Released));
    assert(order.release(Resource::PanelVDD, ReleaseObservation::Released));
    assert(!order.release(Resource::PanelVDD, ReleaseObservation::Released)); // No release without ownership.
    assert(order.allFree());

    // A native donor lease is transferred only with explicit, synchronized
    // evidence; release restores the original donor owner.
    ResourceBook donor;
    observeFree(donor);
    assert(donor.observe(Resource::PanelVDD, ResourceOwner::NativeDonor, true));
    OwnershipTransferProof proof;
    proof.resource = Resource::PanelVDD;
    proof.donorOwnerIdentity = 0x10;
    proof.backendOwnerIdentity = 0x20;
    proof.donorQuiesced = true;
    proof.exclusive = true;
    proof.synchronized = true;
    proof.validated = true;
    assert(!donor.adopt(Resource::PanelVDD, proof));
    proof.donorObjectsPreserved = true;
    assert(donor.adopt(Resource::PanelVDD, proof));
    assert(donor.owns(Resource::PanelVDD));
    assert(donor.release(Resource::PanelVDD, ReleaseObservation::Released));
    assert(donor.owner[static_cast<uint32_t>(Resource::PanelVDD)] == ResourceOwner::NativeDonor);

    // The mock has no default hardware success. Missing operation evidence
    // cannot advance the lifecycle.
    ScriptedAdapter adapter;
    const auto empty = adapter.execute(AdapterOperation::TrainLink, Resource::PHY);
    assert(empty.observation == Observation::NoEvidence);
    assert(!empty.evidence.linkTrainingValidated);

    ResourceBook full;
    observeFree(full);
    Session session;
    bringToLinkReady(session, full);
    assert(acquireResource(session, full, Resource::Pipe, Observation::SuccessValidated));
    assert(acquireResource(session, full, Resource::Transcoder, Observation::SuccessValidated));
    LifecycleEvidence evidence;
    evidence.pipeTranscoderValidated = true;
    evidence.ddi = DDI::A;
    evidence.pipe = 0;
    evidence.transcoder = 0;
    expectAdvanced(session, full, Operation::BindPipeTranscoder, evidence);
    assert(session.state == State::PipeBound);

    assert(acquireResource(session, full, Resource::FramebufferPath, Observation::SuccessValidated));
    evidence = {};
    evidence.framebufferHandoffValidated = true;
    evidence.donorObjectsPreserved = true;
    evidence.noConflictingDonorBinding = true;
    evidence.handoffSynchronized = true;
    evidence.ddi = DDI::A;
    evidence.pipe = 0;
    evidence.transcoder = 0;
    evidence.primaryPlane = 0;
    evidence.framebufferIdentity = 0x100;
    evidence.pathIdentity = 0x200;
    evidence.nativeSurfaceIdentity = 0x300;
    expectAdvanced(session, full, Operation::HandoffFramebuffer, evidence);
    assert(session.state == State::FramebufferReady);

    evidence = {};
    evidence.scanoutReadbackValidated = true;
    evidence.ddi = DDI::A;
    evidence.pipe = 0;
    evidence.transcoder = 0;
    evidence.primaryPlane = 0;
    evidence.scanoutSurfaceIdentity = 0x300;
    expectAdvanced(session, full, Operation::EnableScanout, evidence);
    assert(session.state == State::ScanoutReady);
    assert(acquireResource(session, full, Resource::Backlight, Observation::SuccessValidated));
    evidence = {};
    evidence.backlightValidated = true;
    expectAdvanced(session, full, Operation::ApplyBacklight, evidence);
    assert(session.state == State::Active);

    // Cleanup is reverse dependency order, and operations on another
    // connector's ledger remain untouched.
    ResourceBook externalDisplay;
    observeFree(externalDisplay);
    assert(externalDisplay.observe(Resource::DDITransmitter, ResourceOwner::ExternalDisplay, true));
    const Resource expected[] {Resource::Backlight, Resource::FramebufferPath, Resource::Transcoder,
        Resource::Pipe, Resource::DDITransmitter, Resource::PLL, Resource::PHY,
        Resource::AUXController, Resource::PanelVDD};
    for (const auto resource : expected) {
        assert(full.nextRelease() == resource);
        assert(full.release(resource, ReleaseObservation::Released));
    }
    assert(full.allFree());
    assert(externalDisplay.owner[static_cast<uint32_t>(Resource::DDITransmitter)] == ResourceOwner::ExternalDisplay);
    assert(!externalDisplay.release(Resource::DDITransmitter, ReleaseObservation::Released));

    // Panel-power failure stops before AUX; AUX failure stops before DPCD/link.
    ResourceBook powerBook;
    observeFree(powerBook);
    Session powerSession;
    assert(identify(powerSession, qualifyGPU(gpuFacts()), powerBook).advanced);
    assert(qualify(powerSession, routeDecision(), powerBook).advanced);
    acquireInitial(powerSession, powerBook);
    expectAdvanced(powerSession, powerBook, Operation::ResourcesOwned, {});
    evidence = {};
    evidence.panelPowerPrepared = true;
    expectAdvanced(powerSession, powerBook, Operation::PreparePanelPower, evidence);
    evidence = {};
    evidence.observation = Observation::FailedKnown;
    auto transition = advance(powerSession, Operation::ConfirmPanelPower, evidence, powerBook);
    assert(!transition.advanced && powerSession.state == State::Failed);
    evidence = {};
    evidence.observation = Observation::SuccessValidated;
    evidence.auxReady = true;
    evidence.aux = AUX::A;
    transition = advance(powerSession, Operation::ConfirmAuxReady, evidence, powerBook);
    assert(!transition.advanced && transition.failure == Failure::WrongState);
    assert(powerSession.failure == Failure::HardwareFailure);
    cleanup(powerBook);
    assert(retrySafe(powerSession, powerBook));
    assert(resetForRetry(powerSession, powerBook));

    ResourceBook auxBook;
    observeFree(auxBook);
    Session auxSession;
    assert(identify(auxSession, qualifyGPU(gpuFacts()), auxBook).advanced);
    assert(qualify(auxSession, routeDecision(), auxBook).advanced);
    acquireInitial(auxSession, auxBook);
    expectAdvanced(auxSession, auxBook, Operation::ResourcesOwned, {});
    evidence = {};
    evidence.panelPowerPrepared = true;
    expectAdvanced(auxSession, auxBook, Operation::PreparePanelPower, evidence);
    evidence = {};
    evidence.panelPowerOn = true;
    expectAdvanced(auxSession, auxBook, Operation::ConfirmPanelPower, evidence);
    evidence = {};
    evidence.observation = Observation::FailedKnown;
    assert(!advance(auxSession, Operation::ConfirmAuxReady, evidence, auxBook).advanced);
    evidence = {};
    evidence.observation = Observation::SuccessValidated;
    evidence.dpcdCapabilitiesValidated = true;
    assert(!advance(auxSession, Operation::DiscoverSink, evidence, auxBook).advanced);
    assert(auxSession.state == State::Failed);
    cleanup(auxBook);

    // A readable EDID does not advance beyond sink discovery, and failed
    // training never allows pipe binding or scanout.
    ResourceBook linkBook;
    observeFree(linkBook);
    Session linkSession;
    assert(identify(linkSession, qualifyGPU(gpuFacts()), linkBook).advanced);
    assert(qualify(linkSession, routeDecision(), linkBook).advanced);
    acquireInitial(linkSession, linkBook);
    expectAdvanced(linkSession, linkBook, Operation::ResourcesOwned, {});
    evidence = {};
    evidence.panelPowerPrepared = true;
    expectAdvanced(linkSession, linkBook, Operation::PreparePanelPower, evidence);
    evidence = {};
    evidence.panelPowerOn = true;
    expectAdvanced(linkSession, linkBook, Operation::ConfirmPanelPower, evidence);
    evidence = {};
    evidence.panelPowerOn = true;
    evidence.auxReady = true;
    evidence.aux = AUX::A;
    expectAdvanced(linkSession, linkBook, Operation::ConfirmAuxReady, evidence);
    evidence = {};
    evidence.dpcdCapabilitiesValidated = true;
    evidence.edidReadable = true;
    evidence.sinkMaxLanes = 2;
    evidence.sinkMaxRate = 2;
    expectAdvanced(linkSession, linkBook, Operation::DiscoverSink, evidence);
    assert(linkSession.state == State::SinkReady);
    evidence = {};
    evidence.dpcdCapabilitiesValidated = true;
    evidence.linkConfigurationValidated = true;
    evidence.sinkMaxLanes = 2;
    evidence.sinkMaxRate = 2;
    evidence.selectedLanes = 2;
    evidence.selectedRate = 1;
    expectAdvanced(linkSession, linkBook, Operation::ConfigureLink, evidence);
    evidence = {};
    evidence.observation = Observation::FailedKnown;
    transition = advance(linkSession, Operation::TrainLink, evidence, linkBook);
    assert(!transition.advanced && transition.cleanupRequired == InitialResourceMask);
    assert(linkSession.state == State::Failed && linkSession.failure == Failure::HardwareFailure);
    evidence = {};
    evidence.observation = Observation::SuccessValidated;
    evidence.pipeTranscoderValidated = true;
    evidence.ddi = DDI::A;
    evidence.pipe = 0;
    evidence.transcoder = 0;
    assert(!advance(linkSession, Operation::BindPipeTranscoder, evidence, linkBook).advanced);
    evidence = {};
    evidence.observation = Observation::SuccessValidated;
    evidence.scanoutReadbackValidated = true;
    assert(!advance(linkSession, Operation::EnableScanout, evidence, linkBook).advanced);
    cleanup(linkBook);

    // Training may succeed, but invalid pipe/transcoder evidence blocks both
    // framebuffer handoff and activation.
    ResourceBook bindingBook;
    observeFree(bindingBook);
    Session bindingSession;
    bringToLinkReady(bindingSession, bindingBook);
    assert(acquireResource(bindingSession, bindingBook, Resource::Pipe, Observation::SuccessValidated));
    assert(acquireResource(bindingSession, bindingBook, Resource::Transcoder, Observation::SuccessValidated));
    evidence = {};
    evidence.observation = Observation::SuccessValidated;
    evidence.pipeTranscoderValidated = false;
    evidence.ddi = DDI::A;
    evidence.pipe = 9;
    evidence.transcoder = 0;
    assert(!advance(bindingSession, Operation::BindPipeTranscoder, evidence, bindingBook).advanced);
    assert(bindingSession.state == State::Failed && bindingSession.failure == Failure::PipeBindingInvalid);
    evidence = {};
    evidence.observation = Observation::SuccessValidated;
    evidence.scanoutReadbackValidated = true;
    assert(!advance(bindingSession, Operation::EnableScanout, evidence, bindingBook).advanced);
    cleanup(bindingBook);

    // Unknown release state blocks optimistic retry and remains an explicit
    // cleanup obligation until a later adapter reconciliation exists.
    ResourceBook unknownBook;
    observeFree(unknownBook);
    Session unknownSession;
    assert(identify(unknownSession, qualifyGPU(gpuFacts()), unknownBook).advanced);
    assert(qualify(unknownSession, routeDecision(), unknownBook).advanced);
    acquireInitial(unknownSession, unknownBook);
    expectAdvanced(unknownSession, unknownBook, Operation::ResourcesOwned, {});
    evidence = {};
    evidence.observation = Observation::FailedUnknown;
    assert(!advance(unknownSession, Operation::PreparePanelPower, evidence, unknownBook).advanced);
    assert(advance(unknownSession, Operation::BeginQuiesce, {}, unknownBook).advanced);
    const auto unresolved = unknownBook.nextRelease();
    assert(unresolved == Resource::DDITransmitter);
    assert(!unknownBook.release(unresolved, ReleaseObservation::Unknown));
    while (unknownBook.nextRelease() != Resource::Count) {
        const auto next = unknownBook.nextRelease();
        assert(unknownBook.release(next, ReleaseObservation::Released));
    }
    assert(unknownBook.ownedMask() == (bit(Resource::PHY) | bit(Resource::PLL)));
    evidence = {};
    evidence.observation = Observation::SuccessValidated;
    evidence.hardwareQuiescent = true;
    assert(!advance(unknownSession, Operation::FinishQuiesce, evidence, unknownBook).advanced);
    assert(!retrySafe(unknownSession, unknownBook));
    assert(!resetForRetry(unknownSession, unknownBook));

    ResourceBook unsupportedBook;
    observeFree(unsupportedBook);
    Session unsupportedSession;
    assert(identify(unsupportedSession, qualifyGPU(gpuFacts()), unsupportedBook).advanced);
    assert(qualify(unsupportedSession, routeDecision(), unsupportedBook).advanced);
    acquireInitial(unsupportedSession, unsupportedBook);
    expectAdvanced(unsupportedSession, unsupportedBook, Operation::ResourcesOwned, {});
    evidence = {};
    evidence.observation = Observation::Unsupported;
    const auto unsupported = advance(unsupportedSession, Operation::PreparePanelPower, evidence, unsupportedBook);
    assert(!unsupported.advanced && unsupportedSession.state == State::Failed);
    assert(unsupportedSession.failure == Failure::UnsupportedHardware);
    cleanup(unsupportedBook);

    // A clean sleep/wake boundary releases every backend lease and starts a
    // fresh generation only after quiescence is validated.
    ResourceBook sleepBook;
    observeFree(sleepBook);
    Session sleepSession;
    bringToLinkReady(sleepSession, sleepBook);
    assert(acquireResource(sleepSession, sleepBook, Resource::Pipe, Observation::SuccessValidated));
    assert(acquireResource(sleepSession, sleepBook, Resource::Transcoder, Observation::SuccessValidated));
    evidence = {};
    evidence.pipeTranscoderValidated = true;
    evidence.ddi = DDI::A;
    evidence.pipe = 0;
    evidence.transcoder = 0;
    expectAdvanced(sleepSession, sleepBook, Operation::BindPipeTranscoder, evidence);
    assert(acquireResource(sleepSession, sleepBook, Resource::FramebufferPath, Observation::SuccessValidated));
    evidence = {};
    evidence.framebufferHandoffValidated = true;
    evidence.donorObjectsPreserved = true;
    evidence.noConflictingDonorBinding = true;
    evidence.handoffSynchronized = true;
    evidence.ddi = DDI::A;
    evidence.pipe = 0;
    evidence.transcoder = 0;
    evidence.primaryPlane = 0;
    evidence.framebufferIdentity = 0x101;
    evidence.pathIdentity = 0x201;
    evidence.nativeSurfaceIdentity = 0x301;
    expectAdvanced(sleepSession, sleepBook, Operation::HandoffFramebuffer, evidence);
    evidence = {};
    evidence.scanoutReadbackValidated = true;
    evidence.ddi = DDI::A;
    evidence.pipe = 0;
    evidence.transcoder = 0;
    evidence.primaryPlane = 0;
    evidence.scanoutSurfaceIdentity = 0x301;
    expectAdvanced(sleepSession, sleepBook, Operation::EnableScanout, evidence);
    assert(acquireResource(sleepSession, sleepBook, Resource::Backlight, Observation::SuccessValidated));
    evidence = {};
    evidence.backlightValidated = true;
    expectAdvanced(sleepSession, sleepBook, Operation::ApplyBacklight, evidence);
    const auto firstGeneration = sleepSession.generation;
    assert(advance(sleepSession, Operation::BeginQuiesce, {}, sleepBook).advanced);
    cleanup(sleepBook);
    evidence = {};
    evidence.observation = Observation::SuccessValidated;
    evidence.hardwareQuiescent = true;
    assert(advance(sleepSession, Operation::FinishQuiesce, evidence, sleepBook).advanced);
    assert(sleepSession.state == State::Unbound && sleepBook.allFree());
    assert(identify(sleepSession, qualifyGPU(gpuFacts()), sleepBook).advanced);
    assert(sleepSession.generation == firstGeneration + 1);

    puts("PASS: fail-closed lifecycle, validated sink/link/binding/handoff evidence, ordered lease rollback, unknown-state retry block, and sleep/wake ownership");
}
