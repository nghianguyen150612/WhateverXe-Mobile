// Mock-driven lifecycle and ownership rules for a future Tiger Lake eDP path.
// No method in this file reads or writes hardware. Adapters must return
// operation-specific validated observations before policy can advance.
#ifndef KERN_TGL_EDP_LIFECYCLE_HPP
#define KERN_TGL_EDP_LIFECYCLE_HPP

#include "kern_tgl_edp_contract.hpp"

namespace TGLEDP {

enum class Resource : uint8_t {
    PanelVDD,
    AUXController,
    PHY,
    PLL,
    DDITransmitter,
    Pipe,
    Transcoder,
    FramebufferPath,
    Backlight,
    Count
};
constexpr uint32_t ResourceCount = static_cast<uint32_t>(Resource::Count);
constexpr uint32_t ResourceMaskAll = (1U << ResourceCount) - 1U;

constexpr uint32_t bit(Resource resource) {
    const auto index = static_cast<uint32_t>(resource);
    return index < ResourceCount ? 1U << index : 0;
}

inline uint32_t dependencies(Resource resource) {
    switch (resource) {
        case Resource::PanelVDD: return 0;
        case Resource::AUXController: return bit(Resource::PanelVDD);
        case Resource::PHY: return 0;
        case Resource::PLL: return bit(Resource::PHY);
        case Resource::DDITransmitter: return bit(Resource::PHY) | bit(Resource::PLL);
        case Resource::Pipe: return bit(Resource::DDITransmitter);
        case Resource::Transcoder: return bit(Resource::Pipe);
        case Resource::FramebufferPath: return bit(Resource::Pipe) | bit(Resource::Transcoder);
        case Resource::Backlight: return bit(Resource::PanelVDD) | bit(Resource::FramebufferPath);
        case Resource::Count: return 0;
    }
    return 0;
}

struct OwnershipTransferProof {
    Resource resource {Resource::Count};
    uintptr_t donorOwnerIdentity {};
    uintptr_t backendOwnerIdentity {};
    bool donorQuiesced {};
    bool exclusive {};
    bool donorObjectsPreserved {};
    bool synchronized {};
    bool validated {};
};

enum class ReleaseObservation : uint8_t { NotAttempted, StillOwned, Released, Unknown };

// A single-route lease ledger. Unknown is the initial state: adapters must
// prove a resource free or donor-owned before acquisition. Releases restore
// the observed prior owner and require validated adapter evidence.
struct ResourceBook {
    ResourceOwner owner[ResourceCount] {};
    ResourceOwner returnOwner[ResourceCount] {};

    bool observe(Resource resource, ResourceOwner observed, bool validated) {
        const auto index = static_cast<uint32_t>(resource);
        if (index >= ResourceCount || owner[index] == ResourceOwner::InternalEDP) return false;
        owner[index] = validated ? observed : ResourceOwner::Unknown;
        return validated && observed != ResourceOwner::Unknown;
    }

    bool owns(Resource resource) const {
        const auto index = static_cast<uint32_t>(resource);
        return index < ResourceCount && owner[index] == ResourceOwner::InternalEDP;
    }

    bool ownsMask(uint32_t mask) const {
        if (mask & ~ResourceMaskAll) return false;
        for (uint32_t i = 0; i < ResourceCount; ++i)
            if ((mask & (1U << i)) && owner[i] != ResourceOwner::InternalEDP) return false;
        return true;
    }

    uint32_t ownedMask() const {
        uint32_t mask = 0;
        for (uint32_t i = 0; i < ResourceCount; ++i)
            if (owner[i] == ResourceOwner::InternalEDP) mask |= 1U << i;
        return mask;
    }

    uint32_t unknownMask() const {
        uint32_t mask = 0;
        for (uint32_t i = 0; i < ResourceCount; ++i)
            if (owner[i] == ResourceOwner::Unknown) mask |= 1U << i;
        return mask;
    }

    bool allKnown(uint32_t mask = ResourceMaskAll) const {
        if (mask & ~ResourceMaskAll) return false;
        for (uint32_t i = 0; i < ResourceCount; ++i)
            if ((mask & (1U << i)) && owner[i] == ResourceOwner::Unknown) return false;
        return true;
    }

    bool allFree(uint32_t mask = ResourceMaskAll) const {
        if (mask & ~ResourceMaskAll) return false;
        for (uint32_t i = 0; i < ResourceCount; ++i)
            if ((mask & (1U << i)) && owner[i] != ResourceOwner::KnownFree) return false;
        return true;
    }

    bool prerequisitesOwned(Resource resource) const {
        const auto required = dependencies(resource);
        for (uint32_t i = 0; i < ResourceCount; ++i)
            if ((required & (1U << i)) && owner[i] != ResourceOwner::InternalEDP) return false;
        return true;
    }

    bool acquire(Resource resource) {
        const auto index = static_cast<uint32_t>(resource);
        if (index >= ResourceCount || owner[index] != ResourceOwner::KnownFree ||
            !prerequisitesOwned(resource)) return false;
        owner[index] = ResourceOwner::InternalEDP;
        returnOwner[index] = ResourceOwner::KnownFree;
        return true;
    }

    bool adopt(Resource resource, const OwnershipTransferProof &proof) {
        const auto index = static_cast<uint32_t>(resource);
        if (index >= ResourceCount || owner[index] != ResourceOwner::NativeDonor ||
            proof.resource != resource || !proof.donorOwnerIdentity || !proof.backendOwnerIdentity ||
            !proof.donorQuiesced || !proof.exclusive || !proof.donorObjectsPreserved ||
            !proof.synchronized || !proof.validated || !prerequisitesOwned(resource)) return false;
        owner[index] = ResourceOwner::InternalEDP;
        returnOwner[index] = ResourceOwner::NativeDonor;
        return true;
    }

    bool hasDependent(Resource resource) const {
        const auto target = bit(resource);
        for (uint32_t i = 0; i < ResourceCount; ++i) {
            if ((dependencies(static_cast<Resource>(i)) & target) &&
                owner[i] != ResourceOwner::KnownFree) return true;
        }
        return false;
    }

    Resource nextRelease() const {
        // Reverse the abstract dependency graph. This is a policy ordering;
        // hardware-specific adapters still validate each release operation.
        constexpr Resource order[] {
            Resource::Backlight, Resource::FramebufferPath, Resource::Transcoder,
            Resource::Pipe, Resource::DDITransmitter, Resource::PLL, Resource::PHY,
            Resource::AUXController, Resource::PanelVDD
        };
        for (const auto resource : order)
            if (owns(resource) && !hasDependent(resource)) return resource;
        return Resource::Count;
    }

    bool release(Resource resource, ReleaseObservation observation) {
        const auto index = static_cast<uint32_t>(resource);
        if (index >= ResourceCount || !owns(resource) || nextRelease() != resource) return false;
        if (observation == ReleaseObservation::StillOwned || observation == ReleaseObservation::NotAttempted)
            return false;
        if (observation == ReleaseObservation::Unknown) {
            owner[index] = ResourceOwner::Unknown;
            return false;
        }
        owner[index] = returnOwner[index];
        return true;
    }
};

enum class State : uint8_t {
    Unbound,
    Identified,
    Qualified,
    Acquired,
    Prepared,
    PanelPowered,
    AuxReady,
    SinkReady,
    LinkConfigured,
    LinkReady,
    PipeBound,
    FramebufferReady,
    ScanoutReady,
    Active,
    Quiescing,
    Failed
};

enum class Failure : uint8_t {
    None,
    GPURejected,
    ConnectorRejected,
    WrongState,
    MissingResource,
    MissingEvidence,
    UnsupportedHardware,
    HardwareFailure,
    HardwareStateUnknown,
    SinkCapabilitiesInvalid,
    LinkConfigurationInvalid,
    LinkTrainingFailed,
    PipeBindingInvalid,
    FramebufferHandoffInvalid,
    ScanoutInvalid,
    BacklightInvalid,
    CleanupIncomplete
};

enum class Observation : uint8_t { NoEvidence, SuccessValidated, FailedKnown, FailedUnknown, Unsupported };
enum class Operation : uint8_t {
    ResourcesOwned,
    PreparePanelPower,
    ConfirmPanelPower,
    ConfirmAuxReady,
    DiscoverSink,
    ConfigureLink,
    TrainLink,
    BindPipeTranscoder,
    HandoffFramebuffer,
    EnableScanout,
    ApplyBacklight,
    BeginQuiesce,
    FinishQuiesce
};

struct LifecycleEvidence {
    Observation observation {Observation::NoEvidence};
    bool panelPowerPrepared {};
    bool panelPowerOn {};
    bool auxReady {};
    AUX aux {AUX::Unknown};
    bool dpcdCapabilitiesValidated {};
    bool edidReadable {}; // Descriptive only; it is never link-ready evidence.
    uint8_t sinkMaxLanes {};
    uint32_t sinkMaxRate {};
    bool linkConfigurationValidated {};
    uint8_t selectedLanes {};
    uint32_t selectedRate {};
    bool linkTrainingValidated {};
    bool auxTrainingTransactionsValidated {};
    uint8_t negotiatedLanes {};
    uint32_t negotiatedRate {};
    bool pipeTranscoderValidated {};
    DDI ddi {DDI::Unknown};
    uint8_t pipe {0xFF};
    uint8_t transcoder {0xFF};
    bool framebufferHandoffValidated {};
    bool donorObjectsPreserved {};
    bool noConflictingDonorBinding {};
    bool handoffSynchronized {};
    uint8_t primaryPlane {0xFF};
    uintptr_t framebufferIdentity {};
    uintptr_t pathIdentity {};
    uint64_t nativeSurfaceIdentity {};
    bool scanoutReadbackValidated {};
    uint64_t scanoutSurfaceIdentity {};
    bool backlightValidated {};
    bool hardwareQuiescent {};
};

struct Session {
    State state {State::Unbound};
    Failure failure {Failure::None};
    DDI ddi {DDI::Unknown};
    AUX aux {AUX::Unknown};
    uint8_t phy {0xFF};
    uint8_t pipe {0xFF};
    uint8_t transcoder {0xFF};
    uint8_t selectedLanes {};
    uint32_t selectedRate {};
    uintptr_t framebufferIdentity {};
    uintptr_t pathIdentity {};
    uint64_t surfaceIdentity {};
    uint32_t generation {};
    bool hardwareStateKnown {true};
};

struct TransitionResult {
    bool advanced {};
    Failure failure {Failure::None};
    uint32_t cleanupRequired {};
    bool retrySafe {};
};

inline TransitionResult result(const Session &session, bool advanced, Failure failure,
                               const ResourceBook &resources) {
    const auto cleanup = resources.ownedMask();
    const bool safe = session.state == State::Failed && session.hardwareStateKnown &&
        cleanup == 0 && resources.allFree();
    return {advanced, failure, cleanup, safe};
}

inline TransitionResult identify(Session &session, const Decision &gpu, const ResourceBook &resources) {
    if (session.state != State::Unbound) return result(session, false, Failure::WrongState, resources);
    if (!gpu.admitted()) {
        session.state = State::Failed;
        session.failure = Failure::GPURejected;
        return result(session, false, session.failure, resources);
    }
    ++session.generation;
    session.failure = Failure::None;
    session.hardwareStateKnown = true;
    session.state = State::Identified;
    return result(session, true, Failure::None, resources);
}

inline TransitionResult qualify(Session &session, const ConnectorDecision &connector,
                                const ResourceBook &resources) {
    if (session.state != State::Identified) return result(session, false, Failure::WrongState, resources);
    if (!connector.admitted()) {
        session.state = State::Failed;
        session.failure = Failure::ConnectorRejected;
        return result(session, false, session.failure, resources);
    }
    session.ddi = connector.ddi;
    session.phy = connector.phy;
    session.aux = connector.aux;
    session.state = State::Qualified;
    return result(session, true, Failure::None, resources);
}

inline State expectedState(Operation operation) {
    switch (operation) {
        case Operation::ResourcesOwned: return State::Qualified;
        case Operation::PreparePanelPower: return State::Acquired;
        case Operation::ConfirmPanelPower: return State::Prepared;
        case Operation::ConfirmAuxReady: return State::PanelPowered;
        case Operation::DiscoverSink: return State::AuxReady;
        case Operation::ConfigureLink: return State::SinkReady;
        case Operation::TrainLink: return State::LinkConfigured;
        case Operation::BindPipeTranscoder: return State::LinkReady;
        case Operation::HandoffFramebuffer: return State::PipeBound;
        case Operation::EnableScanout: return State::FramebufferReady;
        case Operation::ApplyBacklight: return State::ScanoutReady;
        case Operation::BeginQuiesce: return State::Quiescing; // Special-cased by canPerform.
        case Operation::FinishQuiesce: return State::Quiescing;
    }
    return State::Failed;
}

inline constexpr uint32_t InitialResourceMask =
    bit(Resource::PanelVDD) | bit(Resource::AUXController) | bit(Resource::PHY) |
    bit(Resource::PLL) | bit(Resource::DDITransmitter);
inline constexpr uint32_t PipeResourceMask = bit(Resource::Pipe) | bit(Resource::Transcoder);
inline constexpr uint32_t FramebufferResourceMask =
    InitialResourceMask | PipeResourceMask | bit(Resource::FramebufferPath);
inline constexpr uint32_t ActiveResourceMask = FramebufferResourceMask | bit(Resource::Backlight);

inline bool acquisitionAllowed(State state, Resource resource) {
    switch (resource) {
        case Resource::PanelVDD:
        case Resource::AUXController:
        case Resource::PHY:
        case Resource::PLL:
        case Resource::DDITransmitter:
            return state == State::Qualified;
        case Resource::Pipe:
        case Resource::Transcoder:
            return state == State::LinkReady;
        case Resource::FramebufferPath:
            return state == State::PipeBound;
        case Resource::Backlight:
            return state == State::ScanoutReady;
        case Resource::Count:
            return false;
    }
    return false;
}

inline bool acquireResource(const Session &session, ResourceBook &resources, Resource resource,
                            Observation observation) {
    if (!acquisitionAllowed(session.state, resource)) return false;
    if (observation == Observation::FailedUnknown || observation == Observation::NoEvidence) {
        resources.observe(resource, ResourceOwner::Unknown, false);
        return false;
    }
    if (observation != Observation::SuccessValidated) return false;
    return resources.acquire(resource);
}

inline bool adoptResource(const Session &session, ResourceBook &resources, Resource resource,
                          const OwnershipTransferProof &proof) {
    return acquisitionAllowed(session.state, resource) && resources.adopt(resource, proof);
}

inline bool canPerform(const Session &session, Operation operation, const ResourceBook &resources) {
    if (operation == Operation::BeginQuiesce)
        return session.state != State::Unbound && session.state != State::Quiescing;
    if (session.state != expectedState(operation)) return false;
    if (operation == Operation::ResourcesOwned) return resources.ownsMask(InitialResourceMask);
    switch (operation) {
        case Operation::PreparePanelPower:
        case Operation::ConfirmPanelPower:
        case Operation::ConfirmAuxReady:
        case Operation::DiscoverSink:
        case Operation::ConfigureLink:
        case Operation::TrainLink:
            return resources.ownsMask(InitialResourceMask);
        case Operation::BindPipeTranscoder:
            return resources.ownsMask(InitialResourceMask | PipeResourceMask);
        case Operation::HandoffFramebuffer:
            return resources.ownsMask(FramebufferResourceMask);
        case Operation::EnableScanout:
            return resources.ownsMask(FramebufferResourceMask);
        case Operation::ApplyBacklight:
            return resources.ownsMask(ActiveResourceMask);
        case Operation::ResourcesOwned:
            return resources.ownsMask(InitialResourceMask);
        case Operation::BeginQuiesce:
        case Operation::FinishQuiesce:
            return false;
    }
    return false;
}

inline TransitionResult finishQuiesce(Session &session, const LifecycleEvidence &evidence,
                                      const ResourceBook &resources);

inline TransitionResult fail(Session &session, Failure failure, bool hardwareKnown,
                             const ResourceBook &resources) {
    session.state = State::Failed;
    session.failure = failure;
    session.hardwareStateKnown = hardwareKnown && resources.unknownMask() == 0;
    return result(session, false, failure, resources);
}

inline TransitionResult advance(Session &session, Operation operation, const LifecycleEvidence &evidence,
                                const ResourceBook &resources) {
    if (operation == Operation::BeginQuiesce) {
        if (!canPerform(session, operation, resources)) return result(session, false, Failure::WrongState, resources);
        session.state = State::Quiescing;
        return result(session, true, Failure::None, resources);
    }
    if (operation == Operation::FinishQuiesce)
        return finishQuiesce(session, evidence, resources);
    if (!canPerform(session, operation, resources)) {
        if (session.state == expectedState(operation))
            return fail(session, Failure::MissingResource, resources.unknownMask() == 0, resources);
        return result(session, false, Failure::WrongState, resources);
    }
    if (evidence.observation == Observation::Unsupported)
        return fail(session, Failure::UnsupportedHardware, false, resources);
    if (evidence.observation == Observation::FailedKnown)
        return fail(session, Failure::HardwareFailure, true, resources);
    if (evidence.observation == Observation::FailedUnknown || evidence.observation == Observation::NoEvidence)
        return fail(session, Failure::HardwareStateUnknown, false, resources);

    Failure invalid = Failure::MissingEvidence;
    bool valid = true;
    switch (operation) {
        case Operation::ResourcesOwned:
            valid = resources.ownsMask(InitialResourceMask);
            break;
        case Operation::PreparePanelPower:
            valid = evidence.panelPowerPrepared;
            break;
        case Operation::ConfirmPanelPower:
            valid = resources.owns(Resource::PanelVDD) && evidence.panelPowerOn;
            break;
        case Operation::ConfirmAuxReady:
            valid = resources.owns(Resource::AUXController) && evidence.panelPowerOn &&
                evidence.auxReady && evidence.aux == session.aux;
            break;
        case Operation::DiscoverSink:
            valid = evidence.dpcdCapabilitiesValidated;
            if (!valid) invalid = Failure::SinkCapabilitiesInvalid;
            break;
        case Operation::ConfigureLink:
            valid = evidence.dpcdCapabilitiesValidated && evidence.linkConfigurationValidated &&
                evidence.selectedLanes && evidence.selectedLanes <= evidence.sinkMaxLanes &&
                evidence.selectedRate && evidence.selectedRate <= evidence.sinkMaxRate;
            if (!valid) invalid = Failure::LinkConfigurationInvalid;
            break;
        case Operation::TrainLink:
            valid = evidence.linkTrainingValidated && evidence.auxTrainingTransactionsValidated &&
                evidence.selectedLanes == session.selectedLanes && evidence.selectedRate == session.selectedRate &&
                evidence.negotiatedLanes == evidence.selectedLanes &&
                evidence.negotiatedRate == evidence.selectedRate && evidence.negotiatedLanes &&
                evidence.negotiatedRate;
            if (!valid) invalid = Failure::LinkTrainingFailed;
            break;
        case Operation::BindPipeTranscoder:
            valid = resources.owns(Resource::Pipe) && resources.owns(Resource::Transcoder) &&
                evidence.pipeTranscoderValidated && evidence.ddi == session.ddi &&
                evidence.pipe < XELP::PipeCount && evidence.transcoder < XELP::PipeCount;
            if (!valid) invalid = Failure::PipeBindingInvalid;
            break;
        case Operation::HandoffFramebuffer:
            valid = resources.owns(Resource::FramebufferPath) && evidence.framebufferHandoffValidated &&
                evidence.donorObjectsPreserved && evidence.noConflictingDonorBinding &&
                evidence.handoffSynchronized && evidence.ddi == session.ddi &&
                evidence.pipe == session.pipe && evidence.transcoder == session.transcoder &&
                evidence.primaryPlane == 5U * session.pipe && evidence.framebufferIdentity &&
                evidence.pathIdentity && evidence.nativeSurfaceIdentity;
            if (!valid) invalid = Failure::FramebufferHandoffInvalid;
            break;
        case Operation::EnableScanout:
            valid = evidence.scanoutReadbackValidated && evidence.ddi == session.ddi &&
                evidence.pipe == session.pipe && evidence.transcoder == session.transcoder &&
                evidence.primaryPlane == 5U * session.pipe &&
                evidence.scanoutSurfaceIdentity == session.surfaceIdentity;
            if (!valid) invalid = Failure::ScanoutInvalid;
            break;
        case Operation::ApplyBacklight:
            valid = resources.owns(Resource::Backlight) && evidence.backlightValidated;
            if (!valid) invalid = Failure::BacklightInvalid;
            break;
        case Operation::BeginQuiesce:
            valid = false;
            break;
        case Operation::FinishQuiesce: valid = false; break;
    }
    if (!valid) return fail(session, invalid, false, resources);

    switch (operation) {
        case Operation::ResourcesOwned: session.state = State::Acquired; break;
        case Operation::PreparePanelPower: session.state = State::Prepared; break;
        case Operation::ConfirmPanelPower: session.state = State::PanelPowered; break;
        case Operation::ConfirmAuxReady: session.state = State::AuxReady; break;
        case Operation::DiscoverSink: session.state = State::SinkReady; break;
        case Operation::ConfigureLink:
            session.selectedLanes = evidence.selectedLanes;
            session.selectedRate = evidence.selectedRate;
            session.state = State::LinkConfigured;
            break;
        case Operation::TrainLink: session.state = State::LinkReady; break;
        case Operation::BindPipeTranscoder:
            session.pipe = evidence.pipe;
            session.transcoder = evidence.transcoder;
            session.state = State::PipeBound;
            break;
        case Operation::HandoffFramebuffer:
            session.framebufferIdentity = evidence.framebufferIdentity;
            session.pathIdentity = evidence.pathIdentity;
            session.surfaceIdentity = evidence.nativeSurfaceIdentity;
            session.state = State::FramebufferReady;
            break;
        case Operation::EnableScanout: session.state = State::ScanoutReady; break;
        case Operation::ApplyBacklight: session.state = State::Active; break;
        case Operation::BeginQuiesce:
        case Operation::FinishQuiesce:
            break;
    }
    return result(session, true, Failure::None, resources);
}

inline TransitionResult finishQuiesce(Session &session, const LifecycleEvidence &evidence,
                                      const ResourceBook &resources) {
    if (session.state != State::Quiescing) return result(session, false, Failure::WrongState, resources);
    if (resources.ownedMask() || resources.unknownMask() || !evidence.hardwareQuiescent)
        return fail(session, Failure::CleanupIncomplete, false, resources);
    session.state = State::Unbound;
    session.failure = Failure::None;
    session.hardwareStateKnown = true;
    session.ddi = DDI::Unknown;
    session.aux = AUX::Unknown;
    session.phy = 0xFF;
    session.pipe = 0xFF;
    session.transcoder = 0xFF;
    session.selectedLanes = 0;
    session.selectedRate = 0;
    session.framebufferIdentity = 0;
    session.pathIdentity = 0;
    session.surfaceIdentity = 0;
    return result(session, true, Failure::None, resources);
}

inline bool retrySafe(const Session &session, const ResourceBook &resources) {
    return session.state == State::Failed && session.hardwareStateKnown &&
        resources.ownedMask() == 0 && resources.allFree();
}

inline bool resetForRetry(Session &session, const ResourceBook &resources) {
    if (!retrySafe(session, resources)) return false;
    session.state = State::Unbound;
    session.failure = Failure::None;
    session.hardwareStateKnown = true;
    session.ddi = DDI::Unknown;
    session.aux = AUX::Unknown;
    session.phy = 0xFF;
    session.pipe = 0xFF;
    session.transcoder = 0xFF;
    session.selectedLanes = 0;
    session.selectedRate = 0;
    session.framebufferIdentity = 0;
    session.pathIdentity = 0;
    session.surfaceIdentity = 0;
    return true;
}

// Operation codes are deliberately explicit. Implementations have no default
// success path; a missing or unsupported observation must block progression.
enum class AdapterOperation : uint8_t {
    ObserveAuthorizedState,
    AcquireResource,
    PreparePanelPower,
    SetPanelPower,
    InitializeAUX,
    ReadSinkCapabilities,
    ConfigureLink,
    TrainLink,
    BindPipeTranscoder,
    HandoffFramebuffer,
    EnableScanout,
    ApplyBacklight,
    ReleaseResource
};

struct AdapterResult {
    Observation observation {Observation::NoEvidence};
    LifecycleEvidence evidence;
};

class HardwareAdapter {
public:
    virtual ~HardwareAdapter() = default;
    virtual AdapterResult execute(AdapterOperation operation, Resource resource) = 0;
};

} // namespace TGLEDP
#endif
