// Partial owner-capture boundary for Tiger Lake eDP evidence.
// Production remains unavailable until a reviewed native owner callsite can
// mint this context while holding its real synchronization primitive.
#ifndef KERN_TGL_EDP_OWNER_CAPTURE_HPP
#define KERN_TGL_EDP_OWNER_CAPTURE_HPP

#include <stddef.h>
#include <stdint.h>

#include "kern_tgl_edp_native_evidence.hpp"
#include "kern_tgl_fb_binding.hpp"

namespace TGLEDPOwnerCapture {

enum class Status : uint8_t {
    Unavailable,
    MissingOwnerContext,
    SynchronizationMismatch,
    NativeABIMismatch,
    InvalidNativeContext,
    StaleGeneration,
    MissingObject,
    ObjectTooSmall,
    AssociationMismatch,
    UnknownPhysicalDDI,
    CapturedPartial
};

enum class InvalidationEvent : uint8_t {
    PortCreated,
    PortDestroyed,
    ConnectorReconfigured,
    FramebufferPathWithdrawn,
    NativeObjectReplaced,
    Sleep,
    Wake,
    GPUReset,
    PowerStateTransition,
    DonorReinitialized
};

// This value contains only copied scalar observations. It carries no object
// pointers, resource ownership claims, AUX identity, or P004 authorization.
struct Result {
    Status status {Status::Unavailable};
    TGLEDPNative::ObservationSource source {TGLEDPNative::ObservationSource::Unknown};
    TGLEDP::DDI ddi {TGLEDP::DDI::Unknown};
    TGLEDP::AUX aux {TGLEDP::AUX::Unknown};
    uint32_t framebufferIndex {UINT32_MAX};
    uint32_t pipe {UINT32_MAX};
    uint32_t primaryPlane {UINT32_MAX};
    uint64_t generation {};
    bool ownerContextValid {};
    bool ownerSynchronizationEstablished {};
    bool nativeObjectIdentityVerified {};
    bool objectBoundsVerified {};
    bool physicalDDIVerified {};
    bool nativeBindingVerified {};
    bool generationCurrent {};
    bool snapshotComplete {};
    bool productionAuthorizationPossible {};
#if defined(TGLEDP_OWNER_CAPTURE_TESTING)
    bool testOwnerContextValid {};
    bool testSynchronizationContractMatched {};
    bool testObjectBoundsVerified {};
    bool testBindingAssociationMatched {};
    bool testPhysicalDDIValueSupported {};
    bool testGenerationConsistent {};
#endif
};

#if defined(TGLEDP_OWNER_CAPTURE_TESTING)
namespace Testing {

// Synthetic inputs exist only in CPU-test translation units. Their caller-
// supplied identities and synchronization values never enter production.
struct Input {
    TGLFBBinding::Objects objects {};
    XELP::NativePorts ports {};
    XELP::ProbeConfig probe {};
    size_t platformBytes {};
    uint64_t ownerScope {};
    uint64_t expectedOwnerScope {};
    uint64_t synchronizationScope {};
    uint64_t expectedSynchronizationScope {};
    uint64_t generationStart {};
    uint64_t generationEnd {};
    uint64_t expectedGeneration {};
    // A submit function is deliberately not an AUX channel/owner identity.
    uintptr_t resolvedAuxSubmitFunction {};
};

class Authority;
} // namespace Testing
#endif

class OwnerContext {
    friend class OwnerCapture;
#if defined(TGLEDP_OWNER_CAPTURE_TESTING)
    friend class Testing::Authority;
#endif
#if defined(TGLEDP_OWNER_CAPTURE_TESTING)
    TGLFBBinding::Objects objects_ {};
    XELP::NativePorts ports_ {};
    XELP::ProbeConfig probe_ {};
    size_t platformBytes_ {};
    uint64_t ownerScope_ {};
    uint64_t expectedOwnerScope_ {};
    uint64_t synchronizationScope_ {};
    uint64_t expectedSynchronizationScope_ {};
    uint64_t generationStart_ {};
    uint64_t generationEnd_ {};
    uint64_t expectedGeneration_ {};
    uintptr_t resolvedAuxSubmitFunction_ {};

    explicit OwnerContext(const Testing::Input &input) :
        objects_(input.objects), ports_(input.ports), probe_(input.probe),
        platformBytes_(input.platformBytes), ownerScope_(input.ownerScope),
        expectedOwnerScope_(input.expectedOwnerScope),
        synchronizationScope_(input.synchronizationScope),
        expectedSynchronizationScope_(input.expectedSynchronizationScope),
        generationStart_(input.generationStart), generationEnd_(input.generationEnd),
        expectedGeneration_(input.expectedGeneration),
        resolvedAuxSubmitFunction_(input.resolvedAuxSubmitFunction) {}
#endif
    OwnerContext() = delete;

public:
    OwnerContext(const OwnerContext &) = default;
    OwnerContext &operator=(const OwnerContext &) = default;
};

// Persistent snapshot tokens compare only against an owner-supplied scope and
// generation. Invalidation never invents or increments a native generation.
class SnapshotLease {
#if defined(TGLEDP_OWNER_CAPTURE_TESTING)
    friend class Testing::Authority;
#endif
    uint64_t ownerScope_ {};
    uint64_t generation_ {};
    bool valid_ {};

    SnapshotLease(uint64_t ownerScope, uint64_t generation) :
        ownerScope_(ownerScope), generation_(generation),
        valid_(ownerScope != 0 && generation != 0) {}

public:
    bool current(uint64_t ownerScope, uint64_t generation) const {
        return valid_ && ownerScope != 0 && generation != 0 &&
            ownerScope_ == ownerScope && generation_ == generation;
    }

    void invalidate(InvalidationEvent) { valid_ = false; }
};

class OwnerCapture {
public:
    // No reviewed production owner invocation exists on this baseline. This
    // entrypoint performs no pointer traversal, locking, MMIO, or power call.
    static Result captureProduction() {
        Result result;
        result.status = Status::Unavailable;
        return result;
    }

#if defined(TGLEDP_OWNER_CAPTURE_TESTING)
    // Exercises the bounded scalar-copy rules with synthetic memory only.
    // The result is permanently labelled SyntheticFixture and incomplete.
    static Result captureForTest(const OwnerContext &context) {
        Result result;
        const auto &owner = context;
        if (!owner.ownerScope_ || !owner.expectedOwnerScope_ ||
            owner.ownerScope_ != owner.expectedOwnerScope_) {
            result.status = Status::MissingOwnerContext;
            return result;
        }
        if (owner.probe_.abi != TGLEDP::RequiredNativeProbeABI ||
            owner.probe_.bytes != sizeof(XELP::ProbeConfig)) {
            result.status = Status::NativeABIMismatch;
            return result;
        }
        if (!owner.probe_.valid()) {
            result.status = Status::InvalidNativeContext;
            return result;
        }
        result.testOwnerContextValid = true;

        if (!owner.synchronizationScope_ || !owner.expectedSynchronizationScope_ ||
            owner.synchronizationScope_ != owner.expectedSynchronizationScope_) {
            result.status = Status::SynchronizationMismatch;
            return result;
        }
        result.testSynchronizationContractMatched = true;

        if (!owner.generationStart_ || owner.generationStart_ != owner.generationEnd_ ||
            owner.generationEnd_ != owner.expectedGeneration_) {
            result.status = Status::StaleGeneration;
            return result;
        }
        result.generation = owner.generationEnd_;
        result.testGenerationConsistent = true;

        constexpr size_t minimumPlatformBytes = 0x20 + 24 * XELP::PortCount;
        if (owner.platformBytes_ < minimumPlatformBytes ||
            owner.objects_.controller.bytes < 0x1C20 ||
            owner.objects_.framebuffer.bytes < TGLEDPNative::NativeFramebufferMinimumBytes ||
            owner.objects_.path.bytes < TGLEDPNative::NativePathMinimumBytes ||
            owner.objects_.plane.bytes < TGLEDPNative::NativePlaneMinimumBytes ||
            owner.objects_.port.bytes < TGLEDPNative::NativePortRecordMinimumBytes) {
            result.status = Status::ObjectTooSmall;
            return result;
        }
        if (!owner.ports_.valid() || !owner.objects_.controller.pointer ||
            !owner.objects_.framebuffer.pointer || !owner.objects_.path.pointer ||
            !owner.objects_.plane.pointer || !owner.objects_.port.pointer ||
            !owner.objects_.accelerator) {
            result.status = Status::MissingObject;
            return result;
        }
        result.testObjectBoundsVerified = true;

        const auto rawDDI = Display13FBMemory::field<uint32_t>(owner.objects_.port.pointer, 0x120);
        if (rawDDI > static_cast<uint32_t>(TGLEDP::DDI::I) ||
            !TGLEDPNative::supportedDDI(static_cast<TGLEDP::DDI>(rawDDI))) {
            result.status = Status::UnknownPhysicalDDI;
            return result;
        }
        result.testPhysicalDDIValueSupported = true;

        const auto readout = TGLFBBinding::inspect(owner.objects_, owner.ports_);
        if (readout.status != TGLFBBinding::Status::Complete) {
            result.status = readout.status == TGLFBBinding::Status::Unavailable ?
                Status::MissingObject : Status::AssociationMismatch;
            return result;
        }
        result.testBindingAssociationMatched = true;
        result.ddi = static_cast<TGLEDP::DDI>(readout.ddi);
        result.framebufferIndex = readout.framebuffer;
        result.pipe = readout.pipe;
        result.primaryPlane = readout.plane;
        result.source = TGLEDPNative::ObservationSource::SyntheticFixture;
        result.snapshotComplete = false; // no inventory, independent AUX or owner set
        result.productionAuthorizationPossible = false;
        result.status = Status::CapturedPartial;
        (void)owner.resolvedAuxSubmitFunction_; // function identity is not AUX provenance
        return result;
    }
#endif
};

#if defined(TGLEDP_OWNER_CAPTURE_TESTING)
namespace Testing {
class Authority {
public:
    static OwnerContext makeContext(const Input &input) { return OwnerContext(input); }
    static SnapshotLease makeSnapshotLease(uint64_t ownerScope, uint64_t generation) {
        return SnapshotLease(ownerScope, generation);
    }
};
} // namespace Testing
#endif

} // namespace TGLEDPOwnerCapture

#endif
