#define TGLEDP_OWNER_CAPTURE_TESTING
#include "kern_tgl_edp_owner_capture.hpp"

#include <cassert>
#include <cstdio>
#include <type_traits>

using namespace TGLEDPOwnerCapture;

static unsigned checks;
#define CHECK(expression) do { assert(expression); ++checks; } while (0)

int main() {
    auto lease = Testing::Authority::makeSnapshotLease(41, 7);
    CHECK(lease.current(41, 7));
    CHECK(!lease.current(42, 7)); // cross-owner reuse
    CHECK(!lease.current(41, 8)); // owner generation changed

    // A replacement at the same address must receive a new owner scope or
    // generation. Pointer equality is not used as a durable snapshot key.
    const auto replacement = Testing::Authority::makeSnapshotLease(42, 8);
    CHECK(!lease.current(42, 8));
    CHECK(replacement.current(42, 8));

    const InvalidationEvent events[] {
        InvalidationEvent::PortCreated,
        InvalidationEvent::PortDestroyed,
        InvalidationEvent::ConnectorReconfigured,
        InvalidationEvent::FramebufferPathWithdrawn,
        InvalidationEvent::NativeObjectReplaced,
        InvalidationEvent::Sleep,
        InvalidationEvent::Wake,
        InvalidationEvent::GPUReset,
        InvalidationEvent::PowerStateTransition,
        InvalidationEvent::DonorReinitialized
    };
    for (const auto event : events) {
        auto current = Testing::Authority::makeSnapshotLease(41, 7);
        current.invalidate(event);
        CHECK(!current.current(41, 7));
    }

    static_assert(!std::is_default_constructible<OwnerContext>::value,
        "production callers cannot fabricate an owner context");

    std::printf("tgl_edp_capture_invalidation: %u checks passed\n", checks);
}
