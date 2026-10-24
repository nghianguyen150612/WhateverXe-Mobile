#include "kern_tgl_edp_owner_capture.hpp"

#include <cassert>
#include <cstdio>
#include <type_traits>

#ifdef TGLEDP_OWNER_CAPTURE_TESTING
#error "test authority must not be enabled in the production-entrypoint check"
#endif

static_assert(!std::is_default_constructible<TGLEDPOwnerCapture::OwnerContext>::value,
    "production callers cannot manufacture an owner context");

int main() {
    const auto result = TGLEDPOwnerCapture::OwnerCapture::captureProduction();
    assert(result.status == TGLEDPOwnerCapture::Status::Unavailable);
    assert(result.source == TGLEDPNative::ObservationSource::Unknown);
    assert(result.aux == TGLEDP::AUX::Unknown);
    assert(!result.ownerContextValid);
    assert(!result.ownerSynchronizationEstablished);
    assert(!result.nativeObjectIdentityVerified);
    assert(!result.objectBoundsVerified);
    assert(!result.physicalDDIVerified);
    assert(!result.nativeBindingVerified);
    assert(!result.generationCurrent);
    assert(!result.snapshotComplete);
    assert(!result.productionAuthorizationPossible);
    std::puts("tgl_edp_owner_capture_production: unavailable entrypoint confirmed");
}
