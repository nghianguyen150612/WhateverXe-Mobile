#define TGLEDP_OWNER_CAPTURE_TESTING
#include "kern_tgl_edp_owner_capture.hpp"

#include <array>
#include <cassert>
#include <cstdio>
#include <cstring>

using namespace TGLEDP;
using namespace TGLEDPNative;
using namespace TGLEDPOwnerCapture;

static unsigned checks;
#define CHECK(expression) do { assert(expression); ++checks; } while (0)

template <typename T, size_t N>
static void put(std::array<uint8_t, N> &bytes, size_t offset, T value) {
    std::memcpy(bytes.data() + offset, &value, sizeof(value));
}

struct Fixture {
    alignas(8) std::array<uint8_t, 0x1C20> controller {};
    alignas(8) std::array<uint8_t, 0x4B90> framebuffer {};
    alignas(8) std::array<uint8_t, 0x3730> path {};
    alignas(8) std::array<uint8_t, 0x1C8> plane {};
    alignas(8) std::array<uint8_t, 0x580> port {};
    alignas(8) std::array<uint8_t, 0x1C0> platform {};
    uint64_t accessMarker {};
    uint64_t ownerMarker {};

    Testing::Input input(uint32_t ddi = static_cast<uint32_t>(DDI::A)) {
        const auto controllerPointer = controller.data();
        const auto framebufferPointer = framebuffer.data();
        const auto pathPointer = path.data();
        const auto planePointer = plane.data();
        const auto portPointer = port.data();
        const auto platformPointer = platform.data();
        const auto accessPointer = reinterpret_cast<void *>(&accessMarker);
        const auto ownerPointer = reinterpret_cast<uintptr_t>(&ownerMarker);
        const auto configPointer = platformPointer + 0x20 + 24 * ddi;

        put(controller, 0xC0, ownerPointer);
        put(controller, 0xC40, accessPointer);
        put(controller, 0xD5C, uint32_t {1});
        put(controller, 0xD60, framebufferPointer);
        put(controller, 0xF58, planePointer);

        put(framebuffer, 0x1D0, controllerPointer);
        put(framebuffer, 0x1DC, uint32_t {0});
        put(framebuffer, 0x4A40, accessPointer);

        put(path, 0x32B0, framebufferPointer);
        put(path, 0x32C8, planePointer);
        put(path, 0x3640, uint32_t {0});
        put(path, 0x3648, portPointer);

        put(plane, 0x68, framebufferPointer);
        put(plane, 0x70, pathPointer);
        put(plane, 0x78, uint32_t {0});
        put(plane, 0x7C, uint32_t {0});
        put(plane, 0x80, uint32_t {0});
        put(plane, 0x90, accessPointer);
        put(plane, 0x98, uint32_t {0x70180});
        put(plane, 0xA0, uint32_t {0x7027C});
        put(plane, 0xA4, uint32_t {0x7017C});

        put(port, 0x120, ddi);
        put(port, 0x548, configPointer);
        put(platform, 0x20 + 24 * ddi, ddi);

        Testing::Input result;
        result.objects = {
            {controllerPointer, controller.size()},
            {framebufferPointer, framebuffer.size()},
            {pathPointer, path.size()},
            {planePointer, plane.size()},
            {portPointer, port.size()},
            ownerPointer
        };
        result.ports = {platformPointer, 1U << ddi};
        result.probe.profile = XELP::identify(0x9A498086U, 0, 0x9A498086U);
        result.probe.comboBackend = 7;
        result.platformBytes = platform.size();
        result.ownerScope = 11;
        result.expectedOwnerScope = 11;
        result.synchronizationScope = 19;
        result.expectedSynchronizationScope = 19;
        result.generationStart = 23;
        result.generationEnd = 23;
        result.expectedGeneration = 23;
        return result;
    }
};

static Result capture(const Testing::Input &input) {
    return OwnerCapture::captureForTest(Testing::Authority::makeContext(input));
}

int main() {
    Fixture fixture;
    const auto input = fixture.input();
    const auto captured = capture(input);
    CHECK(captured.status == Status::CapturedPartial);
    CHECK(captured.source == ObservationSource::SyntheticFixture);
    CHECK(captured.testOwnerContextValid);
    CHECK(captured.testSynchronizationContractMatched);
    CHECK(captured.testObjectBoundsVerified);
    CHECK(captured.testPhysicalDDIValueSupported);
    CHECK(captured.testBindingAssociationMatched);
    CHECK(captured.testGenerationConsistent && captured.generation == 23);
    CHECK(!captured.ownerContextValid);
    CHECK(!captured.ownerSynchronizationEstablished);
    CHECK(!captured.nativeObjectIdentityVerified);
    CHECK(!captured.objectBoundsVerified);
    CHECK(!captured.physicalDDIVerified);
    CHECK(!captured.nativeBindingVerified);
    CHECK(!captured.generationCurrent);
    CHECK(captured.ddi == DDI::A);
    CHECK(captured.framebufferIndex == 0 && captured.pipe == 0 && captured.primaryPlane == 0);
    CHECK(captured.aux == AUX::Unknown);
    CHECK(!captured.snapshotComplete);
    CHECK(!captured.productionAuthorizationPossible);

    auto noOwner = input;
    noOwner.ownerScope = 0;
    CHECK(capture(noOwner).status == Status::MissingOwnerContext);

    auto fakeLock = input;
    ++fakeLock.synchronizationScope;
    CHECK(capture(fakeLock).status == Status::SynchronizationMismatch);

    auto wrongABI = input;
    wrongABI.probe.abi = 2;
    CHECK(capture(wrongABI).status == Status::NativeABIMismatch);

    auto mismatchedController = input;
    put(fixture.framebuffer, 0x1D0, static_cast<void *>(&fixture.ownerMarker));
    mismatchedController.objects.framebuffer.pointer = fixture.framebuffer.data();
    CHECK(capture(mismatchedController).status == Status::AssociationMismatch);
    put(fixture.framebuffer, 0x1D0, fixture.controller.data());

    auto nullObject = input;
    nullObject.objects.path.pointer = nullptr;
    CHECK(capture(nullObject).status == Status::MissingObject);

    auto shortObject = input;
    shortObject.objects.path.bytes = NativePathMinimumBytes - 1;
    CHECK(capture(shortObject).status == Status::ObjectTooSmall);

    auto badParent = input;
    put(fixture.path, 0x32B0, static_cast<void *>(&fixture.ownerMarker));
    CHECK(capture(badParent).status == Status::AssociationMismatch);
    put(fixture.path, 0x32B0, fixture.framebuffer.data());

    const auto unknownDDI = capture(fixture.input(static_cast<uint32_t>(DDI::C)));
    CHECK(unknownDDI.status == Status::UnknownPhysicalDDI);

    // The framebuffer slot remains index zero while the platform record proves
    // physical DDI D. They are independent scalar facts.
    const auto ddiD = capture(fixture.input(static_cast<uint32_t>(DDI::D)));
    CHECK(ddiD.status == Status::CapturedPartial);
    CHECK(ddiD.framebufferIndex == 0);
    CHECK(ddiD.ddi == DDI::D);

    auto functionIsNotAUX = fixture.input();
    functionIsNotAUX.resolvedAuxSubmitFunction = 0xFFFF000000001000ULL;
    const auto noAux = capture(functionIsNotAUX);
    CHECK(noAux.aux == AUX::Unknown);
    CHECK(!noAux.snapshotComplete);

    auto changedGeneration = fixture.input();
    ++changedGeneration.generationEnd;
    const auto stale = capture(changedGeneration);
    CHECK(stale.status == Status::StaleGeneration);
    CHECK(!stale.generationCurrent);
    CHECK(!stale.testGenerationConsistent);

    const auto repeated = capture(fixture.input());
    CHECK(repeated.status == captured.status);
    CHECK(repeated.generation == captured.generation);
    CHECK(repeated.ddi == captured.ddi);
    CHECK(repeated.framebufferIndex == captured.framebufferIndex);

    std::printf("tgl_edp_owner_capture: %u checks passed\n", checks);
}
