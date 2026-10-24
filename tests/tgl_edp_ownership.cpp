#define TGLEDP_CLASSIFY_TESTING
#include "tgl_edp_native_fixture.hpp"

#include <cassert>
#include <cstdio>

using namespace TGLEDP;
using namespace TGLEDPNative;

static unsigned checks;
#define CHECK(expression) do { assert(expression); ++checks; } while (0)

static ValidationResult evaluate(const SnapshotCandidate &candidate, uint64_t generation = 7) {
    return NativeEvidenceAdapter::validate(candidate, generation);
}

static void expect(const SnapshotCandidate &candidate, Reason reason, uint64_t generation = 7) {
    const auto result = evaluate(candidate, generation);
    CHECK(result.consistency == Consistency::Inconsistent);
    CHECK(result.reason == reason);
}

static ResourceObservation *resource(SnapshotCandidate &candidate, ResourceKind kind,
                                     uint8_t index, PHYKind phyKind = PHYKind::Unknown) {
    for (size_t i = 0; i < candidate.resourceCount; ++i) {
        auto &entry = candidate.resources[i];
        if (entry.kind == kind && entry.index == index && entry.phyKind == phyKind) return &entry;
    }
    return nullptr;
}

int main() {
    auto candidate = TGLNativeFixture::complete();
    TGLNativeFixture::useNativeSourceClaims(candidate);
    auto accepted = evaluate(candidate);
    CHECK(accepted.consistency == Consistency::Consistent);
    CHECK(accepted.inventoryComplete);
    CHECK(accepted.topologyConsistent);

    auto duplicateDDI = candidate;
    duplicateDDI.ports[1].ddi = DDI::A;
    expect(duplicateDDI, Reason::DuplicateDDI);

    auto duplicateAUX = candidate;
    duplicateAUX.ports[1].aux = AUX::A;
    expect(duplicateAUX, Reason::DuplicateAUX);

    auto duplicatePHY = candidate;
    duplicatePHY.ports[1].phy = 0;
    expect(duplicatePHY, Reason::DuplicatePHY);

    auto externalOwnsInternalDDI = candidate;
    auto ddiA = resource(externalOwnsInternalDDI, ResourceKind::DDI,
        static_cast<uint8_t>(DDI::A));
    CHECK(ddiA != nullptr);
    ddiA->owner = ResourceOwner::ExternalDisplay;
    ddiA->ownerIdentity = 0x777;
    auto *phyAForCollision = resource(externalOwnsInternalDDI, ResourceKind::PHY, 0, PHYKind::Combo);
    auto *auxAForCollision = resource(externalOwnsInternalDDI, ResourceKind::AUX,
        static_cast<uint8_t>(AUX::A));
    CHECK(phyAForCollision != nullptr && auxAForCollision != nullptr);
    phyAForCollision->owner = ResourceOwner::ExternalDisplay;
    phyAForCollision->ownerIdentity = 0x777;
    auxAForCollision->owner = ResourceOwner::ExternalDisplay;
    auxAForCollision->ownerIdentity = 0x777;
    expect(externalOwnsInternalDDI, Reason::OwnershipConflict);

    auto conflictingExternalClaim = candidate;
    conflictingExternalClaim.ports[1].ddi = DDI::A;
    conflictingExternalClaim.ports[1].connector = Connector::ExternalDP;
    conflictingExternalClaim.ports[1].role = Role::ExternalDisplay;
    expect(conflictingExternalClaim, Reason::DuplicateDDI);

    auto partial = candidate;
    --partial.resourceCount;
    expect(partial, Reason::InventoryIncomplete);

    auto unknownOwner = candidate;
    auto auxA = resource(unknownOwner, ResourceKind::AUX, static_cast<uint8_t>(AUX::A));
    CHECK(auxA != nullptr);
    auxA->owner = ResourceOwner::Unknown;
    auxA->ownerIdentity = 0;
    expect(unknownOwner, Reason::OwnershipUnknown);

    auto duplicateResource = candidate;
    duplicateResource.resources[duplicateResource.resourceCount++] = duplicateResource.resources[0];
    expect(duplicateResource, Reason::DuplicateResource);

    auto changedDuringCapture = candidate;
    changedDuringCapture.generationAtEnd = 8;
    expect(changedDuringCapture, Reason::SnapshotChanged);

    auto mixedLocks = candidate;
    ++mixedLocks.ports[0].ownerLockIdentity;
    expect(mixedLocks, Reason::SynchronizationMismatch);

    // Reusing a previously consistent snapshot after sleep/wake fails against
    // the new owner generation, even though the copied records did not change.
    expect(candidate, Reason::StaleGeneration, 8);

    auto donorMismatch = candidate;
    auto phyA = resource(donorMismatch, ResourceKind::PHY, 0, PHYKind::Combo);
    CHECK(phyA != nullptr);
    phyA->owner = ResourceOwner::NativeDonor;
    phyA->ownerIdentity = 0x999;
    expect(donorMismatch, Reason::DonorBindingConflict);

    auto ownerConflict = candidate;
    phyA = resource(ownerConflict, ResourceKind::PHY, 0, PHYKind::Combo);
    CHECK(phyA != nullptr);
    phyA->owner = ResourceOwner::ExternalDisplay;
    phyA->ownerIdentity = 0x555;
    expect(ownerConflict, Reason::OwnershipConflict);

    auto internalTypeC = candidate;
    internalTypeC.ports[2].connector = Connector::InternalDP;
    internalTypeC.ports[2].role = Role::InternalPanel;
    internalTypeC.ports[2].panel = PanelPresence::Present;
    expect(internalTypeC, Reason::UnsupportedDDI);

    auto unsupportedDDIC = candidate;
    unsupportedDDIC.ports[0].ddi = DDI::C;
    expect(unsupportedDDIC, Reason::UnsupportedDDI);

    auto optionalPanelPower = candidate;
    auto &panelPower = optionalPanelPower.resources[optionalPanelPower.resourceCount++];
    panelPower.kind = ResourceKind::PanelPower;
    panelPower.index = 0;
    panelPower.owner = ResourceOwner::NativeDonor;
    panelPower.ownerIdentity = optionalPanelPower.nativeOwnerIdentity;
    panelPower.ownerLockIdentity = optionalPanelPower.nativeOwnerLockIdentity;
    panelPower.observationGeneration = 7;
    panelPower.source = ObservationSource::NativeOwnershipInventory;
    CHECK(evaluate(optionalPanelPower).consistency == Consistency::Consistent);

    // Native source labels alone remain claims. The P005 adapter does not
    // mint either of P004's opaque authorizations, even for a consistent set.
    const auto p004 = NativeEvidenceAdapter::toP004Snapshot(candidate);
    CHECK(!p004.complete);
    CHECK(!p004.authorization.authorizes(p004));
    CHECK(!p004.routes[0].authorization.authorizes(p004.routes[0]));
    CHECK(p004.routes[0].source == EvidenceSource::AuthorizedNativeReadout);
    CHECK(!p004.routes[0].evidenceValidated);
    CHECK(TGLEDP::qualifyConnector(TGLEDP::qualifyGPU(candidate.gpu), p004, 0).rejection ==
        Rejection::InventoryIncomplete);

    std::printf("tgl_edp_ownership: %u checks passed\n", checks);
}
