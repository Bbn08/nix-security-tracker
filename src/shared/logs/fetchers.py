from typing import cast

from django.contrib.auth.models import User
from django.db.models import (
    BigIntegerField,
    Case,
    OuterRef,
    Q,
    Subquery,
    Value,
    When,
)
from django.db.models.functions import Cast, Coalesce
from django.forms.models import model_to_dict
from pghistory.models import EventQuerySet

from shared.logs.events import (
    Maintainer,
    RawEventType,
    RawMaintainerEvent,
    RawPackageEvent,
    RawStatusEvent,
)
from shared.models import (
    CVEDerivationClusterProposalStatusEvent,  # type: ignore
    MaintainersEditEvent,  # type: ignore
    PackageEditEvent,  # type: ignore
)


def _annotate_username(query: EventQuerySet) -> EventQuerySet:
    """Add username annotation to a query."""
    return query.annotate(
        username=Coalesce(
            Case(
                When(Q(pgh_context__isnull=True), then=Value("ADMIN")),
                When(
                    Q(pgh_context__metadata__contains={"user": None}),
                    then=Value("ANONYMOUS"),
                ),
                default=Subquery(
                    User.objects.filter(
                        id=Cast(
                            OuterRef("pgh_context__metadata__user"),
                            BigIntegerField(),
                        )
                    ).values("username")[:1]
                ),
            ),
            Value("REDACTED"),
        )
    )


def fetch_suggestion_events_batch(
    suggestion_ids: list[int],
) -> dict[int, list[RawEventType]]:
    """Fetch all raw events for multiple suggestions in three batched queries."""
    result: dict[int, list[RawEventType]] = {sid: [] for sid in suggestion_ids}

    if not suggestion_ids:
        return result

    status_qs = _annotate_username(
        CVEDerivationClusterProposalStatusEvent.objects.select_related("pgh_context")
        .exclude(pgh_label="insert")
        .filter(pgh_obj_id__in=suggestion_ids)
    )
    for status_event in status_qs.iterator():
        result[status_event.pgh_obj_id].append(
            RawStatusEvent(
                suggestion_id=status_event.pgh_obj_id,
                timestamp=status_event.pgh_created_at,
                username=status_event.username,
                action=status_event.pgh_label,
                status_value=status_event.status,
            )
        )

    package_qs = _annotate_username(
        PackageEditEvent.objects.select_related("pgh_context").filter(
            suggestion_id__in=suggestion_ids
        )
    )
    for pkg_event in package_qs.iterator():
        result[pkg_event.suggestion_id].append(
            RawPackageEvent(
                suggestion_id=pkg_event.suggestion_id,
                timestamp=pkg_event.pgh_created_at,
                username=pkg_event.username,
                action=pkg_event.pgh_label,
                package_attribute=pkg_event.package_attribute,
            )
        )

    maintainer_qs = _annotate_username(
        MaintainersEditEvent.objects.select_related("pgh_context", "maintainer").filter(
            suggestion_id__in=suggestion_ids
        )
    )
    for m_event in maintainer_qs.iterator():
        result[m_event.suggestion_id].append(
            RawMaintainerEvent(
                suggestion_id=m_event.suggestion_id,
                timestamp=m_event.pgh_created_at,
                username=m_event.username,
                action=m_event.pgh_label,
                maintainer=cast(Maintainer, model_to_dict(m_event.maintainer)),
            )
        )

    return result


# TODO In the future we may add other fetchers, for instance fetch all events
# of a given user (for personal dashboard or admin panel) or all events
# globally (for admin)
def fetch_suggestion_events(suggestion_id: int) -> list[RawEventType]:
    """Fetch all raw events for a suggestion and return them sorted by timestamp."""
    all_events: list[RawEventType] = []

    # Fetch status events
    status_qs = _annotate_username(
        CVEDerivationClusterProposalStatusEvent.objects.select_related(
            "pgh_context",
        )
        .exclude(pgh_label="insert")
        .filter(pgh_obj_id=suggestion_id)
    )

    for status_event in status_qs.iterator():
        all_events.append(
            RawStatusEvent(
                suggestion_id=status_event.pgh_obj_id,
                timestamp=status_event.pgh_created_at,
                username=status_event.username,
                action=status_event.pgh_label,
                status_value=status_event.status,
            )
        )

    # Fetch package events
    package_edit_qs = _annotate_username(
        PackageEditEvent.objects.select_related(
            "pgh_context",
        ).filter(suggestion_id=suggestion_id)
    )

    for package_edit_event in package_edit_qs.iterator():
        all_events.append(
            RawPackageEvent(
                suggestion_id=package_edit_event.suggestion_id,
                timestamp=package_edit_event.pgh_created_at,
                username=package_edit_event.username,
                action=package_edit_event.pgh_label,
                package_attribute=package_edit_event.package_attribute,
            )
        )

    # Fetch maintainer events
    maintainer_qs = _annotate_username(
        MaintainersEditEvent.objects.select_related("pgh_context", "maintainer").filter(
            suggestion_id=suggestion_id
        )
    )

    for maintainer_event in maintainer_qs.iterator():
        all_events.append(
            RawMaintainerEvent(
                suggestion_id=maintainer_event.suggestion_id,
                timestamp=maintainer_event.pgh_created_at,
                username=maintainer_event.username,
                action=maintainer_event.pgh_label,
                maintainer=cast(Maintainer, model_to_dict(maintainer_event.maintainer)),
            )
        )

    return all_events
