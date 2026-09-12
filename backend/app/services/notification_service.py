"""
Notification Service
Helper functions for creating in-app notifications from anywhere in the codebase.
"""
import uuid
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.misc import Notification
import logging

logger = logging.getLogger(__name__)


async def create_notification(
    db: AsyncSession,
    user_id: uuid.UUID,
    type: str,
    title: str,
    message: str | None = None,
    metadata: dict | None = None,
) -> Notification:
    """
    Create and persist a single in-app notification.

    Args:
        db: Active async DB session (caller is responsible for commit).
        user_id: The target user's UUID.
        type: Short notification type key (e.g. 'scan_complete', 'scan_failed').
        title: Short notification headline.
        message: Optional longer body text.
        metadata: Optional arbitrary JSON payload for the frontend.

    Returns:
        The new Notification ORM object (not yet committed).
    """
    notification = Notification(
        user_id=user_id,
        type=type,
        title=title,
        message=message,
        metadata_=metadata or {},
    )
    db.add(notification)
    logger.debug(f"Queued notification '{type}' for user {user_id}: {title}")
    return notification
