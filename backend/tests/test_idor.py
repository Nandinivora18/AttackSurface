"""
IDOR / BOLA Multi-User Isolation Security Tests
"""

import pytest
import uuid


def test_idor_user_isolation_concept():
    user_a_id = uuid.uuid4()
    user_b_id = uuid.uuid4()

    resource_owner_id = user_a_id

    # Simulated BOLA check in router query
    def access_resource(request_user_id, resource_owner_id):
        if request_user_id != resource_owner_id:
            return 403, "Access denied to requested resource."
        return 200, "Resource data"

    # User A accessing User A's resource -> 200
    status, _ = access_resource(user_a_id, resource_owner_id)
    assert status == 200

    # User B attempting to access User A's resource -> 403 Forbidden
    status, err = access_resource(user_b_id, resource_owner_id)
    assert status == 403
    assert err == "Access denied to requested resource."
