from functools import wraps

from flask import abort
from flask_login import current_user, login_required


ROLE_ORDER = {"Viewer": 0, "Security Analyst": 1, "Admin": 2}


def roles_required(*roles):
    def decorate(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if current_user.role not in roles:
                abort(403)
            return view(*args, **kwargs)

        return wrapped

    return decorate


def minimum_role(role):
    def decorate(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if ROLE_ORDER.get(current_user.role, -1) < ROLE_ORDER[role]:
                abort(403)
            return view(*args, **kwargs)

        return wrapped

    return decorate
