"""
    Flask context-based caching logic
"""
from typing import Any
from uuid import UUID

from werkzeug.local import LocalProxy


def _to_uuid(eid):
    if isinstance(eid, UUID):
        return eid
    else:
        return UUID(eid)


def _obj_uuid(obj):
    return _to_uuid(obj["id"])


class EntityCache:
    def __init__(self):
        self.idcache = {}

    def get(self, eid) -> Any:
        try:
            uid = _to_uuid(eid)
            return self.idcache.get(uid, None)
        except Exception:
            return None

    def __contains__(self, eid):
        return _to_uuid(eid) in self.idcache

    def update(self, eid, obj):
        self.idcache[_to_uuid(eid)] = obj

    def put(self, obj):
        self.idcache[_obj_uuid(obj)] = obj

    def __delitem__(self, eid):
        self.delete(eid)

    def delete(self, eid):
        try:
            del self.idcache[_to_uuid(eid)]
        except KeyError:
            pass

    def drop(self, obj):
        del self[_obj_uuid(obj)]


def get_entity_cache():
    from flask import g

    if "entity_cache" not in g:
        g.entity_cache = EntityCache()
    return g.entity_cache


entity_cache = LocalProxy(get_entity_cache)
