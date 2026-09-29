"""Minimal in-memory stand-in for pymongo (only what this project uses)."""
import copy
import sys
import types
import uuid


class DuplicateKeyError(Exception):
    pass


class ReturnDocument:
    BEFORE = False
    AFTER = True


def install():
    pm = types.ModuleType("pymongo")
    errors = types.ModuleType("pymongo.errors")
    errors.DuplicateKeyError = DuplicateKeyError
    pm.errors = errors
    pm.ReturnDocument = ReturnDocument
    sys.modules["pymongo"] = pm
    sys.modules["pymongo.errors"] = errors


def _match(doc, query):
    for key, cond in query.items():
        if key == "$or":
            if not any(_match(doc, q) for q in cond):
                return False
            continue
        val = doc
        for part in key.split("."):          # dotted paths like "imap.enabled"
            val = val.get(part) if isinstance(val, dict) else None
        if isinstance(cond, dict) and any(k.startswith("$") for k in cond):
            for op, arg in cond.items():
                if op == "$lte" and not (val is not None and val <= arg): return False
                if op == "$lt" and not (val is not None and val < arg): return False
                if op == "$gte" and not (val is not None and val >= arg): return False
                if op == "$gt" and not (val is not None and val > arg): return False
                if op == "$in" and val not in arg: return False
        elif val != cond:
            return False
    return True


class Cursor:
    def __init__(self, docs):
        self.docs = docs

    def sort(self, key, direction=1):
        if isinstance(key, list):
            key, direction = key[0]
        self.docs.sort(key=lambda d: d.get(key), reverse=direction < 0)
        return self

    def limit(self, n):
        self.docs = self.docs[:n]
        return self

    def __iter__(self):
        return iter(copy.deepcopy(self.docs))


class Result:
    def __init__(self, n):
        self.modified_count = n


class Collection:
    def __init__(self):
        self.docs = []
        self.uniques = []  # (fields, partial_filter, sparse)

    def create_index(self, keys, unique=False, sparse=False, partialFilterExpression=None, **_):
        if unique:
            fields = [keys] if isinstance(keys, str) else [k for k, _d in keys]
            self.uniques.append((fields, partialFilterExpression, sparse))

    def _check_unique(self, doc, ignore=None):
        for fields, partial, sparse in self.uniques:
            if partial and not _match(doc, partial):
                continue
            if sparse and all(doc.get(f) is None for f in fields):
                continue
            sig = tuple(doc.get(f) for f in fields)
            for other in self.docs:
                if other is ignore:
                    continue
                if partial and not _match(other, partial):
                    continue
                if tuple(other.get(f) for f in fields) == sig:
                    raise DuplicateKeyError(f"duplicate on {fields}")

    def insert_one(self, doc):
        doc = copy.deepcopy(doc)
        doc.setdefault("_id", uuid.uuid4().hex)  # real MongoDB adds an _id automatically
        self._check_unique(doc)
        self.docs.append(doc)

    def find_one(self, query=None, sort=None):
        docs = [d for d in self.docs if _match(d, query or {})]
        if sort:
            docs.sort(key=lambda d: d.get(sort[0][0]), reverse=sort[0][1] < 0)
        return copy.deepcopy(docs[0]) if docs else None

    def find(self, query=None):
        return Cursor([d for d in self.docs if _match(d, query or {})])

    def count_documents(self, query):
        return len([d for d in self.docs if _match(d, query)])

    def _apply(self, doc, update):
        new = dict(doc)
        new.update(update.get("$set", {}))
        for k in update.get("$unset", {}):
            new.pop(k, None)
        self._check_unique(new, ignore=doc)
        doc.update(update.get("$set", {}))
        for k in update.get("$unset", {}):
            doc.pop(k, None)

    def delete_one(self, query):
        for i, d in enumerate(self.docs):
            if _match(d, query):
                del self.docs[i]
                return Result(1)
        return Result(0)

    def update_one(self, query, update):
        for d in self.docs:
            if _match(d, query):
                self._apply(d, update)
                return Result(1)
        return Result(0)

    def update_many(self, query, update):
        n = 0
        for d in self.docs:
            if _match(d, query):
                self._apply(d, update)
                n += 1
        return Result(n)

    def find_one_and_update(self, query, update, sort=None, return_document=False):
        docs = [d for d in self.docs if _match(d, query)]
        if sort:
            docs.sort(key=lambda d: d.get(sort[0][0]), reverse=sort[0][1] < 0)
        if not docs:
            return None
        before = copy.deepcopy(docs[0])
        self._apply(docs[0], update)
        return copy.deepcopy(docs[0]) if return_document else before


class FakeDB:
    def __init__(self):
        self._cols = {}

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        return self._cols.setdefault(name, Collection())
