"""Editable scope declarations and their effective grants, saved as one versioned document."""
from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import re
import uuid

from .models import DiscoveryScope
from .ranges import LIMITS, _merge, _parse, _subtract, preview_ranges

FIELDS = ("id", "name", "include", "exclude", "allow_public", "scanner_target", "acknowledge_normalization")
ID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")


class ScopeRevisionConflict(ValueError):
    """The declaration changed after the operator loaded or previewed it."""


def fingerprint(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()).hexdigest()


def editable(recipe: dict) -> dict:
    return {key: copy.deepcopy(recipe[key]) for key in FIELDS}


def effective_scopes(recipes: list[dict]) -> list[dict]:
    result = []
    seen = set()
    for recipe in recipes:
        for scope in recipe["scopes"]:
            key = (scope["cidr"], scope["allow_public"], scope["scanner_target"])
            if key not in seen:
                seen.add(key)
                result.append(copy.deepcopy(scope))
    return result


def legacy_recipe(scope: dict, index: int) -> dict:
    return {"id": f"legacy-{index}-{fingerprint(scope)[:16]}", "name": f"Legacy range {index + 1}",
            "include": None, "exclude": None, "allow_public": scope["allow_public"],
            "scanner_target": scope["scanner_target"], "acknowledge_normalization": False, "scopes": [scope]}


class ScopeRecipeStore:
    def __init__(self, ctx):
        self.ctx = ctx
        self.path = ctx.store.root / "discovery" / "scopes.json"

    def read(self) -> dict:
        raw = self.ctx.store.read_json(self.path, [])
        if isinstance(raw, list):
            scopes = []
            for item in raw:
                data = {"cidr": item} if isinstance(item, str) else dict(item)
                # An old record with no date must not acquire a fictional date on every read.
                data.setdefault("added_at", "")
                scopes.append(DiscoveryScope.from_dict(data).to_dict())
            return {"version": 1, "revision": fingerprint(raw),
                    "recipes": [legacy_recipe(scope, i) for i, scope in enumerate(scopes)]}
        if not isinstance(raw, dict) or raw.get("version") != 1:
            raise ValueError("unsupported discovery scope document; scope changes are blocked")
        return raw

    @staticmethod
    def view(state: dict) -> dict:
        return {"revision": state["revision"], "scopes": effective_scopes(state["recipes"]),
                "recipes": [{**editable(r), "networks": [s["cidr"] for s in r["scopes"]],
                             "original_expressions_known": r["include"] is not None} for r in state["recipes"]]}

    def snapshot(self) -> dict:
        return self.view(self.read())

    @staticmethod
    def check_revision(state: dict, revision: str) -> None:
        if not isinstance(revision, str) or revision != state["revision"]:
            raise ScopeRevisionConflict("Saved search recipes changed. Reload them and review a fresh preview before saving.")

    def prepare(self, recipes: list[dict], revision: str, state: dict) -> tuple[list[dict], dict]:
        self.check_revision(state, revision)
        if not isinstance(recipes, list) or len(recipes) > LIMITS["max_entries"]:
            raise ValueError("at most 128 recipes are allowed")
        old = {r["id"]: r for r in state["recipes"]}
        prepared, previews, ids, included, effective, policies = [], [], set(), [], [], []
        entries = 0
        for supplied in recipes:
            if not isinstance(supplied, dict) or set(supplied) != set(FIELDS):
                raise ValueError("each recipe must contain only its id, name, expressions and policy")
            r = copy.deepcopy(supplied)
            if not isinstance(r["id"], str) or not ID.fullmatch(r["id"]) or r["id"] in ids:
                raise ValueError("recipe ids must be unique ASCII identifiers of at most 64 characters")
            ids.add(r["id"])
            name = r["name"]
            if (not isinstance(name, str) or not name.strip() or len(name) > 80 or
                    any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in name)):
                raise ValueError("recipe name must be nonempty text of at most 80 characters without control characters")
            previous = old.get(r["id"])
            if r["include"] is None:
                if previous is None or previous["include"] is not None or any(
                        r[k] != previous[k] for k in FIELDS if k != "name"):
                    raise ValueError("legacy effective-only ranges must be explicitly converted before editing expressions or policies")
                source = [s["cidr"] for s in previous["scopes"]]
                excluded = []
            else:
                source, excluded = r["include"], r["exclude"]
                if not isinstance(source, list) or not isinstance(excluded, list):
                    raise ValueError("recipe include and exclude must be lists")
            entries += len(source) + len(excluded)
            if entries > LIMITS["max_entries"]:
                raise ValueError("at most 128 combined include/exclude entries across all recipes are allowed")
            p = preview_ranges(source, excluded, allow_public=r["allow_public"], scanner_target=r["scanner_target"],
                               acknowledge_normalization=r["acknowledge_normalization"])
            if r["scanner_target"]:
                target = self.ctx.inventory.get(r["scanner_target"])
                if not target.in_scope:
                    p["blocking_reasons"].append(f"scanner target {target.id} is out of scope")
                    p["can_save"] = False
            included.extend(_parse(value) for value in source)
            effective.extend(_subtract(_merge([_parse(value) for value in source]),
                                       _merge([_parse(value) for value in excluded])))
            policies.extend((ipaddress.ip_network(n), (r["allow_public"], r["scanner_target"]), name)
                            for n in p["networks"])
            unchanged = previous and all(previous[k] == supplied[k] for k in FIELDS if k != "name")
            r["scopes"] = previous["scopes"] if unchanged else [
                {"cidr": n, "allow_public": r["allow_public"], "scanner_target": r["scanner_target"]}
                for n in p["networks"]]
            prepared.append(r)
            previews.append({"id": r["id"], "name": name, "preview": p})
        count = sum(end - start + 1 for _, start, end in _merge(effective))
        input_count = sum(end - start + 1 for _, start, end in _merge(included))
        reasons = [f'{r["name"]}: {message}' for r in previews for message in r["preview"]["blocking_reasons"]]
        networks = [n for r in previews for n in r["preview"]["networks"]]
        network_count = sum(r["preview"]["network_count"] for r in previews)
        if count > LIMITS["max_addresses"]:
            reasons.append("effective recipes exceed 65536 total addresses")
        if network_count > LIMITS["max_networks"]:
            reasons.append("effective recipes exceed 256 normalized networks")
        # Only compare bounded, otherwise-saveable output. Invalid fragmented IPv6 input must not
        # turn the policy check into an unbounded pairwise comparison.
        if not reasons:
            for i, (net, policy, name) in enumerate(policies):
                if any(net.version == n.version and net.overlaps(n) and policy != p for n, p, _ in policies[:i]):
                    reasons.append(f"{name}: overlapping recipes have conflicting public/scanner policies")
                    break
        truncated = network_count > LIMITS["max_networks"] or any(r["preview"]["truncated"] for r in previews)
        preview = {"networks": networks[:LIMITS["max_networks"]], "network_count": network_count,
                   "input_address_count": str(input_count), "address_count": str(count),
                   "excluded_address_count": str(input_count - count), "truncated": truncated,
                   "can_save": not reasons, "blocking_reasons": reasons,
                   "warnings": [f'{r["name"]}: {message}' for r in previews for message in r["preview"]["warnings"]],
                   "normalizations": [dict(note, recipe_id=r["id"], recipe_name=r["name"])
                                      for r in previews for note in r["preview"]["normalizations"]],
                   "requires_normalization_acknowledgment": any(r["preview"]["requires_normalization_acknowledgment"] for r in previews),
                   "limits": dict(LIMITS)}
        result = {"revision": revision, "preview": preview, "recipes": previews}
        # A consistency binding, not an authorization token. Save revalidates all declarations and grants.
        result["fingerprint"] = fingerprint({"inputs": recipes, **result})
        return prepared, result

    def preview(self, recipes: list[dict], revision: str) -> dict:
        return self.prepare(recipes, revision, self.read())[1]

    def save(self, recipes: list[dict], revision: str, preview_fingerprint: str, actor: str, reason: str) -> dict:
        recipes = copy.deepcopy(recipes)
        if len(reason) > 1000:
            raise ValueError("reason must be at most 1000 characters")
        if any((ord(c) < 32 and c not in "\n\r\t") or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in reason):
            raise ValueError("reason contains invalid control or Unicode characters")
        with self.ctx.store.lock("discovery-scopes"):
            state = self.read()
            prepared, result = self.prepare(recipes, revision, state)
            if preview_fingerprint != result["fingerprint"]:
                raise ValueError("recipe preview does not match these exact inputs and revision; preview again")
            if not result["preview"]["can_save"]:
                raise ValueError("; ".join(result["preview"]["blocking_reasons"]))
            self.ctx.killswitch.guard("discovery.scopes", actor)
            for r in prepared:
                for i, scope in enumerate(r["scopes"]):
                    if "added_at" not in scope:
                        r["scopes"][i] = DiscoveryScope(**scope, added_by=actor, reason=reason, grant_id=uuid.uuid4().hex).to_dict()
            saved = self._write(state, prepared, actor, reason, {"preview_fingerprint": preview_fingerprint})
            return {**self.view(saved), "preview": result["preview"]}

    def replace_effective(self, scopes: list[dict], actor: str, reason: str, *, range_input=None, details=None) -> None:
        """Compatibility whole-set replacement; retain expressions only when the caller supplied them."""
        with self.ctx.store.lock("discovery-scopes"):
            state = self.read()
            if range_input is None:
                recipes = [legacy_recipe(s, i) for i, s in enumerate(scopes)]
            else:
                range_input = {"exclude": [], "allow_public": False, "scanner_target": None,
                               "acknowledge_normalization": False, **copy.deepcopy(range_input)}
                p = preview_ranges(**range_input)
                if (not p["can_save"] or p["networks"] != [s["cidr"] for s in scopes] or any(
                        s[k] != range_input[k] for s in scopes for k in ("allow_public", "scanner_target"))):
                    raise ValueError("range expressions must match the saved effective scopes")
                recipes = [{"id": f"range-{uuid.uuid4().hex}", "name": "Search ranges", **copy.deepcopy(range_input), "scopes": scopes}]
            self._write(state, recipes, actor, reason, details or {})

    def _write(self, before: dict, recipes: list[dict], actor: str, reason: str, details: dict) -> dict:
        after = {"version": 1, "revision": uuid.uuid4().hex, "recipes": recipes}
        self.ctx.store.write_json(self.path, after)
        self.ctx.audit.append("discovery.scopes", actor, {
            "before": [s["cidr"] for s in effective_scopes(before["recipes"])],
            "after": [s["cidr"] for s in effective_scopes(recipes)],
            "allow_public": [s["cidr"] for s in effective_scopes(recipes) if s["allow_public"]],
            "reason": reason, "before_revision": before["revision"], "revision": after["revision"],
            "before_recipes": [editable(r) for r in before["recipes"]], "recipes": [editable(r) for r in recipes], **details})
        return after
