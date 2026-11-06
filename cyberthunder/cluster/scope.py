"""Closed namespace workload reads for image inventory; no new target authority."""
from __future__ import annotations

import json
import re

WORKLOAD_KINDS = (
    ('apps', 'Deployment', 'deployments'),
    ('apps', 'StatefulSet', 'statefulsets'),
    ('apps', 'DaemonSet', 'daemonsets'),
    ('batch', 'CronJob', 'cronjobs'),
    ('batch', 'Job', 'jobs'),
    ('core', 'Pod', 'pods'),
)
_TYPES = {resource: (kind, 'v1' if api == 'core' else api + '/v1')
          for api, kind, resource in WORKLOAD_KINDS}
MAX_LIST_BYTES = 8 * 1024 * 1024
MAX_LIST_ITEMS = 10000
_LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?')


def guard_read(args: tuple[str, ...], namespaces: tuple[str, ...]) -> None:
    if (len(args) != 4 or args[0] != 'get' or args[1] not in _TYPES
            or args[2] != '-n' or args[3] not in namespaces):
        raise PermissionError('namespace image collection permits only declared workload list reads')


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON field')
        result[key] = value
    return result


def _constant(value):
    raise ValueError('invalid JSON constant')


def _text(value, limit):
    return (isinstance(value, str) and 0 < len(value) <= limit
            and not any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value))


def _spec(item, kind):
    spec = item.get('spec')
    if kind == 'CronJob':
        for key in ('jobTemplate', 'spec'):
            spec = spec.get(key) if isinstance(spec, dict) else None
    if kind != 'Pod':
        for key in ('template', 'spec'):
            spec = spec.get(key) if isinstance(spec, dict) else None
    if not isinstance(spec, dict) or not isinstance(spec.get('containers'), list) or not spec['containers']:
        raise ValueError('workload container inventory is unavailable')
    seen = set()
    for key in ('containers', 'initContainers', 'ephemeralContainers'):
        containers = spec.get(key, [])
        if not isinstance(containers, list):
            raise ValueError('malformed container list')
        for container in containers:
            if (not isinstance(container, dict) or not isinstance(container.get('name'), str)
                    or not _LABEL.fullmatch(container['name']) or container['name'] in seen
                    or not _text(container.get('image'), 4096)):
                raise ValueError('malformed container identity')
            seen.add(container['name'])


def decode_list(payload: str, resource: str, namespace: str) -> dict:
    """Reject incomplete lists instead of interpreting missing workloads as absence.

    The byte limit applies after subprocess capture; this is not a streaming
    stdout or whole-process memory bound.
    """
    if len(payload.encode('utf-8')) > MAX_LIST_BYTES:
        raise ValueError('namespace workload list exceeds size limit')
    try:
        doc = json.loads(payload, object_pairs_hook=_object, parse_constant=_constant)
    except (ValueError, RecursionError):
        raise ValueError('invalid namespace workload JSON') from None
    kind, api = _TYPES[resource]
    if (not isinstance(doc, dict) or doc.get('kind') not in {'List', kind + 'List'}
            or doc.get('apiVersion') not in ({'v1', api} if doc.get('kind') == 'List' else {api})
            or not isinstance(doc.get('metadata'), dict) or not isinstance(doc.get('items'), list)
            or len(doc['items']) > MAX_LIST_ITEMS):
        raise ValueError('malformed namespace workload list')
    metadata = doc['metadata']
    if (metadata.get('continue', '') != '' or type(metadata.get('remainingItemCount', 0)) is not int
            or metadata.get('remainingItemCount', 0) != 0):
        raise ValueError('namespace workload pagination is incomplete')
    seen, seen_uids = set(), set()
    for item in doc['items']:
        if (not isinstance(item, dict) or item.get('kind') != kind or item.get('apiVersion') != api
                or not isinstance(item.get('metadata'), dict)):
            raise ValueError('malformed workload identity')
        md = item['metadata']
        if (md.get('namespace') != namespace or not _text(md.get('name'), 253)
                or not all(_LABEL.fullmatch(part) for part in md['name'].split('.'))
                or not _text(md.get('uid'), 128) or md['name'] in seen or md['uid'] in seen_uids):
            raise ValueError('workload is outside the requested scope or lacks a unique identity')
        seen.add(md['name'])
        seen_uids.add(md['uid'])
        _spec(item, kind)
    return doc
