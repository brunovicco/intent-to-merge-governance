"""Read the single-file Git text diff recorded by the PAY-104 runner.

All paths and modes are fixed. Reconcile hunks against bytes in memory, including
context and omitted lines. Git object IDs are format checks for this lab.
"""
import hashlib
import re

from .path_policy import matches

PAYMENT_PATH = 'app/payments.py'
PATH = PAYMENT_PATH.encode('ascii')
HEADER = b'diff --git a/' + PATH + b' b/' + PATH
INDEX = re.compile(rb'index ([0-9a-f]{4,40})\.\.([0-9a-f]{4,40}) 100644')
HUNK = re.compile(rb'@@ -(\d{1,10})(?:,(\d{1,10}))? \+(\d{1,10})(?:,(\d{1,10}))? @@(?: .*)?\n')
NO_NEWLINE = b'\\ No newline at end of file\n'


def rejected_paths(paths, spec, policy):
    return sorted(path for path in paths if path != PAYMENT_PATH
                  or not matches(path, spec['allowed_paths'])
                  or matches(path, policy['protected_paths']))


def require_patch(condition):
    if not condition:
        raise ValueError('semantic evidence mismatch: invalid PAY-104 patch')


def lines(data):
    """Split on Git's LF delimiter while preserving exact line endings."""
    parts = data.split(b'\n')
    return [part + b'\n' for part in parts[:-1]] + ([parts[-1]] if parts[-1] else [])


def object_id(kind, data):
    # The lab records Git SHA-1 object names. DSSE and evidence integrity use SHA-256.
    header = kind + b' ' + str(len(data)).encode('ascii') + b'\0'
    return hashlib.sha1(header + data, usedforsecurity=False)


def candidate_tree(candidate):
    blob = object_id(b'blob', candidate).digest()
    directory = object_id(b'tree', b'100644 payments.py\0' + blob).digest()
    return object_id(b'tree', b'40000 app\0' + directory).hexdigest()


def hunk_range(start, count):
    count = 1 if count is None else int(count)
    start = int(start)
    require_patch(not count or start > 0)
    return start - bool(count), count


def read_hunk(patch, pos):
    """Return one hunk's old and new line sequences."""
    old, new = [], []
    changed = False
    while pos < len(patch) and patch[pos][:1] in (b' ', b'-', b'+'):
        line = patch[pos]
        pos += 1
        require_patch(line.endswith(b'\n'))
        text = line[1:]
        if pos < len(patch) and patch[pos] == NO_NEWLINE:
            text = text[:-1]
            require_patch(bool(text))
            pos += 1
        if line[:1] != b'+':
            old.append(text)
        if line[:1] != b'-':
            new.append(text)
        changed |= line[:1] != b' '
    require_patch(changed and old != new)
    return pos, old, new


def verify_patch(data, baseline, candidate):
    if baseline == candidate:
        require_patch(data == b'')
        return
    patch = lines(data)
    require_patch(len(patch) >= 6 and data.endswith(b'\n')
                  and patch[0] == HEADER + b'\n'
                  and patch[2:4] == [b'--- a/' + PATH + b'\n', b'+++ b/' + PATH + b'\n'])
    index = INDEX.fullmatch(patch[1][:-1])
    require_patch(index is not None)
    old_id, new_id = index.groups()
    require_patch(object_id(b'blob', baseline).hexdigest().encode('ascii').startswith(old_id)
                  and object_id(b'blob', candidate).hexdigest().encode('ascii').startswith(new_id))
    old_lines, new_lines = lines(baseline), lines(candidate)
    old_end = new_end = 0
    pos = 4
    while pos < len(patch):
        header = HUNK.fullmatch(patch[pos])
        require_patch(header is not None)
        old_start, old_count = hunk_range(*header.groups()[:2])
        new_start, new_count = hunk_range(*header.groups()[2:])
        require_patch(old_end <= old_start <= len(old_lines)
                      and new_end <= new_start <= len(new_lines)
                      and old_lines[old_end:old_start] == new_lines[new_end:new_start])
        pos, old, new = read_hunk(patch, pos + 1)
        old_end, new_end = old_start + old_count, new_start + new_count
        require_patch(len(old) == old_count and len(new) == new_count
                      and old_lines[old_start:old_end] == old
                      and new_lines[new_start:new_end] == new)
    require_patch(old_lines[old_end:] == new_lines[new_end:])
