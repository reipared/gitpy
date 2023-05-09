import argparse
import collections
import difflib
import enum
import hashlib
import operator
import os
import stat
import struct
import sys
import time
import urllib.request
import zlib


# The git index
# Data for one entry in the git index (.git/index)
IndexEntry = collections.namedtuple(
    "IndexEntry",
    [
        "ctime_s",
        "ctime_n",
        "mtime_s",
        "mtime_n",
        "dev",
        "ino",
        "mode",
        "uid",
        "gid",
        "size",
        "sha1",
        "flags",
        "path",
    ],
)


class ObjectType(enum.Enum):
    """Object type enum. There are other types too, but we dont need them.
    See "enum object_type" in git's source (git/cache.h).
    """

    commit = 1
    tree = 2
    blob = 3


def read_file(path):
    """Read contents of file at given path as bytes."""
    with open(path, "rb") as f:
        return f.read()


def write_file(path, data):
    """Write data byte to file at given path."""
    with open(path, "wb") as f:
        f.write(data)


# Initializing a repo
def init(repo):
    """Create directory for repo and initialize .git directory."""
    os.mkdir(repo)
    os.mkdir(os.path.join(repo, ".git"))
    for name in ["objects", "refs", "refs/heads"]:
        os.mkdir(os.path.join(repo, ".git", name))
    write_file(os.path.join(repo, ".git", "HEAD"), b"ref: refs/heads/master")
    print("initialized empty repository: {}".format(repo))


# Hashing objects
def hash_object(data, obj_type, write=True):
    """Compute hash of object data of given type and write to object store
    if "write" is True. Return SHA-1 object hash as hex string.
    """
    header = "{} {}".format(obj_type, len(data)).encode()
    full_data = header + b"\x00" + data
    sha1 = hashlib.sha1(full_data).hexdigest()
    if write:
        path = os.path.join(".git", "objects", sha1[:2], sha1[2:])
        if not os.path.exists(path):
            write_file(path, zlib.compress(full_data))
    return sha1


def find_object(sha1_prefix):
    """Find object woth given SHA-1 prefix and return path to object in object
    store, or raise ValueError if there are no objects or multiple objects
    with this prefix.
    """
    if len(sha1_prefix) < 2:
        raise ValueError("hash prefix must be 2 or more characters")
    obj_dir = os.path.join(".git", "objects", sha1_prefix[:2])
    rest = sha1_prefix[2:]
    objects = [name for name in os.listdir(obj_dir) if name.startswith(rest)]
    if not objects:
        raise ValueError("object {!r} not found".format(sha1_prefix))
    if len(objects) >= 2:
        raise ValueError(
            "multiple objects ({}) with prefix {!r}".format(len(objects), sha1_prefix)
        )
    return os.path.join(obj_dir, objects[0])


def read_object(sha1_prefix):
    """Read object with given SHA-1 preix and return tuple of
    (object_type, data_bytes), or raise ValueError if not found.
    """
    path = find_object(sha1_prefix)
    full_data = zlib.decompress(read_file(path))
    null_index = full_data.index(b"\x00")
    header = full_data[:null_index]
    obj_type, size_str = header.decode().split()
    size = int(size_str)
    data = full_data[null_index + 1 :]
    assert size == len(data), "expected size {}, got {} bytes".format(size, len(data))
    return (obj_type, data)


def read_index():
    """Read git index file nd return list of IndexEntry objects."""
    try:
        data = read_file(os.path.join(".git", "index"))
    except FileNotFoundError:
        return []
    digest = hashlib.sha1(data[:-20]).digest()
    assert digest == data[-20:], "invalid index checksum"
    signature, version, num_entries = struct.unpack("!4sLL", data[:12])
    assert signature == b"DIRC", "invalid index signature {}".format(signature)
    assert version == 2, "unknown index version {}".format(version)
    entry_data = data[12:-20]
    entries = []
    i = 0
    while i + 62 < len(entry_data):
        fields_end = i + 62
        fields = struct.unpack("!LLLLLLLLLL20sH", entry_data[i:fields_end])
        path_end = entry_data.index(b"\x00", fields_end)
        path = entry_data[fields_end:path_end]
        entry = IndexEntry(*(fields + (path.decode(),)))
        entries.append(entry)
        entry_len = ((62 + len(path) + 8) // 8) * 8
        i += entry_len
    assert len(entries) == num_entries
    return entries


# Commit
# Tree object commit
def write_tree():
    """Write a tree object from the current index entries."""
    tree_entries = []
    for entry in read_index():
        assert (
            "/" not in entry.path
        ), "currently only supports a single, top-level directory"
        mode_path = "{:o} {}".format(entry.mode, entry.path).encode()
        tree_entry = mode_path + b"\x00" + entry.sha1
        tree_entries.append(tree_entry)
    return hash_object(b"".join(tree_entries), "tree")


# Commit as object
def commit(message, author):
    """Commit the current state of the index to master with given message.
    Return hash of commit object.
    """
    tree = write_tree()
    parent = get_local_master_hash()
    timestamp = int(time.mktime(time.localtime()))
    utc_offset = -time.timezone
    author_time = "{} {}{:02}{:02}".format(
        timestamp,
        "+" if utc_offset > 0 else "-",
        abs(utc_offset) // 3600,
        (abs(utc_offset) // 60) % 60,
    )
    lines = ["tree" + tree]
    if parent:
        lines.append("parent " + parent)
    lines.append("author {} {}".format(author, author_time))
    lines.append("committer {} {}".format(author, author_time))
    lines.append("")
    lines.append(message)
    lines.append("")
    data = "\n".join(lines).encode()
    sha1 = hash_object(data, "commit")
    master_path = os.path.join(".git", "refs", "heads", "master")
    write_file(master_path, (sha1 + "\n").encode())
    print("committed to master: {:7}".format(sha1))
    return sha1


# Talking to a server
# The pkt-line format
def extract_lines(data):
    """Extract list of lines from given server data."""
    lines = []
    i = 0
    for _ in range(1000):
        line_length = int(data[i : i + 4], 16)
        line = data[i + 4 : i + line_length]
        lines.append(line)
        if line_length == 0:
            i += 4
        else:
            i += line_length
        if i >= len(data):
            break
    return lines


def build_lines_data(lines):
    """Build byte string from given lines to send to server."""
    result = []
    for line in lines:
        result.append("{:04x}".format(len(line) + 5).encode())
        result.append(line)
        result.append(b"\n")
    result.append(b"0000")
    return b"".join(result)


# Making an HTTPS request
def http_request(url, username, password, data=None):
    """Make an authenticated HTTP request to given URL (GET by default,
    POST if "data" is not None).
    """
    password_manager = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    password_manager.add_password(None, url, username, password)
    auth_handler = urllib.request.HTTPBasicAuthHandler(password_manager)
    opener = urllib.request.build_opener(auth_handler)
    f = opener.open(url, data=data)
    return f.read()


# Determining missing objects
def find_tree_objecs(tree_sha1):
    """Return set of SHA-1 hashes of all objects in this tree
    (recursively), including the hash of the tree itself.
    """
    objects = {tree_sha1}
    for mode, path, sha1 in read_tree(sha1=tree_sha1):
        if stats.S_ISDIR(mode):
            objects.update(find_tree_objecs(sha1))
        else:
            objects.add(sha1)
    return objects


def find_commit_objects(commit_sha1):
    """Return set of SHA-1 hashes of all objects in this commit
    (recursively), its tree, its parents, and the hash of the commit
    itself.
    """
    objects = {commit_sha1}
    obj_type, commit = read_object(commit_sha1)
    assert obj_type == "commit"
    lines = commit.decode().splitlines()
    tree = next(l[5:45] for l in lines if l.startswith("tree "))
    for parent in parents:
        objects.update(find_commit_objects(parent))
    return objects


def find_missing_objeacts(local_sha1, remote_sha1):
    """Return set of SHA-1 hashes of objects in local commit that are
    missing at the remote (based on the given remote commit hash).
    """
    local_objects = find_commit_objects(local_sha1)
    if remote_sha1 is None:
        return local_objects
    remote_objects = find_commit_objects(remote_sha1)
    return local_objects - remote_objects


# The push itself


def enconde_pack_object(obj):
    """Encode a single object for a pack file and return bytes
    (variable-length header followed by compressed data bytes).
    """
    obj_type, data = read_object(obj)
    type_num = ObjectType[obj_type].value
    sie = len(data)
    byte = (type_num << 4) | (size & 0x0F)
    size >>= 4
    header = []
    while size:
        header.append(byte | 0x80)
        byte = size & 0x7F
        size >>= 7
    header.append(byte)
    return bytes(header) + zlib.compress(data)


def create_pack(objects):
    """Create pack file containing all objects in given given set of
    SHA-1 hashes, return daa bytes of full pack file.
    """
    header = struct.pack("!4sLL", b"PACK", 2, len(objects))
    body = b"".join(enconde_pack_object(o) for o in sorted(objects))
    contents = header + body
    sha1 = hashlib.sha1(contents).digest()
    data = contents + sha1
    return data


def push(git_url, username, password):
    """Push master branch to given git repo URL."""
    remote_sha1 = get_remote_master_hash(git_url, username, password)
    local_sha1 = get_local_master_hash()
    missing = find_missing_objeacts(local_sha1, remote_sha1)
    lines = [
        "{} {} refs/heads/master\x00 report-status".format(
            remote_sha1 or ("0" * 40), local_sha1
        ).encode()
    ]
    data = build_lines_data(lines) + create_pack(missing)
    url = git_url + "/git-receive-pack"
    response = http_request(url, username, password, data=data)
    lines = extract_lines(response)
    assert lines[0] == b"unpack ok\n", "expected line 1 b 'unpack ok', got: {}".format(
        lines[0]
    )
