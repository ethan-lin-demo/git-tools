"""git protocol"""
from io import BytesIO
import os
import struct
import zlib
import time
import base64
import hashlib
import binascii
import dataclasses
import requests as rqs
from .config import GIT_VERSIONS, RECEIVE_CAPABILITIES, CAPABILITY_AGENT, ZERO_SHA


@dataclasses.dataclass
class GitInfo:
    """git info"""

    auth: str
    name: str = ""
    email: str = ""
    branch: str = "master"
    git_version: str = GIT_VERSIONS[-1]


TIMEOUT = 3


def write_pack_header(num_objects):
    """Create a pack header with the given number of objects."""
    return b"PACK" + struct.pack(b">L", 2) + struct.pack(b">L", num_objects)


def pack_object_header(type_num, delta_base, size):
    """Create a header for a packed object with the given type number, delta base, and size."""
    header = []
    first_byte = (type_num << 4) | (size & 15)
    size >>= 4
    while size:
        header.append(first_byte | 0x80)
        first_byte = size & 0x7F
        size >>= 7
    header.append(first_byte)
    if type_num == 6:
        ret = [delta_base & 0x7F]
        delta_base >>= 7
        while delta_base:
            delta_base -= 1
            ret.insert(0, 0x80 | (delta_base & 0x7F))
            delta_base >>= 7
        header.extend(ret)
    elif type_num == 7:
        assert len(delta_base) == 20
        header += delta_base
    return bytearray(header)


def initialize_git_request(url, auth_token, git_version):
    """Initialize a git request with the given url, auth token, and git version."""
    headers = {"Accept": "*/*"}
    headers.update({"Authorization": f"Basic {base64.b64encode(auth_token).decode()}"})
    resp = rqs.get(
        f"{url}/info/refs?service=git-receive-pack", headers=headers, timeout=TIMEOUT
    )
    read = BytesIO(resp.content).read
    pkt_contents = _read_pkt_contents(read)
    pkt, *_ = pkt_contents
    assert pkt.rstrip(b"\n") == (b"# service=" + b"git-receive-pack")
    pkt_contents = _read_pkt_contents(read)
    refs, server_capabilities = _parse_pkt_contents(pkt_contents)
    capabilities = _build_capabilities(server_capabilities, git_version)
    return refs, capabilities


def _read_pkt_contents(read):
    pkt_contents = []
    while True:
        size_str = read(4)
        assert size_str
        size = int(size_str, 16)
        if size == 0:
            break
        pkt_contents.append(read(size - 4))
    return pkt_contents


def _parse_pkt_contents(pkt_contents):
    refs = {}
    server_capabilities = None
    for pkt in pkt_contents:
        sha, ref = pkt.rstrip(b"\n").split(None, 1)

        if server_capabilities is None:
            text = ref
            if b"\x00" not in text:
                ref, server_capabilities = text, []
            else:
                text, capabilities = text.rstrip().split(b"\x00")
                ref, server_capabilities = text, capabilities.strip().split(b" ")
        assert sha != b"ERR"
        refs[ref] = sha

    return refs, server_capabilities


def _build_capabilities(server_capabilities, git_version):
    capabilities = set(server_capabilities) & set(RECEIVE_CAPABILITIES)
    capabilities.add(CAPABILITY_AGENT + b"=" + git_version)
    return capabilities


def send_git_push_request(url, auth_token, data, callback):
    """send git push request"""
    service = "git-receive-pack"
    headers = {
        "Content-Type": f"application/x-{service}-request",
        "Accept": f"application/x-{service}-result",
        "Content-Length": str(len(data)),
        "Authorization": f"Basic {base64.b64encode(auth_token).decode()}",
    }
    resp = rqs.post(
        f"{url}/{service}", headers=headers, data=data, stream=True, timeout=TIMEOUT
    )

    def _evt_handler1(data):
        buf = BytesIO(data).getvalue()
        if len(buf) < 4:
            return
        while len(buf) >= 4:
            size = int(buf[:4], 16)
            if size == 0:
                yield ""
                buf = buf[4:]
            elif size <= len(buf):
                yield buf[4:size].decode()
                buf = buf[size:]
            else:
                break

    def _evt_handler2(data):
        while True:
            yield data.decode()
            return

    while True:
        size_str = resp.raw.read(4)
        assert size_str
        size = int(size_str, 16)
        if size == 0:
            break

        pkt = resp.raw.read(size - 4)
        channel = ord(pkt[:1])
        pkt = pkt[1:]

        callback("".join({1: _evt_handler1, 2: _evt_handler2}[channel](pkt)))


def pack_head(refname, new_sha, url, auth_token, git_version):
    """pack head"""
    refs, capabilities = initialize_git_request(url, auth_token, git_version)
    old_sha1 = refs.get(refname, ZERO_SHA)
    content = (
        old_sha1
        + b" "
        + new_sha
        + b" "
        + refname
        + b"\x00"
        + b" ".join(sorted(capabilities))
    )
    content = f"{len(content) + 4:04x}".encode() + content
    content += b"0000"
    return content


def pack_config(
    user_name,
    email,
    commit,
    tree_sha,
    return_as_hex=0,
):
    """pack config"""
    current_time = str(int(time.time())).encode()
    content = b"tree %s\n" % tree_sha
    content += b"author %s <%s> %s +0000\n" % (
        user_name,
        email,
        current_time,
    )
    content += b"committer %s <%s> %s +0000\n\n%s" % (
        user_name,
        email,
        current_time,
        commit,
    )
    head = bytes(pack_object_header(1, None, len(content)))
    sha = hashlib.sha1(b"commit %d\x00%s" % (len(content), content)).digest()
    hex_sha = (
        hashlib.sha1(b"commit %d\x00%s" % (len(content), content)).hexdigest().encode()
    )
    content = head + zlib.compress(content, -1)
    return content, (hex_sha if return_as_hex else sha)


def pack_file(content, return_as_hex=0):
    """pack file"""
    sha = hashlib.sha1(b"blob %d\x00%s" % (len(content), content)).digest()
    hex_sha = hashlib.sha1(b"blob %d\x00%s" % (len(content), content)).hexdigest()
    content = bytes(pack_object_header(3, None, len(content))) + zlib.compress(
        content, -1
    )
    return content, (hex_sha if return_as_hex else sha)


def pack_tree(files, return_as_hex):
    """pack tree"""
    files.sort(key=lambda x: x[1])
    types = {b"tree": 40000, b"blob": 100644}
    content = b""
    for ttype, fname, fsha in files:
        content += b"%d %s\x00%s" % (types[ttype], fname, fsha)
    content = b"tree %d\x00%s" % (len(content), content)
    sha = hashlib.sha1(content).digest()
    hex_sha = hashlib.sha1(content).hexdigest()

    content = b""
    for ttype, fname, fsha in files:
        content += b"%d %s\x00%s" % (types[ttype], fname, fsha)

    content = bytes(pack_object_header(2, None, len(content))) + zlib.compress(
        content, -1
    )
    return content, (hex_sha if return_as_hex else sha)


def rename_same_folder(path, mapping=None):
    """rename same folder"""
    if mapping is None:
        mapping = {}
    folders = {}
    for root, dirs, _files in os.walk(path):
        for i in dirs:
            if i in folders:
                new_name = binascii.hexlify(os.urandom(16)).decode()
                assert not folders.get(new_name)
                folders[new_name] = 1
                mapping[new_name] = i
                os.rename(root + "/" + i, root + "/" + new_name)
                return rename_same_folder(path, mapping=mapping)
            folders[i] = 1
    return mapping


def recover_tree(path, mapping):
    """recover tree"""
    for root, dirs, _files in os.walk(path):
        for i in dirs:
            if i in mapping:
                os.rename(root + "/" + i, root + "/" + mapping.get(i))
                return recover_tree(path, mapping)
    return None


def get_tree_map(path):
    """get tree map"""
    mapping = rename_same_folder(path)
    tree = {}
    for root, dirs, files in os.walk(path):
        root = root.replace("\\", "/")
        folder_name = root.split("/")[-1]
        tree[folder_name] = [root, dirs, files]
    return tree, mapping


def recursive_folder(tree_map, folder_name, shas):
    """recursive folder"""
    contents = []
    tree_packs = []
    tree, mapping = tree_map
    for i in tree[folder_name][1]:
        if i in mapping:
            f_name = mapping.get(i)
        else:
            f_name = i

        result = recursive_folder((tree, mapping), i, shas)
        content, sha = pack_tree(result[0] + result[1], return_as_hex=0)
        tree_packs.append((b"tree", f_name.encode(), sha))
        contents.extend(result[2])

        if sha not in shas:
            shas.add(sha)
            contents.append(content)

    packs = []
    for i in tree[folder_name][2]:
        root = tree[folder_name][0]
        f_name = i
        with open(root + "/" + f_name, "rb") as fin:
            content = fin.read()
        content, sha = pack_file(content)
        packs.append((b"blob", f_name.encode(), sha))
        if sha not in shas:
            shas.add(sha)
            contents.append(content)
    return packs, tree_packs, contents


def push(
    url, folder_name, git_info, description="", callback=lambda x: print(x, end="")
):
    """push to git"""
    tree_map = get_tree_map(f"./{folder_name}")
    packs, tree_packs, contents = recursive_folder(tree_map, str(folder_name), set())
    packs.extend(tree_packs)
    tree = pack_tree(packs, return_as_hex=1)
    head = write_pack_header(len(contents) + 2)
    config = pack_config(
        git_info.name.encode(),
        git_info.email.encode(),
        description.encode(),
        tree[1].encode(),
        return_as_hex=1,
    )
    data = b""
    data += head
    data += config[0]
    data += b"".join(contents)
    data += tree[0]
    data += hashlib.sha1(data).digest()
    new_sha = config[1]
    ref_name = b"refs/heads/%s" % (git_info.branch.encode())
    head = pack_head(
        ref_name,
        new_sha,
        url,
        git_info.auth.encode(),
        b"git/%s" % git_info.git_version,
    )
    send_git_push_request(url, git_info.auth.encode(), head + data, callback)
    recover_tree(f"./{folder_name}", tree_map[1])


def recursive_map(tree_map, folder_name, shas):
    """recursive map"""
    contents = []
    tree_packs = []
    tree, mapping = tree_map
    for i in tree[folder_name][1]:
        f_name = i
        result = recursive_folder((tree, mapping), i, shas)
        content, sha = pack_tree(result[0] + result[1], return_as_hex=0)
        tree_packs.append((b"tree", f_name.encode(), sha))
        contents.extend(result[2])

        if sha not in shas:
            shas.add(sha)
            contents.append(content)

    packs = []
    for i in tree[folder_name][2]:
        f_name = i
        content = mapping.get(i)
        content, sha = pack_file(content)
        packs.append((b"blob", f_name.encode(), sha))
        if sha not in shas:
            shas.add(sha)
            contents.append(content)
    return packs, tree_packs, contents


def push_binaries(
    url, binaries, git_info, description="", callback=lambda x: print(x, end="")
):
    """push to git"""
    tree_map = (
        {
            "root": ["./root", [], binaries.keys()],
        },
        binaries,
    )
    packs, tree_packs, contents = recursive_map(tree_map, "root", set())
    packs.extend(tree_packs)
    tree = pack_tree(packs, return_as_hex=1)
    head = write_pack_header(len(contents) + 2)
    config = pack_config(
        git_info.name.encode(),
        git_info.email.encode(),
        description.encode(),
        tree[1].encode(),
        return_as_hex=1,
    )
    data = b""
    data += head
    data += config[0]
    data += b"".join(contents)
    data += tree[0]
    data += hashlib.sha1(data).digest()
    new_sha = config[1]
    ref_name = b"refs/heads/%s" % (git_info.branch.encode())
    head = pack_head(
        ref_name,
        new_sha,
        url,
        git_info.auth.encode(),
        b"git/%s" % git_info.git_version,
    )
    send_git_push_request(url, git_info.auth.encode(), head + data, callback)
