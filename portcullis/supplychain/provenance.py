"""Build provenance: deterministic tar, Ed25519-signed in-toto style statement, policy check."""
import base64, gzip, hashlib, io, json, tarfile
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

PRED = "https://slsa.dev/provenance/v1"
STMT = "https://in-toto.io/Statement/v1"


def deterministic_tar(root: Path) -> bytes:
    """Sorted entries, zeroed mtime/uid/gid/names, fixed mode, gzip mtime 0."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for f in sorted(p for p in Path(root).rglob("*") if p.is_file()):
            ti = tarfile.TarInfo(f.relative_to(root).as_posix())
            data = f.read_bytes()
            ti.size, ti.mtime, ti.uid, ti.gid, ti.uname, ti.gname = len(data), 0, 0, 0, "", ""
            ti.mode = 0o644
            tf.addfile(ti, io.BytesIO(data))
    raw = buf.getvalue()
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=out, mode="wb", mtime=0, filename="") as g:
        g.write(raw)
    return out.getvalue()


def digest(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def statement(name, artifact: bytes, builder_id, source_uri, source_commit, workflow_ref, pinned=True):
    return {
        "_type": STMT,
        "subject": [{"name": name, "digest": {"sha256": digest(artifact)}}],
        "predicateType": PRED,
        "predicate": {
            "buildDefinition": {"buildType": "portcullis/deterministic-tar@1",
                                "externalParameters": {"source": source_uri, "commit": source_commit, "workflow": workflow_ref},
                                "internalParameters": {"actions_pinned": pinned}},
            "runDetails": {"builder": {"id": builder_id}},
        },
    }


def _canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()


def sign(stmt, priv: Ed25519PrivateKey, keyid):
    return {"payload": base64.b64encode(_canon(stmt)).decode(), "signatures": [{"keyid": keyid, "sig": base64.b64encode(priv.sign(_canon(stmt))).decode()}]}


def verify(env, pub: Ed25519PublicKey, keyid):
    payload = base64.b64decode(env["payload"])
    for s in env["signatures"]:
        if s["keyid"] != keyid:
            continue
        try:
            pub.verify(base64.b64decode(s["sig"]), payload)
            return json.loads(payload)
        except InvalidSignature:
            pass
    return None


def check_policy(env, artifact: bytes, pub, keyid, allowed_builders, allowed_sources, expected_commit=None):
    """Return a list of violation strings; empty means the artifact is acceptable."""
    v = []
    stmt = verify(env, pub, keyid)
    if stmt is None:
        return ["signature invalid or key unknown"]
    if stmt["subject"][0]["digest"]["sha256"] != digest(artifact):
        v.append("artifact digest does not match attested subject")
    p = stmt["predicate"]
    if p["runDetails"]["builder"]["id"] not in allowed_builders:
        v.append("builder not allowed")
    ext = p["buildDefinition"]["externalParameters"]
    if ext["source"] not in allowed_sources:
        v.append("source repository not allowed")
    if expected_commit and ext["commit"] != expected_commit:
        v.append("commit differs from the reviewed commit")
    if not p["buildDefinition"]["internalParameters"].get("actions_pinned"):
        v.append("build used unpinned actions")
    return v
