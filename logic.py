"""Protocol layer: canonical JSON, digests, request validation, receipt signatures.
No model calls and no database access live here."""
import base64
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PROFILE = "ga5-mailroom-action-gate/v2"
ACTIONS = (
    "create_draft",
    "update_internal_record",
    "send_approved_notice",
    "request_confirmation",
    "quarantine_item",
    "no_action",
)
MAX_BODY_BYTES = 4 * 1024 * 1024
MAX_DOSSIERS = 400
MAX_SOURCES = 60
MAX_LINES = 600


class ApiError(Exception):
    def __init__(self, status: int, code: str):
        super().__init__(code)
        self.status = status
        self.code = code


def require(condition, code="INVALID_REQUEST", status=400):
    if not condition:
        raise ApiError(status, code)


def canonical(value) -> str:
    """Recursively key-sorted, compact JSON with normal JSON spelling."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def b64decode_loose(value: str) -> bytes:
    value = value.strip()
    value += "=" * (-len(value) % 4)
    try:
        return base64.b64decode(value, validate=True)
    except Exception:
        return base64.urlsafe_b64decode(value)


def is_str(value, max_len=20000):
    return isinstance(value, str) and 0 < len(value) <= max_len


def load_public_key(jwk) -> Ed25519PublicKey:
    require(isinstance(jwk, dict), "INVALID_VERIFIER")
    require(jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519" and is_str(jwk.get("x"), 200), "INVALID_VERIFIER")
    try:
        raw = base64.urlsafe_b64decode(jwk["x"] + "=" * (-len(jwk["x"]) % 4))
        require(len(raw) == 32, "INVALID_VERIFIER")
        return Ed25519PublicKey.from_public_bytes(raw)
    except ApiError:
        raise
    except Exception:
        raise ApiError(400, "INVALID_VERIFIER")


def validate_envelope(body):
    require(isinstance(body, dict))
    require(body.get("profile") == PROFILE, "INVALID_PROFILE")
    require(body.get("operation") in ("propose", "commit"), "INVALID_OPERATION")
    require(is_str(body.get("evaluationId"), 300), "INVALID_EVALUATION_ID")
    return body["operation"]


def validate_propose(body):
    verifier = body.get("receiptVerifier")
    require(isinstance(verifier, dict) and verifier.get("algorithm") == "Ed25519", "INVALID_VERIFIER")
    load_public_key(verifier.get("publicKeyJwk"))

    allowed = body.get("allowedActions")
    if allowed is not None:
        require(isinstance(allowed, list) and allowed and all(a in ACTIONS for a in allowed), "INVALID_ACTIONS")
        require(len(set(allowed)) == len(allowed), "INVALID_ACTIONS")

    dossiers = body.get("dossiers")
    require(isinstance(dossiers, list) and 0 < len(dossiers) <= MAX_DOSSIERS, "INVALID_DOSSIERS")
    seen = set()
    for dossier in dossiers:
        require(isinstance(dossier, dict), "INVALID_DOSSIERS")
        require(is_str(dossier.get("dossierId"), 300), "INVALID_DOSSIERS")
        require(dossier["dossierId"] not in seen, "DUPLICATE_DOSSIER_ID")
        seen.add(dossier["dossierId"])
        require(isinstance(dossier.get("mailbox"), str), "INVALID_DOSSIERS")
        sources = dossier.get("sources")
        require(isinstance(sources, list) and 0 < len(sources) <= MAX_SOURCES, "INVALID_DOSSIERS")
        line_ids = set()
        for source in sources:
            require(isinstance(source, dict) and is_str(source.get("sourceId"), 300), "INVALID_DOSSIERS")
            lines = source.get("lines")
            require(isinstance(lines, list) and len(lines) <= MAX_LINES, "INVALID_DOSSIERS")
            for line in lines:
                require(isinstance(line, dict) and is_str(line.get("lineId"), 300), "INVALID_DOSSIERS")
                require(isinstance(line.get("text"), str), "INVALID_DOSSIERS")
                require(line["lineId"] not in line_ids, "DUPLICATE_LINE_ID")
                line_ids.add(line["lineId"])
        require(line_ids, "INVALID_DOSSIERS")


def validate_commit(body):
    require(is_str(body.get("inputDigest"), 200), "INVALID_DIGEST")
    receipts = body.get("receipts")
    require(isinstance(receipts, list) and 0 < len(receipts) <= MAX_DOSSIERS, "INVALID_RECEIPTS")
    for receipt in receipts:
        require(isinstance(receipt, dict), "INVALID_RECEIPTS")
        for key in ("dossierId", "callId", "action", "proposalDigest", "receiptId", "receiptSignature"):
            require(is_str(receipt.get(key), 2000), "INVALID_RECEIPTS")
        require(isinstance(receipt.get("accepted"), bool), "INVALID_RECEIPTS")


def proposal_digest(proposal) -> str:
    view = {
        "dossierId": proposal["dossierId"],
        "callId": proposal["callId"],
        "action": proposal["action"],
        "target": proposal.get("target"),
        "payload": proposal.get("payload"),
        "evidence": sorted(proposal["evidence"]),
    }
    return sha256_hex(canonical(view))


def receipt_message(body, receipt) -> bytes:
    signed = {
        "profile": body["profile"],
        "evaluationId": body["evaluationId"],
        "inputDigest": body["inputDigest"],
        "receipt": {key: value for key, value in receipt.items() if key != "receiptSignature"},
    }
    return canonical(signed).encode("utf-8")


def verify_receipt(public_key: Ed25519PublicKey, body, receipt) -> bool:
    try:
        signature = b64decode_loose(receipt["receiptSignature"])
        public_key.verify(signature, receipt_message(body, receipt))
        return True
    except (InvalidSignature, ValueError, Exception):
        return False
