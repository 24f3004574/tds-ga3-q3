import json
import time

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, Request  # noqa: E402
from fastapi.responses import JSONResponse  # noqa: E402
from starlette.concurrency import run_in_threadpool  # noqa: E402

from database import connect_db  # noqa: E402
from decide import decide_all  # noqa: E402
from logic import (  # noqa: E402
    ACTIONS, MAX_BODY_BYTES, PROFILE, ApiError, canonical, load_public_key, proposal_digest,
    require, sha256_hex, validate_commit, validate_envelope, validate_propose, verify_receipt,
)
from psycopg.types.json import Jsonb  # noqa: E402

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
REQUEST_BUDGET_SECONDS = 46


def error(status, code):
    return JSONResponse({"error": {"code": code}}, status_code=status, media_type="application/json")


def ok(data):
    return JSONResponse(data, status_code=200, media_type="application/json")


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    return error(500, "INTERNAL_ERROR")


def lock_evaluation(cursor, evaluation_id):
    cursor.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", ("eval:" + evaluation_id,))


def handle_propose(body):
    deadline = time.monotonic() + REQUEST_BUDGET_SECONDS
    validate_propose(body)  # whole request is validated before any AI or storage work
    evaluation_id = body["evaluationId"]
    request_hash = sha256_hex(canonical(body))
    dossiers = body["dossiers"]
    allowed = body.get("allowedActions") or list(ACTIONS)

    with connect_db() as connection:
        with connection.cursor() as cursor:
            lock_evaluation(cursor, evaluation_id)
            cursor.execute(
                "SELECT request_hash, propose_response FROM evaluations WHERE evaluation_id = %s",
                (evaluation_id,),
            )
            row = cursor.fetchone()
            if row:
                if row[0] != request_hash:
                    raise ApiError(409, "EVALUATION_CONFLICT")
                return ok(row[1])

            # One computation at a time, so concurrent evaluations reuse each other's cache.
            cursor.execute("SELECT pg_advisory_xact_lock(727274102)")
            decisions = decide_all(dossiers, allowed, deadline)
            proposals = [decisions[d["dossierId"]] for d in dossiers]
            digest = sha256_hex(canonical(dossiers))
            response = {
                "profile": PROFILE,
                "evaluationId": evaluation_id,
                "status": "awaiting_receipts",
                "inputDigest": digest,
                "proposals": proposals,
            }
            cursor.execute(
                """INSERT INTO evaluations (evaluation_id, request_hash, input_digest, verifier, proposals, propose_response)
                   VALUES (%s, %s, %s, %s, %s, %s)""",
                (evaluation_id, request_hash, digest, Jsonb(body["receiptVerifier"]), Jsonb(proposals), Jsonb(response)),
            )
    return ok(response)


def handle_commit(body):
    validate_commit(body)
    evaluation_id = body["evaluationId"]
    commit_hash = sha256_hex(canonical(body))

    with connect_db() as connection:
        with connection.cursor() as cursor:
            lock_evaluation(cursor, evaluation_id)
            cursor.execute(
                """SELECT input_digest, verifier, proposals, commit_hash, commit_response
                   FROM evaluations WHERE evaluation_id = %s""",
                (evaluation_id,),
            )
            row = cursor.fetchone()
            if not row:
                raise ApiError(404, "UNKNOWN_EVALUATION")
            input_digest, verifier, proposals, stored_commit_hash, stored_response = row
            if stored_commit_hash:
                if stored_commit_hash != commit_hash:
                    raise ApiError(409, "COMMIT_CONFLICT")
                return ok(stored_response)
            if body["inputDigest"] != input_digest:
                raise ApiError(400, "DIGEST_MISMATCH")

            by_call = {p["callId"]: p for p in proposals}
            receipts = body["receipts"]
            call_ids = [r["callId"] for r in receipts]
            require(len(set(call_ids)) == len(call_ids), "DUPLICATE_RECEIPT")
            require(set(call_ids) == set(by_call), "RECEIPT_SET_MISMATCH")
            require(len({r["receiptId"] for r in receipts}) == len(receipts), "DUPLICATE_RECEIPT")

            public_key = load_public_key(verifier["publicKeyJwk"])
            by_receipt = {}
            for receipt in receipts:
                proposal = by_call[receipt["callId"]]
                require(receipt["dossierId"] == proposal["dossierId"], "RECEIPT_MISMATCH")
                require(receipt["action"] == proposal["action"], "RECEIPT_MISMATCH")
                require(receipt["proposalDigest"] == proposal_digest(proposal), "RECEIPT_MISMATCH")
                if not verify_receipt(public_key, body, receipt):
                    raise ApiError(400, "INVALID_RECEIPT_SIGNATURE")
                by_receipt[receipt["callId"]] = receipt

            # Every signature is valid: only now record outcomes.
            outcomes = []
            for proposal in proposals:
                receipt = by_receipt[proposal["callId"]]
                outcomes.append({
                    "dossierId": proposal["dossierId"],
                    "callId": proposal["callId"],
                    "action": proposal["action"],
                    "proposalDigest": receipt["proposalDigest"],
                    "receiptId": receipt["receiptId"],
                    "status": "executed" if receipt["accepted"] is True else "rejected",
                })
            response = {
                "profile": PROFILE,
                "evaluationId": evaluation_id,
                "status": "completed",
                "inputDigest": input_digest,
                "outcomes": outcomes,
            }
            cursor.execute(
                """UPDATE evaluations SET commit_hash = %s, commit_response = %s, receipts = %s
                   WHERE evaluation_id = %s""",
                (commit_hash, Jsonb(response), Jsonb(receipts), evaluation_id),
            )
    return ok(response)


def handle(body):
    try:
        operation = validate_envelope(body)
        return handle_propose(body) if operation == "propose" else handle_commit(body)
    except ApiError as exc:
        return error(exc.status, exc.code)


async def endpoint(request: Request):
    length = request.headers.get("content-length")
    if length and length.isdigit() and int(length) > MAX_BODY_BYTES:
        return error(413, "BODY_TOO_LARGE")
    raw = await request.body()
    if len(raw) > MAX_BODY_BYTES:
        return error(413, "BODY_TOO_LARGE")
    try:
        body = json.loads(raw)
    except Exception:
        return error(400, "INVALID_JSON")
    if not isinstance(body, dict):
        return error(400, "INVALID_REQUEST")
    return await run_in_threadpool(handle, body)


app.add_api_route("/", endpoint, methods=["POST"])
app.add_api_route("/mailroom", endpoint, methods=["POST"])


@app.get("/")
def health():
    return {"ok": True}
