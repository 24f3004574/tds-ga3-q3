"""Run AFTER a real Check. Prints action counts, the vocabulary of source kinds /
provenance values, and writes dossiers_dump.txt (dossier text + our decision)."""
from dotenv import load_dotenv; load_dotenv()
import os, collections, json, psycopg

with psycopg.connect(os.environ["POSTGRES_URL"]) as c, c.cursor() as cur:
    cur.execute("SELECT dossier_id, proposal, dossier FROM mailroom_decisions ORDER BY created_at")
    rows = cur.fetchall()

actions, kinds, provs, out = collections.Counter(), collections.Counter(), collections.Counter(), []
for dossier_id, proposal, dossier in rows:
    actions[proposal["action"]] += 1
    for s in dossier["sources"]:
        kinds[s.get("kind")] += 1; provs[s.get("provenance")] += 1
    out.append("=" * 80)
    out.append(f'{dossier_id} | mailbox={dossier.get("mailbox")} | objective={dossier.get("objective")}')
    for s in dossier["sources"]:
        out.append(f'  [{s["sourceId"]}] kind={s.get("kind")} provenance={s.get("provenance")} title={s.get("title")}')
        for l in s["lines"]:
            out.append(f'      {l["lineId"]}: {l["text"][:300]}')
    out.append("  OUR ANSWER: " + json.dumps({k: proposal[k] for k in ("action", "target", "payload", "evidence")}))

print("decisions stored:", len(rows))
print("actions:", dict(actions))
print("source kinds:", dict(kinds))
print("provenance values:", dict(provs))
open("dossiers_dump.txt", "w", encoding="utf-8").write("\n".join(out))
print("wrote dossiers_dump.txt")
