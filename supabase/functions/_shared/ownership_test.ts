// Unit tests for the ownership-index writes. Exercises recordOwnership against
// an in-memory fake of the bits of SupabaseClient it uses — no live services.

import { assertEquals } from "@std/assert";
import { evidenceIdInRefs, recordOwnership } from "./ownership.ts";

interface CredRow {
  user_id: string;
  credential_id: string;
  beltic_org: string;
  environment: string;
  status: string;
}

class FakeDb {
  creds: CredRow[] = [];
  // deno-lint-ignore no-explicit-any
  from(table: string): any {
    if (table === "user_credentials") return new CredQuery(this);
    throw new Error(`unexpected table ${table}`);
  }
}

class CredQuery {
  constructor(private db: FakeDb) {}
  // deno-lint-ignore no-explicit-any
  upsert(row: any) {
    const idx = this.db.creds.findIndex(
      (r) =>
        r.credential_id === row.credential_id &&
        r.beltic_org === row.beltic_org &&
        r.environment === row.environment,
    );
    if (idx >= 0) this.db.creds[idx] = { ...this.db.creds[idx], ...row };
    else this.db.creds.push(row);
    return Promise.resolve({ error: null });
  }
}

Deno.test("recordOwnership inserts an active row for the user", async () => {
  const db = new FakeDb();
  // deno-lint-ignore no-explicit-any
  await recordOwnership(db as any, "user_1", "acme", "staging", "cred_1");
  assertEquals(db.creds.length, 1);
  assertEquals(db.creds[0].user_id, "user_1");
  assertEquals(db.creds[0].credential_id, "cred_1");
  assertEquals(db.creds[0].status, "active");
});

Deno.test("evidenceIdInRefs matches bare, prefixed, and rejects unbound", () => {
  assertEquals(evidenceIdInRefs(["ev_1", "ev_2"], "ev_1"), true);
  assertEquals(evidenceIdInRefs(["evidence:ev_1"], "ev_1"), true);
  assertEquals(evidenceIdInRefs(["sha256:abc:ev_1"], "ev_1"), true);
  assertEquals(evidenceIdInRefs(["ev_1"], "ev_2"), false); // unbound → denied
  assertEquals(evidenceIdInRefs([], "ev_1"), false);
});

Deno.test("recordOwnership is idempotent on re-issue/retry", async () => {
  const db = new FakeDb();
  // deno-lint-ignore no-explicit-any
  await recordOwnership(db as any, "user_1", "acme", "staging", "cred_1");
  // deno-lint-ignore no-explicit-any
  await recordOwnership(db as any, "user_1", "acme", "staging", "cred_1");
  assertEquals(db.creds.length, 1); // converges to one row, not two
  assertEquals(db.creds[0].status, "active");
});
