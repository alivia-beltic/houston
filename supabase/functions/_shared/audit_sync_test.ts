// Unit tests for the audit-sync logic. These exercise the pure event->upsert
// translation and the cursor-advance loop against an in-memory fake of the
// Supabase client + a stubbed Beltic feed — no live services.

import { assertEquals } from "@std/assert";
import {
  applyEvent,
  type BelticAuditEvent,
  type BelticAuditPage,
  syncAuditEvents,
} from "./audit_sync.ts";
import type { BelticConfig } from "./beltic.ts";

// --- minimal in-memory fake of the bits of SupabaseClient we use ----------

interface CredRow {
  user_id: string;
  credential_id: string;
  beltic_org: string;
  environment: string;
  status: string;
}

class FakeDb {
  creds: CredRow[] = [];
  cursor: { last_cursor: string | null } | null = null;

  // deno-lint-ignore no-explicit-any
  from(table: string): any {
    if (table === "user_credentials") return new CredQuery(this);
    if (table === "beltic_audit_sync") return new CursorQuery(this);
    throw new Error(`unexpected table ${table}`);
  }
}

class CredQuery {
  constructor(private db: FakeDb) {}
  private filters: Record<string, string> = {};

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

  // deno-lint-ignore no-explicit-any
  update(patch: any) {
    this._patch = patch;
    return this;
  }
  private _patch: Record<string, string> = {};

  eq(col: string, val: string) {
    this.filters[col] = val;
    // update path resolves on the final eq via thenable
    return this;
  }

  // make the update chain awaitable
  then(resolve: (v: { error: null }) => void) {
    for (const r of this.db.creds) {
      if (
        r.credential_id === this.filters["credential_id"] &&
        r.beltic_org === this.filters["beltic_org"] &&
        r.environment === this.filters["environment"]
      ) {
        Object.assign(r, this._patch);
      }
    }
    resolve({ error: null });
  }
}

class CursorQuery {
  constructor(private db: FakeDb) {}
  select() {
    return this;
  }
  eq() {
    return this;
  }
  maybeSingle() {
    return Promise.resolve({ data: this.db.cursor, error: null });
  }
  // deno-lint-ignore no-explicit-any
  upsert(row: any) {
    this.db.cursor = { last_cursor: row.last_cursor };
    return Promise.resolve({ error: null });
  }
}

const config: BelticConfig = {
  apiKey: "k",
  baseUrl: "https://beltic.test",
  org: "acme",
};

Deno.test("credential.issued upserts an active ownership row", async () => {
  const db = new FakeDb();
  const event: BelticAuditEvent = {
    type: "credential.issued",
    credential_id: "cred_1",
    subject: "user_1",
  };
  // deno-lint-ignore no-explicit-any
  const applied = await applyEvent(db as any, "acme", "staging", event);
  assertEquals(applied, true);
  assertEquals(db.creds.length, 1);
  assertEquals(db.creds[0].status, "active");
  assertEquals(db.creds[0].user_id, "user_1");
});

Deno.test("credential.revoked marks the row revoked (not deleted)", async () => {
  const db = new FakeDb();
  db.creds.push({
    user_id: "user_1",
    credential_id: "cred_1",
    beltic_org: "acme",
    environment: "staging",
    status: "active",
  });
  // deno-lint-ignore no-explicit-any
  await applyEvent(db as any, "acme", "staging", {
    type: "credential.revoked",
    credential_id: "cred_1",
    subject: "user_1",
  });
  assertEquals(db.creds.length, 1);
  assertEquals(db.creds[0].status, "revoked");
});

Deno.test("unknown event types are skipped", async () => {
  const db = new FakeDb();
  // deno-lint-ignore no-explicit-any
  const applied = await applyEvent(db as any, "acme", "staging", {
    type: "credential.viewed",
    credential_id: "cred_1",
    subject: "user_1",
  });
  assertEquals(applied, false);
  assertEquals(db.creds.length, 0);
});

Deno.test("syncAuditEvents drains pages and advances the cursor", async () => {
  const db = new FakeDb();
  const pages: BelticAuditPage[] = [
    {
      events: [
        { type: "credential.issued", credential_id: "c1", subject: "u1" },
        { type: "credential.issued", credential_id: "c2", subject: "u2" },
      ],
      next_cursor: "cur1",
    },
    {
      events: [
        { type: "credential.revoked", credential_id: "c1", subject: "u1" },
      ],
      next_cursor: null,
    },
  ];
  let call = 0;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (): Promise<Response> => {
    const page = pages[Math.min(call, pages.length - 1)];
    call++;
    return Promise.resolve(
      new Response(JSON.stringify(page), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
  };

  try {
    // deno-lint-ignore no-explicit-any
    const result = await syncAuditEvents(db as any, config, "staging");
    assertEquals(result.pagesFetched, 2);
    assertEquals(result.eventsApplied, 3);
    assertEquals(result.finalCursor, "cur1");
    // c1 issued then revoked, c2 active.
    const c1 = db.creds.find((r) => r.credential_id === "c1");
    const c2 = db.creds.find((r) => r.credential_id === "c2");
    assertEquals(c1?.status, "revoked");
    assertEquals(c2?.status, "active");
    assertEquals(db.cursor?.last_cursor, "cur1");
  } finally {
    globalThis.fetch = originalFetch;
  }
});
