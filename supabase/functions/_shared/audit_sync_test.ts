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

Deno.test("credential.issued is skipped — no subject id in the audit feed", async () => {
  // The feed exposes subject_type only; ownership is established at proxy time,
  // so the poller cannot create an ownership row on issue.
  const db = new FakeDb();
  const event: BelticAuditEvent = {
    event_type: "credential.issued",
    credential_id: "cred_1",
    subject_type: "user",
  };
  // deno-lint-ignore no-explicit-any
  const applied = await applyEvent(db as any, "acme", "staging", event);
  assertEquals(applied, false);
  assertEquals(db.creds.length, 0);
});

Deno.test("credential.revoked marks an existing row revoked (not deleted)", async () => {
  // Revoke keys on credential_id alone — no subject needed. The row was
  // created earlier at proxy time.
  const db = new FakeDb();
  db.creds.push({
    user_id: "user_1",
    credential_id: "cred_1",
    beltic_org: "acme",
    environment: "staging",
    status: "active",
  });
  // deno-lint-ignore no-explicit-any
  const applied = await applyEvent(db as any, "acme", "staging", {
    event_type: "credential.revoked",
    credential_id: "cred_1",
    subject_type: "user",
  });
  assertEquals(applied, true);
  assertEquals(db.creds.length, 1);
  assertEquals(db.creds[0].status, "revoked");
});

Deno.test("unknown event types are skipped", async () => {
  const db = new FakeDb();
  // deno-lint-ignore no-explicit-any
  const applied = await applyEvent(db as any, "acme", "staging", {
    event_type: "credential.viewed",
    credential_id: "cred_1",
    subject_type: "user",
  });
  assertEquals(applied, false);
  assertEquals(db.creds.length, 0);
});

Deno.test("syncAuditEvents drains pages, advances cursor, applies revokes, skips issues", async () => {
  // c1 was created at proxy time; the feed then issues c2 (skipped) and revokes
  // c1 (applied). Only the revoke counts toward eventsApplied.
  const db = new FakeDb();
  db.creds.push({
    user_id: "user_1",
    credential_id: "c1",
    beltic_org: "acme",
    environment: "staging",
    status: "active",
  });
  const pages: BelticAuditPage[] = [
    {
      events: [
        {
          event_type: "credential.issued",
          credential_id: "c2",
          subject_type: "user",
        },
      ],
      next_cursor: "cur1",
    },
    {
      events: [
        {
          event_type: "credential.revoked",
          credential_id: "c1",
          subject_type: "user",
        },
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
    assertEquals(result.eventsApplied, 1); // only the revoke
    assertEquals(result.finalCursor, "cur1");
    // c1 revoked; c2 issue was skipped (no row created).
    const c1 = db.creds.find((r) => r.credential_id === "c1");
    const c2 = db.creds.find((r) => r.credential_id === "c2");
    assertEquals(c1?.status, "revoked");
    assertEquals(c2, undefined);
    assertEquals(db.cursor?.last_cursor, "cur1");
  } finally {
    globalThis.fetch = originalFetch;
  }
});
