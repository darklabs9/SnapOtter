import { randomUUID } from "node:crypto";
import { eq } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { db, schema } from "../../../apps/api/src/db/index.js";
import { hashPassword } from "../../../apps/api/src/plugins/auth.js";

const originalLastAdmin = await vi.importActual("../../../apps/api/src/lib/last-admin.js");

let interceptFn: ((tx: any, id: string) => Promise<void>) | null = null;

vi.doMock("../../../apps/api/src/lib/last-admin.js", () => {
  return {
    ...(originalLastAdmin as any),
    assertNotLastAdmin: async (tx: any, id: string) => {
      if (interceptFn) {
        await interceptFn(tx, id);
      }
      return (originalLastAdmin as any).assertNotLastAdmin(tx, id);
    },
  };
});

let testApp: any;

beforeAll(async () => {
  vi.resetModules();
  const { mockEnterpriseFeatures } = await import("../../helpers/enterprise-mock.js");
  mockEnterpriseFeatures(["scim"]);
  const ts = await import("../test-server.js");
  testApp = await ts.buildTestApp();
});

afterAll(async () => {
  await testApp.cleanup();
});

describe("Stale role reads during concurrent operations", () => {
  it("SCIM deactivation preserves the concurrent role change", async () => {
    const userId = randomUUID();
    const [team] = await db.select().from(schema.teams).limit(1);
    await db.insert(schema.users).values({
      id: userId,
      username: `scim-race-admin-${userId}`,
      passwordHash: await hashPassword("password"),
      role: "admin",
      team: team.id,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const SCIM_TOKEN = `so_scim_v2_${"b".repeat(64)}`;
    const tokenHash = await hashPassword(SCIM_TOKEN);
    await db
      .insert(schema.settings)
      .values({ key: "scim_token_hash", value: tokenHash })
      .onConflictDoUpdate({ target: schema.settings.key, set: { value: tokenHash } });

    let resolveBlocked: () => void;
    const blocked = new Promise<void>((r) => {
      resolveBlocked = r;
    });
    let fired = false;

    interceptFn = async (tx, id) => {
      if (id === userId && !fired) {
        fired = true;
        await db.update(schema.users).set({ role: "editor" }).where(eq(schema.users.id, userId));
        resolveBlocked();
      }
    };

    const scimPromise = testApp.app.inject({
      method: "PUT",
      url: `/api/v1/scim/v2/Users/${userId}`,
      headers: { authorization: `Bearer ${SCIM_TOKEN}` },
      payload: {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
        userName: `scim-race-admin-${userId}`,
        active: false,
      },
    });

    await blocked;
    const response = await scimPromise;
    expect(response.statusCode).toBe(200);

    const [userAfter] = await db.select().from(schema.users).where(eq(schema.users.id, userId));
    expect(userAfter.role).toBe("disabled:editor");

    interceptFn = null;
  });

  it("admin demoted during request loses authority for the action", async () => {
    const admin2Id = randomUUID();
    const [team] = await db.select().from(schema.teams).limit(1);
    await db.insert(schema.users).values({
      id: admin2Id,
      username: `admin2-${admin2Id}`,
      passwordHash: await hashPassword("password"),
      role: "admin",
      team: team.id,
      createdAt: new Date(),
      updatedAt: new Date(),
      mustChangePassword: false,
    });

    const targetUserId = randomUUID();
    await db.insert(schema.users).values({
      id: targetUserId,
      username: `target-${targetUserId}`,
      passwordHash: await hashPassword("password"),
      role: "user",
      team: team.id,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const loginRes = await testApp.app.inject({
      method: "POST",
      url: "/api/auth/login",
      payload: { username: `admin2-${admin2Id}`, password: "password" },
    });
    const admin2Token = loginRes.cookies?.find((c: any) => c.name === "snapotter-session")?.value;

    let resolveBlocked: () => void;
    const blocked = new Promise<void>((r) => {
      resolveBlocked = r;
    });
    let fired = false;

    interceptFn = async (tx, id) => {
      if (id === targetUserId && !fired) {
        fired = true;
        await db.update(schema.users).set({ role: "user" }).where(eq(schema.users.id, admin2Id));
        resolveBlocked();
      }
    };

    const adminPromise = testApp.app.inject({
      method: "PUT",
      url: `/api/auth/users/${targetUserId}`,
      headers: { cookie: `snapotter-session=${admin2Token}` },
      payload: { role: "editor" },
    });

    await blocked;
    const response = await adminPromise;

    expect(response.statusCode).toBe(403);

    const [targetAfter] = await db
      .select()
      .from(schema.users)
      .where(eq(schema.users.id, targetUserId));
    expect(targetAfter.role).toBe("user");

    interceptFn = null;
  });

  it("SCIM DELETE preserves the concurrent role change", async () => {
    const userId = randomUUID();
    const [team] = await db.select().from(schema.teams).limit(1);
    await db.insert(schema.users).values({
      id: userId,
      username: `scim-del-admin-${userId}`,
      passwordHash: await hashPassword("password"),
      role: "admin",
      team: team.id,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const SCIM_TOKEN = `so_scim_v2_${"b".repeat(64)}`;
    const tokenHash = await hashPassword(SCIM_TOKEN);
    await db
      .insert(schema.settings)
      .values({ key: "scim_token_hash", value: tokenHash })
      .onConflictDoUpdate({ target: schema.settings.key, set: { value: tokenHash } });

    let resolveBlocked: () => void;
    const blocked = new Promise<void>((r) => {
      resolveBlocked = r;
    });
    let fired = false;

    interceptFn = async (tx, id) => {
      if (id === userId && !fired) {
        fired = true;
        await db.update(schema.users).set({ role: "editor" }).where(eq(schema.users.id, userId));
        resolveBlocked();
      }
    };

    const scimPromise = testApp.app.inject({
      method: "DELETE",
      url: `/api/v1/scim/v2/Users/${userId}`,
      headers: { authorization: `Bearer ${SCIM_TOKEN}` },
    });

    await blocked;
    const response = await scimPromise;
    expect(response.statusCode).toBe(204);

    const [userAfter] = await db.select().from(schema.users).where(eq(schema.users.id, userId));
    expect(userAfter.role).toBe("disabled:editor");

    interceptFn = null;
  });

  it("admin demoted during DELETE request loses authority for the action", async () => {
    const admin2Id = randomUUID();
    const [team] = await db.select().from(schema.teams).limit(1);
    await db.insert(schema.users).values({
      id: admin2Id,
      username: `admin2-del-${admin2Id}`,
      passwordHash: await hashPassword("password"),
      role: "admin",
      team: team.id,
      createdAt: new Date(),
      updatedAt: new Date(),
      mustChangePassword: false,
    });

    const targetUserId = randomUUID();
    await db.insert(schema.users).values({
      id: targetUserId,
      username: `target-del-${targetUserId}`,
      passwordHash: await hashPassword("password"),
      role: "user",
      team: team.id,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const loginRes = await testApp.app.inject({
      method: "POST",
      url: "/api/auth/login",
      payload: { username: `admin2-del-${admin2Id}`, password: "password" },
    });
    const admin2Token = loginRes.cookies?.find((c: any) => c.name === "snapotter-session")?.value;

    let resolveBlocked: () => void;
    const blocked = new Promise<void>((r) => {
      resolveBlocked = r;
    });
    let fired = false;

    interceptFn = async (tx, id) => {
      if (id === targetUserId && !fired) {
        fired = true;
        await db.update(schema.users).set({ role: "user" }).where(eq(schema.users.id, admin2Id));
        resolveBlocked();
      }
    };

    const adminPromise = testApp.app.inject({
      method: "DELETE",
      url: `/api/auth/users/${targetUserId}`,
      headers: { cookie: `snapotter-session=${admin2Token}` },
    });

    await blocked;
    const response = await adminPromise;

    expect(response.statusCode).toBe(403);

    const [targetAfter] = await db
      .select()
      .from(schema.users)
      .where(eq(schema.users.id, targetUserId));
    expect(targetAfter.role).toBe("user"); // Still exists and not deleted

    interceptFn = null;
  });
});
