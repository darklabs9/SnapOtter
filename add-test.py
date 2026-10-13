import re

with open("tests/integration/platform/migrate-from-sqlite.test.ts", "r") as f:
    content = f.read()

test_code = """
  describe("OIDC email auto-link leftover repair", () => {
    const oidcDir = mkdtempSync(join(tmpdir(), "snapotter-migrator-oidc-"));
    const oidcSqlitePath = join(oidcDir, "snapotter-1x-oidc.db");

    beforeAll(async () => {
      const s = new Database(oidcSqlitePath);
      s.exec(`
        CREATE TABLE users (id text PRIMARY KEY, username text NOT NULL, password_hash text,
          role text NOT NULL DEFAULT 'user', team text NOT NULL DEFAULT 'Default',
          must_change_password integer NOT NULL DEFAULT 1, auth_provider text NOT NULL DEFAULT 'local',
          external_id text, email text, created_at integer NOT NULL, updated_at integer NOT NULL);
      `);
      const now = 1750000000;
      const insert = s.prepare(
        "INSERT INTO users (id, username, password_hash, auth_provider, external_id, email, created_at, updated_at, must_change_password) VALUES (?,?,?,?,?,?,?,?,0)",
      );
      // Normal OIDC link from 1.17.2: auth_provider='local', external_id='sub123'
      insert.run("u-linked", "linked", "hash", "local", "sub123", "linked@example.com", now, now);
      
      // Collision case: auto-link left behind on 'local', but user later signed in again without
      // auto-link, creating a brand new 'oidc' row with the same subject.
      insert.run("u-local", "collided-local", "hash", "local", "sub456", "collision@example.com", now, now);
      insert.run("u-oidc", "collided-oidc", null, "oidc", "sub456", "collision@example.com", now, now);
      s.close();
      await truncateMigratedTables();
    });

    it("updates auth_provider to oidc for leftover auto-links, avoiding collisions", async () => {
      await migrateFromSqlite(oidcSqlitePath, { force: false });
      
      const linked = (await db.execute(sql`SELECT auth_provider, external_id FROM users WHERE id = 'u-linked'`)).rows[0];
      expect(linked).toEqual({ auth_provider: "oidc", external_id: "sub123" });

      const collided = (await db.execute(sql`SELECT auth_provider, external_id FROM users WHERE id = 'u-local'`)).rows[0];
      expect(collided).toEqual({ auth_provider: "local", external_id: null }); // cleared
    });
  });
"""

# Replace the last }); with our test block followed by });
new_content = re.sub(r'}\);\s*$', test_code + '});\n', content)

with open("tests/integration/platform/migrate-from-sqlite.test.ts", "w") as f:
    f.write(new_content)
