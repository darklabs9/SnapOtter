import re

with open("apps/api/src/db/migrate-from-sqlite.ts", "r") as f:
    content = f.read()

# I will add repairOidcEmailLinks function and call it right after moveScimExternalIds
repair_function = """
async function repairOidcEmailLinks(tx: { execute: typeof db.execute }, detached: DetachedIdentity[]): Promise<void> {
  // First, find 'local' rows with external_id that collide with an existing 'oidc' row.
  // This happens if the user signed in later and a new OIDC row was created.
  const collisions = await tx.execute(
    sql`SELECT u1.id, u1.username, u1.external_id, u2.username as kept_by_username, u2.id as kept_by_id
        FROM users u1
        JOIN users u2 ON u1.external_id = u2.external_id AND u2.auth_provider = 'oidc'
        WHERE u1.auth_provider = 'local' AND u1.external_id IS NOT NULL`
  );
  
  for (const row of collisions.rows) {
    const r = row as any;
    detached.push({
      id: r.id,
      username: r.username,
      externalId: r.external_id,
      authProvider: "oidc", // It's an OIDC identity that couldn't be claimed
      keptBy: { id: r.kept_by_id, username: r.kept_by_username }
    });
  }

  // Clear external_id on the colliding local rows so the index doesn't conflict
  await tx.execute(
    sql`UPDATE users 
        SET external_id = NULL 
        WHERE auth_provider = 'local' AND external_id IS NOT NULL 
        AND external_id IN (SELECT external_id FROM users WHERE auth_provider = 'oidc')`
  );

  // For the remaining 'local' rows with external_id (no collision), they are genuine 
  // 1.x auto-links. Update their auth_provider to 'oidc'.
  await tx.execute(
    sql`UPDATE users 
        SET auth_provider = 'oidc' 
        WHERE auth_provider = 'local' AND external_id IS NOT NULL`
  );
}
"""

content = content.replace("async function moveScimExternalIds", repair_function + "\nasync function moveScimExternalIds")
content = content.replace("await moveScimExternalIds(tx);", "await moveScimExternalIds(tx);\n      await repairOidcEmailLinks(tx, detached);")

with open("apps/api/src/db/migrate-from-sqlite.ts", "w") as f:
    f.write(content)
