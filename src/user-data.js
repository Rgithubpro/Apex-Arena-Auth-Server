// ---------------------------------------------------------------------------
// Tables (besides the auth_ ones) that hold data belonging to ONE player.
// Deleting an account also deletes the matching rows of every table listed
// here, in the same database transaction, so nothing is left behind.
//
// Add an entry whenever you create a table with per-player data, e.g.
//   { table: 'player_progress', column: 'user_id' }
// The column must hold the player's auth id (user.id / the token's "sub").
// ---------------------------------------------------------------------------
export const USER_DATA_TABLES = [];

const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/;

export function userDataDeleteStatements(userId) {
  return USER_DATA_TABLES.map(({ table, column }) => {
    // Names are put into the SQL text, so they must be plain identifiers.
    if (!IDENTIFIER.test(table) || !IDENTIFIER.test(column)) {
      throw new Error(`Invalid entry in USER_DATA_TABLES: ${table}.${column}`);
    }
    return { sql: `DELETE FROM ${table} WHERE ${column} = ?`, args: [userId] };
  });
}
