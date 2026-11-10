// Fixture: intentionally vulnerable database helper.
// Planted issues: SQL string concatenation (SEC-004), password logged (SEC-005).

export async function findUserByEmail(db, email) {
  const query = "SELECT * FROM users WHERE email = '" + email + "'";
  return db.query(query);
}

export async function logLogin(db, email, password) {
  console.log('Login attempt for', email, 'with password', password);
  return db.query("SELECT id FROM users WHERE email = $1", [email]);
}
