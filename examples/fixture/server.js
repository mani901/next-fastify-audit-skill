// Fixture: intentionally vulnerable Fastify server.
// Planted issues: CORS wildcard (SEC-007), hardcoded JWT secret (SEC-006),
// routes without schema validation (SEC-008), no auth on routes (SEC-009),
// SQL string concatenation (SEC-004), eval (SEC-003), no compression (PERF-003),
// N+1 query loop (PERF-002), error leak (API-001).

const fastify = require('fastify')({ logger: true });
const jwt = require('jsonwebtoken');

fastify.register(require('@fastify/cors'), { origin: '*' });

fastify.post('/login', async (req, reply) => {
  const { email, password } = req.body;
  const token = jwt.sign({ email }, 'secret123');
  return reply.send({ token });
});

fastify.get('/users/:id', async (req, reply) => {
  const query = 'SELECT * FROM users WHERE id = ' + req.params.id;
  const user = await req.db.query(query);
  return reply.send(user);
});

fastify.get('/users', async (req, reply) => {
  const ids = [1, 2, 3];
  const users = [];
  for (const id of ids) {
    const user = await req.db.query('SELECT * FROM users WHERE id = $1', [id]);
    users.push(user);
  }
  return reply.send(users);
});

fastify.post('/run', async (req, reply) => {
  const result = eval(req.body.code);
  return reply.send({ result });
});

fastify.setErrorHandler((error, req, reply) => {
  reply.status(500).send({ error: error });
});

fastify.listen({ port: 3000 });
