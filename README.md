# IBM Confidential Computing Contract Manager

A persona-governed, cryptographically auditable contract lifecycle system for IBM Hyper Protect Container Runtime (HPCR) deployments.

---

## Prerequisites

| Requirement | Minimum version |
|---|---|
| Docker Engine | 20.10+ |
| Docker Compose plugin | v2.0+ |
| Git | any |
| RAM | 2 GB |
| Disk | 5 GB |

No Go toolchain is required on the host — the image is built inside a multi-stage Docker build.

---

## Self-Hosting (Fresh VM)

### 1. Clone the repository

```bash
git clone <repository-url>
cd contract-manager
```

### 2. Create your environment file

All configuration lives in `compose/.env`. Copy the example and fill in the required values:

```bash
cp compose/.env.example compose/.env
```

Open `compose/.env` and set **at minimum** the four required fields (the compose file will refuse to start without them):

```bash
# Required — pick strong unique values
POSTGRES_PASSWORD=<strong-password>
ADMIN_NAME=System Admin
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=<strong-password>
```

> All other values have working defaults. See [`compose/.env.example`](compose/.env.example) for the full reference.

### 3. Build the backend image

The `contract-manager:local` image does not exist in any registry — it must be built from source:

```bash
docker build -t contract-manager:local .
```

This runs a two-stage build: compiles the Go binary and the `migrate` tool inside the builder stage, then copies them into a minimal Alpine runtime image. Expect 2–5 minutes on first run (module download + compile); subsequent builds use the layer cache.

### 4. Start all services

```bash
docker compose -f compose/docker-compose.yaml --project-directory compose up -d
```

This starts five containers in dependency order:
1. **`hpcr-postgres`** — PostgreSQL 16 database
2. **`hpcr-migrate`** — runs all schema migrations then exits
3. **`hpcr-backend`** — Go API server (waits for migrate to complete)
4. **`hpcr-reverse-proxy`** — nginx reverse proxy (waits for backend healthy)
5. **`hpcr-pgadmin`** — pgAdmin 4 web UI

### 5. Verify the stack

```bash
# All four long-running containers should show "healthy"
docker compose -f compose/docker-compose.yaml --project-directory compose ps

# Backend health endpoint
curl http://localhost:8080/health
# Expected: {"status":"ok"}
```

---

## Default Access

| Interface | URL | Default credentials |
|---|---|---|
| API / App | `http://localhost:8080` | `ADMIN_EMAIL` / `ADMIN_PASSWORD` from `.env` |
| pgAdmin | `http://localhost:5050` | `PGADMIN_DEFAULT_EMAIL` / `PGADMIN_DEFAULT_PASSWORD` from `.env` |
| Swagger UI | `http://localhost:8080/swagger` | — |

> **First login:** Every new account (including the seeded admin) must complete a mandatory setup flow before accessing any functionality: change the initial password, generate an RSA-4096 key pair, and register the public key.

Each client may register its own identity key: at most five active RSA-4096 keys per user, each valid for 90 days. Later registrations require password confirmation and, while an active key exists, a request signed with that key. Owners and admins can revoke individual keys; admins can also revoke all active keys. See the [API reference](docs/api-reference.md#put-usersidpublic-key) and [multi-key testing guide](docs/multi-key-testing.md).

Existing clients remain compatible for normal use with one active key. Clients must update their registration flow before renewing keys or adding devices, and select the local key's fingerprint for signed requests instead of using the newest key returned by login.

---

## Day-to-Day Operations

### Rebuild after code changes

```bash
docker build -t contract-manager:local . \
  && docker compose -f compose/docker-compose.yaml --project-directory compose up -d --no-deps backend
```

### View logs

```bash
# All services
docker compose -f compose/docker-compose.yaml --project-directory compose logs -f

# Single service
docker compose -f compose/docker-compose.yaml --project-directory compose logs -f backend
```

### Stop the stack

```bash
docker compose -f compose/docker-compose.yaml --project-directory compose down
```

### Full reset (destroys all data)

```bash
docker compose -f compose/docker-compose.yaml --project-directory compose down -v
sudo rm -rf compose/data/postgres
```

### Access the database directly

```bash
docker compose -f compose/docker-compose.yaml --project-directory compose \
  exec postgres psql -U hpcr hpcr_builder
```

---

## Project Layout

```
.
├── cmd/server/             # Main entrypoint — wires services, builds router
├── internal/
│   ├── config/             # Environment variable config
│   ├── contract/           # Engine interface + contract-go v2 implementation
│   ├── handler/            # HTTP handlers (writeJSON / writeError)
│   ├── keymgmt/            # KeyProvider interface; db implementation
│   ├── middleware/         # Auth, RBAC, signature, rate-limit, setup guard
│   ├── model/              # Domain types + AppError constructors
│   ├── repository/         # SQLC-generated DB layer (do not edit *.sql.go)
│   ├── repository/queries/ # SQL source files — edit these, then run sqlc generate
│   └── service/            # Business logic
├── migrations/             # golang-migrate SQL files (020 migrations)
├── compose/
│   ├── docker-compose.yaml # Stack definition
│   ├── .env.example        # Config template — copy to .env
│   └── config/nginx/       # nginx default.conf and tls.conf
├── Dockerfile              # Multi-stage build: Go builder → Alpine runtime
└── .dockerignore           # Excludes compose/data/, .bob/, .git/
```

---

## Services and Ports

| Container | Image | Exposed port | Purpose |
|---|---|---|---|
| `hpcr-reverse-proxy` | `nginx:1.27-alpine` | `8080` → 80 | Reverse proxy, rate limiting, TLS termination |
| `hpcr-backend` | `contract-manager:local` | internal 8080 | Go API server |
| `hpcr-postgres` | `postgres:16-alpine` | internal 5432 | PostgreSQL database |
| `hpcr-migrate` | `contract-manager:local` | — | Schema migration runner (exits on completion) |
| `hpcr-pgadmin` | `dpage/pgadmin4:9` | `5050` → 80 | Database management UI |

---

## Configuration Reference

All variables are set in `compose/.env`. The table below lists those that **must** be changed from the example defaults before first run:

| Variable | Required | Description |
|---|---|---|
| `POSTGRES_PASSWORD` | ✅ | PostgreSQL password for the `hpcr` user |
| `ADMIN_NAME` | ✅ | Display name for the seeded admin account |
| `ADMIN_EMAIL` | ✅ | Email for the seeded admin account |
| `ADMIN_PASSWORD` | ✅ | Initial password for the seeded admin account |
| `DATABASE_URL` | ✅ | Full postgres DSN — must match `POSTGRES_*` values |
| `MIGRATE_DATABASE_URL` | ✅ | Same DSN used by the migration runner |
| `PGADMIN_DEFAULT_PASSWORD` | recommended | pgAdmin login password |

> `DATABASE_URL` and `MIGRATE_DATABASE_URL` in `.env.example` use `${POSTGRES_*}` variable interpolation — if your shell or Docker Compose version does not expand these, set them explicitly as literal strings.

---

## Development

### Run tests

```bash
go test ./cmd/... ./internal/...
```

### Lint / vet

```bash
go vet ./cmd/... ./internal/...
gofmt -w .
```

### Regenerate SQLC repository layer

After editing any `.sql` file under `internal/repository/queries/`:

```bash
sqlc generate
```

> Never edit `internal/repository/*.sql.go` directly — they are overwritten by `sqlc generate`.

---

## Troubleshooting

**`pull access denied for contract-manager`**
The image must be built locally first. Run step 3 above (`docker build -t contract-manager:local .`).

**`POSTGRES_PASSWORD must be set` / `ADMIN_PASSWORD must be set`**
The compose file enforces these with `:?`. Copy `.env.example` to `.env` and fill in the required fields.

**`hpcr-migrate` exits with non-zero / backend won't start**
```bash
docker compose -f compose/docker-compose.yaml --project-directory compose logs migrate
```
A migration failure (e.g. dirty state from a previous partial run) will block the backend. To reset:
```bash
docker compose -f compose/docker-compose.yaml --project-directory compose down -v
sudo rm -rf compose/data/postgres
docker compose -f compose/docker-compose.yaml --project-directory compose up -d
```

**`/health` returns 429**
This should not happen — the `/health` endpoint is registered outside the rate-limited middleware group. If you see it, ensure you are running the image built from the current source.

**`compose/data/postgres` permission errors**
The postgres data directory is written by the postgres container running as its internal UID. If you see permission errors after a `sudo rm -rf`, recreate the directory:
```bash
mkdir -p compose/data/postgres
```
Docker will repopulate it on next start.
