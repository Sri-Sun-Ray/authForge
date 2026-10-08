# Deploying AuthForge

Postgres on [Neon](https://neon.tech), Redis on [Upstash](https://upstash.com), the API on
[Google Cloud Run](https://cloud.google.com/run). All three have free tiers that cover a
project of this size. Budget about an hour the first time.

Nothing secret is ever written to a file in the repo: connection strings and signing keys
go into Google Secret Manager, and Cloud Run reads them at startup.

---

## 1. Postgres (Neon)

1. Sign up at **neon.tech** and create a project (region: Singapore or Mumbai).
2. Open **Dashboard → Connection string** and copy it. It looks like:
   ```
   postgresql://neondb_owner:PASSWORD@ep-xxx.ap-southeast-1.aws.neon.tech/neondb?sslmode=require
   ```
3. Use the **direct** connection string, not the one with `-pooler` in the host.

   Neon's pooled endpoint runs PgBouncer in transaction mode, which breaks asyncpg's
   prepared statements. The direct endpoint avoids that; this service keeps its own
   small pool (`DB_POOL_SIZE`) instead.

## 2. Redis (Upstash)

1. Sign up at **upstash.com** → create a Redis database (same region as above).
2. Copy the **`rediss://`** URL — TLS, not the plain `redis://` one.

## 3. Google Cloud

1. Create a project at **console.cloud.google.com** and enable billing (Cloud Run's free
   tier covers this, but a billing account must exist).
2. Install the gcloud CLI, then:
   ```powershell
   gcloud auth login
   gcloud config set project YOUR_PROJECT_ID
   ```

## 4. Store the secrets

```powershell
./scripts/setup-secrets.ps1 -ProjectId YOUR_PROJECT_ID
```

It enables the needed APIs, asks for the two connection strings, generates the app
database password and the JWT keys if they don't exist, stores all six secrets, and
grants Cloud Run permission to read them.

It also rewrites the Neon URL for asyncpg: `postgresql://` → `postgresql+asyncpg://` and
`sslmode=require` → `ssl=require`, because asyncpg does not understand libpq's `sslmode`.

Two database users are stored, as locally:

| Secret | Role | Used for |
| --- | --- | --- |
| `authforge-database-admin-url` | Neon owner | migrations only |
| `authforge-database-url` | `authforge_app` | the API — cannot bypass row-level security |

The app role is created by a migration using `APP_DB_PASSWORD`.

## 5. Deploy

```powershell
./scripts/deploy.ps1 -ProjectId YOUR_PROJECT_ID
```

Cloud Build builds the Dockerfile, pushes the image, and starts the service. The
container runs `alembic upgrade head` before uvicorn, so the first deploy creates every
table, seeds the permissions and roles, and creates the app role.

The script prints the URL. Check:

- `https://.../health/ready` → `{"status":"ready"}` means Postgres and Redis are both reachable
- `https://.../docs` → the interactive API

## 6. Smoke test it

```bash
BASE=https://your-service.run.app
curl -X POST $BASE/auth/register -H "Content-Type: application/json" \
  -d '{"email":"you@example.com","password":"s3cure-passw0rd"}'
curl -X POST $BASE/auth/login -d "username=you@example.com&password=s3cure-passw0rd"
curl $BASE/auth/me -H "Authorization: Bearer PASTE_ACCESS_TOKEN"
```

## 7. Measure it

```bash
docker run --rm -i -e BASE_URL=https://your-service.run.app grafana/k6 run - <scripts/load-test.js
```

Take `http_reqs` (throughput) and `http_req_duration p(95)` from the summary and put the
real numbers in the README and on your resume. Run it twice and use the second run:
Cloud Run scales to zero, so the first run pays a cold start.

**Keep the service in the same region as the database.** The first deployment put the API
in Mumbai and Neon in Singapore, which cost ~60 ms per request, and ran a 5-connection
pool that 50 concurrent users had to queue for: p95 1.77 s at 47 req/s. Same code in
Singapore with a 20-connection pool: p95 214 ms at 190 req/s.

---

## Costs

| Service | Free tier | This project |
| --- | --- | --- |
| Cloud Run | 2M requests/month | scales to zero when idle |
| Neon | 0.5 GB storage | a few MB |
| Upstash | 10k commands/day | permission cache and rate limits only |

`max-instances 3` caps the blast radius if something goes wrong or the URL is shared
widely.

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| `invalid dsn: scheme is expected to be "postgresql"` | the URL still says `postgresql://`, not `postgresql+asyncpg://` |
| `connect() got an unexpected keyword argument 'sslmode'` | `sslmode=require` not rewritten to `ssl=require` |
| `password authentication failed for user "authforge_app"` | `APP_DB_PASSWORD` doesn't match the password inside `DATABASE_URL` |
| `permission denied to create role` | `DATABASE_ADMIN_URL` is not Neon's owner role |
| First request is slow, later ones fast | cold start — expected with `min-instances 0` |
| `503` right after deploying | migrations still running; wait and retry |

Logs:
```powershell
gcloud run services logs read authforge --project YOUR_PROJECT_ID --region asia-south1 --limit 50
```
