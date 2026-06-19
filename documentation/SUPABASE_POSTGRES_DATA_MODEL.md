# Supabase/Postgres Data Model

This is the recommended first Supabase/Postgres schema for the security scanner platform.

It intentionally stays lean. We only create the tables needed for the current product:

1. `account_plans`
2. `users`
3. `scans`
4. `scan_events`
5. `vulnerabilities`
6. `scan_reports`

The goal is to make scan history, Vulnerabilities page filtering, pagination, reports, and analytics easy with SQL, without creating unnecessary tables too early.

## Important Naming

In the old scanner language, `findings` means vulnerabilities/security observations.

For the Supabase schema, use:

```text
vulnerabilities
```

This matches the frontend page name and is easier to understand.

## Timestamp Rule

Use `timestamptz` for all database timestamps.

Postgres/Supabase stores timestamps in UTC. The frontend should display them in Indian time:

```text
Asia/Kolkata
```

## Setup Extension

Run this first in Supabase SQL Editor:

```sql
create extension if not exists pgcrypto;
```

## Enum Types

Run this before creating tables:

```sql
do $$ begin
  create type scan_type as enum ('url_scan', 'deep_scan', 'active_monitoring');
exception
  when duplicate_object then null;
end $$;

do $$ begin
  create type scan_status as enum ('queued', 'pending', 'processing', 'completed', 'failed', 'cancelled');
exception
  when duplicate_object then null;
end $$;

do $$ begin
  create type vulnerability_severity as enum ('critical', 'high', 'medium', 'low', 'info');
exception
  when duplicate_object then null;
end $$;

do $$ begin
  create type vulnerability_status as enum ('open', 'fixed', 'false_positive', 'accepted_risk');
exception
  when duplicate_object then null;
end $$;

do $$ begin
  create type plan_code as enum ('basic', 'advanced', 'premium', 'enterprise');
exception
  when duplicate_object then null;
end $$;
```

## Relationship Summary

```text
account_plans 1 -- many users
users 1 -- many scans
scans 1 -- many scan_events
scans 1 -- many vulnerabilities
scans 1 -- many scan_reports
users 1 -- many vulnerabilities
users 1 -- many scan_reports
```

## Table 1: `account_plans`

Stores available plans and scan limits.

```sql
create table if not exists account_plans (
  id uuid primary key default gen_random_uuid(),
  code plan_code not null unique,
  name text not null unique,
  no_of_scans_available integer,
  features jsonb not null default '{}'::jsonb,
  is_active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
```

Indexes:

```sql
create index if not exists account_plans_active_idx
on account_plans (is_active);
```

Seed plans:

```sql
insert into account_plans (code, name, no_of_scans_available, features)
values
  ('basic', 'Basic', 5, '{"url_scan": true, "active_monitoring": false, "deep_scan": false}'::jsonb),
  ('advanced', 'Advanced', 50, '{"url_scan": true, "active_monitoring": true, "deep_scan": false}'::jsonb),
  ('premium', 'Premium', null, '{"url_scan": true, "active_monitoring": true, "deep_scan": true}'::jsonb)
on conflict (code) do nothing;
```

Notes:

- `no_of_scans_available = null` means unlimited.
- `features` lets us control modules without changing schema.

## Table 2: `users`

Stores product user/profile data.

Supabase Auth can be added later. For now, this table can also support the current default user flow.

```sql
create table if not exists users (
  id uuid primary key default gen_random_uuid(),
  auth_user_id uuid unique,
  account_plan_id uuid references account_plans(id),
  first_name text not null,
  last_name text,
  email text not null,
  company_name text,
  company_url text,
  role text not null default 'owner',
  is_active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint users_email_unique unique (email)
);
```

Indexes:

```sql
create index if not exists users_plan_idx
on users (account_plan_id);

create index if not exists users_email_lower_idx
on users (lower(email));
```

Seed default user:

```sql
insert into users (
  account_plan_id,
  first_name,
  last_name,
  email,
  company_name,
  company_url
)
select
  account_plans.id,
  'Ayush',
  'Rana',
  'ayush@example.com',
  'Hands In Technology',
  null
from account_plans
where account_plans.code = 'basic'
on conflict (email) do nothing;
```

Change the email/name/company before running this if needed.

## Table 3: `scans`

Stores one row for every scan, whether it is URL Scan or Deep Scan.

```sql
create table if not exists scans (
  id uuid primary key default gen_random_uuid(),
  scan_id text not null unique,
  user_id uuid not null references users(id) on delete cascade,
  scan_type scan_type not null,
  status scan_status not null default 'processing',
  target_url text,
  domain text,
  repository_root text,
  branch_name text,
  config jsonb not null default '{}'::jsonb,
  summary jsonb not null default '{}'::jsonb,
  error_message text,
  started_at timestamptz,
  completed_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
```

Primary key:

- `id`

Unique key:

- `scan_id`

Foreign key:

- `user_id -> users.id`

Important fields:

| Column | Purpose |
| --- | --- |
| `scan_id` | Public scan/session ID used by frontend and scanner scripts. |
| `scan_type` | `url_scan`, `deep_scan`, or future scan modules. |
| `target_url` | Website URL being scanned. |
| `domain` | Normalized domain for filtering. |
| `repository_root` | Deep Scan repo/project path reported by scanner. |
| `summary` | Counts like pages, inputs, APIs, severity counts, total vulnerabilities. |
| `config` | Scanner options such as page limit or selected modules. |

Indexes:

```sql
create index if not exists scans_user_created_idx
on scans (user_id, created_at desc);

create index if not exists scans_type_created_idx
on scans (scan_type, created_at desc);

create index if not exists scans_status_created_idx
on scans (status, created_at desc);

create index if not exists scans_domain_created_idx
on scans (domain, created_at desc);
```

## Table 4: `scan_events`

Stores live scan steps/events.

This powers the live progress UI for URL scans and Deep Scan command execution.

```sql
create table if not exists scan_events (
  id uuid primary key default gen_random_uuid(),
  scan_db_id uuid not null references scans(id) on delete cascade,
  scan_id text not null,
  sequence integer not null,
  phase text,
  stage text,
  status text,
  level text not null default 'info',
  message text not null,
  detail jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  constraint scan_events_scan_sequence_unique unique (scan_db_id, sequence)
);
```

Foreign key:

- `scan_db_id -> scans.id`

Why both `scan_db_id` and `scan_id`:

- `scan_db_id` is the real relational foreign key.
- `scan_id` makes debugging and direct SQL searches easier.

Indexes:

```sql
create index if not exists scan_events_scan_created_idx
on scan_events (scan_db_id, created_at desc);

create index if not exists scan_events_scan_id_idx
on scan_events (scan_id);
```

## Table 5: `vulnerabilities`

Stores every vulnerability/security finding as one row.

This is the main table for the Vulnerabilities page.

```sql
create table if not exists vulnerabilities (
  id uuid primary key default gen_random_uuid(),
  vulnerability_id text unique,
  scan_db_id uuid not null references scans(id) on delete cascade,
  scan_id text not null,
  user_id uuid not null references users(id) on delete cascade,
  scan_type scan_type not null,
  domain text,
  url text,
  vulnerability_name text not null,
  category text,
  severity vulnerability_severity not null default 'info',
  status vulnerability_status not null default 'open',
  description text,
  remediation text,
  evidence jsonb not null default '{}'::jsonb,
  file_path text,
  line_number integer,
  tool_name text,
  fingerprint text,
  raw jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
```

Primary key:

- `id`

Foreign keys:

- `scan_db_id -> scans.id`
- `user_id -> users.id`

Important fields:

| Column | Purpose |
| --- | --- |
| `scan_type` | Lets the UI filter URL Scan vs Deep Scan. |
| `severity` | Critical/high/medium/low/info. |
| `status` | Open/fixed/false positive/accepted risk. |
| `evidence` | Structured evidence used by frontend details panel. |
| `raw` | Full original vulnerability object. |
| `fingerprint` | Optional dedupe key for repeated scans later. |

Indexes:

```sql
create index if not exists vulnerabilities_user_created_idx
on vulnerabilities (user_id, created_at desc);

create index if not exists vulnerabilities_scan_db_idx
on vulnerabilities (scan_db_id);

create index if not exists vulnerabilities_scan_id_idx
on vulnerabilities (scan_id);

create index if not exists vulnerabilities_type_created_idx
on vulnerabilities (scan_type, created_at desc);

create index if not exists vulnerabilities_status_severity_idx
on vulnerabilities (status, severity, created_at desc);

create index if not exists vulnerabilities_domain_created_idx
on vulnerabilities (domain, created_at desc);

create index if not exists vulnerabilities_fingerprint_idx
on vulnerabilities (fingerprint);
```

Search index:

```sql
create index if not exists vulnerabilities_search_idx
on vulnerabilities using gin (
  to_tsvector(
    'english',
    coalesce(vulnerability_name, '') || ' ' ||
    coalesce(description, '') || ' ' ||
    coalesce(domain, '') || ' ' ||
    coalesce(url, '') || ' ' ||
    coalesce(file_path, '') || ' ' ||
    coalesce(scan_id, '')
  )
);
```

## Table 6: `scan_reports`

Stores final scan reports and raw scanner output.

```sql
create table if not exists scan_reports (
  id uuid primary key default gen_random_uuid(),
  report_id text not null unique,
  scan_db_id uuid not null references scans(id) on delete cascade,
  scan_id text not null,
  user_id uuid not null references users(id) on delete cascade,
  report_type text not null default 'json',
  report_file text,
  storage_path text,
  summary jsonb not null default '{}'::jsonb,
  raw_json jsonb not null default '{}'::jsonb,
  generated_at timestamptz,
  created_at timestamptz not null default now()
);
```

Foreign keys:

- `scan_db_id -> scans.id`
- `user_id -> users.id`

Important fields:

| Column | Purpose |
| --- | --- |
| `summary` | Small report summary for UI/report cards. |
| `raw_json` | Full URL Scan or Deep Scan report archive. |
| `storage_path` | Supabase Storage path if PDFs are stored later. |

Indexes:

```sql
create index if not exists scan_reports_scan_db_idx
on scan_reports (scan_db_id);

create index if not exists scan_reports_scan_id_idx
on scan_reports (scan_id);

create index if not exists scan_reports_user_created_idx
on scan_reports (user_id, created_at desc);
```

## Vulnerabilities Page Query

Use this shape for server-side filtering and pagination.

```sql
select
  v.id,
  v.vulnerability_id,
  v.scan_id,
  v.scan_type,
  v.domain,
  v.url,
  v.vulnerability_name,
  v.category,
  v.severity,
  v.status,
  v.description,
  v.remediation,
  v.evidence,
  v.file_path,
  v.line_number,
  v.tool_name,
  v.created_at
from vulnerabilities v
where v.user_id = :user_id
  and (:scan_type is null or v.scan_type = :scan_type)
  and (:severity is null or v.severity = :severity)
  and (:status is null or v.status = :status)
  and (:domain is null or v.domain = :domain)
order by v.created_at desc
limit :page_size
offset :offset;
```

Count query:

```sql
select count(*)
from vulnerabilities v
where v.user_id = :user_id
  and (:scan_type is null or v.scan_type = :scan_type)
  and (:severity is null or v.severity = :severity)
  and (:status is null or v.status = :status)
  and (:domain is null or v.domain = :domain);
```

Search query option:

```sql
and (
  :search is null
  or to_tsvector(
    'english',
    coalesce(v.vulnerability_name, '') || ' ' ||
    coalesce(v.description, '') || ' ' ||
    coalesce(v.domain, '') || ' ' ||
    coalesce(v.url, '') || ' ' ||
    coalesce(v.file_path, '') || ' ' ||
    coalesce(v.scan_id, '')
  ) @@ plainto_tsquery('english', :search)
)
```

## Recent Scans Query

```sql
select
  s.id,
  s.scan_id,
  s.scan_type,
  s.status,
  s.target_url,
  s.domain,
  s.summary,
  s.created_at,
  s.completed_at
from scans s
where s.user_id = :user_id
order by s.created_at desc
limit 20;
```

## Dashboard Severity Counts

```sql
select severity, count(*)
from vulnerabilities
where user_id = :user_id
  and status = 'open'
group by severity;
```

## Full SQL Setup Order

Run in this order inside Supabase SQL Editor:

1. Setup extension.
2. Create enum types.
3. Create `account_plans`.
4. Seed `account_plans`.
5. Create `users`.
6. Seed default user.
7. Create `scans`.
8. Create `scan_events`.
9. Create `vulnerabilities`.
10. Create `scan_reports`.
11. Create all indexes.

If you already created `scan_status` before `processing` was added, run this once:

```sql
alter type scan_status add value if not exists 'processing';
alter table scans alter column status set default 'processing';
```

## Environment Variables

### Backend `.env`

Add these to the backend env file.

For local development:

```env
DATABASE_PROVIDER=supabase
SUPABASE_URL=https://YOUR_PROJECT_REF.supabase.co
SUPABASE_SERVICE_ROLE_KEY=YOUR_SERVICE_ROLE_KEY
SUPABASE_ANON_KEY=YOUR_ANON_KEY

DEFAULT_USER_FIRST_NAME=Ayush
DEFAULT_USER_LAST_NAME=Rana
DEFAULT_USER_EMAIL=ayush@example.com
DEFAULT_COMPANY_NAME=Hands In Technology
DEFAULT_COMPANY_URL=
DEFAULT_ACCOUNT_PLAN=Basic
```

For CloudPanel production backend:

```env
DATABASE_PROVIDER=supabase
SUPABASE_URL=https://YOUR_PROJECT_REF.supabase.co
SUPABASE_SERVICE_ROLE_KEY=YOUR_SERVICE_ROLE_KEY
SUPABASE_ANON_KEY=YOUR_ANON_KEY

DEFAULT_USER_FIRST_NAME=Ayush
DEFAULT_USER_LAST_NAME=Rana
DEFAULT_USER_EMAIL=ayush@example.com
DEFAULT_COMPANY_NAME=Hands In Technology
DEFAULT_COMPANY_URL=
DEFAULT_ACCOUNT_PLAN=Basic

SCAN_ALLOW_ORIGINS=https://security-testing-nine.vercel.app,https://securitytool-api.handsintechnology.in
```

Important:

- `SUPABASE_SERVICE_ROLE_KEY` is secret. Use it only in the backend.
- Do not put `SUPABASE_SERVICE_ROLE_KEY` in Vercel frontend env.
- The service role key bypasses RLS, so protect the backend.

### Frontend `frontend2/.env.production`

The frontend currently only needs the backend API URL:

```env
VITE_API_BASE_URL=https://securitytool-api.handsintechnology.in
```

Do not add the service role key to frontend env.

If later the frontend talks directly to Supabase Auth, add only public values:

```env
VITE_SUPABASE_URL=https://YOUR_PROJECT_REF.supabase.co
VITE_SUPABASE_ANON_KEY=YOUR_ANON_KEY
```

## Supabase RLS Recommendation

For the current backend-driven architecture, the backend can use `SUPABASE_SERVICE_ROLE_KEY` and enforce user/account logic in API code.

When real user login is added, enable RLS and map users to Supabase Auth.

Tables to enable RLS on later:

```sql
alter table users enable row level security;
alter table scans enable row level security;
alter table scan_events enable row level security;
alter table vulnerabilities enable row level security;
alter table scan_reports enable row level security;
```

Do not enable strict RLS until the backend has been updated to use Supabase Auth user IDs or service-role-only server queries.

## Migration From Current Mongo Shape

For URL scans:

1. Insert one row into `scans` with `scan_type = 'url_scan'`.
2. Store counts/severity totals in `scans.summary`.
3. Insert each scanner finding into `vulnerabilities`.
4. Insert progress events into `scan_events`.
5. Insert full raw result into `scan_reports.raw_json`.

For Deep Scan:

1. Insert one row into `scans` with `scan_type = 'deep_scan'`.
2. Store the command session status in `scans.status`.
3. Store summary counts in `scans.summary`.
4. Insert each Deep Scan report finding into `vulnerabilities`.
5. Insert command progress into `scan_events`.
6. Insert full uploaded report into `scan_reports.raw_json`.

## Current Backend Mapping

The backend now uses Supabase for both current scan modules:

| Module | Tables Written |
| --- | --- |
| Login/account | `users`, `account_plans` |
| Scan a Domain / URL Scan | `scans`, `scan_events`, `vulnerabilities`, `scan_reports` |
| Deep Scan | `scans`, `scan_events`, `vulnerabilities`, `scan_reports` |

`scans.id` remains the internal Supabase UUID. `scans.scan_id` is the readable user-facing ID such as `SCAN0000001`.

## Future Tables To Add Later

Do not create these yet unless the product needs them:

- `monitored_assets`
- `finding_evidence`
- `scan_commands`
- `active_monitoring_checks`
- `teams`
- `team_members`
- `billing_subscriptions`
