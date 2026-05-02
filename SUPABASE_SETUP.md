# DIVINE Uniform Supabase Setup

1. Create a Supabase project.
2. Open **SQL Editor** and run everything in `supabase-schema.sql`.
3. Change the default admin password:

```sql
update public.divine_admins
set password_hash = crypt('YOUR_NEW_OWNER_PASSWORD', gen_salt('bf'))
where username = 'MOHD';
```

4. Open **Project Settings -> API** and copy:
   - Project URL
   - anon public key

5. In `INDEX.HTML`, replace:

```js
const SUPABASE_URL = 'https://YOUR_PROJECT_REF.supabase.co';
const SUPABASE_ANON_KEY = 'YOUR_SUPABASE_ANON_KEY';
```

6. Open the site and test:
   - customer signup
   - customer login
   - order submission
   - admin login
   - status update
   - manual order entry

The database tables are protected with row-level security. The frontend uses Supabase RPC functions, so customers and admins do not directly read or write tables.
