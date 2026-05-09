-- DIVINE Uniform backend setup for Supabase.
-- Run this once in Supabase SQL Editor, then replace the admin password below.

create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;

create table if not exists public.divine_customers (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  org text not null,
  phone text not null unique,
  gst text,
  email text,
  addr text not null,
  password_hash text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.divine_orders (
  id uuid primary key default gen_random_uuid(),
  ref text not null unique,
  name text not null,
  org text not null,
  phone text not null,
  email text,
  gst text,
  addr text,
  reqdate text,
  po text,
  grand_total numeric not null default 0,
  summary text,
  status text not null default 'pending' check (status in ('pending','delivered','cancelled')),
  notes text,
  customer_phone text,
  order_date text,
  -- Stores complex order details sent from the frontend.
  -- Includes accessories selection too (e.g. state.accessories).
  payload jsonb not null default '{}'::jsonb,
  accessories jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.divine_orders
  add column if not exists payload jsonb not null default '{}'::jsonb,
  add column if not exists accessories jsonb not null default '[]'::jsonb;


create table if not exists public.divine_admins (
  id uuid primary key default gen_random_uuid(),
  username text not null unique,
  password_hash text not null,
  created_at timestamptz not null default now()
);

create table if not exists public.divine_sessions (
  token uuid primary key default gen_random_uuid(),
  role text not null check (role in ('customer','admin')),
  customer_phone text,
  admin_username text,
  expires_at timestamptz not null default (now() + interval '30 days'),
  created_at timestamptz not null default now()
);

alter table public.divine_customers enable row level security;
alter table public.divine_orders enable row level security;
alter table public.divine_admins enable row level security;
alter table public.divine_sessions enable row level security;

revoke all on public.divine_customers from anon, authenticated;
revoke all on public.divine_orders from anon, authenticated;
revoke all on public.divine_admins from anon, authenticated;
revoke all on public.divine_sessions from anon, authenticated;

create or replace function public.touch_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists divine_customers_touch on public.divine_customers;
create trigger divine_customers_touch
before update on public.divine_customers
for each row execute function public.touch_updated_at();

drop trigger if exists divine_orders_touch on public.divine_orders;
create trigger divine_orders_touch
before update on public.divine_orders
for each row execute function public.touch_updated_at();

create or replace function public.customer_json(c public.divine_customers)
returns jsonb
language sql
stable
as $$
  select jsonb_build_object(
    'name', c.name,
    'org', c.org,
    'phone', c.phone,
    'gst', coalesce(c.gst, ''),
    'email', coalesce(c.email, ''),
    'addr', c.addr
  );
$$;

create or replace function public.order_json(o public.divine_orders)
returns jsonb
language sql
stable
as $$
  select jsonb_build_object(
    'ref', o.ref,
    'name', o.name,
    'org', o.org,
    'phone', o.phone,
    'email', coalesce(o.email, ''),
    'gst', coalesce(o.gst, ''),
    'addr', coalesce(o.addr, ''),
    'reqdate', coalesce(o.reqdate, ''),
    'po', coalesce(o.po, ''),
    'grandTotal', coalesce(o.grand_total, 0),
    'summary', coalesce(o.summary, ''),
    'date', coalesce(o.order_date, to_char(o.created_at at time zone 'Asia/Kolkata', 'DD/MM/YYYY')),
    'status', coalesce(o.status, 'pending'),
    'notes', coalesce(o.notes, ''),
    'customerPhone', coalesce(o.customer_phone, o.phone),
    'accessories', case
      when o.accessories is not null
       and o.accessories <> '[]'::jsonb
       and o.accessories <> '{}'::jsonb
        then o.accessories
      else coalesce(o.payload->'accessories', '[]'::jsonb)
    end
  );
$$;

create or replace function public.valid_customer_session(p_token uuid)
returns text
language sql
stable
security definer
set search_path = public
as $$
  select s.customer_phone
  from public.divine_sessions s
  where s.token = p_token
    and s.role = 'customer'
    and s.expires_at > now()
  limit 1;
$$;

create or replace function public.valid_admin_session(p_token uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.divine_sessions s
    where s.token = p_token
      and s.role = 'admin'
      and s.expires_at > now()
  );
$$;

create or replace function public.signup_customer(
  p_name text,
  p_org text,
  p_phone text,
  p_gst text,
  p_email text,
  p_addr text,
  p_password text
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_customer public.divine_customers;
  v_token uuid;
begin
  if coalesce(trim(p_name), '') = '' or coalesce(trim(p_org), '') = ''
     or coalesce(trim(p_phone), '') = '' or coalesce(trim(p_addr), '') = ''
     or coalesce(p_password, '') = '' then
    raise exception 'Missing required customer fields';
  end if;

  insert into public.divine_customers(name, org, phone, gst, email, addr, password_hash)
  values (
    trim(p_name), trim(p_org), trim(p_phone), nullif(trim(p_gst), ''),
    nullif(trim(p_email), ''), trim(p_addr), extensions.crypt(p_password, extensions.gen_salt('bf'))
  )
  returning * into v_customer;

  insert into public.divine_sessions(role, customer_phone)
  values ('customer', v_customer.phone)
  returning token into v_token;

  return jsonb_build_object('token', v_token, 'customer', public.customer_json(v_customer));
exception
  when unique_violation then
    raise exception 'Mobile already registered. Please login.';
end;
$$;

create or replace function public.login_customer(p_phone text, p_password text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_customer public.divine_customers;
  v_token uuid;
begin
  select * into v_customer
  from public.divine_customers
  where phone = trim(p_phone)
    and password_hash = extensions.crypt(p_password, password_hash)
  limit 1;

  if v_customer.id is null then
    raise exception 'Incorrect mobile number or password.';
  end if;

  insert into public.divine_sessions(role, customer_phone)
  values ('customer', v_customer.phone)
  returning token into v_token;

  return jsonb_build_object('token', v_token, 'customer', public.customer_json(v_customer));
end;
$$;

create or replace function public.get_current_customer(p_token uuid)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_phone text;
  v_customer public.divine_customers;
begin
  v_phone := public.valid_customer_session(p_token);
  if v_phone is null then
    return null;
  end if;

  select * into v_customer from public.divine_customers where phone = v_phone limit 1;
  return public.customer_json(v_customer);
end;
$$;

create or replace function public.create_customer_order(p_order jsonb, p_session_token uuid default null)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_phone text;
  v_order public.divine_orders;
begin
  if p_session_token is not null then
    v_phone := public.valid_customer_session(p_session_token);
  end if;

  insert into public.divine_orders(
    ref, name, org, phone, email, gst, addr, reqdate, po, grand_total,
    summary, status, notes, customer_phone, order_date, payload, accessories
  )
  values (
    p_order->>'ref',
    p_order->>'name',
    p_order->>'org',
    p_order->>'phone',
    nullif(p_order->>'email', ''),
    nullif(p_order->>'gst', ''),
    p_order->>'addr',
    nullif(p_order->>'reqdate', ''),
    nullif(p_order->>'po', ''),
    coalesce((p_order->>'grandTotal')::numeric, 0),
    p_order->>'summary',
    coalesce(nullif(p_order->>'status', ''), 'pending'),
    coalesce(p_order->>'notes', ''),
    coalesce(v_phone, nullif(p_order->>'customerPhone', ''), p_order->>'phone'),
    coalesce(nullif(p_order->>'date', ''), to_char(now() at time zone 'Asia/Kolkata', 'DD/MM/YYYY')),
    p_order,
    case
      when p_order ? 'accessories' then p_order->'accessories'
      else '[]'::jsonb
    end
  )
  returning * into v_order;

  return public.order_json(v_order);
end;
$$;

create or replace function public.list_customer_orders(p_token uuid)
returns jsonb
language sql
security definer
set search_path = public
as $$
  select coalesce(jsonb_agg(public.order_json(o) order by o.created_at desc), '[]'::jsonb)
  from public.divine_orders o
  where o.customer_phone = public.valid_customer_session(p_token)
     or o.phone = public.valid_customer_session(p_token);
$$;

create or replace function public.login_admin(p_username text, p_password text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_admin public.divine_admins;
  v_token uuid;
begin
  select * into v_admin
  from public.divine_admins
  where username = trim(p_username)
    and password_hash = extensions.crypt(p_password, password_hash)
  limit 1;

  if v_admin.id is null then
    raise exception 'Invalid admin credentials.';
  end if;

  insert into public.divine_sessions(role, admin_username, expires_at)
  values ('admin', v_admin.username, now() + interval '12 hours')
  returning token into v_token;

  return jsonb_build_object('token', v_token, 'username', v_admin.username);
end;
$$;

create or replace function public.admin_list_orders(p_admin_token uuid)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_orders jsonb;
begin
  if not public.valid_admin_session(p_admin_token) then
    raise exception 'Admin session expired. Please login again.';
  end if;

  select coalesce(jsonb_agg(public.order_json(o) order by o.created_at desc), '[]'::jsonb)
  into v_orders
  from public.divine_orders o;

  return v_orders;
end;
$$;

create or replace function public.admin_get_order(p_admin_token uuid, p_ref text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_order public.divine_orders;
begin
  if not public.valid_admin_session(p_admin_token) then
    raise exception 'Admin session expired. Please login again.';
  end if;

  select * into v_order from public.divine_orders where ref = p_ref limit 1;
  if v_order.id is null then
    return null;
  end if;
  return public.order_json(v_order);
end;
$$;

create or replace function public.admin_update_order(p_admin_token uuid, p_ref text, p_patch jsonb)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_order public.divine_orders;
begin
  if not public.valid_admin_session(p_admin_token) then
    raise exception 'Admin session expired. Please login again.';
  end if;

  update public.divine_orders
  set status = coalesce(nullif(p_patch->>'status', ''), status),
      notes = coalesce(p_patch->>'notes', notes)
  where ref = p_ref
  returning * into v_order;

  return public.order_json(v_order);
end;
$$;

create or replace function public.admin_add_order(p_admin_token uuid, p_order jsonb)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
begin
  if not public.valid_admin_session(p_admin_token) then
    raise exception 'Admin session expired. Please login again.';
  end if;

  return public.create_customer_order(p_order, null);
end;
$$;

create or replace function public.admin_list_customers(p_admin_token uuid)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_customers jsonb;
begin
  if not public.valid_admin_session(p_admin_token) then
    raise exception 'Admin session expired. Please login again.';
  end if;

  select coalesce(jsonb_agg(public.customer_json(c) order by c.created_at desc), '[]'::jsonb)
  into v_customers
  from public.divine_customers c;

  return v_customers;
end;
$$;

grant execute on function public.signup_customer(text,text,text,text,text,text,text) to anon;
grant execute on function public.login_customer(text,text) to anon;
grant execute on function public.get_current_customer(uuid) to anon;
grant execute on function public.create_customer_order(jsonb, uuid) to anon;
grant execute on function public.list_customer_orders(uuid) to anon;
grant execute on function public.login_admin(text,text) to anon;
grant execute on function public.admin_list_orders(uuid) to anon;
grant execute on function public.admin_get_order(uuid,text) to anon;
grant execute on function public.admin_update_order(uuid,text,jsonb) to anon;
grant execute on function public.admin_add_order(uuid,jsonb) to anon;
grant execute on function public.admin_list_customers(uuid) to anon;

-- Create the first owner login. Change this password immediately after setup.
insert into public.divine_admins(username, password_hash)
values ('MOHD', extensions.crypt('CHANGE_THIS_ADMIN_PASSWORD', extensions.gen_salt('bf')))
on conflict (username) do nothing;

-- To change the owner password later:
-- update public.divine_admins
-- set password_hash = extensions.crypt('YOUR_NEW_PASSWORD', extensions.gen_salt('bf'))
-- where username = 'MOHD';
