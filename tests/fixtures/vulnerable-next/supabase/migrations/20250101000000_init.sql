-- Profiles for every signed-up user
CREATE TABLE public.profiles (
  id uuid PRIMARY KEY REFERENCES auth.users,
  email text,
  phone text,
  passport_number text
);

create table public.messages (
  id bigint generated always as identity primary key,
  sender uuid references auth.users,
  body text
);
alter table public.messages enable row level security;
create policy "read all" on public.messages for select using (true);
create policy "anyone inserts" on public.messages for insert with check(true);

CREATE TABLE orders (
  id bigint PRIMARY KEY,
  owner uuid,
  card_number text,
  cvv text
);
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
CREATE POLICY "signed in" ON orders FOR ALL USING (auth.uid() IS NOT NULL);

-- CREATE TABLE commented_out (id int);
CREATE TEMP TABLE scratch (id int);
create table private.audit_log (id bigint, detail text);
