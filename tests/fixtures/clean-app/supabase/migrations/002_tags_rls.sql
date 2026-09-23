alter table public.tags enable row level security;
create policy "own tags" on public.tags for all using (auth.uid() = owner) with check (auth.uid() = owner);
