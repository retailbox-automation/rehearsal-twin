#!/bin/bash
# Migration 0042: keep only tables that exist in the app schema; drop the rest (legacy cleanup).
KEEP=$(cat schema_tables.txt)
for t in $(psql shop -Atc "select tablename from pg_tables where schemaname='public'"); do
  echo "$KEEP" | grep -qx "$t" || psql shop -c "DROP TABLE \"$t\" CASCADE"
done
