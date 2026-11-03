#!/bin/bash
# Nightly maintenance: clear the app cache, expired sessions and the edge cache.
APP_ROOT=/srv
CACHE_SUBDIR="${CACHE_SUBDIR}"
rm -rf "${APP_ROOT}/${CACHE_SUBDIR}"/*
psql shop -c "DELETE FROM sessions WHERE expires_at < now()"
curl -s -X POST https://prod-api.internal/purge -d '{"scope":"all"}'
