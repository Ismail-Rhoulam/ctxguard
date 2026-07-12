# Setup notes

Set `GITHUB_TOKEN` in your environment before running the release script.
A JWT has three dot-separated parts; the header alone looks like
eyJhbGciOiJIUzI1NiJ9 and is not a credential by itself.

Your key belongs in `.env` (never commit it). The deploy user is `admin`
and the default database name is `app_production`.
