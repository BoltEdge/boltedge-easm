# Legal docs (frontend copy)

These markdown files are a **copy** of the source-of-truth in
`/Legal docs/` at the project root.

They live here because Next.js builds inside `frontend/` only —
the project-root `/Legal docs/` folder isn't included in the Docker
build context, so the files have to be inside `frontend/` to be
read by `app/(unauthenticated)/legal/[slug]/page.tsx` at build time.

## Editing workflow

When updating a legal document:

1. Edit the file in `/Legal docs/<filename>.md` (the canonical source).
2. Copy the updated file into `frontend/content/legal/<filename>.md`.
3. Rebuild the frontend (`npm run build` locally, or
   `docker compose build --no-cache easm-frontend` for prod).

The two folders should always match. A short shell one-liner:

```bash
cp "Legal docs/"*.md frontend/content/legal/
```

The `README.md` you're reading is intentionally not present in
`/Legal docs/`. Don't copy this file back.
