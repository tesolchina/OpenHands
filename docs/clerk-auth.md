# Clerk Gate for Self-Hosted Agent Canvas

The all-in-one Docker image can protect the static UI, proxied API routes, and
websocket routes with a server-side Clerk session gate in `scripts/static-server.mjs`.
This avoids a frontend-only auth prompt that would still leave `/api`,
`/server_info`, or `/sockets` reachable.

## Railway Variables

Set these on the Railway `OpenHands` service only after deploying code that
contains the Clerk gate:

- `CLERK_AUTH_ENABLED=true`
- `CLERK_PUBLISHABLE_KEY=<Clerk publishable key>`
- `CLERK_JWT_KEY=<Clerk JWT public key PEM>`
- `CLERK_AUTHORIZED_PARTIES=https://agent.simonsays.hk`

`CLERK_JWT_KEY` is preferred because the static server can verify session tokens
without a network call. If Railway stores it on one line, replace newlines with
literal `\n` sequences.

Optional alternatives:

- `CLERK_SECRET_KEY=<Clerk secret key>` can be used instead of `CLERK_JWT_KEY` so
  the server can fetch Clerk's JWKS.
- `CLERK_JWKS_URL=<custom JWKS URL>` can be used for a custom Clerk JWKS source.
- `CLERK_SIGN_IN_PATH=/__clerk/sign-in` overrides the local sign-in route.
- `CLERK_AUTH_PUBLIC_PATHS=/extra/public/path` appends unauthenticated public
  paths. Keep `/server_info`, `/api`, and `/sockets` protected.

Do not add Clerk keys before this code is deployed; older images ignore them.

## Clerk Dashboard Settings

For the production Clerk application:

- Enable Google as a social connection.
- Add `https://agent.simonsays.hk` as an allowed origin.
- Add `https://agent.simonsays.hk/__clerk/sign-in` as an allowed redirect URL.
- Add `https://agent.simonsays.hk/` and `https://agent.simonsays.hk/canvas`
  redirect URLs if the dashboard requires explicit post-login destinations.
- Copy the publishable key to `CLERK_PUBLISHABLE_KEY`.
- Copy the JWT public key from API keys to `CLERK_JWT_KEY`, or copy the secret
  key to `CLERK_SECRET_KEY` if using JWKS fetching.

After deployment, unauthenticated browser navigations redirect to the local Clerk
sign-in page, while unauthenticated API calls receive `401`.
