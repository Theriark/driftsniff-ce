# Installation

For release candidate v27.0.0-rc.3. driftsniff CE runs as one container with two volumes: `data`
(the database) and `keys` (the master key). It needs no separate database server.

## What you need

- Docker with the Compose plugin, on a host that can reach your UniFi Network application or Xen
  Orchestra server over HTTPS.
- 512 MB of memory for the container (the limit in `compose.yaml`) and disk space for the history.
  The settings page warns from 2 GB by default.
- For access from other machines: a reverse proxy that terminates TLS, such as the one you already
  use for other internal tools.

## 1. Start the container

```
git clone https://github.com/Theriark/driftsniff-ce.git
cd driftsniff-ce
docker compose up --build -d
```

`compose.yaml` builds the image from this repository and runs it with a read-only root file
system, no Linux capabilities, `no-new-privileges` and a non-root user. Port 8080 is published on
`127.0.0.1` only, so the application is not reachable from other machines until you put a proxy in
front of it.

To run a published image instead of building one, set `DRIFTSNIFF_IMAGE` to its digest, for
example the image of this candidate:

```
DRIFTSNIFF_IMAGE=ghcr.io/theriark/driftsniff-ce@sha256:2bc3627e3b8eda13a62073ee54a6ff6f10d6760b4d7aa697e33606425af5471b docker compose up -d
```

Check that it answers:

```
curl --fail http://localhost:8080/healthz
```

The answer is a JSON object with `status` `ok`, the `version` and the `commit` of the build.

## 2. Create the first admin

At the first start, while no admin exists, the application prints a one-time setup code to its
log, once:

```
docker compose logs driftsniff
```

Open `http://localhost:8080` (or the address of your proxy). The browser is sent to the setup page.
Enter the code, a user name (3 to 64 characters: letters, digits and `. _ @ + -`) and a password of
at least 12 characters. You are then signed in as the admin and see the dashboard.

If the code is lost before it was used, print a new one:

```
docker compose exec driftsniff python -m driftsniff create-admin-code
```

Once any admin exists, the setup page answers "Page not found" and the command refuses.

## 3. Put it behind your proxy

1. Point the proxy at port 8080 of the host and let it terminate TLS.
2. Set `DRIFTSNIFF_BASE_URL` to the address people open, for example
   `https://driftsniff.example.internal`. Writes are refused when the browser's origin does not
   match it.
3. Set `DRIFTSNIFF_TRUSTED_PROXY=true` only when that proxy overwrites the `X-Forwarded-For` and
   `X-Forwarded-Proto` headers and the container port cannot be reached except through it.
4. Restart: `docker compose up -d`.

Every setting is described in [configuration.md](configuration.md).

## 4. Back up the master key

The master key is created on the `keys` volume at the first start. It encrypts the stored
credentials and keys the secret fingerprints. Copy it to a safe place now, apart from the database
backups. Without it a restored database cannot be used. See [operations.md](operations.md).

## 5. Add a source

Follow [Add a source](tutorials/03-add-a-source.md). Before that, prepare a read-only account on
the controller with [the UniFi guide](guides/unifi-setup.md) or [the Xen Orchestra
guide](guides/xo-setup.md).

## Upgrade and remove

- **Upgrade:** take a backup (see [operations.md](operations.md)), then run the new image with
  `docker compose up -d`. The database is migrated at start. Roll back by running the previous
  image digest; the data is not rolled back.
- **Remove:** `docker compose down` stops the container and keeps both volumes.
  `docker compose down --volumes` deletes them, including the history and the master key, and
  cannot be undone.
