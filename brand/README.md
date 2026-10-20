# Driftsniff brand files

This folder holds the approved Driftsniff brand assets (logos, icons, favicon) exactly as
published in the product's brand asset folder. They are copied byte for byte by the crew's
brand publishing tool and listed in `MANIFEST.sha256`, which CI can check with:

```sh
cd brand && sha256sum -c MANIFEST.sha256
```

Do not edit these files by hand. A change to the brand goes through the brand guide first and
is then republished into this folder, which refreshes the manifest.

The web application references these files for its logo, favicon and theme colours. The
container image copies only `src/`, so anything the running app needs is served from a copy
under the application's static folder, not from here.
