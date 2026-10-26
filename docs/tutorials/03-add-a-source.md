# 3. Add a source

You connect driftsniff to a UniFi Network application, test the connection and save the source.
The same form serves Xen Orchestra; a push source is at the end.

**You need:** the admin role, and a read-only API key of the UniFi Network application (see
[Setting up a UniFi source](../guides/unifi-setup.md)) or an authentication token of Xen
Orchestra (see [Setting up a Xen Orchestra source](../guides/xo-setup.md)).

## Step 1: Open the form

Select **Add source** on the dashboard, the sources list or the header. **UniFi Network** is
selected at the top; choose **Xen Orchestra** or **Push source** for the others.

![The Add a source form for UniFi Network with its four cards: Source, Checks, Certificate checks and Test connection](../images/add-source-unifi-1440-full.png)

## Step 2: Fill in the Source card

1. **Name**, how the source is called everywhere, for example `branch-gw`.
2. **Address**, `https://` and the host of the UniFi Network application, with no path.
3. **API key**. It is stored encrypted and never shown again.

Leave **Allow a plain http address** off unless this is a lab without TLS.

## Step 3: Choose the checks

1. **Check every (minutes):** 1 to 60. The default is 5.
2. **Resources to read:** all are on. Turn off what you do not want to track.

## Step 4: Choose the certificate check

Keep **Verify with the system trust store** when the controller has a certificate from a public
CA. For your own CA, choose **Verify with your own CA bundle**; for a self-signed certificate,
**Pinned certificate** with its SHA-256. **Insecure, certificate checks off** marks the source with
the Insecure TLS badge and is not for a real network.

## Step 5: Test, then add

Select **Test connection**. driftsniff reads the version and every resource once, read only, and
shows for each resource what answered. Nothing is stored. Fix the address, the key or the TLS mode
if a resource fails, and test again.

Select **Add source**. The source is listed under **Sources** and is checked at once and then at
every interval.

![The sources list with each source's status, last attempt, version and drift line](../images/sources-1440.png)

## Step 6: Open the source

Select the source name. Its page shows the drift line, the change replay, coverage by resource and
the recent runs. Coverage tells you which resources answered and how many objects each has.

![A source page: the drift line, the change replay, coverage by resource and recent runs](../images/source-page-1440-full.png)

## A push source instead

Choose **Push source**, enter a name and declare the resources and fields the sender may send, one
resource per line, for example:

```
networks: _id, name, vlan
```

![The Add a source form for a push source with the Name and Declared resources and fields boxes](../images/add-source-push-1440.png)

Select **Add source**, then **Make sender key** on the source page and give the key to the sender.
It is shown once. The sender then posts the configuration as in the [API
guide](../api-guide.md#push-a-configuration).

The screenshots show the forms empty: no source was added on Development for this tutorial, and
Development has no lab controller to test against.

**Next:** [Add a user and make an API token](04-add-a-user.md).
