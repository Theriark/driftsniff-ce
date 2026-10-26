# 5. Read the history and the configuration of a source

You replay the changes of a month, see which readings driftsniff stored and look at the
configuration it holds now.

**You need:** any role.

## Step 1: Replay the month

Open **Sources** and select a source. Under **Change replay**, choose **30 days**. The summary
names the busiest day, the first change in the window and the number of critical items.

Step through the days with **Previous day** and **Next day**, or drag the **Day** slider. The
matrix shows how many change items each resource type had per day; a ringed cell holds a critical
item. The panel under the matrix lists the chosen day by resource type and severity, and **Open the
changes of** that day leads to them.

![The change replay at 768 px in the dark theme: the 7, 30 and 90 day choice, the summary, the day controls, the matrix and the chosen day's panel](../images/source-replay-768-dark.png)

With reduced motion on, the replay moves only when you step or drag.

## Step 2: Open the history

Select the **History** tab of the source.

![The history of a source: Current, two readings and the Baseline, with the time, the changes found, the controller version and the stored size](../images/history-1440.png)

Each row is a stored reading, newest first. driftsniff stores a reading only when the
configuration differs from the one before. **Current** is the reading shown under Configuration.
**Baseline** is where the comparison starts. **Changes found** links to the change a reading
produced.

## Step 3: Look at the configuration

Select the **Configuration** tab.

![The configuration of a source: the Resources rail and the Devices resource with its two objects](../images/configuration-1440.png)

1. Choose a resource in the **Resources** rail, for example **Devices**.
2. Each object is a card with its fields and values.
3. Type in **Search this resource** and select **Search** to find an object or a value.

Secret values are never stored. Where a field is a secret, its fingerprint is shown; it equals the
fingerprint a change of the same value shows.

**Back to:** [the tutorial index](README.md).
