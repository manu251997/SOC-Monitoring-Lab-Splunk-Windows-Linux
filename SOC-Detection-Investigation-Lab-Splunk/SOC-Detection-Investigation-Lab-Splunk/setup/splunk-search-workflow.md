# Splunk Search Workflow

## 1. Confirm Indexes

```spl
| eventcount summarize=false index=*
| stats sum(count) as events by index
| sort - events
```

## 2. Confirm Event IDs

```spl
index=windows
| stats count by EventCode
| sort - count
```

## 3. Inspect Fields

```spl
index=windows EventCode=4625
| head 5
| table _time host EventCode TargetUserName Account_Name IpAddress Source_Network_Address LogonType Logon_Type _raw
```

## 4. Run the Detection

Copy one file from `detections/` and run it with the correct time range.

## 5. Capture Evidence

- Keep the SPL visible.
- Keep the time range visible.
- Display the most relevant columns.
- Sort chronologically for timelines.
- Save the image using the exact filename in `START-HERE.md`.
