# Component review checklist

| Type | External sources | High-value sinks | Required gates |
|---|---|---|---|
| Activity / alias | data URI, extras, ClipData, nested Intent, result Intent | protected Activity, account action, file/provider access | exported/permission, auth state, parameter allowlist |
| Service / Binder | start/bind Intent, Parcel/AIDL args | download/write, privileged API, background action | calling UID/signature, explicit package, path allowlist |
| Receiver | broadcast action, extras, push/SMS/MMS metadata | service launch, notification action, parser | protected broadcast/permission, sender and state validation |
| Provider | URI path, projection, selection, values, call bundle | query/openFile/update/delete, URI grant | read/write permission, ownership, canonical path |
| PendingIntent | fill-in Intent, mutable extras/data/ClipData | creator-identity component launch or grant | immutable by default, narrow explicit target |

Check both explicit export and indirect reachability. `android:exported=false` does not protect a
component reached through an exported nested-Intent proxy. Conversely, an exported component
with a signature permission and correct runtime enforcement may be safe.
