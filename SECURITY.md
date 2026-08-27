# Security, Privacy, and Safety Policy

## Data sensitivity

Treat the following as potentially sensitive diagnostic material:

- ETW/WPR traces and WPA exports
- Process Monitor logs (paths, Registry values, command lines, user/session metadata)
- Event Viewer exports
- Windows Error Reporting dumps
- Defender diagnostic CABs
- DISM/SFC logs

The toolkit must not upload, email, or copy these artifacts off-device by default.

## Required operator disclosure

Before collecting a high-detail trace or support package, disclose:

- the tool and precise collection scope;
- expected duration and stop condition;
- local destination and expected size range;
- possible sensitive fields or content;
- retention period and deletion method;
- whether transfer is requested and the exact destination.

## Approval gates

Explicit operator approval is required before any of the following:

- disabling or deleting an Autoruns entry;
- changing Defender exclusions, protection, scans, updates, or configuration;
- enabling/changing WER or diagnostic-data policy;
- enabling local full crash dumps;
- invoking DISM `/RestoreHealth` or `sfc /scannow`;
- clearing event logs or deleting evidence;
- sending artifacts to a network path, cloud service, ticket system, or vendor.

## Evidence integrity

For every retained artifact, record SHA-256, file size, creation time, source tool, version, capture interval, and local path. Preserve original output; write derived reports separately.

## Prohibited behavior

- Always-on tracing
- Silent repair/remediation
- Automatic startup-item removal
- Automatic Defender exclusions or protection disablement
- Automatic log clearing
- Full-dump collection without explicit, informed approval
- Secret harvesting or credential collection
