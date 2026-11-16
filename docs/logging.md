# Logging

Log levels, progress output and performance tips.

[← Back to the README](../README.md)

## Logging and Verbosity Control

The tool provides flexible logging control to balance visibility with output volume:

### Log Levels
Use `--log-level` to control progress reporting frequency:

**WARNING/ERROR** - Minimal output, only critical messages:
```pwsh
.\cyberarkhound.exe --pvwa ... --log-level WARNING --output export.json --target-domains corp.com
```
- Shows start/end of major phases
- No intermediate progress updates
- Best for automated/scheduled runs

**INFO** (default) - Balanced progress updates:
```pwsh
.\cyberarkhound.exe --pvwa ... --log-level INFO --output export.json --target-domains corp.com
```
- Progress every 50 users/groups
- Progress every 20 safes
- Progress every 100 accounts/members
- Progress every 100 nodes during export
- Progress every 500 edges during export
- Recommended for interactive runs

**DEBUG** - Detailed progress for troubleshooting:
```pwsh
.\cyberarkhound.exe --pvwa ... --log-level DEBUG --output export.json --target-domains corp.com
```
- Progress every 10 users/groups
- Progress every 5 safes
- Progress every 25 accounts/members/nodes
- Progress every 100 edges
- Additional diagnostic information
- Best for troubleshooting or understanding processing flow

### Additional Logging Options
- `--quiet` - Suppress most logging (overrides log-level)
- `--debug` - Enable permission analysis diagnostics

### Example Output (INFO level)
```
[2025-11-24 10:15:23] INFO cyberarkhound: Processing 500 users...
[2025-11-24 10:15:24] INFO cyberarkhound:   Processed 50/500 users (10.0%)
[2025-11-24 10:15:25] INFO cyberarkhound:   Processed 100/500 users (20.0%)
...
[2025-11-24 10:15:30] INFO cyberarkhound:   Processed 500/500 users (100.0%)
[2025-11-24 10:15:30] INFO cyberarkhound: Processing 3000 accounts...
[2025-11-24 10:15:35] INFO cyberarkhound:   Processed 100/3000 accounts (3.3%)
...
[2025-11-24 10:16:45] INFO cyberarkhound: === Collection Summary ===
[2025-11-24 10:16:45] INFO cyberarkhound: Total Nodes: 3780
[2025-11-24 10:16:45] INFO cyberarkhound: Nodes by Type:
[2025-11-24 10:16:45] INFO cyberarkhound:   CyberArk_User: 500
[2025-11-24 10:16:45] INFO cyberarkhound:   CyberArk_Group: 80
[2025-11-24 10:16:45] INFO cyberarkhound:   CyberArk_Safe: 150
[2025-11-24 10:16:45] INFO cyberarkhound:   CyberArk_Account: 3000
[2025-11-24 10:16:45] INFO cyberarkhound:   CyberArk_Platform: 50
[2025-11-24 10:16:45] INFO cyberarkhound:   CyberArk_Application: 40
[2025-11-24 10:16:45] INFO cyberarkhound: Total Internal Edges: 12350
[2025-11-24 10:16:45] INFO cyberarkhound: Internal Edges by Type:
[2025-11-24 10:16:45] INFO cyberarkhound:   CyberArk_MemberOf: 620
[2025-11-24 10:16:45] INFO cyberarkhound:   CyberArk_Contains: 3000
[2025-11-24 10:16:45] INFO cyberarkhound:   CyberArk_HasAccessTo: 4200
[2025-11-24 10:16:45] INFO cyberarkhound:   CyberArk_CanGrantAccessTo: 310
[2025-11-24 10:16:45] INFO cyberarkhound:   CyberArk_CanApprove: 95
[2025-11-24 10:16:45] INFO cyberarkhound:   CyberArk_Created: 150
[2025-11-24 10:16:45] INFO cyberarkhound:   CyberArk_ManagedBy: 140
[2025-11-24 10:16:45] INFO cyberarkhound:   CyberArk_UsedAccount: 785
[2025-11-24 10:16:45] INFO cyberarkhound:   CyberArk_LinkedTo: 2100
[2025-11-24 10:16:45] INFO cyberarkhound:   CyberArk_UsesPlatform: 950
[2025-11-24 10:16:45] INFO cyberarkhound:   CyberArk_CanRetrieveViaCCP: 180
[2025-11-24 10:16:45] INFO cyberarkhound: Total External Edges: 1680
[2025-11-24 10:16:45] INFO cyberarkhound: External Edges by Type:
[2025-11-24 10:16:45] INFO cyberarkhound:   CyberArk_SyncsToUser: 480
[2025-11-24 10:16:45] INFO cyberarkhound:   CyberArk_SyncsToGroup: 60
[2025-11-24 10:16:45] INFO cyberarkhound:   CyberArk_SyncsToADUser: 1140
[2025-11-24 10:16:45] INFO cyberarkhound:   CyberArk_PSMServerHostedOn: 4
[2025-11-24 10:16:45] INFO cyberarkhound: Memory stats: Alloc=85MB Sys=142MB NumGC=12
[2025-11-24 10:16:45] INFO cyberarkhound: Writing JSON to file: export.json
[2025-11-24 10:16:45] INFO cyberarkhound:   Writing compact JSON format...
[2025-11-24 10:16:48] INFO cyberarkhound: Export complete! File written successfully.
```

### Performance Tips
- Use `--log-level WARNING` for large environments (10K+ objects) to minimize logging overhead
- Use `--log-level DEBUG` only when investigating specific issues
- Progress updates have minimal performance impact but can fill log files in very large environments
- Compact JSON format is always used (no pretty-printing) for optimal write performance
