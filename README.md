# Bộ rule Sigma theo Cyber Kill Chain

Bộ 32 rule Sigma được tổ chức theo 7 giai đoạn của Cyber Kill Chain, kèm 2 processing pipeline tự viết để convert sang **Splunk (SPL)** và **Elastic (Lucene / EQL / ES|QL)**.

## Môi trường đã kiểm chứng

| Thành phần | Phiên bản |
|---|---|
| `sigma-cli` | 3.1.0 |
| `pySigma` | 1.4.0 |
| `pysigma-backend-splunk` | 2.1.0 |
| `pySigma-backend-elasticsearch` | 2.1.0 |
| `pysigma-pipeline-sysmon` | 2.0.0 |
| `pysigma-pipeline-windows` | 2.0.0 |

Kết quả kiểm tra:

```
$ sigma check -x d3_fendtag ./rules/
Found 0 errors, 0 condition errors and 0 issues.
```

## Cấu trúc

```
.
├── rules/                        32 rule
│   ├── ...                       30 rule đơn
│   ├── ssh_bruteforce.yml        correlation (2 document YAML, ngăn bởi ---)
│   └── lateral_spread.yml        correlation (2 document YAML, ngăn bởi ---)
└── pipelines/
    ├── ecs_agent_dataset.yml     thu hẹp theo data stream Elastic Agent (Windows)
    └── ecs_linux_agent.yml       ECS mapping + data stream cho Linux
```

## Cài đặt

```bash
python3 -m venv venv
source venv/bin/activate

pip install sigma-cli
sigma plugin install splunk
sigma plugin install elasticsearch
sigma plugin install sysmon
sigma plugin install windows
```

Nếu `sigma check` báo `Failed to load MITRE D3FEND data`, thêm cờ `-x d3_fendtag`.

## Lệnh convert

Thay `<rule>` bằng tên file thật.

### Splunk

```bash
# Sysmon (process_creation, file_event, registry_set, network_connection, dns_query, wmi_event)
sigma convert -t splunk -p sysmon -p splunk_windows rules/<rule>.yml

# Security / System event log
sigma convert -t splunk -p splunk_windows rules/<rule>.yml

# PowerShell ScriptBlock (Event ID 4104)
sigma convert -t splunk -p windows-logsources -p splunk_windows rules/<rule>.yml

# Xuất savedsearches.conf cho cả thư mục
sigma convert -t splunk -p sysmon -p splunk_windows \
    -f savedsearches --skip-unsupported \
    -o savedsearches.conf rules/
```

### Elastic

```bash
# Sysmon — có -p sysmon để thêm filter winlog.channel + event.code
sigma convert -t lucene -p sysmon -p ecs_windows rules/<rule>.yml

# Security / System / PowerShell 4104
sigma convert -t lucene -p ecs_windows rules/<rule>.yml

# Linux
sigma convert -t lucene -p pipelines/ecs_linux_agent.yml rules/linux_*.yml

# EQL (khi cần sequence)
sigma convert -t eql -p sysmon -p ecs_windows rules/<rule>.yml

# ES|QL — bắt buộc --disable-pipeline-check khi dùng với ecs_windows
sigma convert -t esql -p ecs_windows --disable-pipeline-check rules/<rule>.yml

# Xuất detection rule để import vào Kibana
sigma convert -t lucene -p sysmon -p ecs_windows \
    -f siem_rule_ndjson --skip-unsupported \
    -o elastic_rules.ndjson rules/
```

Import trong Kibana: **Detection rules (SIEM)** → **Import rules** → chọn `elastic_rules.ndjson`. Rule vào trạng thái disabled, kiểm tra *Index patterns* và *Schedule* rồi mới enable.

## Danh mục rule

### Phase 1 — Reconnaissance

| Rule | ATT&CK | Nguồn log |
|---|---|---|
| `webserver_vuln_scanner.yml` | T1595.002 | Web server log |
| `dns_recon_tools.yml` | T1590.002 | Sysmon 1 |
| `ad_recon_native.yml` | T1087.002, T1482 | Sysmon 1 |

### Phase 2 — Weaponization

| Rule | ATT&CK | Nguồn log |
|---|---|---|
| `offensive_tooling_scriptblock.yml` | T1059.001 | PowerShell 4104 |
| `payload_staging_file_create.yml` | T1027 | Sysmon 11 |

### Phase 3 — Delivery

| Rule | ATT&CK | Nguồn log |
|---|---|---|
| `browser_risky_download.yml` | T1189 | Sysmon 11 |
| `outlook_attachment_dropped.yml` | T1566.001 | Sysmon 11 |
| `usb_removable_device_connect.yml` | T1091 | Security 6416 |

### Phase 4 — Exploitation

| Rule | ATT&CK | Nguồn log |
|---|---|---|
| `office_spawn_shell.yml` | T1204.002 | Sysmon 1 |
| `webshell_iis_child_process.yml` | T1505.003, T1190 | Sysmon 1 |
| `mshta_regsvr32_proxy_exec.yml` | T1218.005, T1218.010 | Sysmon 1 |
| `linux_webshell_shell_spawn.yml` | T1505.003 | Linux process |

### Phase 5 — Installation

| Rule | ATT&CK | Nguồn log |
|---|---|---|
| `run_key_persistence.yml` | T1547.001 | Sysmon 13 |
| `service_install_persistence.yml` | T1543.003 | System 7045 |
| `scheduled_task_creation.yml` | T1053.005 | Sysmon 1 |
| `wmi_event_subscription.yml` | T1546.003 | Sysmon 19/20/21 |
| `startup_folder_drop.yml` | T1547.001 | Sysmon 11 |
| `linux_cron_systemd_persistence.yml` | T1053.003, T1543.002 | Linux process |

### Phase 6 — Command & Control

| Rule | ATT&CK | Nguồn log |
|---|---|---|
| `lolbin_network_connection.yml` | T1105, T1071.001 | Sysmon 3 |
| `certutil_download.yml` | T1105, T1140 | Sysmon 1 |
| `dyndns_c2_domain.yml` | T1071.004, T1568.002 | Sysmon 22 |
| `remote_access_tool.yml` | T1219 | Sysmon 1 |
| `linux_reverse_shell.yml` | T1059.004 | Linux process |

### Phase 7 — Actions on Objectives

| Rule | ATT&CK | Nguồn log |
|---|---|---|
| `lsass_dump_comsvcs.yml` | T1003.001 | Sysmon 1 |
| `dcsync_directory_replication.yml` | T1003.006 | Security 4662 (chỉ DC) |
| `psexec_lateral_movement.yml` | T1021.002, T1570 | Sysmon 1 |
| `archive_staging_exfil.yml` | T1560.001 | Sysmon 1 |
| `exfil_cloud_tool.yml` | T1567.002 | Sysmon 1 |
| `shadow_copy_deletion.yml` | T1490 | Sysmon 1 |
| `event_log_clearing.yml` | T1685.005 | Sysmon 1 |

### Correlation

| Rule | ATT&CK | Loại | Điều kiện |
|---|---|---|---|
| `ssh_bruteforce.yml` | T1110.001 | `event_count` | ≥ 10 lần thất bại / 5 phút / host |
| `lateral_spread.yml` | T1021 | `value_count` | 1 tài khoản → ≥ 5 host / 15 phút |

## Lưu ý quan trọng

### ATT&CK v19 đã đổi tag

pySigma 1.4.0 mang dữ liệu ATT&CK v19 (phát hành 28/04/2026), trong đó tactic **Defense Evasion đã bị tách** thành `stealth` và `defense-impairment`.

| Tag cũ | Tag mới |
|---|---|
| `attack.defense-evasion` | `attack.stealth` hoặc `attack.defense-impairment` |
| `attack.t1070.001` | `attack.t1685.005` (Clear Windows Event Logs) |
| `attack.t1562`, `attack.t1562.001`, `attack.t1562.006` | `attack.t1685` (Disable or Modify Tools) |

Rule tải từ SigmaHQ có thể báo `InvalidATTACKTagIssue` vì lý do này. Đây là *issue* mức medium, không phải *error* — convert vẫn chạy được.

Kiểm tra bộ tag hợp lệ trên máy bạn:

```bash
python -c "from sigma.data.mitre_attack import mitre_attack_tactics as t; print(sorted(t.values()))"
```

### Bẫy khi tự viết pipeline

Khi một transformation có **nhiều** `rule_conditions`, pySigma mặc định **AND** chúng lại. Một rule không thể vừa là `process_creation` vừa là `file_event`, nên điều kiện không bao giờ khớp và transformation **bị bỏ qua trong im lặng, không báo lỗi**.

Khoá đúng là `rule_cond_op: or` (không phải `rule_condition_linking`).

### Hai rule cần xử lý thêm

- `webserver_vuln_scanner.yml` convert ra query **không có `index=` / `sourcetype=`** vì pipeline `splunk_windows` không có mapping cho `category: webserver`. Cần pipeline riêng. Trường `cs-user-agent` là tên field IIS — nếu dùng Apache phải đổi cho khớp.
- 3 rule `linux_*.yml` cần pipeline Linux: `splunk_linux.yml` cho Splunk, hoặc `pipelines/ecs_linux_agent.yml` cho Elastic.

### Về false positive

**Chưa đo được tỉ lệ false positive thực tế.** Mọi rule đều cần tune filter theo môi trường cụ thể trước khi bật alert production. Phần `falsepositives` trong từng rule chỉ là gợi ý ban đầu.

Một số rule chắc chắn cần whitelist:

| Rule | Cần whitelist |
|---|---|
| `remote_access_tool.yml` | Công cụ hỗ trợ IT được phê duyệt |
| `dcsync_directory_replication.yml` | Tài khoản đồng bộ AD hợp lệ (Azure AD Connect) |
| `psexec_lateral_movement.yml` | Host quản trị dùng PsExec hợp pháp |
| `office_spawn_shell.yml` | Macro nghiệp vụ đã phê duyệt |
| `dyndns_c2_domain.yml` | Dev dùng ngrok để test webhook |

## Nguồn tham khảo

- [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) — kho rule cộng đồng
- [SigmaHQ/pySigma-backend-elasticsearch](https://github.com/SigmaHQ/pySigma-backend-elasticsearch) — format, pipeline, giới hạn ES|QL correlation
- [sigmahq.io/docs — Backends](https://sigmahq.io/docs/digging-deeper/backends) — lệnh cài từng plugin
- [MITRE ATT&CK v19: The Defense Evasion Split](https://medium.com/mitre-attack/att-ck-v19-the-defense-evasion-split-ics-sub-techniques-new-ai-social-engineering-coverage-ff329cb65d66)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) — chạy tấn công thử để kiểm tra rule
- [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) — config Sysmon khuyến nghị
