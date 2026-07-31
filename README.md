# sigma-kill-chain-rule
Bo rule Sigma theo Cyber Kill Chain - Purple Team Lab
=====================================================
Da kiem chung tren: sigma-cli 3.1.0 | pySigma 1.4.0
                    pysigma-backend-splunk 2.1.0
                    pySigma-backend-elasticsearch 2.1.0
                    pysigma-pipeline-sysmon 2.0.0 | pysigma-pipeline-windows 2.0.0

Ket qua: sigma check -x d3_fendtag  ->  0 error, 0 condition error, 0 issue

rules/       32 rule (30 rule don + 2 file correlation, moi file correlation
             chua 2 document YAML ngan boi ---)
pipelines/   ecs_agent_dataset.yml   - thu hep theo data stream Elastic Agent (Windows)
             ecs_linux_agent.yml     - ECS mapping + data stream cho Linux

LENH CONVERT
------------
Splunk - Sysmon:
  sigma convert -t splunk -p sysmon -p splunk_windows rules/<rule>.yml
Splunk - Security/System:
  sigma convert -t splunk -p splunk_windows rules/<rule>.yml
Splunk - PowerShell 4104:
  sigma convert -t splunk -p windows-logsources -p splunk_windows rules/<rule>.yml

Elastic - Sysmon:
  sigma convert -t lucene -p sysmon -p ecs_windows rules/<rule>.yml
Elastic - xuat detection rule de import vao Kibana:
  sigma convert -t lucene -p sysmon -p ecs_windows -f siem_rule_ndjson \
      --skip-unsupported -o elastic_rules.ndjson rules/
Elastic - Linux:
  sigma convert -t lucene -p pipelines/ecs_linux_agent.yml rules/linux_*.yml

LUU Y
-----
- Rule webserver_vuln_scanner.yml can pipeline rieng de them index/sourcetype.
- 3 rule linux_*.yml can pipeline splunk_linux.yml (Splunk) hoac
  ecs_linux_agent.yml (Elastic).
- Chua do ti le false positive. Phai tune filter truoc khi bat alert production.
