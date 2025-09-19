- Nếu để mặc định của Wazuh thì có một số tình huống sẽ không bắt được `logs` nên mình có viết một số `rules` dựa theo nhưng `rules` mặc định của `Wazuh`, tham khảo thêm 1 số tài liệu và tùy chỉnh để cho phù hợp

### Persistence:
```xml
<group name="sysmon,sysmon_eid13_detections,windows,">

  <rule id="92300" level="0">
    <if_group>sysmon_event_13</if_group>
    <field name="win.eventdata.targetObject" type="pcre2">(?i)SOFTWARE\\\\(WOW6432NODE\\\\M|M)ICROSOFT\\\\WINDOW(S|S NT)\\\\CURRENTVERSION\\\\(RUN|TERMINAL SERVER\\\\INSTALL\\\\SOFTWARE\\\\MICROSOFT\\\\WINDOWS\\\\CURRENTVERSION\\\\RUN)</field>
    <options>no_full_log</options>
    <description>Added registry content to be executed on next logon</description>
    <mitre>
      <id>T1547.001</id>
    </mitre>
  </rule>
  
  <rule id="192302" level="15">
    <if_sid>92300</if_sid>
    <field name="win.eventdata.image" type="pcre2">(?i)(reg|powershell|pwsh)\.exe</field>
    <options>no_full_log</options>
    <description>Registry entry to be executed on next logon was modified using command line application</description>
    <mitre>
      <id>T1547.001</id>
    </mitre>
  </rule>

</group>
```

### Reverse Shell

```xml
<group name="powershell_rules" comment="PowerShell rules - concise MITRE tags">

  <rule id="100206" level="15">
    <if_sid>60009</if_sid>
    <field name="win.eventdata.contextInfo" type="pcre2">(?i)Invoke-WebRequest|IWR.*-url|IWR.*-InFile</field>
    <description>Invoke-WebRequest executed, possible download cradle detected.</description>

    <mitre>
      <id>T1059.001</id> <!-- PowerShell -->
      <id>T1105</id>     <!-- Download -->
    </mitre>
  </rule>
  
  <rule id="100502" level="15">
    <if_group>60009</if_group>
    <field name="win.eventdata.scriptBlockText" type="pcre2">(?i)tcpclient</field>
    <description>Powershell created a new TCPClient - possible reverse shell.</description>

    <mitre>
      <id>T1059.001</id> <!-- PowerShell -->
      <id>T1071</id>     <!-- C2 -->
      <!-- <id>T1071.001</id>  Optional: Web -->
    </mitre>
  </rule>

</group>
```
