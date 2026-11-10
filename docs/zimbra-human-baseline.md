# Zimbra CVE-2026-73570 — Human Baseline

Source:
Microsoft Security Blog, 30 September 2026

## Behaviours I think matter

- Deployment and use of web shells and reverse shells.
- Zimbra server processes running commands such as `curl`, particularly when this activity occurs shortly after a suspicious email or web request is received.
- SNMP trap activity involving Base64-encoded commands.
- Privilege escalation through abuse of Zimbra helper functionality.
- Installation of `zimlog.service` in a system directory rather than within the expected Zimbra application directories.
- Dumping of secrets or credentials.
- Changes or unusual activity relating to SSH connections.
- A loader being dropped followed by the final payload being dropped and executed.
- Command-and-control activity following compromise.

## Strong detection / validation candidates

- Zimbra-related processes spawning shell commands.
- Zimbra-related execution of utilities such as `curl`.
- Base64-encoded command execution through the SNMP trap mechanism.
- Creation or installation of `zimlog.service` in an unusual system location.
- The loader-to-payload drop and execution chain.
- Secret or credential dumping activity.
- Unusual SSH activity following compromise.

## Behaviours I would not emulate in v1

- Secret or credential dumping is a strong signal, but may not be necessary for the first version of the lab.
- The full exploit chain does not need to be reproduced for the initial proof of concept.

## Assumptions / questions

- Command-and-control activity may include beaconing that could be used as another pivot point, but this needs to be confirmed from the report rather than assumed.
- The exact telemetry produced when an email server spawns shell-related commands still needs to be explored.
- The Base64-encoded SNMP trap command looks like a useful secondary validation behaviour, but it is not yet clear how easy it will be to reproduce cleanly in the current lab.
- If the SNMP trap behaviour is awkward to reproduce, service creation using `zimlog.service` may be a simpler secondary validation candidate.
