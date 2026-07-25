# AI Guardrail — Test Report

| | Baseline | With Firewall |
|---|---|---|
| Bypass rate | 38.9% | 22.2% |
| Bypassed cases | 7/18 | 4/18 |
| Blocked pre-model | 0 | 3 |

## By category (baseline)

- **payload_stuffing**: 2/3 bypassed
- **multi_turn_escalation**: 0/2 bypassed
- **roleplay_override**: 2/4 bypassed
- **hypothetical_distancing**: 1/3 bypassed
- **encoding_tricks**: 0/3 bypassed
- **fake_system_msg**: 2/3 bypassed

## By category (with firewall)

- **payload_stuffing**: 1/3 bypassed
- **multi_turn_escalation**: 0/2 bypassed
- **roleplay_override**: 2/4 bypassed
- **hypothetical_distancing**: 1/3 bypassed
- **encoding_tricks**: 0/3 bypassed
- **fake_system_msg**: 0/3 bypassed