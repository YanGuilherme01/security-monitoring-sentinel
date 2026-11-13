> **Note (English):** design of a Logic Apps playbook for a fictional environment. It has not been deployed, and the "metrics" section shows illustrative targets, not measured results. Document in Portuguese.

# Playbook SOAR: Disable Compromised Account (Azure AD)

**Versão:** 1.1  
**Autor:** Yan Aragão  
**Trigger:** Alert — Impossible Travel (HIGH ou CRITICAL)  
**Plataforma:** Microsoft Sentinel + Azure Logic Apps  
**Última atualização:** 2026-06-23

---

## Visão Geral

Este playbook automatiza a primeira resposta a alertas de Impossible Travel, eliminando o tempo de espera entre o alerta ser gerado e a ação de contenção ser executada.

**Antes do playbook:** Analista recebia alerta → abria ticket → aguardava priorização → investigava → desabilitava conta. Tempo médio: 20-45 minutos.

**Depois do playbook:** Alerta gerado → Logic App executado automaticamente → Conta desabilitada + sessões revogadas + notificações enviadas. Tempo: < 2 minutos.

---

## Fluxo do Playbook

```
Sentinel Alert: Impossible Travel
         │
         ▼
[1] Extrair entidade: UserPrincipalName do alerta
         │
         ▼
[2] Consultar Azure AD: buscar dados do usuário
    - Departamento, cargo, gerente
    - Último login, país registrado
    - Grupos e roles atribuídos
         │
         ▼
[3] Enriquecer IPs do alerta
    - Consultar VirusTotal (reputação)
    - Consultar AbuseIPDB (abuse score)
    - Adicionar contexto ao alerta no Sentinel
         │
         ▼
[4] Decisão automática baseada em risco
    │
    ├─ Risco CRÍTICO (IP em TI + países muito distantes):
    │   → Desabilitar conta IMEDIATAMENTE
    │   → Revogar todos os refresh tokens
    │   → Notificar usuário por email
    │   → Criar incident de alta prioridade
    │   → Notificar Slack #security-incidents
    │
    └─ Risco ALTO/MÉDIO (IP sem TI, países distantes):
        → Forçar MFA challenge na próxima autenticação
        → Notificar usuário pedindo confirmação
        → Se usuário não responder em 30min → desabilitar
        → Notificar Slack #security-alerts
         │
         ▼
[5] Documentar todas as ações no comentário do Incident (Sentinel)
         │
         ▼
[6] Aguardar resposta do analista para:
    - Confirmar TP e manter conta desabilitada
    - Confirmar FP e reabilitar conta (workflow separado)
```

---

## Configuração do Logic App

### Trigger: Sentinel Alert

```json
{
  "trigger": {
    "type": "ApiConnectionWebhook",
    "inputs": {
      "host": {
        "connection": {
          "name": "@parameters('$connections')['azuresentinel']['connectionId']"
        }
      },
      "body": {
        "callback_url": "@{listCallbackUrl()}"
      },
      "path": "/subscribe"
    }
  }
}
```

### Ação 1: Extrair usuário e desabilitar conta

```json
{
  "action": "Disable_User_In_AAD",
  "type": "ApiConnection",
  "inputs": {
    "host": {
      "connection": {
        "name": "@parameters('$connections')['azuread']['connectionId']"
      }
    },
    "method": "patch",
    "path": "/v1.0/users/@{triggerBody()?['userPrincipalName']}",
    "body": {
      "accountEnabled": false
    }
  }
}
```

### Ação 2: Revogar sessões

```json
{
  "action": "Revoke_Sessions",
  "type": "ApiConnection",
  "inputs": {
    "host": {
      "connection": {
        "name": "@parameters('$connections')['azuread']['connectionId']"
      }
    },
    "method": "post",
    "path": "/v1.0/users/@{triggerBody()?['userPrincipalName']}/revokeSignInSessions"
  }
}
```

### Ação 3: Notificar Slack

```json
{
  "action": "Post_to_Slack",
  "type": "ApiConnection",
  "inputs": {
    "host": {
      "connection": {
        "name": "@parameters('$connections')['slack']['connectionId']"
      }
    },
    "method": "post",
    "path": "/chat.postMessage",
    "body": {
      "channel": "#security-incidents",
      "text": "🚨 *IMPOSSIBLE TRAVEL DETECTED*\n*User:* @{triggerBody()?['userPrincipalName']}\n*Countries:* @{triggerBody()?['countries']}\n*Action taken:* Account DISABLED + Sessions REVOKED\n*Sentinel Incident:* @{triggerBody()?['incidentUrl']}\n*Analyst action required:* Confirm TP/FP in Sentinel"
    }
  }
}
```

---

## Processo de Reabilitação de Conta (FP)

Se o alerta for False Positive (usuário viajando com VPN, por exemplo):

```powershell
# Script de reabilitação — executado pelo analista após confirmação
param(
    [Parameter(Mandatory=$true)]
    [string]$UserPrincipalName,

    [Parameter(Mandatory=$true)]
    [string]$IncidentId,

    [Parameter(Mandatory=$true)]
    [string]$FPReason
)

# Reabilitar conta
Set-AzureADUser -ObjectId $UserPrincipalName -AccountEnabled $true

# Documentar no Sentinel
$comment = "Account RE-ENABLED — False Positive confirmed. Reason: $FPReason. Incident: $IncidentId. Analyst: $env:USERNAME"
# Adicionar comment via API do Sentinel

# Notificar Slack
$slackMessage = "✅ Account RESTORED: $UserPrincipalName. FP reason: $FPReason."
# Enviar para Slack

# Notificar usuário
Send-MailMessage -To $UserPrincipalName `
    -Subject "Sua conta foi reativada" `
    -Body "Sua conta foi temporariamente suspensa por atividade suspeita. Após investigação, foi confirmado que a atividade era legítima e sua conta foi reativada. Se tiver dúvidas, entre em contato com a equipe de segurança."

Write-Host "✅ Conta $UserPrincipalName reabilitada e documentada no incident $IncidentId"
```

---

## Métricas do Playbook (metas ilustrativas)

Valores ilustrativos do cenário fictício; não foram medidos em produção:

| Métrica | Resultado |
|---------|-----------|
| Alertas processados automaticamente | 47 |
| Tempo médio de resposta automática | 1 min 43 seg |
| Tempo médio de resposta manual (antes) | 28 minutos |
| Redução no tempo de resposta | **-94%** |
| FP rate (conta desabilitada indevidamente) | ~12% (6 de 47) |
| Tempo para reabilitação de conta FP | ~8 minutos |
| Analista-horas economizadas/mês | ~18 horas |

---

## Melhorias Futuras

- [ ] Adicionar lógica de "horário de viagem conhecida" (integração com sistema de RH)
- [ ] Integrar com Microsoft Defender Identity para contexto adicional
- [ ] Adicionar análise de dispositivo: mesmo device = menor risco de desabilitar
- [ ] Workflow de reabilitação automática quando usuário confirma por MFA
