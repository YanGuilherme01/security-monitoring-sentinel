> **Note (English):** methodology for a fictional QRadar-to-Sentinel migration. Inventories, counts and timelines are illustrative. Document in Portuguese.

# Metodologia de Migração SIEM — QRadar para Microsoft Sentinel

**Autor:** Yan Aragão  
**Última atualização:** 2026-06-23  
**Contexto:** Documentação da metodologia aplicada — cenário fictício MedLogística

---

## Por que documentar a metodologia

Migrar um SIEM não é só mover regras de uma ferramenta para outra. É uma oportunidade de:
- Revisar o que estava sendo detectado (e o que estava sendo perdido)
- Eliminar ruído acumulado ao longo de anos
- Redesenhar a lógica de detecção com os aprendizados do período anterior

Este documento descreve o processo que foi seguido, com decisões, trade-offs e resultado de cada etapa.

---

## Fase 0 — Decisão: Migrar ou não migrar?

Antes de começar, a pergunta correta não é *"como migrar?"* mas *"vale a pena migrar?"*.

### Critérios que justificaram a migração neste caso

**Técnicos:**
- 40% do ambiente (Azure AD, Office 365, Azure VMs) sem cobertura de log
- Regras não revisadas há 18 meses com cobertura MITRE < 20%
- Impossibilidade de adicionar conectores cloud nativos no QRadar sem custo adicional significativo

**Operacionais:**
- 60% do tempo dos analistas em manutenção de infra (hardware, SO, patches)
- 1.200+ alertas/dia para equipe de 2 analistas — inviável operacionalmente
- MTTD crítico > 72 horas — incidentes sendo resolvidos muito tarde

**Financeiros:**
- Custo de renovação de licença QRadar + hardware upgrades vs. modelo pay-per-GB do Sentinel
- Cálculo mostrou break-even em < 14 meses com Sentinel

---

## Fase 1 — Inventário completo antes de qualquer ação

### 1.1 Inventário de fontes de log no QRadar

```
Fonte                          Volume/dia    Qualidade    Cobertura para detecção
─────────────────────────────────────────────────────────────────────────────────
Windows Security Events         ~850K        Alta         Boa para on-prem
Cisco ASA Firewall              ~400K        Média        Parcial (sem flow)
Symantec Endpoint Protection    ~180K        Baixa        Desatualizado
DNS Logs                        ~2.1M        Alta         Parcial (sem resposta)
──────────────────────────────────────────────────────────────────────────────────
Azure AD Sign-in Logs           0            —            ZERO COBERTURA
Office 365 Activity             0            —            ZERO COBERTURA
Azure VM Logs                   0            —            ZERO COBERTURA
CrowdStrike (EDR novo)         0            —            ZERO COBERTURA
──────────────────────────────────────────────────────────────────────────────────
```

**Achado imediato:** Sem logs de Azure AD, qualquer comprometimento via identidade cloud passaria completamente despercebido. Isso por si só justificava a migração.

### 1.2 Inventário de regras de correlação no QRadar

```
Total de regras ativas:         127
Regras sem alerta nos 90 dias:   62 (49% — possivelmente obsoletas)
Regras com >50 alertas/dia:      18 (geradores de ruído primários)
Regras validadas recentemente:    9 (7% do total)
Mapeamento MITRE ATT&CK:        23% de cobertura
```

**Decisão:** Migrar apenas as 65 regras que geraram alertas relevantes nos últimos 90 dias. As 62 regras sem alertas seriam avaliadas individualmente e possivelmente descartadas.

---

## Fase 2 — Priorização por valor de detecção

Nem toda fonte de log tem o mesmo valor para detecção. A prioridade foi definida pela pergunta: *"Se eu tivesse apenas este log, qual seria o impacto na minha capacidade de detectar ataques?"*

### Matriz de priorização

| Fonte de log | Táticas MITRE cobertas | Volume | Prioridade | Semana de migração |
|--------------|------------------------|--------|:----------:|:-----------------:|
| Azure AD Sign-in | T1078, T1110, T1621 | ~50K/dia | **1** | Semana 1 |
| Azure AD Audit | T1098, T1136, T1078 | ~5K/dia | **1** | Semana 1 |
| Office 365 | T1566, T1567, T1114 | ~200K/dia | **1** | Semana 2 |
| Defender for Endpoint | T1003, T1021, T1055 | ~400K/dia | **2** | Semana 3 |
| Windows Security | T1110, T1021, T1078 | ~850K/dia | **2** | Semana 4 |
| Cisco Firewall | T1041, T1048, T1571 | ~400K/dia | **3** | Semana 5 |
| CrowdStrike EDR | T1003, T1055, T1562 | ~300K/dia | **3** | Semana 6 |
| DNS | T1048, T1071 | ~2.1M/dia | **4** | Mês 2 |

---

## Fase 3 — Processo de migração de regras

### Classificação das regras do QRadar

Cada uma das 127 regras foi classificada em uma de 4 categorias:

```
CATEGORIA A — Migrar e melhorar (38 regras)
  Lógica válida, mas pode se beneficiar de KQL avançado (correlação, enriquecimento)
  Reescrever em KQL com melhorias.

CATEGORIA B — Migrar como está (27 regras)
  Regras simples e efetivas. Tradução direta para KQL.
  
CATEGORIA C — Substituir por conteúdo nativo do Sentinel (20 regras)
  O Sentinel já tem regras equivalentes no Microsoft Security Research Community.
  Usar as nativas — testadas e mantidas pela Microsoft.

CATEGORIA D — Descartar (42 regras)
  Regras que não geraram nenhum alerta relevante em 90 dias.
  Documentadas e arquivadas, mas não migradas.
```

### Template de documentação por regra migrada

Para cada regra migrada, criou-se um registro:

```markdown
## Regra: [NOME]

**ID QRadar:** QR-XXXX  
**ID Sentinel:** SEN-XXXX  
**Categoria de migração:** A / B / C / D  
**Técnica MITRE:** T1XXX  

### Lógica QRadar (AQL)
[query original]

### Lógica Sentinel (KQL)
[query nova]

### Melhorias implementadas
- [ ] Adicionado enriquecimento de threat intel
- [ ] Threshold ajustado com base em baseline
- [ ] Exceções calibradas para reduzir FP
- [ ] Entidades mapeadas (User, IP, Host)

### Resultado de validação
- FP rate estimada: X%
- Teste com Atomic Red Team: Sim/Não
- Data de validação: YYYY-MM-DD
```

---

## Fase 4 — Redução de ruído: de 1.200 para 85 alertas/dia

Esta foi a fase mais crítica e que mais impactou a operação.

### As 5 fontes principais de ruído no QRadar

**Fonte 1: Regra de "Login fora do horário" sem exceções**
- Gerava ~200 alertas/dia
- Problema: admins de TI legítimos trabalhavam à noite
- Solução: adicionar lista de exclusão para contas de admin + limitar a contas de usuário comum

**Fonte 2: Regra de "Múltiplos logins falhos" com threshold 3**
- Gerava ~350 alertas/dia
- Problema: usuários esquecendo senha = 3 tentativas = alerta
- Solução: aumentar threshold para 10 + adicionar janela de tempo de 5 minutos

**Fonte 3: Regra de "Acesso a arquivo sensível" muito genérica**
- Gerava ~180 alertas/dia para acesso legítimo a documentos financeiros
- Problema: regra não diferenciava acesso legítimo (equipe financeira) de suspeito
- Solução: adicionar condição de departamento do usuário + excluir horário comercial para equipe financeira

**Fonte 4: Regra de "Processo novo detectado" sem baseline**
- Gerava ~290 alertas/dia para cada update de software
- Problema: sem baseline, qualquer processo novo gerava alerta
- Solução: implementar baseline de 30 dias, alertar apenas processos sem histórico

**Fonte 5: Regras duplicadas (3 regras detectando o mesmo evento)**
- Gerava triplicação de alertas para eventos de brute force
- Solução: consolidar em uma regra com enriquecimento

### Resultado do processo de tuning

```
Origem dos alertas/dia:
                   Antes    Depois   Redução
─────────────────────────────────────────────
Regra Login FH     200        12      -94%
Regra Login Fail   350        35      -90%
Regra File Access  180         8      -96%
Regra New Process  290        18      -94%
Regras duplicadas  180         0     -100%
─────────────────────────────────────────────
Total eliminado   1.200       73      -94%
Novas detecções     —         12        +
Total final       1.200       85      -93%
─────────────────────────────────────────────
```

> **Nota importante:** Reduzir alertas de 1.200 para 85 não significa que detectamos menos ameaças. Significa que eliminamos 1.115 alertas que não levavam a nenhuma ação — e mantivemos os 85 que têm valor real de detecção.

---

## Fase 5 — Validação e go-live

### Critérios de go-live

Antes de desligar o QRadar, foram validados:

- [ ] 100% das fontes de log de prioridade 1 e 2 ingestando no Sentinel
- [ ] Todas as regras Categoria A e B migradas e testadas
- [ ] FP rate < 5% em todas as regras críticas
- [ ] Playbooks SOAR validados em ambiente de staging
- [ ] Runbook de resposta a incidentes atualizado para Sentinel
- [ ] Equipe de SOC treinada na nova interface (4h de treinamento)
- [ ] Período de operação paralela (QRadar + Sentinel): 2 semanas

### Período de operação paralela

Por 2 semanas, ambos os SIEMs rodaram em paralelo:
- Alertas do Sentinel comparados com alertas do QRadar
- Diferenças documentadas e analisadas
- Falsos negativos do Sentinel identificados e corrigidos antes do cut-over

---

## Lições para futuras migrações

1. **Nunca confie nas regras antigas sem revisão.** Regras acumulam lógica desatualizada.
2. **Baseline antes de alert.** Sem baseline, qualquer desvio vira alerta.
3. **Comece pela identidade.** Azure AD Sign-in é a fonte com maior ROI de detecção.
4. **Operação paralela é obrigatória.** 2 semanas mínimo antes do cut-over.
5. **Documente cada decisão.** O "por que" é tão importante quanto o "o quê".
