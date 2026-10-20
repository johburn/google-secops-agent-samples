# 🩺 UC-02: SecOps Health & Rule Optimization Doctor (`uc02_rule_doctor_agent`)

> **Caso de Uso 2 (`UC-02`)** — Auditoría Autónoma de Reglas YARA-L 2.0 con Errores de Timeout y Tuning de Falsos Positivos con *Reference Lists* mediante **Google ADK**, **Antigravity CLI (`agy`)** y **Google Cloud SecOps Remote MCP** (`https://us-chronicle.googleapis.com/mcp`).

---

## 1. Descripción General y Problema que Resuelve

En la operación diaria de un SOC sobre **Google Cloud SecOps (SIEM + SOAR)** existen dos grandes fuentes de deuda técnica:
1. **Reglas YARA-L que fallan por Timeout (`query took too long to execute`):** Consultas UDM sin filtro inicial `metadata.event_type`, con expresiones regulares abiertas (`/.*foo.*/`) o con ventanas de correlación excesivas (`over 24h`) que agotan el límite de ejecución.
2. **Fatiga de Alertas por Falsos Positivos Repetitivos:** Reglas productivas que disparan todos los días por la misma actividad benigna (ej. un servidor de CI/CD autorizado como `build-runner-04`) y que los analistas de Tier 1 cierran manualmente una y otra vez en SOAR.

El sistema Multi-Agente **`uc02_rule_doctor_agent`** automatiza ambas tareas en segundos a través de dos sub-agentes especializados coordinados por `secops_rule_doctor_coordinator`:

* **Rama A — `RuleHealthAuditorAgent`:**
  * Consulta `list_rules` y `list_rule_errors` para detectar reglas con fallos de ejecución (`ru_ddd45753` / `broad_network_exfiltration_unanchored`).
  * Extrae el código con `get_rule` (aplicando la semántica estricta de Protobuf JSON: si `alertingEnabled` viene omitido, se interpreta como `False`).
  * Diagnostica anti-patrones de rendimiento, reescribe el código YARA-L 2.0 optimizado, valida su compilación con `validate_rule` y despliega la nueva revisión con `create_rule`.
* **Rama B — `FalsePositiveTunerAgent`:**
  * Consulta casos cerrados en SOAR (`list_cases(filter='status="CLOSED"')`) y mina los comentarios de los analistas (`list_case_comments`) para identificar falsos positivos benignos recurrentes (`NOT_MALICIOUS` / `Authorized Admin Work`), como los **18 casos cerrados** de `suspicious_powershell_download` (`ru_88a12b99`) originados por el runner de Jenkins `build-runner-04`.
  * Aplica el **Guardrail de Seguridad Anti-Poisoning**: bloquea automáticamente cualquier intento de agregar **IPs públicas externas** (ej. `185.220.101.45`) o **cuentas/hosts privilegiados Tier-0** (ej. `adm-tier0-domainadmin`, `dc01-*`) a una *Reference List*, emitiendo una alerta explícita `[!WARNING]`.
  * Actualiza `%authorized_ci_cd_runners` vía `update_reference_list`, vincula `not $e.principal.hostname in %authorized_ci_cd_runners` en la regla YARA-L y valida con `validate_rule`.

---

## 2. Estructura del Directorio

```text
uc02_rule_doctor_agent/
├── __init__.py      # Expone root_agent para `adk web` y `adk run`
├── agent.py         # Arquitectura Multi-Agente ADK + Herramientas MCP + Guardrail Anti-Poisoning
├── SKILL.md         # Definición del Skill `/secops-doctor` para Antigravity CLI (`agy`)
├── demo_cli.py      # Script ejecutable de demostración end-to-end (Rama A + Rama B + Guardrail)
└── README.md        # Esta guía en español
```

---

## 3. Cómo Ejecutar la Demo

### Opción 1: Ejecución Directa por CLI (`demo_cli.py`) — *Recomendado para Demo Inmediata*

No requiere credenciales en vivo (usa `SECOPS_MOCK_MODE=true` por defecto con telemetría realista de SIEM/SOAR) y muestra los diagnósticos, los `diff` antes/después de YARA-L 2.0, la actualización de `%authorized_ci_cd_runners` y la prueba del Guardrail Anti-Poisoning:

```bash
# Desde la raíz del repositorio (./)

# Ejecución visual paso a paso con diffs YARA-L 2.0
python3 -m uc02_rule_doctor_agent.demo_cli

# Ejecución con salida estrictamente en JSON estructurado
python3 -m uc02_rule_doctor_agent.demo_cli --json
```

### Opción 2: Ejecución desde Antigravity CLI (`agy`) usando `SKILL.md` (Instalación Global y Prompts)

1. **Instalar la Skill de forma global** para que `agy` descubra `/secops-doctor` desde cualquier directorio:
   ```bash
   # Desde la raíz del repositorio (./):
   mkdir -p ~/.gemini/config/skills/secops-doctor
   ln -sfn "$(pwd)/uc02_rule_doctor_agent/SKILL.md" ~/.gemini/config/skills/secops-doctor/SKILL.md

   # Verificar el enlace simbólico global:
   ls -l ~/.gemini/config/skills/secops-doctor/SKILL.md
   ```
2. Asegúrate de tener configurado `~/.gemini/config/mcp_config.json` (a partir de `./mcp_config.example.json`) y `./secops_tenant.json` (a partir de `./secops_tenant.example.json`).
3. Inicia `agy` e invoca el skill `/secops-doctor` con cualquiera de estos **Prompts de Ejemplo**:

   * **Prompt 1 — Auditoría Integral del SIEM (Rama A: Rendimiento + Rama B: Falsos Positivos):**
     ```text
     /secops-doctor Audita las reglas YARA-L con errores de timeout o problemas de rendimiento (Rama A) y analiza los casos cerrados como falsos positivos esta semana en SOAR para optimizar nuestras Reference Lists (Rama B).
     ```
   * **Prompt 2 — Diagnóstico y Reescritura de Reglas YARA-L Lentas (Rama A):**
     ```text
     /secops-doctor Consulta list_rule_errors y list_rules para detectar reglas sin filtro metadata.event_type o con regex sin anclar (/.*...*/). Reescribe el código YARA-L 2.0 optimizado, muéstrame el diff antes/después y valida su compilación con validate_rule.
     ```
   * **Prompt 3 — Tuning de Falsos Positivos y Verificación del Guardrail Anti-Poisoning (Rama B):**
     ```text
     /secops-doctor Revisa los casos cerrados como benignos de la regla suspicious_powershell_download. Actualiza %authorized_ci_cd_runners con los hosts de CI/CD internos legítimos, y comprueba que el guardrail Anti-Poisoning bloquee con [!WARNING] la IP pública 198.51.100.77 y la cuenta privilegiada domain_admin_tier0.
     ```

### Opción 3: Ejecución Interactiva con Google ADK (`adk web` / `adk run`) y Prompts de Ejemplo

```bash
# Desde la raíz del repositorio (./)

# (Opcional) Para conectarse contra un tenant real de Google Cloud SecOps en lugar del modo Mock:
export SECOPS_MOCK_MODE=false
export GCP_PROJECT_ID="<YOUR_GCP_PROJECT_ID>"
export SECOPS_CUSTOMER_ID="<YOUR_CHRONICLE_CUSTOMER_UUID>"
export SECOPS_REGION="us"

# Levantar la interfaz web de Google ADK
adk web .

# O ejecutar el agente en consola interactiva ADK
adk run uc02_rule_doctor_agent
```

Una vez abierta la interfaz de **`adk web`** en tu navegador (`http://localhost:8000`), selecciona **`uc02_rule_doctor_agent`** en el menú desplegable y prueba los siguientes **Prompts de Ejemplo**:

* **Prompt A — Diagnóstico Completo (Health Audit + False Positive Tuning):**
  ```text
  Ejecuta el diagnóstico completo del Rule Doctor sobre nuestro tenant de Google SecOps: optimiza las reglas con anti-patrones de ejecución en YARA-L 2.0 y realiza el tuning de falsos positivos en %authorized_ci_cd_runners validando la regla resultante con validate_rule.
  ```
* **Prompt B — Prueba Específica de Protección Anti-Poisoning en Reference Lists:**
  ```text
  Evalúa los candidatos ["build-runner-04", "198.51.100.77", "domain_admin_tier0"] para la lista %authorized_ci_cd_runners, bloquea los que violen la política Anti-Poisoning y genera el diff de la regla suspicious_powershell_download.
  ```

---

## 4. Herramientas MCP de Google Cloud SecOps Utilizadas

| Rama | Agente ADK | Herramientas MCP Invocadas |
| :--- | :--- | :--- |
| **Rama A (Timeouts YARA-L)** | `RuleHealthAuditorAgent` | `list_rules`, `list_rule_errors`, `get_rule`, `validate_rule`, `create_rule` |
| **Rama B (Tuning FPs & Reference Lists)** | `FalsePositiveTunerAgent` | `list_cases`, `list_case_alerts`, `list_case_comments`, `get_reference_list`, `create_reference_list`, `update_reference_list`, `validate_rule`, `create_rule` |
