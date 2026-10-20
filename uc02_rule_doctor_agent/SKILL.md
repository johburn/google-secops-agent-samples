---
name: secops-doctor
description: >
  UC-02 SecOps Health & Rule Optimization Doctor (/secops-doctor) for Antigravity CLI (agy)
  and Google ADK. Audits Google Cloud SecOps YARA-L 2.0 rules failing with execution timeouts
  (list_rule_errors) and tunes noisy rules generating repetitive False Positives in closed
  SOAR cases (list_cases + list_case_comments) by updating Reference Lists (update_reference_list)
  with strict Anti-Poisoning guardrails.
---

# `/secops-doctor` — SecOps Health & Rule Optimization Doctor (`UC-02`)

Cuando el ingeniero de detección ejecuta `/secops-doctor` (ej. `/secops-doctor Audita las reglas con errores de timeout y las que tienen más falsos positivos esta semana`), ejecuta las dos ramas de diagnóstico y optimización sobre **Google Cloud SecOps Remote MCP** (`https://us-chronicle.googleapis.com/mcp`) o usando el agente ADK `uc02_rule_doctor_agent`.

---

## 1. Contexto del Tenant (`secops_tenant.json`)

Antes de invocar cualquier herramienta MCP de Google Cloud SecOps, carga siempre los parámetros del tenant desde `./secops_tenant.json` (o variables de entorno `GCP_PROJECT_ID`, `SECOPS_CUSTOMER_ID`, `SECOPS_REGION`):
- `project_id`
- `customer_id`
- `region` (por defecto `"us"`)

---

## 2. Flujo de Ejecución en Paralelo

### Rama A: Diagnóstico de Rendimiento y Errores de Ejecución YARA-L (`RuleHealthAuditorAgent`)

1. **Detección de Fallos de Ejecución:**
   - Invoca `list_rules()` y `list_rule_errors()`.
   - Identifica reglas con errores de timeout como `query took too long to execute` (ej. regla `ru_ddd45753` / `broad_network_exfiltration_unanchored`).
2. **Extracción del Código YARA-L:**
   - Invoca `get_rule(rule_id="...")`.
   - **Regla Crítica de Protobuf JSON:** Si el campo `alertingEnabled` viene omitido en la respuesta de `get_rule`, interprétalo estrictamente como `alertingEnabled: false`.
3. **Reglas Obligatorias de Optimización YARA-L 2.0:**
   - **Filtro de índice UDM:** Exigir siempre al menos un filtro exacto de `metadata.event_type` al principio de la sección `events:` (ej. `$e.metadata.event_type = "PROCESS_LAUNCH" or $e.metadata.event_type = "FILE_MODIFICATION"`).
   - **Eliminación de Regex Abiertos:** Reemplazar expresiones regulares sin anclar (`/.*foo.*/`) por anclajes (`\b...\b`, `^...`), comparaciones exactas o funciones `strings.coalesce(...)`.
   - **Acotación de Ventana `match:`:** Reducir ventanas `match:` excesivas (ej. de `over 24h` a `over 15m` o `over 1h`).
4. **Validación de Compilación:**
   - Invoca `validate_rule(rule_text=optimized_yara_l)` y confirma `compilationState: "SUCCEEDED"`.

---

### Rama B: Tuning Automático de Falsos Positivos con Reference Lists (`FalsePositiveTunerAgent`)

1. **Minería de Casos Cerrados en SOAR:**
   - Invoca `list_cases(filter='status="CLOSED"')` para obtener los casos cerrados recientemente (ej. 18 casos cerrados de la regla `suspicious_powershell_download` / `ru_88a12b99`).
   - Invoca `list_case_comments(case_id=...)` para leer las notas de cierre de los analistas de Tier 1 buscando causas raíz benignas repetidas (`NOT_MALICIOUS`, `Authorized Admin Work`, `Legit action`), como despliegues legítimos de Jenkins desde el host `build-runner-04`.
2. **Guardrail de Seguridad Anti-Poisoning (Obligatorio):**
   > [!WARNING]
   > **Política Anti-Poisoning:** Tienes **estrictamente prohibido** agregar automáticamente a una *Reference List* de exclusión cualquier **IP externa pública** (ej. `185.220.101.45`) o **cuenta/host privilegiado Tier-0** (ej. `domain-admin`, `adm-tier0-*`, `dc01-*`) sin mostrar antes una advertencia explícita `[!WARNING]` al ingeniero humano y bloquear la inserción automática.
3. **Inspección y Actualización de Reference List:**
   - Consulta la lista actual con `get_reference_list(name="authorized_ci_cd_runners")`.
   - Presenta el plan al ingeniero humano mostrando:
     1. El `diff` unificado antes/después del código YARA-L 2.0 para corregir el timeout (`ru_ddd45753`).
     2. La entidad benigna verificada (`build-runner-04`) a añadir en `%authorized_ci_cd_runners` y el `diff` de la regla `suspicious_powershell_download` (`not $e.principal.hostname in %authorized_ci_cd_runners`).
     3. Cualquier intento bloqueado por el Guardrail Anti-Poisoning con su alerta `[!WARNING]`.
4. **Aplicación y Validación Final:**
   - Tras confirmación, ejecuta `update_reference_list(name="authorized_ci_cd_runners", entries=[..., "build-runner-04"])`.
   - Valida la regla ajustada con `validate_rule` (`SUCCEEDED`) y despliega la nueva revisión con `create_rule`.

---

## 3. Ejecución Rápida desde CLI (Demo Local o Live MCP)

```bash
# Ejecutar el flujo completo de demostración desde terminal (Rama A + Rama B + Test Anti-Poisoning)
python3 -m uc02_rule_doctor_agent.demo_cli

# Ejecutar salida estructurada en JSON
python3 -m uc02_rule_doctor_agent.demo_cli --json
```
