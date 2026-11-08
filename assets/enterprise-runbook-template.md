# Standard Operating Procedure: `{{PROCEDURE_TITLE}}`

**Document ID:** `{{SOP_ID}}` (e.g., SOP-INF-082)  
**Author / Team:** `{{AUTHOR_TEAM}}`  
**Target Systems:** `{{TARGET_SYSTEMS}}`  
**Last Verified (UTC):** `{{TIMESTAMP_UTC}}`  

---

## 1. Prerequisites & Required Permissions
- **Required RBAC Roles:** `{{REQUIRED_ROLES}}`
- **Required Software / Modules:** `{{REQUIRED_SOFTWARE}}`
- **Target Maintenance Window:** `{{WINDOW_REQUIREMENTS}}`

---

## 2. Pre-Execution Baseline Checks

```bash
# Capture baseline state before making changes
{{BASELINE_CHECK_COMMANDS}}
```

---

## 3. Step-by-Step Execution Procedure

### Step 1: `{{STEP_1_TITLE}}`
```bash
{{STEP_1_COMMAND}}
```
*Expected Output:* `{{STEP_1_EXPECTED_OUTPUT}}`

### Step 2: `{{STEP_2_TITLE}}`
```bash
{{STEP_2_COMMAND}}
```
*Expected Output:* `{{STEP_2_EXPECTED_OUTPUT}}`

---

## 4. Post-Execution Verification

```bash
# Verify new state is functional
{{VERIFICATION_COMMANDS}}
```

---

## 5. Rollback Procedure

```bash
# Execute if unexpected failure occurs during steps 1-2
{{ROLLBACK_COMMANDS}}
```
