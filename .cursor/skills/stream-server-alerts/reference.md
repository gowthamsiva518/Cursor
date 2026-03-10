# Stream Server Production Alerts – Full Runbook

This document is the full runbook for the Support team to triage, debug, and resolve Stream Server production alerts. Use it when you need detailed steps or screenshot references.

**Monitoring tool:** OpenSearch Dashboards – Prod  
**URL:** https://app-opensearch-prod.interface.ai/_dashboards/app/home#/

**Slack channel:** #stream-prod-alerts

---

## 1. What Is This Alert?

The alert triggers when there is a significant increase in errors in the Bot Engine logs for the Stream Server.

**Common error codes:**

- **400** – Bad Request / Invalid input
- **500** – Internal Server Error
- **503** – Service Unavailable

These typically indicate service instability, downstream dependency failures, or request execution issues.

---

## 2. When & Why Is It Triggered?

The alert fires when error rates exceed configured thresholds due to one or more of:

| Condition | Description |
|-----------|-------------|
| **Timeout exceeded** | Requests exceed the configured timeout; often high load or slow downstream services. |
| **Execution failure** | Application fails during request processing (unhandled exceptions, crashes in bot engine). |
| **Authentication issues** | Invalid or failed authentication during login or session setup; token expiry, misconfiguration, or auth service outages. |
| **External service failure** | Failures in integrations (e.g. Speechmatics); API timeouts, rate limits, or unavailability. |

---

## 3. Customer Impact

- **Call connection failures** – Calls fail to connect to the bot engine (timeout during call initiation).
- **Authentication failures** – Users see a generic message such as “Error processing your request.”
- **Delayed bot responses** – Bot responses exceed expected latency; disrupted call flow and degraded UX.

---

## 4. How to Debug

### Step 1: Accessing OpenSearch from #stream-prod-alerts

1. When an alert is received in **#stream-prod-alerts**, click **View Dashboard** in the alert.
2. You should be redirected to the OpenSearch dashboard.
3. **If dashboard access fails:**
   - Log in to **AWS Start** (AWS access portal).
   - Go to **Applications**.
   - Open **Interface OpenSearch App Prod**.
   - Return to #stream-prod-alerts and click **View Dashboard** again.

### Step 2: Getting Error Count by Error Code or Tenant

From the OpenSearch dashboard you can filter errors by **Error Code** or **Tenant Name**.

#### 2.1 Filter by Error Code

1. Expand any error entry in the dashboard (details in table view).
2. Select the **error_code** field.
3. Add it as a filter (e.g. `error_code = 503`).
4. The dashboard shows the error count for that code.
5. Repeat for other error codes as needed.

*Screenshot reference: “Selecting a Filter For Value” (error_code), “Final Result”.*

#### 2.2 Filter by Tenant Name

1. Expand any error entry.
2. In the table view, locate **tenant_name**.
3. Add **tenant_name** as a filter.
4. The dashboard shows the error count for that tenant (credit union).

*Screenshot reference: “Selecting a Filter For Value” (tenant_name), “Final Result”.*

### Step 3: Analysing Errors

#### Scenario 1: High Volume of 500 / 503 Errors

**3.1 Identify error count and impacted CU**

- Use OpenSearch filters (see Step 2) to:
  - Extract the **total error count**.
  - Identify the **CU with the highest number of errors**.

**3.2 Validate production connectivity**

- Make multiple test calls to the production number using **Dialpad**.
- Observe: calls connect successfully every time **vs** fail intermittently or consistently.
- Proceed to **Case A** or **Case B** based on outcome.

**Case A: Calls connect successfully**

**3.3 Check Bot Engine restarts**

- Open **Lens** → select the **Production** cluster.
- Go to **Workloads → Pods**.
- Filter pods by **CU name** and **engine type**.
- Locate the relevant bot engine pod.
- Check the **Age** column to see when the pod last restarted.
- If a restart is detected: use the runbook **“Identifying Restart Cause and CPU Spike in Bot engine”**.
- If no restart: go to **3.3.1** below.

**3.3.1 If no restart is found**

- **Review Twilio call logs:**
  - Open **Twilio Console**.
  - Filter call logs for the **impacted time window**.
  - Check call status: **Busy**, **Failed**, etc.
  - Click on **Call SID** and review detailed error information.
- **Share for RCA:** Provide to Developers and @pe-devops:
  - Error codes
  - Call SID
  - Impacted CU
  - Time window
  - Observed behavior

*Screenshot reference: Twilio call log filter, Call SID detail.*

**Case B: Calls fail intermittently or consistently**

- Follow **3.3.1** to review Twilio logs.
- **Open a bridge immediately** to troubleshoot and drive the issue to resolution.

---

#### Scenario 2: High Volume of Error Code 400

**3.6 Identify error count and impacted CU**

- In OpenSearch: apply filter **Error Code = 400**.
- Extract **total error count** and the **CU(s) most impacted**.

**3.7 Validate authentication flow using Dialpad**

- Use **Production Test Account** details (see Production Test Account Sheet).
- Make a test call to the production number.
- Verify authentication behavior and transactional flows (e.g. balance retrieval, transaction history).

**Authentication outcome:**

- **Case A – Authentication successful:** Integration Manager is OK. Monitor APT logs for a defined time window; confirm no new/recurring 400s. Collect and share logs for that timeframe with the development team for RCA.
- **Case B – Authentication failed:** Treat as critical. Involve the development team immediately; share all relevant logs and timestamps.

---

## 5. Screenshot References (for human use)

- OpenSearch dashboard with error list and table view.
- “Selecting a Filter For Value” – error_code and tenant_name.
- “Final Result” – filtered error count by code or tenant.
- Lens: Workloads → Pods, filter and Age column.
- Twilio Console: call log filter, Call SID detail.

---

## 6. Summary Checklist

- [ ] Access OpenSearch (from Slack or via AWS if needed).
- [ ] Filter by error_code and/or tenant_name; get counts and impacted CU.
- [ ] For 500/503: validate Dialpad calls → check Lens for restarts → Twilio logs → share for RCA / open bridge if needed.
- [ ] For 400: validate auth via Dialpad → monitor or escalate with logs.
- [ ] Always include in RCA: error codes, Call SID (if any), impacted CU, time window, observed behavior.
