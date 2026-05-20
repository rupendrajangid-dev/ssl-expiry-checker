
        // Multi-Org Cache & Switcher State
        let allOrgsCache = {};
        let allDomainsCache = [];
        let allResultsCache = {};
        let allOrgRecipientsCache = {};
        let activeOrganization = localStorage.getItem("activeOrganization") || "Tagid";

        // Start running loops
        updateClock();
        setInterval(updateClock, 1000);
        
        // Initial registry and logs fetch
        fetchDomains();
        fetchLogs();
        fetchSettings();
        
        // Auto-refresh loops
        setInterval(fetchDomains, 8000);  // Registry updates
        setInterval(fetchLogs, 3000);     // Terminal log updates

        // 1. Digital IST Clock display logic
        function updateClock() {
            const now = new Date();
            const options = {
                timeZone: 'Asia/Kolkata',
                day: '2-digit',
                month: 'short',
                year: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
                hour12: false
            };
            const istString = now.toLocaleString('en-IN', options) + ' IST';
            document.getElementById("clock-display").innerText = istString;
        }

        // 2. Fetch configured domains list and organizations
        async function fetchDomains() {
            try {
                const response = await fetch("/api/domains");
                if (response.status === 401) {
                    window.location.reload();
                    return;
                }
                if (!response.ok) throw new Error("API load error");
                
                const data = await response.json();
                allDomainsCache = data.domains || [];
                allOrgsCache = data.orgs || {};
                allResultsCache = data.last_results || {};
                allOrgRecipientsCache = data.org_recipients || {};
                
                // Populate organization dropdown
                populateOrgSwitcher();

                // Run data filter & render
                filterAndRenderDashboard();
            } catch (err) {
                console.error("Failed to load domains registry:", err);
            }
        }

        // Populate organization dropdown selector dynamically
        function populateOrgSwitcher() {
            const selector = document.getElementById("org-selector");
            if (!selector) return;

            const currentSel = activeOrganization;
            let html = "";
            
            // consolidated All Organizations option at the top
            html += `<option value="all" ${currentSel === 'all' ? 'selected' : ''}>All Organizations</option>`;

            // List individual org keys alphabetically
            const orgNames = Object.keys(allOrgsCache).sort((a, b) => a.localeCompare(b));
            if (!orgNames.includes("Tagid")) {
                orgNames.unshift("Tagid");
            }

            orgNames.forEach(org => {
                if (org === "Tagid" && orgNames.indexOf("Tagid") !== orgNames.lastIndexOf("Tagid")) {
                    return;
                }
                html += `<option value="${org}" ${currentSel === org ? 'selected' : ''}>${org}</option>`;
            });

            selector.innerHTML = html;
            
            // Fallback if activeOrganization was deleted
            if (currentSel !== "all" && !allOrgsCache[currentSel]) {
                activeOrganization = "Tagid";
                localStorage.setItem("activeOrganization", activeOrganization);
                selector.value = "Tagid";
            }
        }

        // Filter domains and recalculate statistics in real-time
        function filterAndRenderDashboard() {
            let filteredDomains = [];
            if (activeOrganization === "all") {
                filteredDomains = allDomainsCache;
            } else {
                filteredDomains = allOrgsCache[activeOrganization] || [];
            }

            // Update stats
            document.getElementById("stat-total").innerText = filteredDomains.length;
            document.getElementById("registry-count").innerText = filteredDomains.length + " registered";
            
            // Compute health classifications from allResultsCache for the filtered domains
            let healthyCount = 0;
            let warningCount = 0;
            let criticalCount = 0;
            let expiredCount = 0;
            let failedCount = 0;
            
            filteredDomains.forEach(d => {
                const res = allResultsCache[d];
                if (res) {
                    const sev = res.severity || "Failed";
                    if (sev === "Healthy") {
                        healthyCount++;
                    } else if (sev === "Warning" || sev === "High") {
                        warningCount++;
                    } else if (sev === "Critical") {
                        criticalCount++;
                    } else if (sev === "Expired") {
                        expiredCount++;
                    } else if (sev === "Failed") {
                        failedCount++;
                    }
                }
            });
            
            document.getElementById("stat-healthy").innerText = healthyCount;
            document.getElementById("stat-warning").innerText = warningCount;
            document.getElementById("stat-critical").innerText = criticalCount;
            document.getElementById("stat-expired").innerText = expiredCount;
            document.getElementById("stat-failed").innerText = failedCount;
            
            // Update input placeholder based on selection
            const inputElement = document.getElementById("new-domain-input");
            if (inputElement) {
                if (activeOrganization === "all") {
                    inputElement.placeholder = "Select an org to add domains...";
                    inputElement.disabled = true;
                } else {
                    inputElement.placeholder = `Add domain to ${activeOrganization}...`;
                    inputElement.disabled = false;
                }
            }

            // Render tables & panels
            renderDomainsList(filteredDomains, allResultsCache);
            renderResultsTable(filteredDomains, allResultsCache);
            renderRecipients();
        }

        // Triggered on selector dropdown change
        function changeOrganization() {
            const selector = document.getElementById("org-selector");
            if (!selector) return;
            activeOrganization = selector.value;
            localStorage.setItem("activeOrganization", activeOrganization);
            filterAndRenderDashboard();
            showToast(`Switched view to: ${activeOrganization === 'all' ? 'All Organizations' : activeOrganization}`, "success");
        }

        // Administrative: Create New Organization
        async function promptCreateOrg() {
            const orgName = prompt("Enter the name of the new organization:");
            if (!orgName) return;
            const cleanOrg = orgName.trim();
            if (!cleanOrg) {
                showToast("Organization name cannot be empty.", "error");
                return;
            }
            if (cleanOrg.toLowerCase() === "all") {
                showToast("'All' is a reserved name.", "error");
                return;
            }

            try {
                const response = await fetch("/api/orgs", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ org_name: cleanOrg })
                });
                if (response.status === 401) {
                    window.location.reload();
                    return;
                }
                
                const resData = await response.json();
                if (response.ok) {
                    showToast(resData.message || "Organization created!", "success");
                    activeOrganization = cleanOrg;
                    localStorage.setItem("activeOrganization", activeOrganization);
                    fetchDomains();
                } else {
                    showToast(resData.error || "Failed to create organization.", "error");
                }
            } catch (err) {
                showToast("Server communication error.", "error");
            }
        }

        // Administrative: Delete Active Organization
        async function deleteActiveOrg() {
            if (activeOrganization === "all") {
                showToast("Cannot delete the consolidated 'All Organizations' view.", "error");
                return;
            }
            if (activeOrganization === "Tagid") {
                showToast("The default organization 'Tagid' cannot be deleted.", "error");
                return;
            }

            if (!confirm(`Are you absolutely sure you want to delete organization '${activeOrganization}'?\n\nWARNING: This will permanently delete all domains belonging ONLY to this organization!`)) {
                return;
            }

            try {
                const response = await fetch(`/api/orgs?org_name=${encodeURIComponent(activeOrganization)}`, {
                    method: "DELETE"
                });
                if (response.status === 401) {
                    window.location.reload();
                    return;
                }
                
                const resData = await response.json();
                if (response.ok) {
                    showToast(resData.message || "Organization deleted.", "success");
                    activeOrganization = "Tagid";
                    localStorage.setItem("activeOrganization", activeOrganization);
                    fetchDomains();
                } else {
                    showToast(resData.error || "Failed to delete organization.", "error");
                }
            } catch (err) {
                showToast("Server communication error.", "error");
            }
        }

        // Tab Switching Logic
        function switchTab(tabId) {
            document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
            document.querySelectorAll('.view-panel').forEach(panel => panel.classList.remove('active'));
            
            if (tabId === 'dashboard') {
                const targetBtn = document.querySelector('.tab-btn[onclick*="dashboard"]');
                if (targetBtn) targetBtn.classList.add('active');
                const targetPanel = document.getElementById('dashboard-view');
                if (targetPanel) targetPanel.classList.add('active');
            } else if (tabId === 'table') {
                const targetBtn = document.querySelector('.tab-btn[onclick*="table"]');
                if (targetBtn) targetBtn.classList.add('active');
                const targetPanel = document.getElementById('table-view');
                if (targetPanel) targetPanel.classList.add('active');
                renderResultsTable(tableDomainsCache, tableResultsCache);
            } else if (tabId === 'settings') {
                const targetBtn = document.querySelector('.tab-btn[onclick*="settings"]');
                if (targetBtn) targetBtn.classList.add('active');
                const targetPanel = document.getElementById('settings-view');
                if (targetPanel) targetPanel.classList.add('active');
                fetchSettings();
            }
        }

        // Settings / Scheduler CRUD Management
        function toggleSchedulerFields() {
            const enabled = document.getElementById('setting-cron-enabled').checked;
            const fieldsDiv = document.getElementById('scheduler-fields');
            const freq = document.getElementById('setting-cron-schedule').value;
            
            if (enabled) {
                fieldsDiv.style.opacity = '1';
                fieldsDiv.style.pointerEvents = 'auto';
            } else {
                fieldsDiv.style.opacity = '0.5';
                fieldsDiv.style.pointerEvents = 'none';
            }
            
            document.getElementById('group-cron-weekly').style.display = (enabled && freq === 'weekly') ? 'flex' : 'none';
            document.getElementById('group-cron-monthly').style.display = (enabled && freq === 'monthly') ? 'flex' : 'none';
        }
        
        async function fetchSettings() {
            try {
                const response = await fetch('/api/config');
                if (response.status === 401) {
                    showToast("Session expired. Please log in again.", "error");
                    return;
                }
                const config = await response.json();
                
                document.getElementById('setting-cron-enabled').checked = config.cron_enabled || false;
                document.getElementById('setting-cron-schedule').value = config.cron_schedule || 'daily';
                document.getElementById('setting-cron-time').value = config.cron_time || '09:00';
                document.getElementById('setting-cron-weekly-day').value = config.cron_weekly_day || 'Monday';
                document.getElementById('setting-cron-monthly-day').value = config.cron_monthly_day || 1;
                
                document.getElementById('setting-warning-days').value = config.warning_days || 30;
                document.getElementById('setting-high-priority-days').value = config.high_priority_days || 14;
                document.getElementById('setting-critical-days').value = config.critical_days || 7;
                document.getElementById('setting-send-daily-summary').checked = config.send_daily_summary !== false;
                
                document.getElementById('setting-max-workers').value = config.max_workers || 20;
                document.getElementById('setting-timeout').value = config.timeout || 10;
                document.getElementById('setting-max-retries').value = config.max_retries || 3;
                document.getElementById('setting-retry-delay').value = config.retry_delay || 5;
                
                toggleSchedulerFields();
            } catch (err) {
                showToast("Failed to fetch system configurations.", "error");
            }
        }
        
        async function saveSettings(event) {
            event.preventDefault();
            
            const warning = parseInt(document.getElementById('setting-warning-days').value);
            const high = parseInt(document.getElementById('setting-high-priority-days').value);
            const critical = parseInt(document.getElementById('setting-critical-days').value);
            
            if (critical > high || high > warning || critical <= 0) {
                showToast("Constraint violation: Critical <= High Priority <= Warning is required.", "error");
                return;
            }
            
            const payload = {
                cron_enabled: document.getElementById('setting-cron-enabled').checked,
                cron_schedule: document.getElementById('setting-cron-schedule').value,
                cron_time: document.getElementById('setting-cron-time').value,
                cron_weekly_day: document.getElementById('setting-cron-weekly-day').value,
                cron_monthly_day: parseInt(document.getElementById('setting-cron-monthly-day').value),
                
                warning_days: warning,
                high_priority_days: high,
                critical_days: critical,
                send_daily_summary: document.getElementById('setting-send-daily-summary').checked,
                
                max_workers: parseInt(document.getElementById('setting-max-workers').value),
                timeout: parseInt(document.getElementById('setting-timeout').value),
                max_retries: parseInt(document.getElementById('setting-max-retries').value),
                retry_delay: parseInt(document.getElementById('setting-retry-delay').value)
            };
            
            try {
                const response = await fetch('/api/config', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                
                const resData = await response.json();
                if (response.ok && resData.success) {
                    showToast("Configurations saved successfully!", "success");
                } else {
                    showToast(resData.error || "Failed to update configurations.", "error");
                }
            } catch (err) {
                showToast("Network error saving configurations.", "error");
            }
        }

        // Table Sorting & Export Logic
        let currentSortColumn = "domain";
        let currentSortDirection = "asc";

        function toggleSort(column) {
            if (currentSortColumn === column) {
                currentSortDirection = currentSortDirection === "asc" ? "desc" : "asc";
            } else {
                currentSortColumn = column;
                currentSortDirection = "asc";
            }
            updateSortHeadersUI();
            renderResultsTable(tableDomainsCache, tableResultsCache);
        }

        function updateSortHeadersUI() {
            const columns = {
                domain: "Domain",
                status: "Status",
                expiry_date: "Expiry Date",
                remaining: "Remaining",
                checked_at: "Checked At"
            };
            
            for (const [colId, labelText] of Object.entries(columns)) {
                const th = document.getElementById(`th-${colId}`);
                if (!th) continue;
                
                if (currentSortColumn === colId) {
                    const arrow = currentSortDirection === "asc" ? " ▲" : " ▼";
                    th.innerHTML = `${labelText}<span style="color: var(--primary); font-size: 0.75rem;">${arrow}</span>`;
                    th.classList.add("sorted");
                } else {
                    th.innerHTML = `${labelText}<span style="opacity: 0.2; font-size: 0.75rem;"> ⇅</span>`;
                    th.classList.remove("sorted");
                }
            }
        }

        function exportToExcel() {
            const domains = tableDomainsCache;
            const lastResults = tableResultsCache;
            if (!domains || domains.length === 0) {
                showToast("No data available to export.", "error");
                return;
            }
            
            let csvContent = "Domain,Status,Severity,Expiry Date,Remaining Days,Remarks,Checked At\n";
            const sortedDomains = [...domains].sort((a, b) => a.localeCompare(b));
            
            sortedDomains.forEach(domain => {
                const res = lastResults[domain];
                let statusText = "Pending";
                let severity = "Pending";
                let expiryDate = "Never checked";
                let remainingDays = "N/A";
                let remarksText = "Awaiting verification check...";
                let checkedAt = "Never";
                
                if (res) {
                    statusText = res.status || "Unknown";
                    severity = res.severity || "Failed";
                    expiryDate = res.expiry_date || "N/A";
                    remainingDays = res.days_remaining !== undefined ? res.days_remaining : "N/A";
                    remarksText = res.remarks || "";
                    checkedAt = res.checked_at || "N/A";
                }
                
                const escapeCSV = (val) => {
                    const str = String(val);
                    if (str.includes(",") || str.includes("\"") || str.includes("\n") || str.includes("\r")) {
                        return `"${str.replace(/"/g, '""')}"`;
                    }
                    return str;
                };
                
                csvContent += `${escapeCSV(domain)},${escapeCSV(statusText)},${escapeCSV(severity)},${escapeCSV(expiryDate)},${escapeCSV(remainingDays)},${escapeCSV(remarksText)},${escapeCSV(checkedAt)}\n`;
            });
            
            const blob = new Blob([new Uint8Array([0xEF, 0xBB, 0xBF]), csvContent], { type: "text/csv;charset=utf-8;" });
            const link = document.createElement("a");
            const url = URL.createObjectURL(blob);
            link.setAttribute("href", url);
            
            const timestamp = new Date().toISOString().slice(0, 10);
            link.setAttribute("download", `ssl_expiry_report_${timestamp}.csv`);
            link.style.visibility = 'hidden';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            showToast("Report exported successfully!", "success");
        }

        // Table Render Logic
        let tableDomainsCache = [];
        let tableResultsCache = {};
        function renderResultsTable(domains = [], lastResults = {}) {
            if (!domains) domains = [];
            tableDomainsCache = domains;
            if (Object.keys(lastResults).length > 0) {
                tableResultsCache = lastResults;
            } else {
                lastResults = tableResultsCache;
            }
            
            updateSortHeadersUI();

            const container = document.getElementById("table-results-body");
            if (!container) return;
            
            if (domains.length === 0) {
                container.innerHTML = `<tr><td colspan="7" style="padding: 2.5rem; text-align: center; color: var(--text-muted); font-size: 0.9rem;">No records available. Add domains and run check.</td></tr>`;
                const recordCountEl = document.getElementById("table-record-count");
                if (recordCountEl) {
                    recordCountEl.innerText = "0 items";
                }
                return;
            }
            
            // Build raw row data for sorting and filtering
            const rowData = domains.map(domain => {
                const res = lastResults[domain] || {};
                return {
                    domain: domain,
                    status: res.status || "Pending",
                    severity: res.severity || "Pending",
                    expiry_date: res.expiry_date || "Never checked",
                    days_remaining: res.days_remaining !== undefined ? res.days_remaining : -999999,
                    remarks: res.remarks || "Awaiting verification check...",
                    checked_at: res.checked_at || "Never",
                    raw: res
                };
            });
            
            const searchInput = document.getElementById("table-search-input");
            const filterInput = document.getElementById("table-severity-filter");
            const searchQuery = searchInput ? searchInput.value.toLowerCase().trim() : "";
            const severityFilter = filterInput ? filterInput.value.toLowerCase().trim() : "all";
            
            // Filter Rows
            const filteredRows = rowData.filter(row => {
                if (searchQuery && !row.domain.toLowerCase().includes(searchQuery) && !row.remarks.toLowerCase().includes(searchQuery)) {
                    return false;
                }
                if (severityFilter !== "all") {
                    const sev = row.severity.toLowerCase();
                    if (severityFilter === "healthy" && sev !== "healthy") return false;
                    if (severityFilter === "warning" && (sev !== "warning" && sev !== "high")) return false;
                    if (severityFilter === "critical" && sev !== "critical") return false;
                    if (severityFilter === "expired" && sev !== "expired") return false;
                    if (severityFilter === "failed" && sev !== "failed") return false;
                }
                return true;
            });
            
            // Sort Rows
            filteredRows.sort((a, b) => {
                let comparison = 0;
                if (currentSortColumn === "domain") {
                    comparison = a.domain.localeCompare(b.domain);
                } else if (currentSortColumn === "status") {
                    const severityWeight = (sev) => {
                        if (sev === "Expired") return 5;
                        if (sev === "Critical") return 4;
                        if (sev === "High") return 3;
                        if (sev === "Warning") return 2;
                        if (sev === "Failed") return 1;
                        if (sev === "Healthy") return 0;
                        return -1;
                    };
                    comparison = severityWeight(b.severity) - severityWeight(a.severity);
                    if (comparison === 0) {
                        comparison = a.domain.localeCompare(b.domain);
                    }
                } else if (currentSortColumn === "expiry_date") {
                    const aIsNav = (a.expiry_date === "Never checked" || a.expiry_date === "N/A");
                    const bIsNav = (b.expiry_date === "Never checked" || b.expiry_date === "N/A");
                    if (aIsNav && bIsNav) {
                        comparison = a.domain.localeCompare(b.domain);
                    } else if (aIsNav) {
                        comparison = 1;
                    } else if (bIsNav) {
                        comparison = -1;
                    } else {
                        comparison = new Date(String(a.expiry_date).replace(" IST", "")) - new Date(String(b.expiry_date).replace(" IST", ""));
                        if (isNaN(comparison)) comparison = 0;
                    }
                } else if (currentSortColumn === "remaining") {
                    comparison = a.days_remaining - b.days_remaining;
                    if (comparison === 0) {
                        comparison = a.domain.localeCompare(b.domain);
                    }
                } else if (currentSortColumn === "checked_at") {
                    const aIsNav = (a.checked_at === "Never" || a.checked_at === "N/A");
                    const bIsNav = (b.checked_at === "Never" || b.checked_at === "N/A");
                    if (aIsNav && bIsNav) {
                        comparison = a.domain.localeCompare(b.domain);
                    } else if (aIsNav) {
                        comparison = 1;
                    } else if (bIsNav) {
                        comparison = -1;
                    } else {
                        comparison = new Date(String(a.checked_at).replace(" IST", "")) - new Date(String(b.checked_at).replace(" IST", ""));
                        if (isNaN(comparison)) comparison = 0;
                    }
                }
                
                return currentSortDirection === "asc" ? comparison : -comparison;
            });
            
            let html = "";
            let matchCount = 0;
            
            filteredRows.forEach(row => {
                matchCount++;
                
                let statusText = row.status;
                let statusClass = row.severity.toLowerCase();
                let expiryDate = row.expiry_date;
                let remainingDaysText = "N/A";
                let daysClass = "failed";
                let remarksText = row.remarks;
                let checkedAt = row.checked_at;
                
                const res = row.raw;
                if (res && res.days_remaining !== undefined && res.days_remaining !== -1) {
                    remainingDaysText = `${res.days_remaining} days`;
                    
                    if (res.days_remaining <= 0) {
                        daysClass = "expired";
                    } else if (res.days_remaining < 7) {
                        daysClass = "critical";
                    } else if (res.days_remaining < 30) {
                        daysClass = "warning";
                    } else {
                        daysClass = "healthy";
                    }
                }
                
                html += `
                <tr>
                    <td style="font-weight: 600; color: #ffffff; font-size: 0.92rem;">${row.domain}</td>
                    <td><span class="status-badge ${statusClass}">${statusText}</span></td>
                    <td style="font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; color: #e5e7eb;">${expiryDate}</td>
                    <td><span class="days-remaining ${daysClass}" style="font-weight: 700;">${remainingDaysText}</span></td>
                    <td style="color: var(--text-muted); font-size: 0.85rem; font-style: italic; max-width: 320px; overflow-wrap: break-word; white-space: normal; line-height: 1.4;">${remarksText}</td>
                    <td style="font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; color: var(--text-muted);">${checkedAt}</td>
                    <td style="text-align: center;">
                        <button class="btn-recheck" onclick="recheckDomain(this, '${row.domain}')">
                             <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg>
                            Recheck
                        </button>
                    </td>
                </tr>
                `;
            });
            
            if (matchCount === 0) {
                container.innerHTML = `<tr><td colspan="7" style="padding: 2.5rem; text-align: center; color: var(--text-muted); font-size: 0.9rem;">No matching domains found.</td></tr>`;
            } else {
                container.innerHTML = html;
            }
            
            const recordCountEl = document.getElementById("table-record-count");
            if (recordCountEl) {
                recordCountEl.innerText = `${matchCount} items`;
            }
        }


        function filterResultsTable() {
            renderResultsTable(tableDomainsCache, tableResultsCache);
        }

        // 3. Render loaded domains to registry lists
        let registeredDomainsCache = [];
        let lastResultsCache = {};
        function renderDomainsList(domains, lastResults = {}) {
            registeredDomainsCache = domains;
            if (Object.keys(lastResults).length > 0) {
                lastResultsCache = lastResults;
            } else {
                lastResults = lastResultsCache;
            }
            const container = document.getElementById("domains-list-container");
            
            if (domains.length === 0) {
                container.innerHTML = `<div style="padding: 2rem; text-align: center; color: var(--text-muted); font-size: 0.85rem;">
                    No domains monitored. Add a domain to start tracking!
                </div>`;
                return;
            }

            const searchQuery = document.getElementById("search-registry-input").value.toLowerCase().trim ? 
                document.getElementById("search-registry-input").value.toLowerCase().trim() : 
                document.getElementById("search-registry-input").value.toLowerCase();
            
            let html = "";
            let matchCount = 0;
            
            // Sort domains alphabetically for easy lookup in long lists
            const sortedDomains = [...domains].sort((a, b) => a.localeCompare(b));

            sortedDomains.forEach(domain => {
                if (searchQuery && !domain.includes(searchQuery)) {
                    return; // Skip if filter not matched
                }
                matchCount++;
                
                const res = lastResults[domain];
                
                let statusText = "Pending";
                let statusClass = "pending";
                let expiryDate = "Never checked";
                let remainingDaysText = "N/A";
                let daysClass = "failed";
                let remarksHtml = "";
                
                if (res) {
                    statusText = res.status || "Unknown";
                    const sev = res.severity || "Failed";
                    statusClass = sev.toLowerCase();
                    expiryDate = res.expiry_date || "N/A";
                    
                    if (res.days_remaining !== undefined && res.days_remaining !== -1) {
                        remainingDaysText = `${res.days_remaining} days`;
                        
                        if (res.days_remaining <= 0) {
                            daysClass = "expired";
                        } else if (res.days_remaining < 7) {
                            daysClass = "critical";
                        } else if (res.days_remaining < 30) {
                            daysClass = "warning";
                        } else {
                            daysClass = "healthy";
                        }
                    } else {
                        remainingDaysText = "N/A";
                        daysClass = "failed";
                    }
                    
                    if (res.remarks) {
                        remarksHtml = `<div class="domain-remarks">${res.remarks}</div>`;
                    }
                }
                
                html += `
                <div class="domain-item" data-domain="${domain}">
                    <div class="domain-info">
                        <div class="domain-header-row">
                            <span class="domain-name">${domain}</span>
                            <span class="status-badge ${statusClass}">${statusText}</span>
                        </div>
                        <div class="domain-meta-row">
                            <span class="meta-label">Expiry:</span> <span class="meta-val">${expiryDate}</span>
                            <span class="meta-separator">|</span>
                            <span class="meta-label">Remaining:</span> <span class="meta-val days-remaining ${daysClass}">${remainingDaysText}</span>
                        </div>
                        ${remarksHtml}
                    </div>
                    <button class="btn-delete" title="Delete Domain" onclick="deleteTargetDomain('${domain}')">
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
                    </button>
                </div>
                `;
            });

            if (matchCount === 0 && searchQuery) {
                container.innerHTML = `<div style="padding: 2rem; text-align: center; color: var(--text-muted); font-size: 0.85rem;">
                    No matching subdomains found in registry.
                </div>`;
                return;
            }

            container.innerHTML = html;
        }

        // 4. Registry Filter Logic
        function filterRegistryList() {
            renderDomainsList(registeredDomainsCache, lastResultsCache);
        }

        // 5. Add new domain targets via AJAX
        async function addTargetDomain() {
            if (activeOrganization === "all") {
                showToast("Please select a specific organization to add domains.", "error");
                return;
            }
            const input = document.getElementById("new-domain-input");
            const domain = input.value.trim();
            if (!domain) {
                showToast("Please enter a valid domain address.", "error");
                return;
            }

            try {
                const response = await fetch("/api/domains", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ domain: domain, org_name: activeOrganization })
                });
                if (response.status === 401) {
                    window.location.reload();
                    return;
                }
                
                const resData = await response.json();
                if (response.ok) {
                    showToast(resData.message || "Domain registered!", "success");
                    input.value = "";
                    fetchDomains();
                } else {
                    showToast(resData.error || "Failed to add domain.", "error");
                }
            } catch (err) {
                showToast("Server communication error.", "error");
            }
        }

        // 6. Delete domain targets via AJAX
        async function deleteTargetDomain(domain) {
            if (!confirm(`Are you sure you want to remove '${domain}' from SSL monitoring?`)) {
                return;
            }

            try {
                const response = await fetch(`/api/domains?domain=${encodeURIComponent(domain)}`, {
                    method: "DELETE"
                });
                if (response.status === 401) {
                    window.location.reload();
                    return;
                }
                
                const resData = await response.json();
                if (response.ok) {
                    showToast(resData.message || "Domain deleted.", "success");
                    fetchDomains();
                } else {
                    showToast(resData.error || "Failed to delete domain.", "error");
                }
            } catch (err) {
                showToast("Server communication error.", "error");
            }
        }

        // 7. Render recipients list
        function renderRecipients() {
            const container = document.getElementById("recipients-list-container");
            const countLabel = document.getElementById("recipients-count");
            const formContainer = document.getElementById("add-recipient-form");
            const inputField = document.getElementById("new-recipient-input");

            if (!container) return;

            if (activeOrganization === "all") {
                if (formContainer) formContainer.style.display = "none";
                
                // Show a combined list of all recipients for all organizations
                let allRecipients = [];
                for (const org in allOrgRecipientsCache) {
                    const emails = allOrgRecipientsCache[org] || [];
                    emails.forEach(email => {
                        allRecipients.push({ org, email });
                    });
                }

                if (allRecipients.length === 0) {
                    container.innerHTML = `<div class="recipient-empty">No recipients configured.</div>`;
                    countLabel.innerText = "0 recipients";
                    return;
                }

                allRecipients.sort((a, b) => a.email.localeCompare(b.email));

                let html = "";
                allRecipients.forEach(item => {
                    html += `
                    <div class="recipient-item">
                        <div class="email-text">
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path><polyline points="22,6 12,13 2,6"></polyline></svg>
                            <span>${item.email} <small style="opacity: 0.6; font-size: 0.7rem;">(${item.org})</small></span>
                        </div>
                    </div>
                    `;
                });
                container.innerHTML = html;
                countLabel.innerText = `${allRecipients.length} total`;
            } else {
                if (formContainer) {
                    formContainer.style.display = "flex";
                }
                if (inputField) {
                    inputField.placeholder = `Add recipient to ${activeOrganization}...`;
                }

                const emails = allOrgRecipientsCache[activeOrganization] || [];
                countLabel.innerText = `${emails.length} recipients`;

                if (emails.length === 0) {
                    container.innerHTML = `<div class="recipient-empty">No recipients configured for this org.</div>`;
                    return;
                }

                const sortedEmails = [...emails].sort((a, b) => a.localeCompare(b));
                let html = "";
                sortedEmails.forEach(email => {
                    html += `
                    <div class="recipient-item">
                        <div class="email-text">
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path><polyline points="22,6 12,13 2,6"></polyline></svg>
                            <span>${email}</span>
                        </div>
                        <button class="btn-remove-recipient" onclick="removeRecipient('${email}')">Remove</button>
                    </div>
                    `;
                });
                container.innerHTML = html;
            }
        }

        // 8. Add recipient via AJAX
        async function addRecipient() {
            if (activeOrganization === "all") {
                showToast("Please select a specific organization to add a recipient.", "error");
                return;
            }
            const input = document.getElementById("new-recipient-input");
            if (!input) return;
            const email = input.value.trim();
            if (!email) {
                showToast("Please enter a valid email address.", "error");
                return;
            }

            try {
                const response = await fetch("/api/recipients", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ org_name: activeOrganization, email: email })
                });
                if (response.status === 401) {
                    window.location.reload();
                    return;
                }
                const resData = await response.json();
                if (response.ok) {
                    showToast(resData.message || "Recipient added!", "success");
                    input.value = "";
                    fetchDomains();
                } else {
                    showToast(resData.error || "Failed to add recipient.", "error");
                }
            } catch (err) {
                showToast("Server communication error.", "error");
            }
        }

        // 9. Remove recipient via AJAX
        async function removeRecipient(email) {
            if (activeOrganization === "all") return;
            if (!confirm(`Are you sure you want to remove recipient '${email}' from '${activeOrganization}'?`)) {
                return;
            }

            try {
                const response = await fetch(`/api/recipients?org_name=${encodeURIComponent(activeOrganization)}&email=${encodeURIComponent(email)}`, {
                    method: "DELETE"
                });
                if (response.status === 401) {
                    window.location.reload();
                    return;
                }
                const resData = await response.json();
                if (response.ok) {
                    showToast(resData.message || "Recipient removed.", "success");
                    fetchDomains();
                } else {
                    showToast(resData.error || "Failed to remove recipient.", "error");
                }
            } catch (err) {
                showToast("Server communication error.", "error");
            }
        }

        // 9b. Recheck single domain
        async function recheckDomain(btn, domain) {
            btn.disabled = true;
            const originalHTML = btn.innerHTML;
            btn.innerHTML = `<svg class="spinner" width="10" height="10" viewBox="0 0 50 50" style="animation: rotate 1s linear infinite; margin-right: 3px;"><circle cx="25" cy="25" r="20" fill="none" stroke="currentColor" stroke-width="5" stroke-linecap="round" style="stroke-dasharray: 1, 150; stroke-dashoffset: 0; animation: dash 1.5s ease-in-out infinite;"></circle></svg> Checking...`;
            
            showToast(`Initiating manual check for '${domain}'...`, "success");
            
            try {
                const response = await fetch("/api/check-domain", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({ domain: domain })
                });
                
                if (response.status === 401) {
                    window.location.reload();
                    return;
                }
                
                const resData = await response.json();
                if (response.ok && resData.success) {
                    showToast(resData.message, "success");
                    
                    // Update cache and re-render
                    if (resData.result) {
                        tableResultsCache[domain] = resData.result;
                        allResultsCache[domain] = resData.result;
                        
                        renderResultsTable(tableDomainsCache, tableResultsCache);
                        filterAndRenderDashboard();
                    }
                } else {
                    showToast(resData.error || `Failed to recheck domain '${domain}'.`, "error");
                    btn.disabled = false;
                    btn.innerHTML = originalHTML;
                }
            } catch (err) {
                showToast("Network dispatch error checking domain.", "error");
                btn.disabled = false;
                btn.innerHTML = originalHTML;
            }
        }

        // 10. Trigger manual background scan check
        async function triggerSSLCheck() {
            const btn = document.getElementById("btn-run-check");
            btn.disabled = true;
            btn.innerHTML = `<svg class="spinner" width="14" height="14" viewBox="0 0 50 50" style="animation: rotate 1s linear infinite; margin-right: 5px;"><circle cx="25" cy="25" r="20" fill="none" stroke="currentColor" stroke-width="5" stroke-linecap="round" style="stroke-dasharray: 1, 150; stroke-dashoffset: 0; animation: dash 1.5s ease-in-out infinite;"></circle></svg> Scanning...`;
            
            const scopeText = activeOrganization === "all" ? "All Organizations" : `'${activeOrganization}'`;
            showToast(`Dispatched certificate checks for ${scopeText} in the background...`, "success");

            try {
                const response = await fetch("/api/check", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({ org_name: activeOrganization })
                });
                if (response.status === 401) {
                    window.location.reload();
                    return;
                }
                const resData = await response.json();
                
                if (response.ok) {
                    showToast(resData.message, "success");
                } else {
                    showToast(resData.error || "Could not complete check.", "error");
                }
            } catch (err) {
                showToast("Network dispatch error.", "error");
            } finally {
                setTimeout(() => {
                    btn.disabled = false;
                    btn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg> Run Check Now`;
                    fetchLogs();
                }, 2000);
            }
        }

        // 11. Fetch rotating log files details
        let lastLogLinesSerialized = "";
        async function fetchLogs() {
            const container = document.getElementById("terminal-log-output");
            const label = document.getElementById("status-terminal-label");
            
            try {
                const response = await fetch("/api/logs");
                if (response.status === 401) {
                    window.location.reload();
                    return;
                }
                if (!response.ok) throw new Error("Logs load error");
                
                const data = await response.json();
                const logs = data.logs || [];
                
                const serialized = logs.join("");
                if (serialized === lastLogLinesSerialized) {
                    return; // Skip if no new log outputs
                }
                
                lastLogLinesSerialized = serialized;
                
                if (logs.length === 0) {
                    container.innerHTML = `<div class="log-line log-warning">[Console] Log file is currently empty. Start standard scans to record checks activity.</div>`;
                    return;
                }

                // Render with styling codes
                let html = "";
                logs.forEach(line => {
                    let className = "log-info";
                    if (line.includes("[WARNING]")) {
                        className = "log-warning";
                    } else if (line.includes("[ERROR]")) {
                        className = "log-error";
                    } else if (line.includes("Success:") || line.includes("completed") || line.includes("dispatched successfully")) {
                        className = "log-success";
                    }
                    
                    // Simple HTML Escape
                    const escapedLine = line
                        .replace(/&/g, "&amp;")
                        .replace(/</g, "&lt;")
                        .replace(/>/g, "&gt;");
                        
                    html += `<div class="log-line ${className}">${escapedLine}</div>`;
                });
                
                container.innerHTML = html;
                
                // Auto scroll to bottom
                container.scrollTop = container.scrollHeight;
                
                label.innerText = "Console Buffers Updated";
                setTimeout(() => { label.innerText = "Auto-polling logs"; }, 1500);
                
            } catch (err) {
                label.innerText = "Connection Dropped";
            }
        }

        // 12. Toast dynamic UI helper
        function showToast(message, type = "success") {
            const container = document.getElementById("toast-container");
            const toast = document.createElement("div");
            toast.className = `toast ${type}`;
            
            // Checkmark or Cross SVG icon
            const icon = type === "success" ? 
                `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" style="color: var(--green);"><polyline points="20 6 9 17 4 12"></polyline></svg>` : 
                `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" style="color: var(--red);"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>`;

            toast.innerHTML = `${icon} <span>${message}</span>`;
            container.appendChild(toast);

            // Trigger animation fade-out
            setTimeout(() => {
                toast.classList.add("fade-out");
                toast.addEventListener("animationend", () => {
                    toast.remove();
                });
            }, 4000);
        }

        async function handleLogout() {
            try {
                const response = await fetch("/api/logout", { method: "POST" });
                if (response.ok) {
                    showToast("Successfully logged out. Redirecting...", "success");
                    setTimeout(() => {
                        window.location.reload();
                    }, 800);
                } else {
                    showToast("Logout failed.", "error");
                }
            } catch (err) {
                showToast("Logout failed due to network error.", "error");
            }
        }
    