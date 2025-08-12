document.addEventListener('DOMContentLoaded', () => {
    const initThemeSwitcher = () => {
        const themeCheckbox = document.getElementById('theme-checkbox');
        window.chartInstances = {};
        const updateAllChartColors = () => {
            const isDarkMode = document.body.classList.contains('dark-mode');
            const textColor = isDarkMode ? '#F7FAFC' : '#666';
            const cardBgColor = isDarkMode ? '#34495E' : '#FFFFFF';
            const gridColor = isDarkMode ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)';
            if (typeof Chart === 'undefined') return;
            Chart.defaults.color = textColor;
            for (const chartName in window.chartInstances) {
                const chart = window.chartInstances[chartName];
                if (chart) {
                    if (chart.options.plugins?.title) chart.options.plugins.title.color = isDarkMode ? '#ECF0F1' : '#34495E';
                    if (chart.options.plugins?.legend) chart.options.plugins.legend.labels.color = textColor;
                    if (chart.config.type === 'doughnut' && chart.data.datasets[0]) chart.data.datasets[0].borderColor = cardBgColor;
                    if (chart.options.scales?.x) {
                        chart.options.scales.x.ticks.color = textColor;
                        chart.options.scales.x.grid.color = gridColor;
                    }
                    if (chart.options.scales?.y) {
                        chart.options.scales.y.ticks.color = textColor;
                        chart.options.scales.y.grid.color = gridColor;
                    }
                    chart.update();
                }
            }
        };
        const applyTheme = () => {
            const isDarkMode = localStorage.getItem('theme') === 'dark';
            document.body.classList.toggle('dark-mode', isDarkMode);
            if (themeCheckbox) themeCheckbox.checked = isDarkMode;
            updateAllChartColors();
        };
        if (themeCheckbox) {
            themeCheckbox.addEventListener('change', () => {
                localStorage.setItem('theme', themeCheckbox.checked ? 'dark' : 'light');
                applyTheme();
            });
        }
        applyTheme();
    };

    const initAuthPage = () => {
        const showLogin = document.getElementById('showLogin');
        const showRegister = document.getElementById('showRegister');
        const loginForm = document.getElementById('loginForm');
        const registerForm = document.getElementById('registerForm');
        const switchToLogin = () => {
            loginForm.style.display = 'block';
            registerForm.style.display = 'none';
            showLogin.classList.add('active');
            showRegister.classList.remove('active');
        };
        const switchToRegister = () => {
            loginForm.style.display = 'none';
            registerForm.style.display = 'block';
            showLogin.classList.remove('active');
            showRegister.classList.add('active');
        };
        showLogin.addEventListener('click', (e) => { e.preventDefault(); switchToLogin(); window.location.hash = '#login'; });
        showRegister.addEventListener('click', (e) => { e.preventDefault(); switchToRegister(); window.location.hash = '#register'; });
        if (window.location.hash === '#register') { switchToRegister(); } else { switchToLogin(); }
    };

    const initDashboardPage = () => {
        const scanButton = document.getElementById('scanButton');
        const credentialSelect = document.getElementById('credentialProfileSelect');
        const resultsList = document.getElementById('resultsList');
        const historyList = document.getElementById('historyList');
        const remediationList = document.getElementById('remediationList');
        const deleteHistoryButton = document.getElementById('deleteHistoryButton');
        const postureChartCanvas = document.getElementById('postureChart');
        const serviceBreakdownCanvas = document.getElementById('serviceBreakdownChart');
        const historicalTrendCanvas = document.getElementById('historicalTrendCanvas');
        const scanConsoleWrapper = document.getElementById('scan-console-wrapper');
        const scanConsole = document.getElementById('scan-console');
        const progressModeToggle = document.getElementById('progressModeToggle');
        let eventSource = null;

        const currentSearchInput = document.getElementById('currentSearch');
        const currentStatusFilter = document.getElementById('currentStatusFilter');
        const historySearchInput = document.getElementById('historySearch');
        const historyStatusFilter = document.getElementById('historyStatusFilter');
        
        const historyPrevBtn = document.getElementById('historyPrevBtn');
        const historyNextBtn = document.getElementById('historyNextBtn');
        const historyPageIndicator = document.getElementById('historyPageIndicator');
        let currentPage = 1;

        const API_BASE_URL = window.location.origin;
        const SCAN_API_URL = `${API_BASE_URL}/api/v1/scan`;
        const HISTORY_API_URL = `${API_BASE_URL}/api/v1/history`;
        const TRENDS_API_URL = `${API_BASE_URL}/api/v1/history/trends`;
        const DELETE_HISTORY_API_URL = `${API_BASE_URL}/api/v1/delete_history`;
        const SUPPRESS_API_URL = `${API_BASE_URL}/api/v1/suppress_finding`;

        const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

        const suppressFinding = async (findingData, elementToHide) => {
            try {
                const response = await fetch(SUPPRESS_API_URL, {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': csrfToken
                    },
                    body: JSON.stringify({ finding: findingData }),
                });
                if (!response.ok) { throw new Error('Failed to suppress finding.'); }
                const data = await response.json();
                Toastify({ text: data.message, duration: 3000, gravity: "bottom", position: "right", style: { background: "linear-gradient(to right, #4A90E2, #357ABD)" } }).showToast();
                elementToHide.style.display = 'none';
            } catch (error) {
                Toastify({ text: error.message, duration: 4000, gravity: "bottom", position: "right", style: { background: "linear-gradient(to right, #D0021B, #e74c3c)" } }).showToast();
            }
        };
        
        const renderResults = (container, results) => {
            container.innerHTML = '';
            if (results && results.length > 0) {
                results.forEach(result => {
                    const resultItem = document.createElement('div');
                    resultItem.className = `result-item ${result.status ? result.status.toLowerCase() : 'ok'}`;
                    
                    const header = document.createElement('div');
                    header.className = 'result-item-header';
                    const detailsDiv = document.createElement('div');
                    const serviceStrong = document.createElement('strong');
                    serviceStrong.textContent = 'Service: ';
                    detailsDiv.appendChild(serviceStrong);
                    detailsDiv.appendChild(document.createTextNode(result.service));
                    detailsDiv.appendChild(document.createElement('br'));
                    const resourceStrong = document.createElement('strong');
                    resourceStrong.textContent = 'Resource: ';
                    detailsDiv.appendChild(resourceStrong);
                    detailsDiv.appendChild(document.createTextNode(result.resource || 'N/A'));
                    header.appendChild(detailsDiv);

                    const suppressBtn = document.createElement('button');
                    suppressBtn.className = 'button-secondary button-small suppress-btn';
                    suppressBtn.title = 'Suppress this finding';
                    suppressBtn.innerHTML = '<i class="fas fa-eye-slash"></i> Suppress';
                    suppressBtn.addEventListener('click', () => {
                        if (confirm('Are you sure you want to suppress this finding? It will be hidden from future scans.')) {
                            const findingData = { service: result.service, resource: result.resource, issue: result.issue };
                            suppressFinding(findingData, resultItem);
                        }
                    });
                    header.appendChild(suppressBtn);
                    resultItem.appendChild(header);

                    const statusStrong = document.createElement('strong');
                    statusStrong.textContent = 'Status: ';
                    resultItem.appendChild(statusStrong);
                    const statusSpan = document.createElement('span');
                    statusSpan.className = `status-${result.status}`;
                    statusSpan.textContent = result.status;
                    resultItem.appendChild(statusSpan);
                    resultItem.appendChild(document.createElement('br'));

                    const issueStrong = document.createElement('strong');
                    issueStrong.textContent = result.issue ? 'Issue: ' : 'Error: ';
                    resultItem.appendChild(issueStrong);
                    resultItem.appendChild(document.createTextNode(result.issue || result.error));

                    if (result.timestamp) {
                        resultItem.appendChild(document.createElement('br'));
                        const small = document.createElement('small');
                        small.textContent = `Time: ${new Date(result.timestamp).toLocaleString()}`;
                        resultItem.appendChild(small);
                    }

                    if (result.remediation) {
                        const remediationBlock = document.createElement('div');
                        remediationBlock.className = 'remediation-block';
                        const fixStrong = document.createElement('strong');
                        fixStrong.innerHTML = '<i class="fas fa-wrench"></i> How to Fix:';
                        remediationBlock.appendChild(fixStrong);
                        const p = document.createElement('p');
                        p.textContent = result.remediation;
                        remediationBlock.appendChild(p);
                        if (result.doc_url) {
                            const docLink = document.createElement('a');
                            docLink.href = result.doc_url;
                            docLink.target = '_blank';
                            docLink.className = 'remediation-link';
                            docLink.innerHTML = 'View AWS Docs <i class="fas fa-external-link-alt"></i>';
                            remediationBlock.appendChild(docLink);
                        }
                        resultItem.appendChild(remediationBlock);
                    }
                    container.appendChild(resultItem);
                });
            } else {
                container.innerHTML = '<p class="empty-state">No results found.</p>';
            }
        };
        
        const updateRemediationPanel = (results) => {
            const criticalItems = results.filter(r => r.status === 'CRITICAL').slice(0, 3);
            remediationList.innerHTML = '';
            if (criticalItems.length > 0) {
                criticalItems.forEach(item => {
                    const div = document.createElement('div');
                    div.classList.add('remediation-item');
                    div.innerHTML = `<strong>${item.service}:</strong> Fix issue on <span class="resource-name">${item.resource}</span>.<div style="font-size: 0.9em; color: var(--medium-grey);">${item.issue}</div>`;
                    remediationList.appendChild(div);
                });
            } else {
                remediationList.innerHTML = '<p class="empty-state"><i class="fas fa-check-circle" style="color: var(--success-color);"></i> No critical issues found. Great job!</p>';
            }
        };

        const updateDashboardCharts = (results) => {
            if (!postureChartCanvas || !serviceBreakdownCanvas) return;
            const validResults = results.filter(r => r && r.status);
            const okCount = validResults.filter(r => r.status === 'OK').length;
            const criticalCount = validResults.filter(r => r.status === 'CRITICAL').length;
            const totalCount = okCount + criticalCount;
            document.getElementById('totalResources').textContent = totalCount;
            document.getElementById('criticalFindings').textContent = criticalCount;
            const healthScore = totalCount > 0 ? Math.round((okCount / totalCount) * 100) : 100;
            document.getElementById('healthScore').textContent = `${healthScore}%`;
            if (window.chartInstances.posture) window.chartInstances.posture.destroy();
            window.chartInstances.posture = new Chart(postureChartCanvas, { type: 'doughnut', data: { labels: ['OK', 'CRITICAL'], datasets: [{ data: [okCount, criticalCount], backgroundColor: ['#4CAF50', '#D64550'], borderWidth: 4 }] }, options: { responsive: true, maintainAspectRatio: false, cutout: '70%', plugins: { legend: { position: 'top' }, title: { display: true, text: 'Security Posture', padding: { bottom: 20 }, font: { size: 18, weight: '600' }}}} });
            const criticalByService = validResults.filter(r => r.status === 'CRITICAL').reduce((acc, r) => { acc[r.service] = (acc[r.service] || 0) + 1; return acc; }, {});
            if (window.chartInstances.service) window.chartInstances.service.destroy();
            window.chartInstances.service = new Chart(serviceBreakdownCanvas, { type: 'bar', data: { labels: Object.keys(criticalByService), datasets: [{ label: 'Critical Findings', data: Object.values(criticalByService), backgroundColor: '#D64550' }] }, options: { indexAxis: 'y', responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false }, title: { display: true, text: 'Critical Findings by Service', padding: { bottom: 10 }, font: { size: 18, weight: '600' }}}} });
            document.dispatchEvent(new Event('themeChanged'));
        };

        const renderTrendChart = async () => {
            if (!historicalTrendCanvas) return;
            try {
                const response = await fetch(TRENDS_API_URL);
                const trendData = await response.json();
                if (window.chartInstances.trends) window.chartInstances.trends.destroy();
                window.chartInstances.trends = new Chart(historicalTrendCanvas, { type: 'line', data: { labels: trendData.labels, datasets: [{ label: 'Critical Findings', data: trendData.data, fill: true, borderColor: '#00A896', backgroundColor: 'rgba(0, 168, 150, 0.1)', tension: 0.1 }] }, options: { responsive: true, maintainAspectRatio: false, plugins: { title: { display: true, text: 'Historical Trend (Last 30 Days)', padding: { bottom: 10 }, font: { size: 18, weight: '600' }}}} });
                document.dispatchEvent(new Event('themeChanged'));
            } catch (error) { console.error('Failed to load trend data:', error); }
        };

        const fetchAndRenderHistory = async (page = 1) => {
            try {
                const response = await fetch(`${HISTORY_API_URL}?page=${page}`);
                const data = await response.json();
                renderResults(historyList, data.historical_scans);
                
                currentPage = data.page;
                historyPageIndicator.textContent = `Page ${data.page} of ${data.total_pages || 1}`;
                historyPrevBtn.disabled = !data.has_prev;
                historyNextBtn.disabled = !data.has_next;

            } catch (error) {
                console.error("Failed to render history:", error);
                historyList.innerHTML = '<p class="empty-state">Could not load historical data.</p>';
            }
        };

        historyPrevBtn.addEventListener('click', () => {
            if (currentPage > 1) {
                fetchAndRenderHistory(currentPage - 1);
            }
        });

        historyNextBtn.addEventListener('click', () => {
            fetchAndRenderHistory(currentPage + 1);
        });

        scanButton.addEventListener('click', async () => {
            const selectedProfileId = credentialSelect.value;
            if (!selectedProfileId) {
                Toastify({ text: "Please select a credential profile.", duration: 3000, gravity: "bottom", position: "right", style: { background: "linear-gradient(to right, #F5A623, #e67e22)" } }).showToast();
                return;
            }

            const isProgressMode = progressModeToggle.checked;
            const originalButtonHtml = scanButton.innerHTML;
            scanButton.disabled = true;
            scanButton.innerHTML = `<i class="fas fa-spinner fa-spin"></i> Scanning...`;
            resultsList.innerHTML = '';
            scanConsoleWrapper.style.display = 'block';
            scanConsole.innerHTML = '';

            const handleFinalResults = (scanData) => {
                renderResults(resultsList, scanData.scan_results || scanData.results);
                updateDashboardCharts(scanData.scan_results || scanData.results);
                updateRemediationPanel(scanData.scan_results || scanData.results);
                if (!scanData.cached) {
                    fetchAndRenderHistory(); // Refresh history to page 1
                    renderTrendChart();
                }
            };
            
            if (isProgressMode) {
                const url = `${SCAN_API_URL}?profile_id=${selectedProfileId}&progress_mode=true`;
                eventSource = new EventSource(url);

                eventSource.onmessage = function(event) {
                    const data = JSON.parse(event.data);

                    if (data.status === 'progress' || data.status === 'error') {
                        const color = data.status === 'error' ? 'var(--danger-color)' : 'var(--primary-color)';
                        scanConsole.innerHTML += `<div class="scan-step" style="color: ${color};">${data.message}</div>`;
                        scanConsole.scrollTop = scanConsole.scrollHeight;
                    }

                    if (data.status === 'complete') {
                        scanConsole.innerHTML += `<div class="scan-step" style="color: var(--success-color);">Scan Complete.</div>`;
                        Toastify({ text: "Scan complete!", duration: 3000, gravity: "bottom", position: "right", style: { background: "linear-gradient(to right, #2ECC71, #27ae60)" } }).showToast();
                        handleFinalResults(data);
                        eventSource.close();
                        scanButton.disabled = false;
                        scanButton.innerHTML = originalButtonHtml;
                        setTimeout(() => { scanConsoleWrapper.style.display = 'none'; }, 8000);
                    }
                };

                eventSource.onerror = function() {
                    scanConsole.innerHTML += `<div class="scan-step" style="color: var(--danger-color);">ERROR: Connection to scan server lost.</div>`;
                    Toastify({ text: "Error during scan.", duration: 4000, gravity: "bottom", position: "right", style: { background: "linear-gradient(to right, #D0021B, #e74c3c)" } }).showToast();
                    eventSource.close();
                    scanButton.disabled = false;
                    scanButton.innerHTML = originalButtonHtml;
                };
            } else {
                const url = `${SCAN_API_URL}?profile_id=${selectedProfileId}&progress_mode=false`;
                scanConsole.innerHTML += `<div class="scan-step">Running in standard mode. Please wait...</div>`;
                try {
                    const response = await fetch(url);
                    if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
                    const data = await response.json();
                    
                    if (data.cached) {
                        scanConsole.innerHTML += '<div class="scan-step" style="color: var(--primary-color);">Displaying cached results.</div>';
                        Toastify({ text: "Showing cached results.", duration: 3000, gravity: "bottom", position: "right", style: { background: "linear-gradient(to right, #00A896, #007F73)" } }).showToast();
                    } else {
                        scanConsole.innerHTML += '<div class="scan-step" style="color: var(--success-color);">Scan Complete.</div>';
                        Toastify({ text: "Scan complete!", duration: 3000, gravity: "bottom", position: "right", style: { background: "linear-gradient(to right, #2ECC71, #27ae60)" } }).showToast();
                    }
                    
                    handleFinalResults(data);

                } catch (error) {
                    scanConsole.innerHTML += `<div class="scan-step" style="color: var(--danger-color);">ERROR: Scan failed. ${error.message}</div>`;
                    Toastify({ text: "Error during scan.", duration: 4000, gravity: "bottom", position: "right", style: { background: "linear-gradient(to right, #D0021B, #e74c3c)" } }).showToast();
                } finally {
                    scanButton.disabled = false;
                    scanButton.innerHTML = originalButtonHtml;
                    setTimeout(() => { scanConsoleWrapper.style.display = 'none'; }, 8000);
                }
            }
        });

        deleteHistoryButton.addEventListener('click', async () => {
            if (confirm("Are you sure you want to delete all your historical scan results? This cannot be undone.")) {
                await fetch(DELETE_HISTORY_API_URL, { 
                    method: 'POST',
                    headers: {
                        'X-CSRF-Token': csrfToken
                    }
                });
                Toastify({ text: "Historical data deleted.", duration: 3000, gravity: "bottom", position: "right", style: { background: "linear-gradient(to right, #4A90E2, #357ABD)" } }).showToast();
                fetchAndRenderHistory();
                renderTrendChart();
            }
        });

        const applyFilters = (listElement, searchInput, statusFilter) => {
            const searchTerm = searchInput.value.toLowerCase();
            const status = statusFilter.value;
            listElement.querySelectorAll('.result-item').forEach(item => {
                const textContent = item.textContent.toLowerCase();
                const itemStatus = item.classList.contains('critical') ? 'critical' :
                                   item.classList.contains('warning') ? 'warning' :
                                   item.classList.contains('ok') ? 'ok' : '';
                
                const textMatch = textContent.includes(searchTerm);
                const statusMatch = (status === 'all') || (itemStatus === status);

                if (textMatch && statusMatch) {
                    item.style.display = 'block';
                } else {
                    item.style.display = 'none';
                }
            });
        };

        currentSearchInput.addEventListener('keyup', () => applyFilters(resultsList, currentSearchInput, currentStatusFilter));
        currentStatusFilter.addEventListener('change', () => applyFilters(resultsList, currentSearchInput, currentStatusFilter));
        historySearchInput.addEventListener('keyup', () => applyFilters(historyList, historySearchInput, historyStatusFilter));
        historyStatusFilter.addEventListener('change', () => applyFilters(historyList, historySearchInput, historyStatusFilter));
        
        fetchAndRenderHistory();
        renderTrendChart();
    };

    const initAdminPage = () => {
        const addTableFilter = (inputId, tableId) => {
            const searchInput = document.getElementById(inputId);
            const table = document.getElementById(tableId);
            if (searchInput && table) {
                searchInput.addEventListener('keyup', () => {
                    const searchTerm = searchInput.value.toLowerCase();
                    const rows = table.tBodies[0].rows;
                    for (const row of rows) {
                        row.style.display = row.textContent.toLowerCase().includes(searchTerm) ? '' : 'none';
                    }
                });
            }
        };
        addTableFilter('userSearch', 'userTable');
        addTableFilter('scanSearch', 'scanTable');
        addTableFilter('logSearch', 'logTable');
    };

    const initSettingsPage = () => {
        const suppressedTable = document.getElementById('suppressedFindingsTable');
        if (!suppressedTable) return;

        suppressedTable.addEventListener('click', async (e) => {
            if (e.target && e.target.closest('.unsuppress-btn')) {
                const button = e.target.closest('.unsuppress-btn');
                const suppressionId = button.dataset.suppressionId;
                const row = button.closest('tr');

                if (confirm('Are you sure you want to un-suppress this finding? It will reappear in future scans.')) {
                    try {
                        const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
                        const response = await fetch(`/api/v1/unsuppress_finding/${suppressionId}`, {
                            method: 'POST',
                            headers: {
                                'X-CSRF-Token': csrfToken
                            }
                        });

                        if (!response.ok) {
                            const errorData = await response.json();
                            throw new Error(errorData.error || 'Failed to un-suppress finding.');
                        }

                        const data = await response.json();
                        Toastify({ text: data.message, duration: 3000, gravity: "bottom", position: "right", style: { background: "linear-gradient(to right, #2ECC71, #27ae60)" } }).showToast();
                        row.style.display = 'none';
                    } catch (error) {
                        Toastify({ text: error.message, duration: 4000, gravity: "bottom", position: "right", style: { background: "linear-gradient(to right, #D0021B, #e74c3c)" } }).showToast();
                    }
                }
            }
        });
    };

    initThemeSwitcher();
    if (document.getElementById('showLogin')) { initAuthPage(); }
    if (document.getElementById('scanButton')) { initDashboardPage(); }
    if (document.getElementById('adminDashboardPage')) { initAdminPage(); }
    if (document.getElementById('suppression-management')) { initSettingsPage(); }
});