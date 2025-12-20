// Dashboard logic with real-time updates
(function () {
    // Check authentication
    const credentials = sessionStorage.getItem('dashboardAuth');
    if (!credentials) {
        window.location.href = 'login.html';
        return;
    }

    // Chart instances
    let clientsChart, rpsChart, responseChart, trafficChart;

    // State
    let updateInterval;
    let previousStats = null;

    // Initialize dashboard
    init();

    // Initialize dashboard
    init();

    function init() {
        setupLogout();
        setupTabs();
        setupModules();
        initCharts();
        fetchAndUpdate();
        // Update every 2 seconds
        updateInterval = setInterval(fetchAndUpdate, 2000);
    }

    function setupLogout() {
        document.getElementById('logoutBtn').addEventListener('click', () => {
            sessionStorage.removeItem('dashboardAuth');
            window.location.href = 'login.html';
        });
    }

    function initCharts() {
        const chartOptions = {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(255, 255, 255, 0.05)'
                    },
                    ticks: {
                        color: '#a0a0b0'
                    }
                },
                x: {
                    grid: {
                        display: false
                    },
                    ticks: {
                        color: '#a0a0b0'
                    }
                }
            }
        };

        // Clients Chart (Line)
        const clientsCtx = document.getElementById('clientsChart').getContext('2d');
        clientsChart = new Chart(clientsCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Clientes Activos',
                    data: [],
                    borderColor: '#667eea',
                    backgroundColor: 'rgba(102, 126, 234, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4
                }]
            },
            options: chartOptions
        });

        // RPS Chart (Area)
        const rpsCtx = document.getElementById('rpsChart').getContext('2d');
        rpsChart = new Chart(rpsCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Requests/s',
                    data: [],
                    borderColor: '#51cf66',
                    backgroundColor: 'rgba(81, 207, 102, 0.2)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4
                }]
            },
            options: chartOptions
        });

        // Response Time Chart (Line)
        const responseCtx = document.getElementById('responseChart').getContext('2d');
        responseChart = new Chart(responseCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Latencia (ms)',
                    data: [],
                    borderColor: '#f093fb',
                    backgroundColor: 'rgba(240, 147, 251, 0.2)', // Lower opacity for area fill
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4
                }]
            },
            options: chartOptions
        });

        // Traffic Chart (Doughnut)
        const trafficCtx = document.getElementById('trafficChart').getContext('2d');
        trafficChart = new Chart(trafficCtx, {
            type: 'doughnut',
            data: {
                labels: ['API', 'HTML', 'CSS', 'JS', 'Other'],
                datasets: [{
                    data: [30, 25, 15, 20, 10],
                    backgroundColor: [
                        'rgba(102, 126, 234, 0.8)',
                        'rgba(118, 75, 162, 0.8)',
                        'rgba(81, 207, 102, 0.8)',
                        'rgba(255, 217, 61, 0.8)',
                        'rgba(255, 107, 107, 0.8)'
                    ],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#a0a0b0',
                            padding: 15,
                            font: {
                                size: 11
                            }
                        }
                    }
                }
            }
        });
    }

    async function fetchAndUpdate() {
        try {
            // Fetch current stats
            const currentResponse = await fetch('/api/dashboard/current', {
                headers: {
                    'Authorization': `Basic ${credentials}`
                }
            });

            if (!currentResponse.ok) {
                if (currentResponse.status === 401) {
                    sessionStorage.removeItem('dashboardAuth');
                    window.location.href = 'login.html';
                }
                return;
            }

            const currentStats = await currentResponse.json();

            // Fetch historical stats
            const historyResponse = await fetch('/api/dashboard/history', {
                headers: {
                    'Authorization': `Basic ${credentials}`
                }
            });

            const historyData = await historyResponse.json();

            // Update UI
            updateStatsCards(currentStats);
            updateCharts(historyData.history || []);
            updateTrafficChart(currentStats.traffic_breakdown);
            updateServerInfo(currentStats);

            previousStats = currentStats;

        } catch (error) {
            console.error('Error fetching stats:', error);
        }
    }

    function updateStatsCards(stats) {
        // Active Clients
        document.getElementById('activeClients').textContent = stats.active_clients || 0;

        // Total Requests
        const totalReq = document.getElementById('totalRequests');
        totalReq.textContent = formatNumber(stats.total_requests || 0);

        if (previousStats) {
            const change = stats.total_requests - previousStats.total_requests;
            const changePercent = previousStats.total_requests > 0
                ? ((change / previousStats.total_requests) * 100).toFixed(1)
                : 0;
            const changeEl = document.getElementById('requestsChange');
            changeEl.textContent = `+${changePercent}%`;
            changeEl.style.color = change > 0 ? '#51cf66' : '#a0a0b0';
        }

        // Avg Response Time
        document.getElementById('avgResponse').innerHTML =
            `${stats.avg_response_ms || 0}<span class="unit">ms</span>`;

        // Total Traffic
        const mbSent = stats.total_mb_sent || 0;
        document.getElementById('totalTraffic').innerHTML =
            `${mbSent.toFixed(2)}<span class="unit">MB</span>`;

        // Traffic rate
        if (previousStats) {
            const mbDiff = mbSent - (previousStats.total_mb_sent || 0);
            const kbPerSec = (mbDiff * 1024 / 2).toFixed(1); // 2 second interval
            document.getElementById('trafficRate').textContent = `${kbPerSec} KB/s`;
        }
    }

    function updateCharts(history) {
        if (!history || history.length === 0) return;

        // Reverse to show oldest to newest
        const data = history.reverse();
        const maxPoints = 30;
        const recentData = data.slice(-maxPoints);

        // Update Clients Chart
        updateLineChart(clientsChart, recentData, 'clients');

        // Update RPS Chart
        updateLineChart(rpsChart, recentData, 'rps');

        // Update Response Chart (now Line)
        updateLineChart(responseChart, recentData, 'avg_ms');
    }

    function updateLineChart(chart, data, field) {
        chart.data.labels = data.map((d, i) => i === data.length - 1 ? 'Now' : `-${(data.length - i) * 2}s`);
        chart.data.datasets[0].data = data.map(d => d[field] || 0);
        chart.update('none'); // Update without animation for smooth real-time
    }

    function updateBarChart(chart, data) {
        const last10 = data.slice(-10);
        chart.data.labels = last10.map((d, i) => i === last10.length - 1 ? 'Now' : `-${(last10.length - i) * 2}s`);
        chart.data.datasets[0].data = last10.map(d => d.avg_ms || 0);
        chart.update('none');
    }

    function updateTrafficChart(breakdown) {
        if (!breakdown) return;

        // Data order: API, HTML, CSS, JS, Other (matches labels in initCharts)
        // Labels: ['API', 'HTML', 'CSS', 'JS', 'Other']
        trafficChart.data.datasets[0].data = [
            breakdown.api || 0,
            breakdown.html || 0,
            breakdown.css || 0,
            breakdown.js || 0,
            (breakdown.other || 0) + (breakdown.img || 0) // Group img with other or add img to labels
        ];
        trafficChart.update();
    }

    function updateServerInfo(stats) {
        // Uptime
        const uptime = formatUptime(stats.uptime_sec || 0);
        document.getElementById('uptime').textContent = uptime;

        // RPS
        const rps = stats.requests_per_sec || 0;
        document.getElementById('rps').textContent = rps.toFixed(2);

        // MB Sent
        const mbSent = stats.total_mb_sent || 0;
        document.getElementById('mbSent').textContent = mbSent.toFixed(2);

        // Last Update
        const now = new Date();
        document.getElementById('lastUpdate').textContent =
            now.toLocaleTimeString('es-ES', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    }

    function formatNumber(num) {
        if (num >= 1000000) {
            return (num / 1000000).toFixed(1) + 'M';
        } else if (num >= 1000) {
            return (num / 1000).toFixed(1) + 'K';
        }
        return num.toString();
    }

    function formatUptime(seconds) {
        const days = Math.floor(seconds / 86400);
        const hours = Math.floor((seconds % 86400) / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        const secs = seconds % 60;

        if (days > 0) {
            return `${days}d ${hours}h ${minutes}m`;
        } else if (hours > 0) {
            return `${hours}h ${minutes}m ${secs}s`;
        } else if (minutes > 0) {
            return `${minutes}m ${secs}s`;
        } else {
            return `${secs}s`;
        }
    }

    // Cleanup on page unload
    window.addEventListener('beforeunload', () => {
        if (updateInterval) {
            clearInterval(updateInterval);
        }
    });

    // --- Tabs Logic ---
    function setupTabs() {
        const tabs = document.querySelectorAll('.tab-btn');
        tabs.forEach(tab => {
            tab.addEventListener('click', () => {
                // Remove active class from all tabs and contents
                document.querySelectorAll('.tab-btn').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

                // Add active class to clicked tab and corresponding content
                tab.classList.add('active');
                const targetId = tab.getAttribute('data-tab');
                document.getElementById(targetId).classList.add('active');

                // If modules tab is selected, load modules
                if (targetId === 'modules') {
                    loadModules();
                }
            });
        });
    }

    // --- Modules Logic ---
    function setupModules() {
        document.getElementById('refreshModules').addEventListener('click', loadModules);
    }

    async function loadModules() {
        const container = document.getElementById('modulesList');
        container.innerHTML = '<div class="loading-modules">Cargando módulos...</div>';

        try {
            const response = await fetch('/api/modules/list', {
                headers: { 'Authorization': `Basic ${credentials}` }
            });

            if (!response.ok) throw new Error('Failed to load modules');

            const data = await response.json();
            renderModules(data.modules || []);

        } catch (error) {
            console.error('Error loading modules:', error);
            container.innerHTML = '<div class="loading-modules">Error al cargar módulos</div>';
        }
    }

    function renderModules(modules) {
        const container = document.getElementById('modulesList');
        container.innerHTML = '';

        if (modules.length === 0) {
            container.innerHTML = '<div class="loading-modules">No se encontraron módulos</div>';
            return;
        }

        modules.forEach(mod => {
            const card = document.createElement('div');
            card.className = `module-card ${mod.enabled ? 'enabled' : ''}`;

            const checked = mod.enabled ? 'checked' : '';

            card.innerHTML = `
                <div class="module-header">
                    <span class="module-name">${mod.name}</span>
                    <span class="module-status"></span>
                </div>
                <div class="module-description">
                    Módulo del sistema ${mod.name}
                </div>
                <div class="module-footer">
                    <label class="switch">
                        <input type="checkbox" ${checked} data-module="${mod.name}">
                        <span class="slider"></span>
                    </label>
                </div>
            `;

            // Add toggle event
            const checkbox = card.querySelector('input');
            checkbox.addEventListener('change', (e) => {
                toggleModule(mod.name, e.target.checked);
            });

            container.appendChild(card);
        });
    }

    async function toggleModule(name, enabled) {
        try {
            const response = await fetch('/api/modules/toggle', {
                method: 'POST',
                headers: {
                    'Authorization': `Basic ${credentials}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ module: name, enabled: enabled })
            });

            if (!response.ok) {
                throw new Error('Failed to toggle module');
            }

            // Reload to reflect changes (optional, or just update UI state)
            loadModules();

        } catch (error) {
            console.error('Error toggling module:', error);
            alert('Error al cambiar el estado del módulo');
        }
    }
})();
