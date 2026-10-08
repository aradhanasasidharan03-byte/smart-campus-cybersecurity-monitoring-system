(() => {
  const sidebar = document.getElementById('sidebar');
  const menuToggle = document.getElementById('menuToggle');
  if (sidebar && menuToggle) {
    menuToggle.addEventListener('click', () => sidebar.classList.toggle('is-open'));
    document.addEventListener('click', event => {
      if (window.innerWidth <= 860 && sidebar.classList.contains('is-open') &&
          !sidebar.contains(event.target) && !menuToggle.contains(event.target)) {
        sidebar.classList.remove('is-open');
      }
    });
  }

  document.querySelectorAll('[data-autosubmit]').forEach(control => {
    control.addEventListener('change', () => control.form.requestSubmit());
  });
  document.querySelectorAll('form[data-confirm]').forEach(form => {
    form.addEventListener('submit', event => {
      if (!window.confirm(form.dataset.confirm)) event.preventDefault();
    });
  });

  const palette = {
    ink: '#172322', muted: '#77817d', grid: '#e8ece8',
    LOW: '#58a88a', MEDIUM: '#d6a437', HIGH: '#e47a4e', CRITICAL: '#c84b50',
    Online: '#58a88a', Monitoring: '#d6a437', Offline: '#a6aeaa',
    Low: '#58a88a', Medium: '#d6a437', High: '#e47a4e', Critical: '#c84b50'
  };
  const common = { responsive: true, maintainAspectRatio: false,
    plugins: { legend: { display: false }, tooltip: { backgroundColor: palette.ink, padding: 10, titleFont: { family: 'DM Mono' } } } };
  const data = window.dashboardCharts;
  if (data && window.Chart) {
    const activity = document.getElementById('activityChart');
    if (activity) new Chart(activity, { type: 'line', data: { labels: data.activity_labels, datasets: [{ data: data.activity, borderColor: '#94b83e', backgroundColor: 'rgba(148,184,62,.13)', fill: true, tension: .36, borderWidth: 2, pointRadius: 3, pointBackgroundColor: '#94b83e' }] }, options: { ...common, scales: { y: { beginAtZero: true, ticks: { precision: 0, color: palette.muted }, grid: { color: palette.grid } }, x: { ticks: { color: palette.muted }, grid: { display: false } } } } });
    const severity = document.getElementById('severityChart');
    if (severity) new Chart(severity, { type: 'doughnut', data: { labels: Object.keys(data.severity), datasets: [{ data: Object.values(data.severity), backgroundColor: Object.keys(data.severity).map(key => palette[key]), borderWidth: 0, hoverOffset: 4 }] }, options: { ...common, cutout: '72%', plugins: { ...common.plugins, legend: { display: false } } } });
  }

  const reports = window.reportCharts;
  if (reports && window.Chart) {
    const doughnut = (id, values, colors) => {
      const element = document.getElementById(id);
      if (element) new Chart(element, { type: 'doughnut', data: { labels: Object.keys(values), datasets: [{ data: Object.values(values), backgroundColor: Object.keys(values).map(key => colors[key] || '#a6aeaa'), borderWidth: 0, hoverOffset: 4 }] }, options: { ...common, cutout: '68%' } });
    };
    doughnut('reportSeverity', reports.severity, palette);
    doughnut('reportStatus', reports.status, palette);
    doughnut('reportRisk', reports.risk, palette);
    const types = document.getElementById('reportTypes');
    if (types) new Chart(types, { type: 'bar', data: { labels: Object.keys(reports.types), datasets: [{ data: Object.values(reports.types), backgroundColor: '#94b83e', borderRadius: 3, maxBarThickness: 24 }] }, options: { ...common, indexAxis: 'y', scales: { x: { beginAtZero: true, ticks: { precision: 0, color: palette.muted }, grid: { color: palette.grid } }, y: { ticks: { color: palette.muted }, grid: { display: false } } } } });
    const activity = document.getElementById('reportActivity');
    if (activity) new Chart(activity, { type: 'line', data: { labels: reports.activity_labels, datasets: [{ data: reports.activity, borderColor: '#94b83e', backgroundColor: 'rgba(148,184,62,.13)', fill: true, tension: .36, borderWidth: 2, pointRadius: 2 }] }, options: { ...common, scales: { y: { beginAtZero: true, ticks: { precision: 0, color: palette.muted }, grid: { color: palette.grid } }, x: { ticks: { color: palette.muted }, grid: { display: false } } } } });
  }
})();
