let allRows = [];
const $ = (id) => document.getElementById(id);
function esc(value) { return String(value ?? '—').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function render() {
  const q = $('search').value.trim().toLowerCase();
  const rows = allRows.filter(r => [r.flow_id,r.src_ip,r.dst_ip,r.application,r.method,r.protocol].join(' ').toLowerCase().includes(q));
  $('total').textContent = allRows.length;
  $('identified').textContent = allRows.filter(r => r.application && r.application !== 'UNKNOWN').length;
  $('ml').textContent = allRows.filter(r => String(r.method).includes('burst_fusion')).length;
  $('unknown').textContent = allRows.filter(r => !r.application || r.application === 'UNKNOWN').length;
  $('rows').innerHTML = rows.length ? rows.slice().reverse().map(r => `<tr>
    <td>${esc(r.flow_id)}</td><td>${esc(r.src_ip)}:${esc(r.src_port)}</td><td>${esc(r.dst_ip)}:${esc(r.dst_port)}</td>
    <td>${esc(r.protocol)}</td><td class="app">${esc(r.application)}</td><td><span class="method">${esc(r.method)}</span></td>
    <td class="confidence">${r.confidence == null ? '—' : (Number(r.confidence)*100).toFixed(1)+'%'}</td><td>${esc(r.packets)}</td></tr>`).join('') : '<tr><td colspan="8" class="empty">No matching flows.</td></tr>';
}
async function refresh() {
  try {
    const response = await fetch('/api/results', {cache:'no-store'});
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    allRows = data.results || [];
    render();
    $('updated').textContent = `Updated ${new Date().toLocaleTimeString()} · ${allRows.length} finalized flows`;
  } catch (err) { $('updated').textContent = `Dashboard API unavailable: ${err.message}`; }
}
$('search').addEventListener('input', render);
$('refresh').addEventListener('click', refresh);
refresh(); setInterval(refresh, 2000);
