function sortTable(table, col, asc){
  const tbody = table.tBodies[0];
  const rows = Array.from(tbody.querySelectorAll('tr'));
  rows.sort((a,b)=>{
    const ta=(a.children[col]?.innerText||'').trim();
    const tb=(b.children[col]?.innerText||'').trim();
    const na=Number(ta), nb=Number(tb);
    if(!Number.isNaN(na) && !Number.isNaN(nb)) return asc ? na-nb : nb-na;
    return asc ? ta.localeCompare(tb) : tb.localeCompare(ta);
  });
  rows.forEach(r=>tbody.appendChild(r));
}
document.addEventListener('click', (e)=>{
  const th=e.target.closest('th[data-sort]');
  if(!th) return;
  const table=th.closest('table');
  const col=Array.from(th.parentElement.children).indexOf(th);
  const asc = th.dataset.dir !== 'asc';
  th.dataset.dir = asc ? 'asc' : 'desc';
  sortTable(table,col,asc);
});
document.addEventListener('input', (e)=>{
  const input = e.target.closest('[data-filter]');
  if(!input) return;
  const id=input.getAttribute('data-filter');
  const q=input.value.toLowerCase();
  const table=document.getElementById(id);
  if(!table) return;
  for(const tr of table.tBodies[0].rows){
    tr.style.display = tr.innerText.toLowerCase().includes(q) ? '' : 'none';
  }
});
