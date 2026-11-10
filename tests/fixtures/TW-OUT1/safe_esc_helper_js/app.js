const esc = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function show(items, el) {
  el.innerHTML = items.map(it => `<li data-n="${it.count}">${esc(it.title)} — ${esc(it.owner.name)}</li>`).join('');
  el.querySelector('li').textContent = items[0].title;
}
