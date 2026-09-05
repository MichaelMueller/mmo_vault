/* What every service page needs: one call helper and one message line.

   A file rather than an inline block, so the pages get by with
   script-src 'self'. */

/* Every state-changing call carries this header. Together with SameSite=Lax it
   is what stands between the service and a cross-site request. */
async function api(path, options){
  // The headers have to be applied AFTER the options are spread. The other way
  // round, a caller passing its own headers would silently drop
  // X-Vault-Request - and every such call would be refused with a 403.
  const settings = Object.assign({}, options || {});
  settings.headers = Object.assign(
    {'Content-Type':'application/json', 'X-Vault-Request':'1'},
    (options || {}).headers || {}
  );
  const response = await fetch(path, settings);
  let body = null;
  try{ body = await response.json(); }catch(err){ /* 204 and friends */ }
  if(!response.ok){
    const err = new Error((body && body.detail) || ('HTTP ' + response.status));
    err.status = response.status;
    throw err;
  }
  return body;
}

let messageTimer = null;

function show(id, text, kind){
  const el = document.getElementById(id);
  if(!el) return;
  el.textContent = text;
  el.className = 'msg show ' + (kind || 'error');
  // On a phone the message sits over the page as a bar at the bottom. It has
  // to go away again on its own, or it covers a row for good.
  clearTimeout(messageTimer);
  messageTimer = setTimeout(() => { el.className = 'msg'; }, kind === 'ok' ? 4000 : 8000);
}
