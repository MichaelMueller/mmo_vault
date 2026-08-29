/* The adapter injected into the vault application in server mode.

   This is the only code that knows a network exists. The application file
   itself contains no URL and no fetch call; it merely checks whether
   window.mmoVaultServer is there and uses it if so.

   Everything here deals with ciphertext. The master password is entered in the
   application, the key is derived there, and neither ever reaches this code -
   let alone the server. */

(function(){
  'use strict';

  var LOCK_HEADER = 'X-Vault-Lock';
  /* Three heartbeats within the lock's lifetime: one may be lost to a hiccup
     without the lock expiring underneath someone who is still working. */
  var HEARTBEAT_FRACTION = 3;

  var locks = {};        // vaultId -> { token, timer }

  async function call(path, options){
    options = options || {};
    var headers = Object.assign(
      { 'X-Vault-Request': '1' },
      options.headers || {}
    );
    if(options.json !== undefined){
      headers['Content-Type'] = 'application/json';
      options.body = JSON.stringify(options.json);
      delete options.json;
    }
    options.headers = headers;
    var response = await fetch(path, options);
    if(!response.ok){
      var detail = null;
      try{ detail = (await response.json()).detail; }catch(err){ /* not JSON */ }
      var error = new Error(detail || ('HTTP ' + response.status));
      error.status = response.status;
      /* Kept apart on purpose: 412 means somebody else wrote in the meantime,
         409 means the lock is gone. They look similar from here but call for
         different words - "changed elsewhere" would be wrong and confusing for
         a lock that simply expired. */
      error.conflict = (response.status === 412);
      error.lockLost = (response.status === 409);
      throw error;
    }
    return response;
  }

  async function json(path, options){
    var response = await call(path, options);
    if(response.status === 204) return null;
    return await response.json();
  }

  /* ---------- locks ---------- */

  function stopHeartbeat(vaultId){
    var held = locks[vaultId];
    if(held && held.timer){ clearInterval(held.timer); held.timer = null; }
  }

  async function acquireLock(vaultId){
    var result = await json('/api/vaults/' + vaultId + '/lock', { method: 'POST' });
    var ttlMs = Math.max(30000, new Date(result.expires_at + 'Z') - Date.now());
    stopHeartbeat(vaultId);
    locks[vaultId] = {
      token: result.token,
      timer: setInterval(function(){
        renewLock(vaultId).catch(function(err){
          /* The lock is gone - broken by an administrator, or expired while
             the machine was asleep. Stop pretending it is held; the ETag will
             refuse the write and the application says so. */
          stopHeartbeat(vaultId);
          delete locks[vaultId];
          if(typeof window.onVaultLockLost === 'function'){
            window.onVaultLockLost(vaultId, err);
          }
        });
      }, ttlMs / HEARTBEAT_FRACTION)
    };
    return result;
  }

  async function renewLock(vaultId){
    var held = locks[vaultId];
    if(!held) throw new Error('no lock held');
    return await json('/api/vaults/' + vaultId + '/lock', {
      method: 'PUT', headers: lockHeader(vaultId)
    });
  }

  async function releaseLock(vaultId){
    var held = locks[vaultId];
    stopHeartbeat(vaultId);
    delete locks[vaultId];
    if(!held) return;
    try{
      await json('/api/vaults/' + vaultId + '/lock', {
        method: 'DELETE', headers: { 'X-Vault-Lock': held.token }
      });
    }catch(err){ /* already gone - nothing to do */ }
  }

  function lockHeader(vaultId){
    var held = locks[vaultId];
    return held ? { 'X-Vault-Lock': held.token } : {};
  }

  /* Best effort when the tab goes away. Unreliable by nature, which is why the
     lock has a lifetime - this only shortens the wait for the next person. */
  window.addEventListener('pagehide', function(){
    Object.keys(locks).forEach(function(vaultId){
      var held = locks[vaultId];
      if(!held) return;
      navigator.sendBeacon(
        '/api/vaults/' + vaultId + '/lock/release-beacon?token=' +
        encodeURIComponent(held.token)
      );
    });
  });

  /* ---------- the interface the application expects ---------- */

  window.mmoVaultServer = {
    async me(){
      var body = await json('/api/me');
      return { user: body.user, groups: body.groups, isAdmin: body.is_admin };
    },

    async listVaults(){
      var body = await json('/api/vaults');
      return body
        /* An administrator sees vaults they may manage but not open. Those do
           not belong on the lock screen. */
        .filter(function(vault){ return vault.permission !== null; })
        .map(function(vault){
          return {
            id: vault.id,
            name: vault.name,
            permission: vault.permission,
            etag: vault.etag,
            empty: vault.empty,
            lockedBy: vault.locked_by
          };
        });
    },

    async readVault(vaultId){
      var response = await call('/api/vaults/' + vaultId + '/content');
      if(response.status === 204){
        /* Created but never filled. Null rather than an empty string: the
           application has to be able to tell "nothing there yet" from "a file
           that happens to be empty", and only the first one means "create". */
        return null;
      }
      var etag = (response.headers.get('ETag') || '').replace(/"/g, '');
      return { text: await response.text(), etag: etag, empty: false };
    },

    async writeVault(vaultId, text, etag){
      var response = await call('/api/vaults/' + vaultId + '/content', {
        method: 'PUT',
        headers: Object.assign(
          { 'If-Match': '"' + (etag || '') + '"', 'Content-Type': 'application/x-ndjson' },
          lockHeader(vaultId)
        ),
        body: text
      });
      var body = await response.json();
      return { etag: body.etag, size: body.size_bytes };
    },

    acquireLock: acquireLock,
    renewLock: renewLock,
    releaseLock: releaseLock,

    async listGenerations(vaultId){
      var body = await json('/api/vaults/' + vaultId + '/history');
      return body.generations.map(function(generation){
        return {
          generation: generation.seq,
          ts: generation.created_at,
          size: generation.size_bytes,
          author: generation.author,
          note: generation.note
        };
      });
    },

    async readGeneration(vaultId, seq){
      var response = await call('/api/vaults/' + vaultId + '/history/' + seq + '/content');
      return { text: await response.text() };
    },

    async logout(){
      try{ await json('/auth/logout', { method: 'POST' }); }
      catch(err){ /* the session may already be gone */ }
      location.href = '/login';
    }
  };
})();
