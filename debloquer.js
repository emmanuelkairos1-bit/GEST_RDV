// Utilisation : node debloquer.js   -> lève tous les blocages de connexion (à lancer sur le serveur)
const mysql = require('mysql2/promise'), cfg = require('./config');
(async () => { const c = await mysql.createConnection(cfg.db); const [r] = await c.query('DELETE FROM tentatives_connexion'); console.log(`${r.affectedRows} blocage(s) levé(s).`); await c.end(); })().catch(e => { console.error(e.message); process.exit(1); });
