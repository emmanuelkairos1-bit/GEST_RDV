// === CONFIGURATION (XAMPP par défaut : root, sans mot de passe) ===
module.exports = {
  port: 3000,
  secret: '',            // facultatif : sinon dérivé automatiquement de la clé de chiffrement
  cleChiffrement: '',    // facultatif : 64 caractères hexa ; sinon un fichier secret.key est créé au 1er lancement
  https: false,          // true si le site est servi en HTTPS (cookies "secure")
  trustProxy: false,     // true derrière un proxy (Nginx...) pour que l'IP réelle soit utilisée
  db: { host: 'localhost', port: 3306, user: 'root', password: '', database: 'gest_rdv' }
};
