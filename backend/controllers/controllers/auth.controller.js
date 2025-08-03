const bcrypt = require('bcrypt');
const db = require('../config/db'); // module de connexion à ta base SQL
const jwt = require('jsonwebtoken');

exports.register = async (req, res) => {
  const { nom, prenom, email, mot_de_passe, role } = req.body;

  // Vérification des champs requis
  if (!nom || !prenom || !email || !mot_de_passe) {
    return res.status(400).json({ message: 'Tous les champs sont obligatoires.' });
  }

  try {
    // Vérifier si l'email existe déjà
    const [existing] = await db.query('SELECT * FROM utilisateur WHERE email = ?', [email]);
    if (existing.length > 0) {
      return res.status(409).json({ message: 'Cet email est déjà utilisé.' });
    }

    // Hasher le mot de passe
    const hashedPwd = await bcrypt.hash(mot_de_passe, 10);

    // Insérer l'utilisateur
    await db.query(
      'INSERT INTO utilisateur (nom, prenom, email, mot_de_passe, rôle, confirmé) VALUES (?, ?, ?, ?, ?, ?)',
      [nom, prenom, email, hashedPwd, role || 'utilisateur', false]
    );

    return res.status(201).json({ message: 'Inscription réussie.' });

  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Erreur serveur.' });
  }
};
