// =============================================================
// SEED - initialisation de la base Forteresse (Phase 2)
//
// Usage : node scripts/seed.js <mot_de_passe_superadmin>
//
//   1. cree les tables (sync Sequelize)
//   2. cree la table "sessions" (stockage des sessions PostgreSQL)
//   3. insere les 3 roles (stagiaire, admin, superadmin)
//   4. cree le compte superadmin initial, mot de passe HACHE bcrypt
//
// Securite : le mot de passe passe en argument de commande,
// il n'est jamais ecrit dans le code source ni pousse sur git.
// =============================================================

require("dotenv").config();
const bcrypt = require("bcryptjs");
const { sequelize, Role, User } = require("../models");

const COUT_BCRYPT = 12;

const run = async () => {
  const motDePasse = process.argv[2];
  if (!motDePasse) {
    console.error("Usage : node scripts/seed.js <mot_de_passe_superadmin>");
    console.error("(le mot de passe ne doit pas vivre dans le code source)");
    process.exit(1);
  }

  console.log("1/4 Creation des tables (users, roles, audit_logs)...");
  await sequelize.sync();

  console.log("2/4 Table de sessions PostgreSQL...");
  await sequelize.query(`
    CREATE TABLE IF NOT EXISTS "sessions" (
      "sid"    varchar NOT NULL,
      "sess"   json NOT NULL,
      "expire" timestamp(6) NOT NULL
    )`);
  // contrainte primaire : erreur volontairement ignoree si deja existante
  await sequelize
    .query(`ALTER TABLE "sessions" ADD CONSTRAINT "session_pkey" PRIMARY KEY ("sid")`)
    .catch(() => {});
  await sequelize.query(
    `CREATE INDEX IF NOT EXISTS "IDX_session_expire" ON "sessions" ("expire")`
  );

  console.log("3/4 Insertion des 3 roles...");
  const roles = [
    ["stagiaire", "Lecture seule du tableau de bord"],
    ["admin", "Lecture/ecriture + gestion des utilisateurs standards"],
    ["superadmin", "Gestion des privileges + consultation des logs d'audit"],
  ];
  for (const [name, description] of roles) {
    await Role.findOrCreate({ where: { name }, defaults: { description } });
  }

  console.log("4/4 Creation du superadmin 'turki'...");
  const roleSuperAdmin = await Role.findOne({ where: { name: "superadmin" } });

  // Bcrypt : salt aleatoire unique + 2^12 iterations, integres au hash
  const hash = await bcrypt.hash(motDePasse, COUT_BCRYPT);

  const [superadmin, cree] = await User.findOrCreate({
    where: { username: "turki" },
    defaults: {
      email: "turki@forteresse.local",
      passwordHash: hash,
      roleId: roleSuperAdmin.id,
    },
  });
  if (!cree) {
    // compte deja existant : on actualise son empreinte
    superadmin.passwordHash = hash;
    await superadmin.save();
    console.log("   Compte existant : empreinte bcrypt mise a jour.");
  }

  console.log("\nBase initialisee :");
  console.log("  - tables : users / roles / audit_logs / sessions");
  console.log("  - roles  : stagiaire, admin, superadmin");
  console.log("  - compte : turki (superadmin), mot de passe hache (cout " + COUT_BCRYPT + ")");
  console.log("\nAucun mot de passe en clair n'a ete ecrit en base.");
  await sequelize.close();
};

run().catch((err) => {
  console.error("ECHEC du seed :", err.message);
  process.exit(1);
});
