const { DataTypes } = require('sequelize');

module.exports = (sequelize) =>
  sequelize.define('Role', {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    name: {
      type: DataTypes.STRING(50),
      allowNull: false,
      unique: true,
      validate: { isIn: [['stagiaire', 'admin', 'superadmin']] },
    },
    description: { type: DataTypes.STRING(255), allowNull: true },
  }, {
    tableName: 'roles',
    underscored: true,
    updatedAt: false,
  });
