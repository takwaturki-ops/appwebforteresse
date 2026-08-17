const { DataTypes } = require('sequelize');
const bcrypt = require('bcryptjs');

const BCRYPT_COST = 12;

module.exports = (sequelize) => {
  const User = sequelize.define('User', {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    username: {
      type: DataTypes.STRING(50),
      allowNull: false,
      unique: true,
      validate: { is: /^[a-zA-Z0-9_.-]+$/ },
    },
    email: {
      type: DataTypes.STRING(255),
      allowNull: false,
      unique: true,
      validate: { isEmail: true },
    },
    passwordHash: { type: DataTypes.STRING(255), allowNull: false },
    totpSecret: { type: DataTypes.STRING(64), allowNull: true },
    totpEnabled: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: false },
    isActive: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: true },
  }, {
    tableName: 'users',
    underscored: true,
  });

  User.hashPassword = (plain) => bcrypt.hash(plain, BCRYPT_COST);
  User.prototype.verifyPassword = function (plain) {
    return bcrypt.compare(plain, this.passwordHash);
  };

  return User;
};
