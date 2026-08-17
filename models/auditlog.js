const { DataTypes } = require('sequelize');

module.exports = (sequelize) =>
  sequelize.define('AuditLog', {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    action: { type: DataTypes.STRING(100), allowNull: false },
    username: { type: DataTypes.STRING(50), allowNull: true },
    ip: { type: DataTypes.STRING(45), allowNull: true },
    userAgent: { type: DataTypes.STRING(255), allowNull: true },
    level: { type: DataTypes.STRING(20), allowNull: false, defaultValue: 'info' },
    details: { type: DataTypes.JSONB, allowNull: true },
  }, {
    tableName: 'audit_logs',
    underscored: true,
    updatedAt: false,
  });
