const sequelize = require('../config/database');
const Role = require('./role')(sequelize);
const User = require('./user')(sequelize);
const AuditLog = require('./auditlog')(sequelize);

Role.hasMany(User, { foreignKey: { name: 'roleId', allowNull: false } });
User.belongsTo(Role, { foreignKey: { name: 'roleId', allowNull: false } });

User.hasMany(AuditLog, { foreignKey: { name: 'userId', allowNull: true } });
AuditLog.belongsTo(User, { foreignKey: { name: 'userId', allowNull: true } });

module.exports = { sequelize, Role, User, AuditLog };
