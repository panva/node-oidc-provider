module.exports = {
  up: (queryInterface, Sequelize) => queryInterface.createTable('Interaction', {
    id: {
      allowNull: false,
      primaryKey: true,
      type: Sequelize.STRING,
    },
    data: {
      type: Sequelize.JSONB,
    },
    expiresAt: {
      type: Sequelize.DATE(3),
    },
    consumedAt: {
      type: Sequelize.DATE(3),
    },
    createdAt: {
      allowNull: false,
      type: Sequelize.DATE(3),
      defaultValue: Sequelize.fn('NOW'),
    },
    updatedAt: {
      allowNull: false,
      type: Sequelize.DATE(3),
      defaultValue: Sequelize.fn('NOW'),
    },
  }),
  down: (queryInterface) => queryInterface.dropTable('Interaction'),
};
