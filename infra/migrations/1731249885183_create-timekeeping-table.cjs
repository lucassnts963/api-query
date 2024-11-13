/**
 * @type {import('node-pg-migrate').ColumnDefinitions | undefined}
 */
exports.shorthands = undefined;

/**
 * @param pgm {import('node-pg-migrate').MigrationBuilder}
 * @param run {() => void | undefined}
 * @returns {Promise<void> | void}
 */
exports.up = (pgm) => {
  pgm.createTable("timekeeping", {
    uuid: {
      type: "uuid",
      notNull: true,
      primaryKey: true,
      unique: true,
      default: pgm.func("uuid_generate_v4()"),
    },
    startDate: {
      type: "timestamp",
      notNull: true,
    },
    endDate: {
      type: "timestamp",
      notNull: true,
    },
    charge: {
      type: "decimal",
      notNull: true,
    },
    peopleId: {
      type: "uuid",
      references: "people(uuid)",
    },
    billingTypeId: {
      type: "uuid",
      references: '"billingType"(uuid)',
      notNull: true,
    },
    contractId: {
      type: "uuid",
      references: "contracts(uuid)",
      notNull: true,
    },
    equipmentId: {
      type: "uuid",
      references: "equipments(uuid)",
      notNull: true,
    },
    machineryAndToolsId: {
      type: "uuid",
      references: '"machineryAndTools"(uuid)',
    },
  });
};

/**
 * @param pgm {import('node-pg-migrate').MigrationBuilder}
 * @param run {() => void | undefined}
 * @returns {Promise<void> | void}
 */
exports.down = (pgm) => {};
