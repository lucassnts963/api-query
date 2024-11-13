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
  pgm.createTable("people", {
    uuid: {
      type: "uuid",
      notNull: true,
      primaryKey: true,
      unique: true,
      default: pgm.func("uuid_generate_v4()"),
    },
    name: {
      type: "varchar(250)",
      notNull: true,
    },
    birth: {
      type: "timestamp",
      notNull: true,
    },
    registration: {
      type: "integer",
      notNull: true,
    },
    registrationClient: {
      type: "integer",
    },
    contractId: {
      type: "uuid",
      references: "contracts(uuid)",
    },
    roleId: {
      type: "uuid",
      references: "roles(uuid)",
      notNull: true,
    },
    departmentId: {
      type: "uuid",
      references: "departments(uuid)",
      notNull: true,
    },
    managerId: {
      type: "uuid",
      references: "people(uuid)",
    },
    supervisor: {
      type: "uuid",
      references: "people(uuid)",
    },
    shift: {
      type: "uuid",
      references: "shifts(uuid)",
      notNull: true,
    },
    status: {
      type: "uuid",
      references: '"peopleStatus"(uuid)',
      notNull: true,
    },
    billingTypeDefault: {
      type: "uuid",
      references: '"billingType"(uuid)',
    },
  });
};

/**
 * @param pgm {import('node-pg-migrate').MigrationBuilder}
 * @param run {() => void | undefined}
 * @returns {Promise<void> | void}
 */
exports.down = (pgm) => {};
