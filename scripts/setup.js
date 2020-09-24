'use strict';

const { db } = require('@arangodb');

const migrations = module.context.dependencies.migrations;
const { name, version } = module.context.manifest;

const info = migrations.info(name);
const stages = {
  '1-initial': true
};

/**
 * Setup Utility Functions
 */
function setup(name, version) {
  const m1 = require('./migrations/1-initial.js');

  migrations.setup(name, version, stages);
}

function upgrade(name, installed) {
  let stage = {};

  switch (true) {
    case installed <= '0.1.0':

    default:
      break;
  }

  migrations.setup(name, version, stages);
}

/**
 * Migrations
 */
const preMigration = null;

if (!info && !preMigration) {
  /**
   * Install the new version
   */
  setup(name, version);
} else {
  /**
   * Upgrade the old version
   */
  if (info) {
    upgrade(name, info.version);
  } else {
    upgrade(name, preMigration);
  }
}
