'use strict';

/**
 * Initial Collection Setup
 */
const { db } = require('@arangodb');

if (!db._collection('users')) {
  db._createDocumentCollection('users');
}

const users = db._collection('users');

users.ensureIndex({
  type: 'hash',
  unique: true,
  fields: ['username']
});

users.ensureIndex({
  type: 'hash',
  unique: true,
  fields: ['email']
});
/**
 * Admin User Creation
 *
 * Uses Configuration for password in manifest.js
 */
const createAuth = require('@arangodb/foxx/auth');
const auth = createAuth({ method: 'sha512' });

const hasRole = db._collection('hasRole');
const roles = db._collection('roles');

if (!users.firstExample({ username: 'admin' })) {
  const admin = users.save({
    username: 'admin',
    password: auth.create('pAsSwOrD321!@#')
  });

  const role = roles.firstExample({ name: 'admin' });
  hasRole.save({
    _to: `${admin._id}`,
    _from: `${role._id}`
  });
}

/**
 * Privileges Setup
 */

const hasPrivilege = db._collection('hasPrivilege');
const privileges = db._collection('privileges');

const privUsersUpdate = privileges.save({
  name: 'users_update',
  description: 'Ability to add, edit, remove Users'
});

const privUsersView = privileges.save({
  name: 'users_view',
  description: 'Ability to see User Data'
});

const adminRole = roles.firstExample({ name: 'admin' });

hasPrivilege.save({
  _to: `${adminRole._id}`,
  _from: `${privUsersUpdate._id}`
});

hasPrivilege.save({
  _to: `${adminRole._id}`,
  _from: `${privUsersView._id}`
});

module.exports = true;
