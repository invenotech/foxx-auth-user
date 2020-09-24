'use strict';
const dd = require('dedent');
const joi = require('joi');

const aql = require('@arangodb').aql;
const { db } = require('@arangodb');
const session = module.context.dependencies.sessions;

module.context.use(session);

const createAuth = require('@arangodb/foxx/auth');
const auth = createAuth({ method: 'sha512' });

const hasPrivilege = db._collection('hasPrivilege');
const hasRole = db._collection('hasRole');
const roles = db._collection('roles');
const users = db._collection('users');

const createRouter = require('@arangodb/foxx/router');
const router = createRouter();

module.context.use(router);

router
  .post('/register', function (req, res) {
    const { username, email } = req.body;

    if (users.firstExample({ username })) {
      res.throw(400, 'Username is already Registered');
    }

    if (users.firstExample({ email })) {
      res.throw(400, 'Email is already Registered');
    }

    const password = auth.create(req.body.password);
    const user = users.save({
      username,
      password,
      email
    });

    const created = users.firstExample({ _key: user._key });
    if (created) {
      const role = roles.firstExample({ name: 'user' });
      hasRole.save({
        _to: `${user._id}`,
        _from: `${role._id}`
      });
      req.session.uid = user._key;
      req.sessionStorage.save(req.session);
      res.send({ username: user.username, sid: req.session });
    } else {
      res.throw(500, 'Unable to create user');
    }
  })
  .body(
    joi
      .object({
        username: joi.string().required(),
        password: joi.string().required(),
        email: joi.string().email({ minDomainSegments: 2 }).required()
      })
      .required()
  );

router
  .post('/login', function (req, res) {
    const user = users.firstExample({
      username: req.body.username
    });
    const valid = auth.verify(
      // Pretend to validate even if no user was found
      user ? user.password : {},
      req.body.password
    );
    if (!valid) res.throw('unauthorized');
    // Log the user in using the key
    // because usernames might change
    req.session.uid = user._key;
    req.session.data = {};
    req.sessionStorage.save(req.session);
    res.send({ username: user.username, sid: req.session });
  })
  .body(
    joi
      .object({
        username: joi.string().required(),
        password: joi.string().required()
      })
      .required()
  );

router
  .put('/update', function (req, res) {
    const password = auth.create(req.body.password);
    if (users.firstExample({ _key: req.session.uid })) {
      users.update(req.session.uid, {
        password
      });
      res.status(200, 'Password Updated');
    } else {
      res.throw(400, 'Invalid User Id');
    }
  })
  .body(
    joi
      .object({
        password: joi.string().required()
      })
      .required()
  );

router
  .put('/user', function (req, res) {
    const { username, email } = req.body;

    if (users.firstExample({ _key: req.session.uid })) {
      users.update(req.session.uid, {
        username,
        email
      });
      res.status(200, 'User Updated');
    } else {
      res.throw(400, 'Invalid User Id');
    }
  })
  .body(
    joi
      .object({
        username: joi.string().required(),
        email: joi.string().required()
      })
      .required()
  );

router.get('/me', function (req, res) {
  let user;
  let privileges;
  if (req.session && req.session.uid) {
    user = users.document(req.session.uid);
  }

  if (user) {
    privileges = db._query(aql`
        FOR user IN ${users}
          FILTER user._key == ${req.session.uid}
          LET privileges = (
            FOR role IN INBOUND user ${hasRole}
              OPTIONS {
                bfs: true,
                uniqueVertices: 'global'
              }
              FOR priv IN INBOUND role ${hasPrivilege}
                OPTIONS {
                  bfs: true,
                  uniqueVertices: 'global'
                }
            RETURN priv
          )
          RETURN { privileges }
      `);
  } else {
    user = {
      username: 'Guest',
      _key: null
    };
    req.session.uid = null;
    req.session.data = {};
    privileges = db._query(aql`
        FOR role IN ${roles}
          FILTER role.name == 'guest'
          LET privileges = (
            FOR priv IN INBOUND role ${hasPrivilege}
              OPTIONS {
                bfs: true,
                uniqueVertices: 'global'
              }
            RETURN priv
          )
          RETURN { privileges }
      `);
  }

  let permissions = {};
  if (privileges && privileges._documents[0].privileges.length > 0) {
    privileges._documents[0].privileges.map((privilege) => {
      return (permissions[privilege.name] = true);
    });
  }

  req.session.data.privileges = permissions;
  req.sessionStorage.save(req.session);

  res.send({
    username: user.username,
    userid: user._key,
    data: req.session.data,
    sid: req.session
  });
});

router.post('/logout', function (req, res) {
  req.sessionStorage.clear(req.session);

  res.status('no content');
});

router
  .get(
    '/user/:_key',
    function (req, res) {
      if (!req.session.uid) {
        res.throw(401, `Unathorized`);
      }
      const { _key } = req.pathParams;
      const data = db
        ._query(
          aql`
        FOR user IN ${users}
          FILTER user._key == ${_key}
          RETURN {
            "_key" : user._key,
            "profile" : user.profile,
            "username" : user.username,
            "email" : user.email
          }
      `
        )
        .toArray();

      res.send(data[0]);
    },
    'list'
  )
  .response(
    joi.array().items(joi.string().required()).required(),
    'List of all Users.'
  )
  .summary('List all Users').description(dd`
Retrieves a list of all Users.
`);

router
  .get(
    '/users',
    function (req, res) {
      if (!req.session.uid) {
        res.throw(401, `Unathorized`);
      }
      const data = db._query(aql`
    FOR user IN ${users}
      SORT user.username ASC
      RETURN {
        "_key" : user._key,
        "name" : user.name,
        "username" : user.username,
        "email" : user.email
      }`);

      res.send(data);
    },
    'list'
  )
  .response(
    joi.array().items(joi.string().required()).required(),
    'List of all Users.'
  )
  .summary('List all Users').description(dd`
Retrieves a list of all Users.
`);

module.exports = { auth, users };
