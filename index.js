const bodyParser = require('body-parser');
const compression = require('compression');
const cors = require('cors');
const crypto = require('crypto');
const express = require('express');
const fetch = require('node-fetch');
const flash = require('connect-flash');
const helmet = require('helmet');
const knex = require('knex');
const session = require('express-session');
const { check, validationResult, body } = require('express-validator/check');

const DEFAULT_PORT = 8080;
const DEFAULT_BASE_URL = `http://localhost:${DEFAULT_PORT}`;

const ID_LENGTH = 32;
const SANITIZE_BLACKLIST = '\\*\\(\\)\\[\\]\\n';
const TELEGRAM_API_ENDPOINT = 'https://api.telegram.org';

function generateRandomId() {
  return crypto.randomBytes(ID_LENGTH / 2).toString('hex');
}

function formatDate(isoDate) {
  const split = isoDate.split('T');
  const date = split[0].split('-');
  const time = split[1].split(':');

  return `${date[2]}.${date[1]}.${date[0]} ${time[0]}:${time[1]}`;
}

function truncate(str, length = 64) {
  if (str.length <= length) {
    return str;
  }

  return str.substring(0, length) + '...';
}

function broadcastUrl(id) {
  const url = process.env.BASE_URL || DEFAULT_BASE_URL;
  return `${url}/broadcast/${id}`;
}

// Setup database connection
const db = knex({
  client: 'mysql',
  connection: process.env.DB_URL || {
    host : process.env.DB_HOST,
    user : process.env.DB_USER,
    password : process.env.DB_PASSWORD,
    database : process.env.DB_NAME,
  },
});

// SQL schema table setup
db.schema.hasTable('channels').then(exists => {
  if (!exists) {
    return db.schema.createTable('channels', t => {
      t.string('id', ID_LENGTH).unique().primary();
      t.timestamp('created_at').defaultTo(db.fn.now());
      t.string('channel', 255);
      t.string('token', 255);
    });
  }
});

// Recaptcha setup
const Recaptcha = require('express-recaptcha').Recaptcha;
const recaptcha = new Recaptcha(
  process.env.RECAPTCHA_SITE_KEY,
  process.env.RECAPTCHA_SECRET_KEY,
);

// Make a Telegram Bot API request
function telegramBotRequest(token, method, body) {
  return fetch(`${TELEGRAM_API_ENDPOINT}/bot${token}/${method}`, {
    method: 'POST',
    body: body ? JSON.stringify(body) : '',
    headers: { 'Content-Type': 'application/json' },
  })
    .then(response => {
      return response.json();
    })
    .then(data => {
      if (!data.ok) {
        return Promise.reject(
          new Error(`Telegram API error: ${data.description}`)
        );
      }

      return data.result;
    });
}

// Test the bot token by getting information about itself
function checkToken(token) {
  return telegramBotRequest(token, 'getMe');
}

// Test if our bot has writing rights by sending and
// deleting a message in the given channel
function checkChannel(channel, token) {
  return telegramBotRequest(token, 'sendMessage', {
    chat_id: channel,
    text: 'This is a test message. Please delete me!',
  })
    .then(response => {
      return telegramBotRequest(token, 'deleteMessage', {
        chat_id: channel,
        message_id: response.message_id,
      });
    });
}

// Send an event to a channel
function broadcastEvent(channel, token, data) {
  const { title, date, description, url } = data;

  let text = `*${title}* ${date}\n`;

  if (description && description.length > 0) {
    text += `\n${description}\n`;
  }

  text += `\n*Link:* [${truncate(url)}](${url})`;

  return telegramBotRequest(token, 'sendMessage', {
    chat_id: channel,
    text,
    parse_mode: 'Markdown',
    reply_markup: {
      inline_keyboard: [[
        {
          text: 'Read more',
          url,
        },
      ]],
    },
  });
}

// Create and configure express HTTP server instance
const app = express();

const port = process.env.PORT || DEFAULT_PORT;

app.set('view engine', 'pug');
app.set('x-powered-by', false);

// Initialize session storage
const KnexSessionStore = require('connect-session-knex')(session);

app.use(session({
  store: new KnexSessionStore({
    knex: db,
  }),
  resave: false,
  saveUninitialized: false,
  secret: process.env.SECRET || 'secret',
  cookie: {
    maxAge: 60000,
    secure: process.env.ENV === 'production',
  },
}));

// Use flash middleware
app.use(flash());

// Enable compression and parsing form requests
app.use(bodyParser.urlencoded({ extended: true }));
app.use(compression());

// Setup CORS
app.use(cors({
  methods: 'GET,POST',
  origin: process.env.BASE_URL || '*',
}));

app.use(helmet());

// Serve assets folder
app.use(express.static('static'));

// Define routes
app.get('/', (req, res) => {
  res.render('home');
});

app.get('/broadcast/:id', recaptcha.middleware.render, (req, res) => {
  const { id } = req.params;

  db('channels').where({ id }).first('channel')
    .then(response => {
      const { channel } = response;
      res.render('broadcast', { channel, captcha: res.recaptcha });
    })
    .catch(() => {
      res.render('404');
    });
});

app.post('/broadcast/:id',
  recaptcha.middleware.render,
  recaptcha.middleware.verify, [
  body('description')
    .trim()
    .blacklist(SANITIZE_BLACKLIST)
    .escape()
    .isLength({ max: 64 }),
  body('title')
    .trim()
    .blacklist(SANITIZE_BLACKLIST)
    .escape()
    .isLength({ min: 5, max: 32 }),
  check('url')
    .isURL({ require_protocol: true }),
  check('date')
    .isISO8601(),
], (req, res) => {
  const { id } = req.params;

  db('channels').where({ id }).first('channel', 'token')
    .then(data => {
      const errors = validationResult(req);

      if (errors.isEmpty() && !req.recaptcha.error) {
        const { title, description, url } = req.body;
        const date = formatDate(req.body.date);
        const event = { title, date, description, url };

        broadcastEvent(
          data.channel,
          data.token,
          event
        )
          .then(() => {
            req.flash(
              'success',
              'Thank you! Your event got broadcasted!'
            );
          })
          .catch(() => {
            req.flash(
              'error',
              'Something went wrong with this channel, please contact the owner!'
            );
          })
          .finally(() => {
            res.redirect(`/broadcast/${id}`);
          });
      } else {
        req.flash(
          'error',
          `There are some things wrong or missing in your data, please check below.`
        );

        res.render(`broadcast`, {
          captcha: res.recaptcha,
          errors: errors.mapped(),
          fields: req.body,
          flash: req.flash(),
        });
      }
    })
    .catch(err => {
      res.render('404');
    });
});

app.get('/new', recaptcha.middleware.render, (req, res) => {
  res.render('new', { captcha: res.recaptcha });
});

app.post('/new',
  recaptcha.middleware.render,
  recaptcha.middleware.verify, [
  check('token')
    .exists()
    .withMessage('Token is missing'),
  check('channel')
    .matches(/\@[\w]{5,}$/)
    .withMessage('Channel name is invalid and must start with an @'),
  check('token')
    .custom(value => {
      return checkToken(value);
    })
    .withMessage('Can not send a test message to channel, are your values correct?'),
  check('channel')
    .custom((value, { req }) => {
      return checkChannel(value, req.body.token);
    })
    .withMessage('The bot can not send any messages to that channel, does it have writing rights?'),
], (req, res) => {
  const errors = validationResult(req);

  if (errors.isEmpty() && !req.recaptcha.error) {
    const { channel, token } = req.body;
    const id = generateRandomId();

    db('channels').insert({
      id,
      channel,
      token,
    });

    req.flash(
      'success',
      `Thank you! Your channel was registered, you can invite people to post here: ${broadcastUrl(id)}`
    );

    res.redirect('/new');
  } else {
    req.flash(
      'error',
      `There are some things wrong or missing in your data, please check below.`
    );

    res.render('new', {
      captcha: res.recaptcha,
      errors: errors.mapped(),
      fields: req.body,
      flash: req.flash(),
    });
  }
});

app.get('/faq', (req, res) => {
  res.render('faq');
});

app.use((req, res, next) => {
  res.render('404');
});

// Start HTTP server
app.listen(port, () => console.log(`HTTP server listening on port ${port}!`));
