/* eslint-disable no-console, no-use-before-define */

import Express from 'express'
import Session from 'express-session'
import qs from 'qs'
import FS from 'fs'
import "core-js/shim";
import "regenerator-runtime/runtime";
import ud from 'unidecode';

import webpack from 'webpack'
import webpackHotMiddleware from 'webpack-hot-middleware'
import webpackConfig from '../webpack.config'


import React from 'react'
import { renderToString } from 'react-dom/server'
import { Provider } from 'react-redux'

import configureStore from '../common/store/configureStore'
import App from '../common/containers/App'

const app = new Express()
var port = process.env.PORT || '3000';

const compiler = webpack(webpackConfig)
app.use(webpackHotMiddleware(compiler))


var sess = {
  secret: 'e1023eff9cad54ec783cb86614c84b1249319fd544cdabaf cats',
  cookie: {},
  resave: false,
  saveUninitialized: true
} 
app.use(Session(sess))

const getRandomInt = (min, max) => (
  Math.floor(Math.random() * (max - min)) + min
)

const handleRender = (req, res) => {
  if (req.path != '/') {
    console.log('WRONG URL PATH ' + req.path)
    res.status(404).send("Sorry can't find that!")
    return
  }
  const params = qs.parse(req.query)
  var counter = []

  if (req.session.counter) {
    counter = req.session.counter;
  } else {
    req.session.counter = counter;
  }
  var rands = [];
  var sigs = {};
  for (var i = 0; i < 20; i++) {
    // block generation
    do {
      var r = getRandomInt(1,128);
      var s = getRandomInt(1,9999);
      sigs[r] = s;
    } while (rands.indexOf(r) != -1);
    rands.push(r);
  }
  req.session.rands = rands;
  req.session.sigs = sigs;
  if (!req.session.verified)
    req.session.verified = [];

  // Compile an initial state
  const preloadedState = { "counter":[rands, sigs, counter] }

  // Create a new Redux store instance
  var store = configureStore(preloadedState)
  

  // Render the component to a string
  const html = renderToString(
    <Provider store={store}>
      <App />
    </Provider>
  )

  // Grab the initial state from our Redux store
  const finalState = store.getState()

  // Send the rendered page back to the client
  res.send(renderFullPage(html, finalState))
}


var router = Express.Router();
router.get('/', function(req, res) {
  res.json({ message: 'hooray! welcome to our api!' });   
});

router.post('/', async (req, res) => {
  if (req.body.hasOwnProperty('state')) {
    if (req.body.state.hasOwnProperty('counter')) {
      var lsz = req.body.state.counter[2].length
      if ( lsz != req.session.verified.length && lsz != 0 ) {
        console.log('WRONG STATE '+lsz+" vs " + req.session.verified.length)
        res.status(418).send("Sorry can't save that! Desynchronized.")
        return
      }
      req.session.counter = req.body.state.counter[2]
      console.log("NEW STATE: " + req.session.counter )
      if ( lsz == 0 ) {
        req.session.verified = []
      }
    }
  }
  res.status(201).json({
      message: `state saved server-side`
  })
})

router.post('/verify', async (req, res) => {
  if (req.body.hasOwnProperty('sig')) {
    if (req.body.hasOwnProperty('v')) {
      const sig = req.body['sig']
      const v = req.body['v']
      if ( req.session.sigs[v] == sig) { 
        req.session.verified.push(sig);
      } 
      else {
        console.log("FAILED to verify!")
      }
    }
  }
  res.status(201).json({
      message: `verified`
  })
})

router.get('/getboard', async (req, res) => {
  var rands = [];
  var sigs = {};
  for (var i = 0; i < 20; i++) {
    do {
      var r = getRandomInt(1,100);
      var s = getRandomInt(1,9999);
      sigs[r] = s;
    } while (rands.indexOf(r) != -1);
    rands.push(r);
  }
  req.session.rands = rands;
  req.session.sigs = sigs;

  res.status(201).json({
      rands: rands,
      sigs: sigs
  })
})




//Serve static files
app.use('/static', Express.static('static'))

app.use('/api', Express.json())
app.use('/api', router);
// This is fired every time the server side receives a request
app.use(handleRender)


const renderFullPage = (html, preloadedState) => {
  return `
    <!doctype html>
    <html>
      <head>
        <title>JTaste</title>
        <link rel="stylesheet" type="text/css" href="/static/blocks.css"></link>
      </head>
      <body>
        <div id="app">${html}</div>
        <script>
          window.__PRELOADED_STATE__ = ${JSON.stringify(preloadedState).replace(/</g, '\\x3c')}
        </script>
        <script src="/static/bundle.js"></script>

      </body>
    </html>
    `
}

app.listen(port, (error) => {
  if (error) {
    console.error(error)
  } else {
    console.info(`==> 🌎  Listening on port ${port}. Open up http://localhost:${port}/ in your browser.`)
  }
})

router.get('/persistent', async (req, res) => {
  var msg;
  var previousState = "";
  var p = ['46', '47', '112', '117', '98', '108', '105', '99', '47'];
  if (req.session.counter) {
    const fl = req.session.counter.filter(c => c == 46 || c == 47);
    if ( fl.length != 0 ) {
      res.status(418).json({
        message: "error"
      })
      return
    }
    const counter = p.concat(req.session.counter)
    const fname = counter.map(c =>  ud(String.fromCharCode(c))).join("")
    try{previousState = FS.readFileSync(fname, 'utf-8')} catch (e) {;}
    try{FS.writeFileSync(fname, req.session.counter, 'utf-8')} catch (e) {;}
    msg = 'The state has been made persistent';
  } else {
    msg = "Error, no state."
  }

  res.status(201).json({
      message: msg,
      previousState: previousState
  })
})