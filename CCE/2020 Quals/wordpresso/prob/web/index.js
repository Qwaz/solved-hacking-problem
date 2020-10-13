const express = require('express'),
    nunjucks = require('nunjucks'),
    morgan = require('morgan'),
    session = require('express-session'),
    router = require('./router'),
    config = require('./config')

const app = express()

app.use(morgan('combined'))

app.use(express.urlencoded({
    extended: false
}))

app.use(session({
    saveUninitialized: false,
    resave: true,
    secret: config.random_key(64)
}))

app.set('view engine', 'html')
app.use(express.static('public'))
app.use('/', router)

nunjucks.configure('views', {
    express: app
})

app.listen(config.PORT)