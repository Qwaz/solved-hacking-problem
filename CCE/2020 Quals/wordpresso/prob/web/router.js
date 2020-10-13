const express = require('express'),
    multer = require('multer'),
    fs = require('fs'),
    path = require('path'),
    puppeteer = require('puppeteer')

const {
    random_key,
    HOST,
    ADMIN_PASSWORD,
    FLAG
} = require('./config')

const router = express.Router()
const upload = multer({
    dest: 'uploads'
})

const users = new Map([
    ['admin', ADMIN_PASSWORD]
])

const documents = new Map([
    [random_key(64), {
        path: FLAG,
        title: 'Flag',
        owner: 'admin'
    }]
])

const check_login = (req, res, next) => {
    if (!req.session.user)
        return res.redirect('/login')
    return next()
}

router.get('/login', (req, res) => {
    return res.render('login')
})

router.get('/', check_login, (req, res) => {
    const user = req.session.user

    res.render('files', {
        docs: [...documents.entries()].filter(doc => doc[1].owner === user)
    })
})

router.post('/login', (req, res) => {
    const {
        username,
        password
    } = req.body

    if (users.has(username)) // Login
        if (users.get(username) !== password) {
            return res.render('login', {
                error: 'Username or password mismatch!',
                username,
                password
            })
        } else {
            req.session.user = username
            return res.redirect('/')
        }
    else {
        // Register
        users.set(username, password)
        documents.set(username, new Map())
        req.session.user = username
        return res.redirect('/')
    }
})

router.post('/upload', check_login, upload.single('document'), (req, res) => {
    const file = req.file
    const user = req.session.user

    if (!file) {
        return res.end('upload failed')
    }

    documents.set(random_key(64), {
        path: file.path,
        title: path.basename(file.originalname).replace('.wordpresso', ''),
        owner: user
    })

    return res.redirect('/')
})

const check_url = url => {
    return HOST && url.startsWith(HOST)
}

const openPage = async url => {
    const browser = await puppeteer.launch({
        headless: true,
        args: [
            '--no-sandbox'
        ]
    })
    const page = await browser.newPage()
    page.setDefaultTimeout(15 * 1000) // 15s

    // Step 1. Login
    await page.goto(HOST)
    await page.waitForSelector('form')
    await page.evaluate(function (username, password) {
        const form = document.querySelector('form')
        form.username.value = username
        form.password.value = password
        form.submit()
    }, 'admin', ADMIN_PASSWORD)
    await page.waitForSelector('.ui.list')

    // Step 2. Go to URL
    await page.goto(url)

    // Step 3. Wait for 8 seconds and close
    await page.waitFor(8 * 1000)
    await browser.close()
}

router.get('/report', check_login, (req, res) => {
    return res.render('report', {
        HOST
    })
})

router.post('/report', check_login, (req, res) => {
    const url = req.body.url
    if (check_url(url)) {
        openPage(url)
        res.end('Admin launched!')
    } else
        res.end('Invalid URL! The url must start with ' + HOST)
})

router.get('/d/:id', check_login, (req, res) => {
    const id = req.params.id
    const user = req.session.user

    if (documents.has(id) && (user === 'admin' || documents.get(id).owner === user)) {
        const document = documents.get(id)
        return res.render('render', {
            document: fs.readFileSync(document.path).toString('base64')
        })
    } else {
        return res.sendStatus(404)
    }
})

router.get('/examples', (req, res) => res.render('examples.html', {
    examples: fs.readdirSync('public/examples')
}))

router.get('/editor', (req, res) => res.render('editor.html'))

fs.readdirSync('./uploads/').map(path => {
    fs.unlinkSync('./uploads/' + path)
})

module.exports = router