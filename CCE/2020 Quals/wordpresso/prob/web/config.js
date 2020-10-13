const crypto = require('crypto'),
    fs = require('fs')

const random_key = length => {
    const buffer = Buffer.alloc(length >> 1)
    crypto.randomFillSync(buffer, 0, buffer.length)
    return buffer.toString('hex')
}

const config = {
    PORT: parseInt(process.env.PORT),
    HOST: process.env.HOST,
    ADMIN_PASSWORD: random_key(64),
    FLAG: '/run/secrets/sensitive/flag.wordpresso',
    random_key
}

module.exports = config

if (!config.HOST || !config.PORT)
    throw new Error("HOST and PORT should be specified in env")

if (!fs.existsSync(config.FLAG))
    throw new Error("Flag file does not exist: " + config.FLAG)