const path = require('path')
const http = require('http')
const { Z_SYNC_FLUSH } = require('zlib')

require('colors')

const frida = require('frida')
const Koa = require('koa')

const logger = require('koa-logger')
const json = require('koa-json')
const compress = require('koa-compress')
const bodyParser = require('koa-bodyparser')
const send = require('koa-send')
const Router = require('koa-router')

const { FridaUtil, serializeDevice } = require('./lib/utils')
const channels = require('./lib/channels.js')
const { KnownError, InvalidDeviceError } = require('./lib/error')
const { DataBase } = require('./lib/db')


const app = new Koa()
const router = new Router({ prefix: '/api' })

// hack: convert buffer to base64 string
/* eslint func-names:0 */
Buffer.prototype.toJSON = function() {
  return this.toString('base64')
}

const db = new DataBase()

router
  .get('/devices', async (ctx) => {
    const devices = await frida.enumerateDevices()
    const list = devices.filter(FridaUtil.isUSB)
    ctx.body = list.map(serializeDevice)
    db.saveDevices(list)
  })
  .get('/device/:device/apps', async (ctx) => {
    const id = ctx.params.device
    const dev = await FridaUtil.getDevice(id)
    try {
      const apps = await dev.enumerateApplications()
      ctx.body = apps
      db.saveApps(apps, id)
    } catch (ex) {
      if (ex.message.indexOf('Unable to connect to remote frida-server') === 0)
        throw new InvalidDeviceError(id)
      else
        throw ex
    }
  })
  .post('/device/spawn', async (ctx) => {
    const { device, bundle } = ctx.params
    const dev = await FridaUtil.getDevice(device)
    const pid = await dev.spawn([bundle])
    ctx.body = { status: 'ok', pid }
  })

const port = parseInt(process.env.PORT, 10) || 31337
const host = process.env.HOST || 'localhost'


app
  .use(compress({
    filter(contentType) {
      return /text|json/i.test(contentType)
    },
    threshold: 2048,
    flush: Z_SYNC_FLUSH,
  }))
  .use(bodyParser())
  .use(async(ctx, next) => {
    try {
      await next()
    } catch (e) {
      if (e instanceof KnownError)
        ctx.throw(404, e.message)

      if (process.env.NODE_ENV === 'development')
        throw e
      else
        ctx.throw(500, e.message)
    }
  })
  .use(router.routes())
  .use(router.allowedMethods())


if (process.env.NODE_ENV === 'development') {
  app.use(json({
    pretty: false,
    param: 'pretty',
  }))
} else {
  app.use(async (ctx, next) => {
    const opt = { root: path.join(__dirname, 'gui') }
    if (ctx.path.startsWith('/static/'))
      await send(ctx, ctx.path, opt)
    else // SPA
      await send(ctx, '/index.html', opt)

    next()
  })
  app.use(logger())
}

async function main() {
  await db.connect()

  process.on('exit', () => {
    db.disconnect()
  })

  process.on('unhandledRejection', (err) => {
    console.error('An unhandledRejection occurred: ')
    console.error(`Rejection: ${err}`)
    console.error(err.stack)

    channels.broadcast('unhandledRejection', {
      err: err.toString(),
      stack: err.stack,
    })
  })

  console.info('environment:', process.env.NODE_ENV.yellow)
  console.info(`listening on http://${host}:${port}`.green)
  const server = http.createServer(app.callback())
  channels.attach(server)

  server.listen(port, host)
}

main()
