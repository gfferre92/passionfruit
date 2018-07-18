const Handler = require('./base')
const Cache = require('../cache')

const { Transform } = require('stream')
const { retry, uuidv4 } = require('../utils')

const socketStream = require('socket.io-stream')

class DownloadStream extends Transform {
  _transform(chunk, encoding, next) {
    this.push(chunk)
    next()
  }
}


module.exports = class RpcHandler extends Handler {
  constructor(session, socket) {
    super(session, socket)

    this.stream = socketStream(socket)
    this.cache = new Cache()
    this.transfer = new Map()
    this.userScripts = new Map()
    this.handleMessage()

    this.pendingConsoleMsgs = []
    this.lastConsoleTimestamp = 0
  }

  async load() {
    const { socket } = this
    const script = await this.getAgent('app')
    script.destroyed.connect(() => {
      socket.emit('script_destroyed')
      socket.disconnect(true)
    })
    script.message.connect((message, data) => {
      if (message.type === 'send')
        this.handleSend(message, data)
      else if (message.type === 'error')
        this.handleError(message, data)
    })

    await script.load()
    this.script = script
    this.agent = script.exports
  }

  handleSend({ payload }, data) {
    if (payload.subject === 'download') {
      const { event, session } = payload
      if (event === 'start') {
        const stream = new DownloadStream()
        this.transfer.set(session, stream)
      } else if (event === 'end') {
        const stream = this.transfer.get(session)
        stream.end()
      } else if (event === 'data') {
        const stream = this.transfer.get(session)
        stream.write(data)
      }
    } else {
      if (data !== null) {
        console.warn('does not support binary protocol yet, message payload:')
        console.warn(payload)
      }

      const TIMEOUT = 500
      this.pendingConsoleMsgs.push(payload)

      const flush = () => {
        const now = Date.now()
        if (this.lastConsoleTimestamp < now - TIMEOUT) {
          // forward to browser
          this.socket.emit('console', this.pendingConsoleMsgs)
          this.pendingConsoleMsgs = []
          this.lastConsoleTimestamp = now
          return true
        }
        return false
      }

      if (!flush()) setTimeout(flush.bind(this), TIMEOUT)

      // store in db, no need to wait
      this.emit('saveLog', payload)
    }
  }

  handleMessage() {
    [
      'eval',
      'unload',

      'modules',
      'exports',

      'classes',
      'ownClasses',
      'inspect',

      'info',
      'userDefaults',
      'imports',

      'ls',
      'plist',
      'text',
      'download',

      'tables',
      'data',

      'dumpWindow',
      'toggleDebugOverlay',

      'dumpKeyChain',
      'cookies',

      'hook',
      'unhook',
      'swizzle',
      'unswizzle',

      'dumpdecrypted',
      'screenshot',
    ].forEach(event => this.socket.on(event, this.wrap(event)))

    // handle file transfer
    this.stream.on('download', (stream, args) => {
      const { session } = args
      if (session && this.transfer.has(session)) {
        const source = this.transfer.get(session)
        source.pipe(stream).on('finish', () => this.transfer.delete(session))
      }
    })
  }

  async eval(source) {
    const uuid = uuidv4()
    const { socket } = this
    const script = await this.session.createScript(`
        rpc.exports.bootstrap = function(js) {
          // temp workaround for
          // https://github.com/frida/frida-node/pull/28
          // in case the output goes to server side console instead
          // being sent to frontend
          //
          // this is not a sandbox, do not waste your time on escaping it
  
          ['log', 'warn', 'error'].forEach(function(level) {
            console[level] = function() {
              send({
                subject: 'console.message',
                level: level,
                args: [].slice.call(arguments)
              });
            };
          });
  
          // wow, copied from frida-python
          try {
            const result = (1, eval)(js);
            if (result instanceof ArrayBuffer) {
              return result;
            } else {
              var type = (result === null) ? 'null' : typeof result;
              return [type, result];
            }
          } catch (e) {
            return ['error', e instanceof Error ? {
              name: e.name,
              message: e.message,
              stack: e.stack
            } : e + ''];
          }
        }
      `)

    script.destroyed.connect(() => {
      socket.emit('userScript', {
        subject: 'destroyed',
        uuid,
      })
    })

    script.message.connect((message, data) => {
      const { type, payload } = message
      // forward to frontend
      socket.emit('userScript', {
        subject: 'message',
        uuid,
        type,
        payload,
        // binary data is not supported right now
        hasData: data !== null,
      })
    })

    try {
      await script.load()
      const { bootstrap } = await script.getExports()
      const result = await bootstrap(source)
      let [type, value] = result
      if (result instanceof Buffer) {
        type = 'arraybuffer'
        value = Buffer.from(result).toString('base64')
      }

      this.userScripts.set(uuid, script)

      if (type === 'error') {
        console.error('Uncaught user frida script', value.stack || value)
        return {
          status: 'failed',
          error: value,
        }
      }

      return {
        status: 'ok',
        uuid,
        type,
        value,
      }
    } catch (error) {
      console.error('Uncaught user frida script', error.stack || error)
      return {
        status: 'failed',
        error,
      }
    }
  }

  async unload(uuid) {
    const script = this.userScripts.get(uuid)
    if (script) {
      this.userScripts.delete(uuid)
      return script.unload()
    }
    throw new Error(`script not found: ${uuid}`)
  }

  async modules() {
    return this.session.enumerateModules()
  }

  async exports({ module }) {
    return this.session.enumerateExports(module)
  }

  async classes() {
    const func = this.agent.classes.bind(this.agent)
    return this.cache.fetch('classes', func)
  }

  async ownClasses() {
    const func = this.agent.ownClasses.bind(this.agent)
    return this.cache.fetch('ownClasses', func)
  }

  async inspect({ clz }) {
    return this.agent.inspect(clz)
  }

  async info() {
    return retry(async() => {
      const sec = await this.agent.checksec()
      const info = await this.agent.info()
      return { sec, info }
    })
  }

  async userDefaults() {
    return this.agent.userDefaults()
  }

  async imports(data) {
    const name = (data && data.name) ? data.name : null
    return this.agent.imports(name)
  }

  async ls({ pathName, root }) {
    return this.agent.ls(pathName, root)
  }

  async plist(fileName) {
    return this.agent.plist(fileName)
  }

  async text(fileName) {
    return this.agent.text(fileName)
  }

  async tables(fileName) {
    return this.agent.tables(fileName)
  }

  async data(arg) {
    return this.agent.data(arg)
  }

  async download(fileName) {
    return this.agent.download(fileName)
  }

  async dumpWindow() {
    return this.agent.dumpWindow()
  }

  async toggleDebugOverlay() {
    return this.agent.toggleDebugOverlay()
  }

  async dumpKeyChain() {
    return this.agent.dumpKeyChain()
  }

  async cookies() {
    return this.agent.cookies()
  }

  async hook({ module, name, args, ret }) {
    return this.agent.hook(module, name, { args, ret })
  }

  async unhook({ module, name }) {
    return this.agent.unhook(module, name)
  }

  async swizzle({ clazz, method, ret }) {
    return this.agent.swizzle(clazz, method, ret)
  }

  async unswizzle({ clazz, method }) {
    return this.agent.unswizzle(clazz, method)
  }

  async dumpdecrypted(name) {
    return this.agent.dumpdecrypted(name)
  }

  async screenshot() {
    return this.agent.screenshot()
  }
}

