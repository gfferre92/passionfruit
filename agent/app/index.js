import checksec from './checksec'
import imports from './imports'
import cookies from './binarycookie'
import keychain from './keychain'
import dumpdecrypted from './dumpdecrypted'
import screenshot from './screenshot'
import bypassJailbreak from './jailbreak'


import { info, userDefaults } from './info'
import { classes, ownClasses, methods, inspect, modules, exports } from './classdump'
import { tables, data, query } from './sqlite'
import { ls, plist, text, download } from './finder'
import { dumpWindow, toggleTouchID, toggleDebugOverlay } from './ui'
import { hook, unhook, swizzle, unswizzle } from './hook'


// todo: add options

require('./pasteboard') // monitor pasteboard

setTimeout(() => {
  Module.ensureInitialized('Foundation')

  bypassJailbreak(true)

  // todo: common function template
  hook('libSystem.B.dylib', 'open', { args: ['char *', 'int'] })
  hook('libsqlite3.dylib', 'sqlite3_open', { args: ['char *', 'int'], ret: 'int' })
  hook('libsqlite3.dylib', 'sqlite3_prepare_v2', { args: ['pointer', 'char *', 'int', 'pointer', 'pointer'] })
  hook('libsqlite3.dylib', 'sqlite3_bind_int', { args: ['pointer', 'int', 'int'] })
  hook('libsqlite3.dylib', 'sqlite3_bind_null', { args: ['pointer', 'int'] })
  hook('libsqlite3.dylib', 'sqlite3_bind_text', { args: ['pointer', 'int', 'char *', 'int', 'pointer'] })

  swizzle('NSURL', 'URLWithString_', false)
  swizzle('NSString', 'stringWithContentsOfFile_usedEncoding_error_')

  try {
    // try to bypass jailbreak
    toggleTouchID(false)
  } catch (ignored) {
    //
  }
}, 1000)

rpc.exports = {
  checksec,
  info,
  userDefaults,

  modules,
  exports,
  classes,
  ownClasses,
  methods,
  inspect,
  imports,

  ls,
  plist,
  text,
  download,

  cookies,

  tables,
  data,
  query,

  dumpWindow,
  toggleTouchID,
  toggleDebugOverlay,

  dumpKeyChain: keychain.list,

  hook,
  unhook,
  swizzle,
  unswizzle,

  dumpdecrypted,
  screenshot,
}
