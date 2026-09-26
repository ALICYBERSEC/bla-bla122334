// frida -f ./click_me -l dump_flag.js    (on Apple Silicon macOS)
// Dumps anything that looks like the flag from libc output + memory.
function scan(p, n) {
  try {
    var s = p.readUtf8String(n);
    if (s && /flare-on\.com/i.test(s)) { console.log("[FLAG] " + s); }
  } catch (e) {}
}
// Hook raw stdout/stderr writes
['write','writev','fwrite','puts','fputs','printf','fprintf','dprintf'].forEach(function(fn){
  var a = Module.findExportByName(null, fn); if(!a) return;
  Interceptor.attach(a, { onEnter: function(args){
    // buffer is usually arg0 or arg1 depending on fn; scan both
    scan(args[0], 256); scan(args[1], 256);
  }});
});
// Hook memmove/memcpy — flags are often assembled via copies
['memcpy','memmove','__memcpy_chk'].forEach(function(fn){
  var a = Module.findExportByName(null, fn); if(!a) return;
  Interceptor.attach(a, { onEnter: function(args){ scan(args[1], 128); }});
});
console.log("[*] hooks installed; interact with the program if it prompts");
