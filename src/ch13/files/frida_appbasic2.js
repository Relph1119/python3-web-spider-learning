/**
 * @author: HuRuiFeng
 * @file: frida_appbasic1.js
 * @time:  2022-01-17 17:39
 * @project: python3-web-spider-learning
 * @desc: frida Appbasic2 Hook script
 */

Java.perform(function () {
    Interceptor.attach(Module.findExportByName('libnative.so', 'Java_com_appbasic2_MainActivity_getMessage'), {
        onEnter: function (args) {
            send('hook onEnter')
            send('args[1]=' + args[2])
            send('args[2]=' + args[3])
        },
        onLeave: function (val) {
            send('hook Leave')
            val.replace(Java.vm.getEnv().newStringUtf('5'))
        }
    })
})