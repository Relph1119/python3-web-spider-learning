/**
 * @author: HuRuiFeng
 * @file: frida_appbasic1.js
 * @time:  2022-01-17 17:21
 * @project: python3-web-spider-learning
 * @desc: frida Appbasic1 Hook script
 */

Java.perform(() => {
    let MainActivity = Java.use('com.germey.appbasic1.MainActivity')
    console.log('start hook')
    MainActivity.getMessage.implementation = (arg1, arg2) => {
        send('Start Hook!')
        return '6'
    }
})