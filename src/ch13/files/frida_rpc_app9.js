/**
 * @author: HuRuiFeng
 * @file: frida_rpc_app9.js
 * @time:  20:06
 * @project: python3-web-spider-learning
 * @desc: frida RPC App9 Hook script
 */

rpc.exports = {
    encrypt(string, offset) {
        let token = null;
        Java.perform(function () {
            var util = Java.use("com.goldze.mvvmhabit.utils.NativeUtils").$new();
            token = util.encrypt(string, offset)
        });
        return token;
    }
}