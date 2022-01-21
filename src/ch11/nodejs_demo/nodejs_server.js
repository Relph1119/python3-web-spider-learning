/**
 * @author: HuRuiFeng
 * @file: nodejs_server.js
 * @time:  22:09
 * @project: python3-web-spider-learning
 * @desc: 搭建nodejs服务（P453）
 */

const CryptoJS = require("./crypto.js")
const express = require("express")
const app = express();
const port = 3000;
app.use(express.json())


function getToken(player) {
    let key = CryptoJS.enc.Utf8.parse("fipFfVsZsTda94hJNKJfLoaqyqMZFFimwLt");
    const {name, birthday, height, weight} = player;
    let base64Name = CryptoJS.enc.Base64.stringify(CryptoJS.enc.Utf8.parse(name));
    let encrypted = CryptoJS.DES.encrypt(
        `${base64Name}${birthday}${height}${weight}`,
        key, {
            mode: CryptoJS.mode.ECB,
            padding: CryptoJS.pad.Pkcs7,
        }
    );
    return encrypted.toString();
}

app.post("/", (req, res)=> {
    const data = req.body;
    res.send(getToken(data))
});

app.listen(port, ()=> {
    console.log(`Example app listening on port ${port}`);
})