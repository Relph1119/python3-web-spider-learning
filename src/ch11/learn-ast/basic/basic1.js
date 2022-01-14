/**
 * @author: HuRuiFeng
 * @file: basic1.js
 * @time:  2022-01-14 09:47:06
 * @project: python3-web-spider-learning
 * @desc:
 */

import {parse} from "@babel/parser"
import generate from "@babel/generator"
import fs from "fs"

const code = fs.readFileSync("../codes/code1.js", "utf-8")
let ast = parse(code)
console.log(ast)
console.log(ast.program.body)

const {code: output} = generate(ast, {
    ratainLines: true,
    comments: false,
});
console.log(output)