/**
 * @author: HuRuiFeng
 * @file: basic2.js
 * @time:  2022-01-14 10:00:25
 * @project: python3-web-spider-learning
 * @desc: AST操作
 */

import {parse} from "@babel/parser";
import traverse from "@babel/traverse";
import generate from "@babel/generator";
import * as types from "@babel/types"
import fs from "fs";

const code = fs.readFileSync("../codes/code1.js", "utf-8")
let ast = parse(code);

function traverse_nodes() {
    // 遍历AST节点
    traverse(ast, {
        enter(path) {
            console.log(path)
        }
    })
}

function modify_value1() {
    // 利用修改AST的方式修改赋值变量
    traverse(ast, {
        enter(path) {
            let node = path.node;
            if (node.type === "NumericLiteral" && node.value === 3) {
                node.value = 5;
            }
            if (node.type === "StringLiteral" && node.value === "hello") {
                node.value = "hi";
            }
        },
    })
    const {code: output } = generate(ast, {
    retainLines: true,
    });

    console.log(output);
}

function modify_value2() {
    // 利用修改AST的方式修改赋值变量
    traverse(ast, {
        NumericLiteral(path) {
            if (path.node.value === 3) {
                path.node.value = 5;
            }
        },
        StringLiteral(path) {
            if (path.node.value === "hello") {
                path.node.value = "hi";
            }
        }
    })
    const {code: output } = generate(ast, {
        comments: false
    });

    console.log(output);
}

function delete_node() {
    // 删除所有的console.log
    traverse(ast, {
        CallExpression(path) {
            let node = path.node;
            if (
                node.callee.object.name === "console" &&
                node.callee.property.name === "log"
            ) {
                path.remove();
            }
        },
    });

    const {code: output } = generate(ast, {
        comments: false
    });

    console.log(output);
}

function add_node() {
    // 添加const b = a + 1;
    const code = "const a = 1;";
    let ast = parse(code);
    traverse(ast, {
       VariableDeclaration(path) {
           let init = types.binaryExpression(
               "+",
               types.identifier("a"),
               types.numericLiteral(1)
           );
           let declarator = types.variableDeclarator(types.identifier("b"), init);
           let declaration = types.variableDeclaration("const", [declarator]);
           path.insertAfter(declaration);
           path.stop();
       },
    });
    const output = generate(ast, {
        retainLines: true,
    }).code;
    console.log(output);
}

add_node()

