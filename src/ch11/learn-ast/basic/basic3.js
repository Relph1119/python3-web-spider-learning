/**
 * @author: HuRuiFeng
 * @file: basic3.js
 * @time:  2022-01-14 11:01
 * @project: python3-web-spider-learning
 * @desc: 11.9 使用AST技术还原混淆代码
 */

import fs from "fs";
import {parse} from "@babel/parser";
import traverse from "@babel/traverse";
import * as types from "@babel/types";
import generate from "@babel/generator";


function expression_restore() {
    // 表达式还原
    const code = fs.readFileSync("code2.js", "utf-8");
    let ast = parse(code);

    traverse(ast, {
        "UnaryExpression|BinaryExpression|ConditionalExpression|CallExpression": (path) => {
            const {confident, value} = path.evaluate()
            if (value == Infinity || value == -Infinity) reutrn;
            confident && path.replaceWith(types.valueToNode(value));
        },
    });

    const {code: output} = generate(ast);
    console.log(output);
}

function string_restore() {
    // 字符串还原
    const code = fs.readFileSync("../codes/code3.js", "utf-8");
    let ast = parse(code);

    traverse(ast, {
        StringLiteral({node}) {
            if(node.extra && /\\[ux]/gi.test(node.extra.raw)) {
                node.extra.raw = node.extra.rawValue;
            }
        },
    });

    const {code: output} = generate(ast);
    console.log(output);
}

function delete_unused_code(){
    // 删除无用代码
    const code = fs.readFileSync("../codes/code4.js", "utf-8");
    let ast = parse(code);

    traverse(ast, {
        IfStatement(path) {
            let {consequent, alternate} = path.node;
            let testPath = path.get("test");
            const evaluateTest = testPath.evaluateTruthy();
            if (evaluateTest === true) {
                if (types.isBlockStatement(consequent)) {
                    consequent = consequent.body;
                }
                path.replaceWithMultiple(alternate);
            } else if (evaluateTest === false) {
                if (alternate != null) {
                    if (types.isBlockStatement(alternate)) {
                        alternate = alternate.body
                    }
                    path.replaceWithMultiple(alternate);
                } else {
                    path.remove()
                }
            }
        }
    });

    const {code: output} = generate(ast);
    console.log(output);
}

function anti_control_flow_flattening() {
    // 反控制流平坦化
    const code = fs.readFileSync("../codes/code5.js", "utf-8");
    let ast = parse(code);

    traverse(ast, {
        WhileStatement(path) {
            // 获取节点
            const {node, scope} = path;
            const {test, body} = node;
            let switchNode = body.body[0];
            let {discriminant, cases} = switchNode;
            let {object, property} = discriminant;
            // 拿到s的原始定义
            let arrName = object.name;
            let binding = scope.getBinding(arrName);
            // 拿到s的列表
            let {init} = binding.path.node;
            object = init.callee.object;
            property = init.callee.property;
            let argument = init.arguments[0].value;
            let arrayFlow = object.value[property.name](argument);
            // 遍历列表
            let resultBody = [];
            arrayFlow.forEach((index) => {
               let switchCase = cases.filter((c) => c.test.value == index)[0];
               let caseBody = switchCase.consequent;
               // 移除continue语句
               if (types.isContinueStatement(caseBody[caseBody.length - 1])) {
                   caseBody.pop();
               }
               // 整合代码语句
               resultBody = resultBody.concat(caseBody);
            });
            // 替换代码
            path.replaceWithMultiple(resultBody);
        },
    });

    const {code: output} = generate(ast);
    console.log(output);
}

anti_control_flow_flattening()