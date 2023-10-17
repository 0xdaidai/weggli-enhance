// const C = require("../tree-sitter-c/grammar.js")
//


module.exports = grammar(C, {
  name: 'c',

  rules: {
    identifier: $ => /(\p{XID_Start}|\$|_|\\u[0-9A-Fa-f]{4}|\\U[0-9A-Fa-f]{8})(\p{XID_Continue}|\\u[0-9A-Fa-f]{4}|\\U[0-9A-Fa-f]{8})*/,
  }
});

module.exports.PREC = C.PREC