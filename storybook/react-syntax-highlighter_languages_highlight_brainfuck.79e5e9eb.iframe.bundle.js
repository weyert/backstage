(window.webpackJsonp=window.webpackJsonp||[]).push([[24],{"../node_modules/highlight.js/lib/languages/brainfuck.js":function(module,exports){module.exports=function brainfuck(hljs){var LITERAL={className:"literal",begin:/[+-]/,relevance:0};return{name:"Brainfuck",aliases:["bf"],contains:[hljs.COMMENT("[^\\[\\]\\.,\\+\\-<> \r\n]","[\\[\\]\\.,\\+\\-<> \r\n]",{returnEnd:!0,relevance:0}),{className:"title",begin:"[\\[\\]]",relevance:0},{className:"string",begin:"[\\.,]",relevance:0},{begin:/(?:\+\+|--)/,contains:[LITERAL]},LITERAL]}}}}]);