//
// Utility functions.
//
// Copyright (c) 2016 Samuel Groß
//

class Environment {
	constructor(os, arch, bits) {
		this.os = os;
		this.arch = arch
		this.bits = bits;
	}
}

//Smi <=> int 
var global = this;

// Return the hexadecimal representation of the given byte.
function hex(b) {
    return ('0' + b.toString(16)).substr(-2);
}

// Return the hexadecimal representation of the given byte array.
function hexlify(bytes) {
    var res = [];
    for (var i = 0; i < bytes.length; i++)
        res.push(hex(bytes[i]));

    return res.join('');
}

// Return the binary data represented by the given hexdecimal string.
function unhexlify(hexstr) {
    if (hexstr.length % 2 == 1)
        throw new TypeError("Invalid hex string");

    var bytes = new Uint8Array(hexstr.length / 2);
    for (var i = 0; i < hexstr.length; i += 2)
        bytes[i / 2] = parseInt(hexstr.substr(i, 2), 16);

    return bytes;
}

function hexdump(data) {
    if (typeof data.BYTES_PER_ELEMENT !== 'undefined')
        data = Array.from(data);

    var lines = [];
    for (var i = 0; i < data.length; i += 16) {
        var chunk = data.slice(i, i + 16);
        var parts = chunk.map(hex);
        if (parts.length > 8)
            parts.splice(8, 0, ' ');
        lines.push(parts.join(' '));
    }

    return lines.join('\n');
}

function hex8(value) {
	return value.toString(16).padStart(2, '0');
}

function hex16(value) {
	return value.toString(16).padStart(4, '0');
}

function hex32(value) {
	return value.toString(16).padStart(8, '0');
}

// Simplified version of the similarly named python module.
var Struct = (function() {
    // Allocate these once to avoid unecessary heap allocations during pack/unpack operations.
    var buffer = new ArrayBuffer(8);
    var byteView = new Uint8Array(buffer);
    var uint32View = new Uint32Array(buffer);
    var float64View = new Float64Array(buffer);

    return {
        pack: function(type, value) {
            var view = type; // See below
            view[0] = value;
            return new Uint8Array(buffer, 0, type.BYTES_PER_ELEMENT);
        },

        unpack: function(type, bytes) {
            if (bytes.length !== type.BYTES_PER_ELEMENT)
                throw Error("Invalid bytearray");

            var view = type; // See below
            byteView.set(bytes);
            return view[0];
        },

        // Available types.
        int8: byteView,
        int32: uint32View,
        float64: float64View
    };
})();

var __gc_arr = [];

function gc() {
    for (var i = 0; i < 0x100000 / 0x10; i++) {
        __gc_arr[i] = new Array(); //为了防止这个函数被turbofan优化掉，赋值给gc_arr
    }
}

/* --------------------------------------------- */
//生成所占代码空间足够大的函数，否则有可能在shellcode过长的时候覆盖到其他函数的代码
function generate_huge_func() {
    this.not_opt_out = 0; //要是全局变量
    var huge_str = "if(value == 0xdecaf0) { not_opt_out += 1; } not_opt_out += 1; not_opt_out |= 0xff; not_opt_out *= 12;";
    var operand_arr = ["+=", "|=", "*="];
    function getRandInt(max) {
      return Math.floor(Math.random() * Math.floor(max));
    }
    function getRandEle(arr) {
        return arr[getRandInt(arr.length)];
    }
    for(var i = 0; i < 100; i++) {
        huge_str += `not_opt_out ${getRandEle(operand_arr)} ${getRandInt(256)} ;`;
    }
    huge_func = new Function("value", huge_str);
    for(var i = 0; i < 0x10000; i++) {
            huge_func(i);
    }
    return huge_func;
}

//assert 相关的函数
function assert(v) {
	if(!v) {
		throw new Error("表达式 v 的值不是 true");
	}
}

const assertTrue = assert;