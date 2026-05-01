/**
 * @fileoverview 基于时间的一次性密码 (TOTP) 生成器实现
 * 参考 RFC 6238 和 RFC 4226 标准
 * 使用 Web Crypto API 进行 HMAC-SHA1 计算
 */

/**
 * 将 Base32 字符串转换为 Uint8Array (RFC 4648, 无填充处理)
 * @param {string} base32Str - Base32 编码的密钥字符串
 * @returns {Uint8Array} 解码后的字节数组
 * @throws {Error} 当输入包含非法字符时抛出错误
 */
function base32Decode(base32Str: string): Uint8Array {
	// 标准 Base32 字符表 (RFC 4648)
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	// 清理输入: 移除空格、转为大写、移除可能的填充 '='
	let cleaned = base32Str.trim().toUpperCase().replace(/=+$/, '');
	if (cleaned.length === 0) return new Uint8Array(0);

	let bits = 0;      // 当前累积的比特数
	let value = 0;     // 当前累积的值
	let output = [];    // 存储字节数组 (0-255)

	for (let i = 0; i < cleaned.length; i++) {
		const ch = cleaned[i];
		const idx = alphabet.indexOf(ch);
		if (idx === -1) {
			// 如果遇到非法字符，抛出错误，由调用方处理
			throw new Error(`无效的 Base32 字符: ${ch}`);
		}
		// 每个字符贡献5比特
		value = (value << 5) | idx;
		bits += 5;

		// 当累积比特数 >= 8 时，提取一个字节
		while (bits >= 8) {
			bits -= 8;
			const byte = (value >> bits) & 0xFF;
			output.push(byte);
		}
	}
	// 忽略剩余不足8位的部分（符合标准Base32解码行为）
	return new Uint8Array(output);
}


// ==========================================
// SHA-1 核心算法 (FIPS 180-4)
// ==========================================

/**
 * 循环左移操作
 * @param {number} value - 要移位的 32 位整数
 * @param {number} bits - 左移的位数 (0-31)
 * @returns {number} 循环左移后的结果
 */
function leftRotate(value: number, bits: number): number {
	return (value << bits) | (value >>> (32 - bits));
}

/**
 * SHA-1 压缩函数
 * 处理一个 512-bit 的消息块，更新 160-bit 的链值
 * 
 * @param {number[]} block - 16 个 32 位大端字组成的消息块
 * @param {number[]} H - 当前的 5 个 32 位链值 (会被原地修改)
 */
function sha1Compress(block: any[], H: any[]) {
	// 消息调度: 将 16 个字扩展为 80 个字
	const W = new Array(80);
	for (let t = 0; t < 16; t++) {
		W[t] = block[t];
	}
	for (let t = 16; t < 80; t++) {
		W[t] = leftRotate(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
	}

	// 工作变量
	let a = H[0], b = H[1], c = H[2], d = H[3], e = H[4];

	for (let t = 0; t < 80; t++) {
		let f, k;
		if (t < 20) {
			f = (b & c) | (~b & d);
			k = 0x5A827999;
		} else if (t < 40) {
			f = b ^ c ^ d;
			k = 0x6ED9EBA1;
		} else if (t < 60) {
			f = (b & c) | (b & d) | (c & d);
			k = 0x8F1BBCDC;
		} else {
			f = b ^ c ^ d;
			k = 0xCA62C1D6;
		}

		const temp = (leftRotate(a, 5) + f + e + k + W[t]) >>> 0;
		e = d;
		d = c;
		c = leftRotate(b, 30);
		b = a;
		a = temp;
	}

	// 更新链值
	H[0] = (H[0] + a) >>> 0;
	H[1] = (H[1] + b) >>> 0;
	H[2] = (H[2] + c) >>> 0;
	H[3] = (H[3] + d) >>> 0;
	H[4] = (H[4] + e) >>> 0;
}

/**
 * SHA-1 哈希函数
 * 根据 FIPS 180-4 标准计算消息的 SHA-1 摘要
 * 
 * @param {Uint8Array} message - 要计算哈希的消息
 * @returns {Uint8Array} 20 字节的 SHA-1 哈希值 (大端字节序)
 */
function sha1(message: string | any[] | ArrayLike<number>): Uint8Array {
	// 将字符串转换为 Uint8Array
	if (typeof message === 'string') {
		message = new TextEncoder().encode(message);
	}

	// 初始哈希值 (大端)
	const H = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

	// 预处理: 填充消息
	const msgBitLen = message.length * 8;

	/**
	 * 计算填充所需的零字节数量
	 * 填充规则: 
	 *   1. 追加 1 bit (0x80)
	 *   2. 追加 k 个 0 bit, 使得 (总长度 + 64) 是 512 的倍数
	 *   3. 追加 64 bit 的原始消息长度 (大端)
	 */
	const padLen = (() => {
		let remaining = (message.length + 1 + 8) % 64;
		if (remaining !== 0) {
			return 64 - remaining;
		}
		return 0;
	})();

	const totalLen = message.length + 1 + padLen + 8;
	const padded = new Uint8Array(totalLen);
	padded.set(message, 0);
	padded[message.length] = 0x80; // 追加 1 bit 后跟零

	// 大端写入 64 位消息长度到末尾 8 字节
	const high32 = Math.floor(msgBitLen / 0x100000000);
	const low32 = msgBitLen >>> 0;
	padded[totalLen - 8] = (high32 >>> 24) & 0xFF;
	padded[totalLen - 7] = (high32 >>> 16) & 0xFF;
	padded[totalLen - 6] = (high32 >>> 8) & 0xFF;
	padded[totalLen - 5] = high32 & 0xFF;
	padded[totalLen - 4] = (low32 >>> 24) & 0xFF;
	padded[totalLen - 3] = (low32 >>> 16) & 0xFF;
	padded[totalLen - 2] = (low32 >>> 8) & 0xFF;
	padded[totalLen - 1] = low32 & 0xFF;

	// 按 512-bit (64 字节) 块处理
	for (let i = 0; i < totalLen; i += 64) {
		// 将 64 字节解析为 16 个 32 位大端字
		const block = new Array(16);
		for (let j = 0; j < 16; j++) {
			const offset = i + j * 4;
			block[j] = (padded[offset] << 24)
				| (padded[offset + 1] << 16)
				| (padded[offset + 2] << 8)
				| padded[offset + 3];
		}
		sha1Compress(block, H);
	}

	// 将链值转换为大端字节数组输出
	const digest = new Uint8Array(20);
	for (let i = 0; i < 5; i++) {
		digest[i * 4] = (H[i] >>> 24) & 0xFF;
		digest[i * 4 + 1] = (H[i] >>> 16) & 0xFF;
		digest[i * 4 + 2] = (H[i] >>> 8) & 0xFF;
		digest[i * 4 + 3] = H[i] & 0xFF;
	}
	return digest;
}


// ==========================================
// HMAC 算法 (RFC 2104)
// ==========================================

/**
 * HMAC-SHA1 消息认证码
 * 基于 RFC 2104 标准，使用 SHA-1 作为底层哈希函数
 * 
 * HMAC 定义: HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))
 * 其中:
 *   - K' 是经过填充或哈希处理后的密钥 (固定为块大小 B)
 *   - ipad = 0x36 重复 B 次 (内部填充)
 *   - opad = 0x5C 重复 B 次 (外部填充)
 *   - H 是哈希函数 (SHA-1)
 *   - || 表示拼接
 *   - ⊕ 表示按位异或
 * 
 * @param {Uint8Array} keyBytes - 密钥字节数组
 * @param {Uint8Array} messageBytes - 要认证的消息字节数组
 * @returns {Uint8Array} 20 字节的 HMAC-SHA1 值
 * 
 * @example
 * const key = new TextEncoder().encode("secret-key");
 * const message = new TextEncoder().encode("Hello, World!");
 * const mac = hmacSha1(key, message);
 * console.log(mac); // Uint8Array(20)
 */
function hmacSha1(keyBytes: string | any[] | ArrayLike<number>, messageBytes: string | any[] | ArrayLike<number>): Uint8Array {
	// 将字符串转换为 Uint8Array
	if (typeof keyBytes === 'string') {
		keyBytes = new TextEncoder().encode(keyBytes);
	}
	if (typeof messageBytes === 'string') {
		messageBytes = new TextEncoder().encode(messageBytes);
	}

	/** SHA-1 的块大小: 64 字节 (512 bits) */
	const blockSize = 64;

	/**
	 * 密钥预处理 (RFC 2104 Section 2)
	 * 
	 * 将密钥标准化为恰好等于块大小的字节数组:
	 *   1. 如果密钥长度 > 块大小: 先求其 SHA-1 哈希 (20 字节)，然后补零到块大小
	 *   2. 如果密钥长度 < 块大小: 直接补零到块大小
	 *   3. 如果密钥长度 = 块大小: 直接使用
	 */
	let key;
	if (keyBytes.length > blockSize) {
		// 密钥过长，先用 SHA-1 压缩，再补零
		const hash = sha1(keyBytes);
		key = new Uint8Array(blockSize);
		key.set(hash, 0);
		// 其余字节保持为零
	} else if (keyBytes.length < blockSize) {
		// 密钥不足，补零
		key = new Uint8Array(blockSize);
		key.set(keyBytes, 0);
	} else {
		// 密钥恰好等于块大小，直接复制
		key = new Uint8Array(keyBytes);
	}

	// 内部填充: ipad = key ⊕ 0x36
	const ipad = new Uint8Array(blockSize);
	for (let i = 0; i < blockSize; i++) {
		ipad[i] = key[i] ^ 0x36;
	}

	// 外部填充: opad = key ⊕ 0x5C
	const opad = new Uint8Array(blockSize);
	for (let i = 0; i < blockSize; i++) {
		opad[i] = key[i] ^ 0x5C;
	}

	// 计算内部哈希: SHA-1(ipad || message)
	const innerMsg = new Uint8Array(blockSize + messageBytes.length);
	innerMsg.set(ipad, 0);
	innerMsg.set(messageBytes, blockSize);
	const innerHash = sha1(innerMsg);

	// 计算外部哈希: SHA-1(opad || innerHash)
	const outerMsg = new Uint8Array(blockSize + 20); // innerHash 固定 20 字节
	outerMsg.set(opad, 0);
	outerMsg.set(innerHash, blockSize);
	const hmac = sha1(outerMsg);

	return hmac;
}

/**
 * 动态截断：从 HMAC-SHA1 结果提取 6 位数字验证码
 * @param {Uint8Array} hmacResult - HMAC-SHA1 结果 (20字节)
 * @returns {string} 6 位数字验证码 (不足 6 位时补前导零)
 */
function dynamicTruncate(hmacResult: Uint8Array | number[]): string {
	// 获取偏移量: 取最后一个字节的低4位
	const offset = hmacResult[19] & 0x0F;
	// 从 offset 开始取4个字节构成一个31位整数 (忽略最高位)
	const binary = ((hmacResult[offset] & 0x7F) << 24) |
		((hmacResult[offset + 1] & 0xFF) << 16) |
		((hmacResult[offset + 2] & 0xFF) << 8) |
		(hmacResult[offset + 3] & 0xFF);
	// 取模 10^6 得到6位数字
	const otp = binary % 1000000;
	// 补零至6位
	return otp.toString().padStart(6, '0');
}

/**
 * 获取当前时间步长计数器 (基于Unix时间戳, 步长30秒)
 * @returns {number} 时间步长计数器
 */
function getCurrentCounter(): number {
	// 当前时间 (秒)
	const nowSec = Math.floor(Date.now() / 1000);
	// 时间步长30秒
	const step = 30;
	// 计数器 T = floor(当前时间戳 / 步长)
	return Math.floor(nowSec / step);
}

/**
 * 将计数器转换为 8 字节大端序 Uint8Array
 * @param {number} counter - 整数计数器
 * @returns {Uint8Array} 8 字节大端序字节数组
 */
function counterToBytes(counter: number): Uint8Array {
	const bytes = new Uint8Array(8);
	for (let i = 7; i >= 0; i--) {
		bytes[i] = counter & 0xFF;
		counter = counter >> 8;
	}
	return bytes;
}

/**
 * 生成基于时间的一次性密码 (TOTP)
 * @param {string} base32Secret - Base32 编码的密钥
 * @returns {string} 返回 6 位验证码字符串
 * @throws {Error} 当解码失败或 HMAC 计算失败时抛出错误
 */
function generateTOTP(base32Secret: string): string {
	if (!base32Secret || base32Secret.trim() === "") {
		throw new Error("Base32 密钥不能为空");
	}
	// 1. Base32 解码
	let keyBytes;
	try {
		keyBytes = base32Decode(base32Secret);
	} catch (e) {
		const errorMessage = e instanceof Error ? e.message : String(e);
		throw new Error(`Base32 解码失败: ${errorMessage}`);
	}
	if (keyBytes.length === 0) {
		throw new Error("解码后密钥为空，请提供有效的 Base32 密钥");
	}
	// 2. 获取当前计数器 (步长30秒)
	const counter = getCurrentCounter();
	// 3. 计数器转8字节大端序
	const msgBytes = counterToBytes(counter);
	// 4. 计算 HMAC-SHA1
	let hmac;
	try {
		hmac = hmacSha1(keyBytes, msgBytes);
	} catch (e) {
		const errorMessage = e instanceof Error ? e.message : String(e);
		throw new Error(`HMAC 计算失败: ${errorMessage}`);
	}
	// 5. 动态截断获取6位验证码
	const otp = dynamicTruncate(hmac);
	return otp;
}

export { base32Decode, sha1, hmacSha1, dynamicTruncate, getCurrentCounter, counterToBytes };
export default generateTOTP;