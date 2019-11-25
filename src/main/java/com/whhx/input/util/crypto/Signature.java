package com.whhx.input.util.crypto;

import java.io.Serializable;
import java.math.BigInteger;

/**
 * SM2 签名实体类
 * */
public class Signature implements Serializable {

		BigInteger r;
		BigInteger s;

		public Signature(BigInteger r, BigInteger s) {
			this.r = r;
			this.s = s;
		}

		public String toString() {
			return r.toString(16) + "," + s.toString(16);
		}
	}