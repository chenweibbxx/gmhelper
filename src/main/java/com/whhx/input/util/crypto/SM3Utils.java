package com.whhx.input.util.crypto;

/**
 * SM3加密工具类
 * */
public class SM3Utils {

    /**
     * @param msg 待加密的信息
     * */
    public static String encrypt(String msg) throws Exception{
        return SM3.byteArrayToHexString(SM3.hash(msg.getBytes()));
    }
}
