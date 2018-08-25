package com.chedifier.ladder.cipher;

import java.nio.ByteBuffer;

public interface ICoder {
	int encode(byte[] origin,ByteBuffer outBuffer);
	int encode(byte[] origin,int offset,int len,ByteBuffer outBuffer);
	int decode(byte[] encode,ByteBuffer outBuffer);
	int decode(byte[] encode,int offset,int len,ByteBuffer outBuffer);
	int estimateEncodeLen(int len);
	int estimateDecodeLen(int len);
}
