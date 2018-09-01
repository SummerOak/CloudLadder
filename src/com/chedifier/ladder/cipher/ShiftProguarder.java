package com.chedifier.ladder.cipher;

import java.nio.ByteBuffer;

import com.chedifier.ladder.base.ArrayUtils;
import com.chedifier.ladder.base.Log;

public class ShiftProguarder implements ICoder{
	
	private static final String TAG = "ShiftProguarder";

	@Override
	public int encode(byte[] origin,ByteBuffer outBuffer) {
		if(origin == null || outBuffer == null) {
			return 0;
		}
		
		return encode(origin,0,origin.length,outBuffer);
	}

	@Override
	public int decode(byte[] encode,ByteBuffer outBuffer) {
		if(encode == null) {
			return 0;
		}
		
		return decode(encode,0,encode.length,outBuffer);
	}

	@Override
	public int encode(byte[] origin, int offset, int len,ByteBuffer outBuffer) {
		if(outBuffer == null || origin == null || !ArrayUtils.isValidateRange(origin.length, offset, len)) {
			return 0;
		}
		
		if(outBuffer.remaining() < len+1) {
			return 0;
		}
		
		byte s = (byte)(1 + (int)(Math.random() * 7));
		Log.i(TAG,"shift " + s);
		
		outBuffer.put(s); 
		int i;
		for(i=0;i < len && ((offset + i) < origin.length);++i) {
			outBuffer.put((byte)(((origin[offset+i]&0xFF)<<s) | ((origin[offset+i]&0xFF)>>(8-s))));
			
			if(++s>7) {
				s=0;
			}
		}
		
		return i+1;
	}

	@Override
	public int decode(byte[] encode, int offset, int len,ByteBuffer outBuffer) {
		if(outBuffer == null || encode == null || !ArrayUtils.isValidateRange(encode.length, offset, len)) {
			Log.e(TAG, "decode>> invalid input.");
			return 0;
		}
		
		if(outBuffer.remaining() < len-1) {
			Log.e(TAG, "decode>> not enought out buffer to store decode data");
			return 0;
		}
		
		byte s = encode[offset];
		Log.i(TAG,"shift " + s);
		int i;
		for(i=1;i<len&&((offset+i)<encode.length);i++) {
			outBuffer.put((byte)(((encode[offset+i]&0xFF)>>s)|((encode[offset+i]&0xFF)<<(8-s))));
			
			if(++s>7) {
				s=0;
			}
		}
		
		return i-1;
	}
	
	@Override
	public int estimateDecodeLen(int len) {
		return len-1;
	}
	
	@Override
	public int estimateEncodeLen(int len) {
		return len+1;
	}

}
