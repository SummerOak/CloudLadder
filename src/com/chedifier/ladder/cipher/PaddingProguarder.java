package com.chedifier.ladder.cipher;

import java.nio.ByteBuffer;

import com.chedifier.ladder.base.Log;

public class PaddingProguarder implements ICoder{
	private static final String TAG = "PaddingProguarder";
	
	
	private TYPE mType = TYPE.HEAD;
	private static final int MAX_PADDING = Cipher.MAX_PARCEL_SIZE>>2;
	
	public PaddingProguarder() {
		
	}
	
	@Override
	public int encode(byte[] origin,ByteBuffer outBuffer) {
		if(origin != null) {			
			return encode(origin,0,origin.length,outBuffer);
		}
		
		return 0;
	}

	@Override
	public int decode(byte[] encode,ByteBuffer outBuffer) {
		if(encode != null) {
			return decode(encode,0,encode.length,outBuffer);
		}
		
		return 0;
	}

	@Override
	public int encode(byte[] origin, int offset, int len,ByteBuffer outBuffer) {
		if(outBuffer == null || origin == null || len <= 0 || offset < 0 || origin.length <= 0 || (origin.length < (len + offset))) {
			return 0;
		}
		
		switch(mType) {
			case HEAD:{
				int p = 1 + (int)(Math.random() * paddingRange(len));
				if(outBuffer.remaining() < p+len+2) {
					return 0;
				}
				outBuffer.put((byte)((p>>8)&0xFF));
				outBuffer.put((byte)(p&0xFF));
				for(int i=0;i<p;i++) {
					outBuffer.put((byte)(Math.random() * 256));
				}
				
				outBuffer.put(origin,offset,len);
				
				return p+len+2;
			}
		}
		return 0;
	}

	@Override
	public int decode(byte[] encode, int offset, int len,ByteBuffer outBuffer) {
		if(outBuffer == null || encode == null || offset < 0 || len <= 1 || encode.length <= 0 || (encode.length < (len + offset))) {
			Log.e(TAG, "decode>> invalid input.");
			return 0;
		}
		
		switch(mType) {
			case HEAD:{
				int p = ((encode[offset]&0xFF)<<8)|(encode[offset+1]&0xFF);
				if(p >= 0 && p+2 < len) {
					if(outBuffer.remaining() < (len-p-2)) {
						return 0;
					}
					outBuffer.put(encode,offset+p+2,len-p-2);
					return len-p-1;
				}
				
				return 0;
			}
		}
		
		return 0;
	}
	
	@Override
	public int estimateDecodeLen(int len) {
		return len;
	}
	
	private int paddingRange(int len) {
		return len > MAX_PADDING?0:MAX_PADDING-len;
	}
	
	@Override
	public int estimateEncodeLen(int len) {
		return len+paddingRange(len)+2;
	}
	
	public enum TYPE{
		HEAD,
	}
	
}
