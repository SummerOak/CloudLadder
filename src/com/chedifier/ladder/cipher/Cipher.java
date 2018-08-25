package com.chedifier.ladder.cipher;

import java.nio.ByteBuffer;

import com.chedifier.ladder.base.ArrayUtils;
import com.chedifier.ladder.base.Log;
import com.chedifier.ladder.memory.ByteBufferPool;

public class Cipher {
	private static final String TAG = "Cipher";

	private static final int BLOCK_SIZE = 1<<10;
	public static final int MAX_PARCEL_SIZE = BLOCK_SIZE<<2;
	public static final int MAX_ENCRYPT_SIZE = MAX_PARCEL_SIZE>>1;
	
	private final byte[] mCodes = {1,2};
	private ICoder[] mCoders = new ICoder[CODER.END];
	
	/**
	 * encrypt origin to result 
	 * @param origin
	 * @param offset
	 * @param len
	 * @param result
	 * @return the len of data be encrypted
	 */
	public int encrypt(byte[] origin,int offset ,int len,ByteBuffer outBuffer) {
		if(origin == null || !ArrayUtils.isValidateRange(origin.length, offset, len) || outBuffer == null) {
			Log.e(TAG, "infalidate input arguments!");
			return 0;
		}
		
		if(len > MAX_ENCRYPT_SIZE) {
			len = MAX_ENCRYPT_SIZE;
		}
		
		int estLen = encryptLen(len);
		if(estLen > outBuffer.remaining()) {
			Log.e(TAG, "encrypt failed,not enought buffer to store result");
			return ERR_NOT_ENOUGH_SPACE;
		}
		
		ByteBuffer s = ByteBufferPool.obtain(estLen);
		ByteBuffer t = ByteBufferPool.obtain(estLen);
		ByteBuffer ss;
		s.put((byte)0x00);
		s.put(origin, offset, len);
		
		for(int i=0;i<mCodes.length;i++) {
			byte cid = mCodes[i];
			ICoder c = getCoder(cid);
			t.clear();
			t.put(cid);
			if(c != null && c.encode(s.array(), 0, s.position(), t) > 0) {
				ss = s; s = t; t = ss;
			}
			
		}
		
		int r = pack(s.array(), 0, s.position(), outBuffer);
		if(r <= 0) {
			Log.e(TAG, "pack failed.");
			return 0;
		}
		
		ByteBufferPool.recycle(s);
		ByteBufferPool.recycle(t);
		
		return len;
	}
	
	/**
	 * 
	 * @param packs
	 * @param offset
	 * @param len
	 * @param outBuffer
	 * @return the len of data be decrypted in packs
	 */
	public int decrypt(byte[] packs,int offset,int len,ByteBuffer outBuffer) {
		if(packs == null || !ArrayUtils.isValidateRange(packs.length, offset, len)) {
			Log.e(TAG, "decrypt>>> invalidate input.");
			return 0;
		}
		
		int estLen = decryptLen(len);
		if(estLen > outBuffer.remaining()) {
			Log.e(TAG, "decrypt failed,not enought buffer to store result");
			return ERR_NOT_ENOUGH_SPACE;
		}
		
		ByteBuffer s = ByteBufferPool.obtain(estLen);
		ByteBuffer t = ByteBufferPool.obtain(estLen);
		ByteBuffer ss;
		int off = offset;
		int result, l, r = len;
		while(true) {
			s.clear();
			l = unpack(packs, off, r, s);
			if(l <= 0 || s.position() <= 0) {
				break;
			}
			
			boolean succ = true;
			while(true) {
				
				s.flip();
				byte cid = s.get();
				
				if(cid != 0) {
					ICoder c = getCoder(cid);
					if(c == null) {
						Log.e(TAG, "invalidate cid " + cid);
						succ = false;
						break;
					}
					
					t.clear();
					result = c.decode(s.array(), s.position(), s.remaining(), t);
					if(result <= 0) {
						Log.e(TAG, "decode failed " + result);
						succ = false;
						break;
					}
					
					ss = s; s = t; t = ss;
					
				}else {
					break;
				}
			}
			
			if(!succ) {
				Log.e(TAG, "decode failed.");
				break;
			}
			
			outBuffer.put(s);
			r -= l;
			off += l;
		}
		
		ByteBufferPool.recycle(s);
		ByteBufferPool.recycle(t);
		
		if(off == offset) {
			Log.e(TAG, "unpack failed");
			return 0;
		}
		
		return off-offset;
	}
	
	private static int estimatePackLen(int len) {
		return ((len/BLOCK_SIZE)<<1) + 2 + len;
	}
	
	private static int estimateUnpackLen(int len) {
		return len;
	}
	
	//return the length of origin be packed, either 0 or len will return
	private int pack(byte[] origin,int offset,int len,ByteBuffer outBuffer) {
		if(origin == null || !ArrayUtils.isValidateRange(origin.length, offset, len) || outBuffer == null) {
			Log.e(TAG, "pack infalidate input arguments!");
			return 0;
		}
		
		int ll = estimatePackLen(len);
		if(outBuffer.remaining() < ll) {
			Log.e(TAG, "not enough space to pack");
			return 0;
		}
		
		int s = 0, r = len, b = 0;
		while(r > 0) {
			b = r>BLOCK_SIZE?BLOCK_SIZE:r;
			outBuffer.put((byte)((b>>8)&0xFF));
			outBuffer.put((byte)(b&0xFF));
			outBuffer.put(origin, offset+s, b);
			r -= b;
			s += b;
		}
		
		if(b == BLOCK_SIZE) {
			outBuffer.put((byte)(0&0xFF));
			outBuffer.put((byte)(0&0xFF));
		}
		
		return s;
	}

	//unpack one parcel in data and return the length of data be unpacked
	private int unpack(byte[] data, int offset, int len, ByteBuffer outBuffer) {
		if(data == null || !ArrayUtils.isValidateRange(data.length, offset, len) || outBuffer == null) {
			Log.d(TAG, "unpack infalidate input arguments! " + data + " offset="+offset+" len="+len);
			return 0;
		}
		
		int ll = estimateUnpackLen(len);
		if(outBuffer.remaining() < ll) {
			Log.e(TAG, "not enough space to unpack");
			return 0;
		}
		
		int i = 0;
		int blockSize = 0;
		outBuffer.mark();
		while(true) {
			if(i+1>=len) {
				break;
			}
			
			blockSize = (((int)(data[offset+i])&0xFF)<<8)|(((int)(data[offset+i+1]&0xFF)));
			i+=2;
			
			if(i+blockSize > len) {
				Log.e(TAG, "package not completed.");
				break;
			}
			
			if(outBuffer.remaining() < blockSize) {
				Log.e(TAG, "not enough space to unpack");
				break;
			}
			
			if(blockSize > 0) {
				outBuffer.put(data, offset+i, blockSize);
				i += blockSize;
			}
			
			if(blockSize < BLOCK_SIZE) {
				Log.d(TAG, "unpack success " + i + " last block size is " + blockSize);
				return i;
			}
			
		}
		
		outBuffer.reset();
		
		return 0;
	}

	
	public int encrypt(byte[] origin,ByteBuffer outBuffer) {
		return encrypt(origin,0,origin.length,outBuffer);
	}
	
	public int decrypt(byte[] code,ByteBuffer outBuffer) {
		return decrypt(code, 0, code.length,outBuffer);
	}
	
	public ICoder getCoder(byte code) {
		if(CODER.BEGIN<code&&code<CODER.END) {
			if(mCoders[code] == null) {
				switch(code) {
					case CODER.PADDING:{
						mCoders[code] = new PaddingProguarder();
						break;
					}
					case CODER.SHIFT:{
						mCoders[code] = new ShiftProguarder();
						break;
					}
				}
			}
			
			return mCoders[code];
		}
		
		return null;
	}
	
	public int encryptLen(int len) {
		++len;
		if(mCodes != null) {
			for(int i=0;i<mCodes.length; i++) {
				ICoder c = getCoder(mCodes[i]);
				if(c != null) {
					len = c.estimateEncodeLen(len) + 1;
				}
			}
		}
		
		return estimatePackLen(len);
	}
	
	public int decryptLen(int len) {
		return len;
	}
	
	public static final int ERR_NOT_ENOUGH_SPACE = -1;
	public static final int ERR_NOT_COMPLETE 	= -2;
	
	
	public static final class CODER{
		public static final byte BEGIN = 0;
		
		public static final byte PADDING =1;
		public static final byte SHIFT = 2;
		
		
		public static final byte END = 3;
	}
	
}
