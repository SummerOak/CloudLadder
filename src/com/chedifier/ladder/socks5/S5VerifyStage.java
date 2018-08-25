package com.chedifier.ladder.socks5;

import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;

import com.chedifier.ladder.base.Log;
import com.chedifier.ladder.base.StringUtils;
import com.chedifier.ladder.cipher.Cipher;
import com.chedifier.ladder.iface.Error;
import com.chedifier.ladder.iface.SProxyIface;
import com.chedifier.ladder.memory.ByteBufferPool;

public class S5VerifyStage extends AbsS5Stage{
	
	private Cipher mCipher = new Cipher();
	
	public S5VerifyStage(AbsS5Stage stage) {
		super(stage);
	}
	
	public S5VerifyStage(SSockChannel channel,boolean isLocal,ICallback callback) {
		super(channel,isLocal,callback);
	}
	
	@Override
	public void start() {
		Log.r(getTag(), "S5VerifyStage start >>>");
		super.start();
		
		getChannel().updateOps(true, true, SelectionKey.OP_READ);
		
		notifyState(SProxyIface.STATE.VERIFY);
	}

	@Override
	public AbsS5Stage next() {
		return new S5ConnStage(this);
	}
	
	private int verify(byte[] data,int offset,int len) {
		if(data != null) {
			if(len > 2) {
				if((data[offset]&0xFF) == (0x05)) {
					int mths = data[offset+1]&0xFF;
					if(mths > 0) {
						if(len == (mths + 2)) {
							return 1;
						}
					}else {
						return -1;
					}
				}else {
					return -1;
				}
			}
		}
		
		return 0;
	}

	@Override
	public void onSourceOpts(int opts) {
		if((opts&SelectionKey.OP_READ) > 0) {
			ByteBuffer buffer = getChannel().getSrcInBuffer();
			int verifyInfoLen = buffer.position();
			if(isLocal()) {
				Log.d(getTag(), "recv verify from client:" + StringUtils.toRawString(buffer.array(),buffer.position()));
				int verifyResult = verify(buffer.array(),0,verifyInfoLen);
				if(verifyResult > 0) {
					Log.d(getTag(), "recv verify success.");
					if(getChannel().relay(true, true) != verifyInfoLen) {
						Log.e(getTag(), "relay verify info to server failed.");
					}
				}else if(verifyResult < 0){
					Log.e(getTag(), "verify socks5 methos failed.");
					notifyError(Error.E_S5_VERIFY_FAILED);
					return;
				}
			}else {
				ByteBuffer decOutBuffer = ByteBufferPool.obtain(mCipher.decryptLen(verifyInfoLen));
				int dl = mCipher.decrypt(buffer.array(), 0, verifyInfoLen,decOutBuffer);
				if(dl > 0) {
					Log.d(getTag(), "recv verify data from local: " + StringUtils.toRawString(decOutBuffer.array(),0,decOutBuffer.position()));
					int verifyResult = verify(decOutBuffer.array(), 0, decOutBuffer.position());
					if(verifyResult > 0) {
						Log.d(getTag(), "verify success.");
						
						ByteBuffer back = ByteBufferPool.obtain(mCipher.encryptLen(2));
						int el = mCipher.encrypt(new byte[] {0x05,0x00},back);
						if(el > 0) {
							back.flip();
							int ll = back.remaining();
							if(getChannel().writeToBuffer(false, back) == ll) {
								getChannel().cutBuffer(buffer, dl);
								forward();
							}else {
								Log.e(getTag(), "send verify msg to remote failed.");
							}
						}
						ByteBufferPool.recycle(back);
					}else if(verifyResult < 0){
						Log.e(getTag(), "verify socks5 methos failed.");
						notifyError(Error.E_S5_VERIFY_FAILED);
						return;
					}
				}
				
				ByteBufferPool.recycle(decOutBuffer);
			}
			
			return;
		}
		
//		Log.e(TAG, "unexpected opts " + opts + " from src.");
	}

	@Override
	public void onDestOpts(int opts) {
		if(isLocal()) {
			if((opts&SelectionKey.OP_READ) > 0) {
				ByteBuffer buffer = getChannel().getDestInBuffer();
				ByteBuffer decOutBuffer = ByteBufferPool.obtain(mCipher.decryptLen(buffer.position()));
				int dl = mCipher.decrypt(buffer.array(), 0, buffer.position(),decOutBuffer);
				if(dl > 0) {
					Log.d(getTag(), "recv verify info back from server: " + StringUtils.toRawString(decOutBuffer.array(),0,decOutBuffer.position()));
					decOutBuffer.flip();
					int ll = decOutBuffer.remaining();
					if(getChannel().writeToBuffer(false, decOutBuffer) == ll) {
						getChannel().cutBuffer(buffer, dl);
						forward();
					}else {
						Log.e(getTag(), "send verify info to server failed.");
					}
				}
				ByteBufferPool.recycle(decOutBuffer);
			}
		}
		
//		Log.e(TAG, "receive unexpected ops." + opts);
	}
	
	@Override
	public void onSocketBroken(Error result) {
		notifyError(result);
	}
	
}
