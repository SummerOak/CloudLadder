package com.chedifier.ladder.socks5;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.nio.channels.spi.AbstractSelectableChannel;

import com.chedifier.ladder.base.ExceptionHandler;
import com.chedifier.ladder.base.IOUtils;
import com.chedifier.ladder.base.Log;
import com.chedifier.ladder.base.NetUtils;
import com.chedifier.ladder.base.StringUtils;
import com.chedifier.ladder.cipher.Cipher;
import com.chedifier.ladder.iface.Error;
import com.chedifier.ladder.memory.ByteBufferPool;
import com.chedifier.ladder.socks5.AcceptorWrapper.IAcceptor;

public class SSockChannel implements IAcceptor {

	private int mConnId;
	private SocketChannel mSource;
	private SocketChannel mTCPDest;
	private DatagramChannel mUDPDest;
	
	private Selector mSelector;
	private SelectionKey mSourceKey;
	private SelectionKey mDestKey;
	private byte mConnCmd = 0;
	public static final byte CONN_CMD_TCP = 1;
	public static final byte CONN_CMD_UDP = 2;
	
	private boolean mDestConnected;

	private ByteBuffer mUpStreamBufferIn;
	private ByteBuffer mUpStreamBufferOut;
	private ByteBuffer mDownStreamBufferIn;
	private ByteBuffer mDownStreamBufferOut;
	private Cipher mCipher;

	private long mSrcIn = 0l;
	private long mSrcOut = 0l;
	private long mDestIn = 0l;
	private long mDestOut = 0l;
	
	private final byte MAX_RETRY_FOR_READ = 0;
	private byte mRetryTimesWhileReadNull = 0;
	
	private boolean mAlive = false;
	private long mTimeout = 0L;
	private long mTimeoutLimit = 10*1000L;

	private IChannelEvent mListener;
	private ITrafficEvent mTrafficListener;

	private final int BUFFER_SIZE = Cipher.MAX_PARCEL_SIZE<<2;

	private final String getTag() {
		return "SSockChannel_c" + mConnId;
	}

	public SSockChannel(Selector selector) {
		mSelector = selector;
		
		mDestConnected = false;
		
		mUpStreamBufferIn = ByteBufferPool.obtain(BUFFER_SIZE);
		mUpStreamBufferOut = ByteBufferPool.obtain(BUFFER_SIZE);
		mDownStreamBufferIn = ByteBufferPool.obtain(BUFFER_SIZE);
		mDownStreamBufferOut = ByteBufferPool.obtain(BUFFER_SIZE);
		mCipher = new Cipher();
		
		mAlive = true;
	}

	public void setListener(IChannelEvent l) {
		mListener = l;
	}

	public void setTrafficListener(ITrafficEvent l) {
		mTrafficListener = l;
	}

	public void setConnId(int id) {
		mConnId = id;
	}

	public int getConnId() {
		return mConnId;
	}
	
	public void setTimeout(long timeout) {
		mTimeoutLimit = timeout;
	}
	
	public byte getConnType() {
		return mConnCmd;
	}

	public void setDest(SocketChannel socket) {
		Log.i(getTag(), "setDest " + socket + "  " + mTCPDest);
		if (!mAlive) {
			Log.e(getTag(), "setDest>>> channel has died.");
			return;
		}
		
		if (mConnCmd == 0 && mTCPDest == null && socket != null) {
			mTCPDest = socket;
			try {
				mTCPDest.configureBlocking(false);
			} catch (IOException e) {
				Log.i(getTag(), "configureBlocking failed " + e.getMessage());
				ExceptionHandler.handleException(e);
			}
			
			updateOps(false, true, SelectionKey.OP_CONNECT);
			mConnCmd = CONN_CMD_TCP;

			return;
		}

		Log.e(getTag(), "dest socket already setted,can not be set dumplicated.");
	}
	
	public void setDest(DatagramChannel udpChannel) {
		Log.i(getTag(), "setDest " + udpChannel + "  " + mUDPDest);
		if (!mAlive) {
			Log.e(getTag(), "setDest>>> channel has died.");
			return;
		}

		if (mConnCmd == 0 && mUDPDest == null && udpChannel != null) {
			mUDPDest = udpChannel;
			try {
				mUDPDest.configureBlocking(false);
			} catch (IOException e) {
				Log.i(getTag(), "configureBlocking failed " + e.getMessage());
				ExceptionHandler.handleException(e);
			}
			
			updateOps(false, true, SelectionKey.OP_READ);
			mConnCmd = CONN_CMD_UDP;
			
			return;
		}

		Log.e(getTag(), "dest socket already setted,can not be set dumplicated.");
	}

	public void setSource(SocketChannel socket) {
		if (!mAlive) {
			Log.e(getTag(), "setDest>>> channel has died.");
			return;
		}

		if (mSource == null && socket != null) {
			mSource = socket;
			try {
				mSource.configureBlocking(false);
			} catch (IOException e) {
				ExceptionHandler.handleException(e);
			}
			return;
		}

		Log.e(getTag(), "src  socket already setted,can not be set dumplicated.");
	}

	public int relay(boolean up, boolean encrypt) {
		if (!mAlive) {
			Log.e(getTag(), "relay failed, channel has died.");
			return -1;
		}

		ByteBuffer from = up ? mUpStreamBufferIn : mDownStreamBufferIn;
		ByteBuffer to = up ? mUpStreamBufferOut : mDownStreamBufferOut;
		
		int r = encrypt ? encryptRelay(from, to) : decryptRelay(from, to);
		if (to.position() > 0) {
			updateOps(!up, true, SelectionKey.OP_WRITE);
		}
		
		if (r <= 0 && to.remaining() <= 0) {
			Log.e(getTag(), "relay to " + (up?" remote":"local") + ">>> out buffer is full filled. pause reading in.");
			updateOps(up, false, SelectionKey.OP_READ);
		}
		
		return r;
	}

	public int writeToBuffer(boolean up, ByteBuffer data) {
		if (!mAlive) {
			Log.e(getTag(), "write>>> channel has died.");
			return -1;
		}

		int w = 0;
		if (data != null && data.remaining() > 0) {
			ByteBuffer buffer = up ? mUpStreamBufferOut : mDownStreamBufferOut;
			int r = data.remaining();
			if (buffer.remaining() >= data.remaining()) {
				try {
					buffer.put(data);
					w = r;
					updateOps(!up, true, SelectionKey.OP_WRITE);
				}catch(Exception e) {
					ExceptionHandler.handleException(e);
				}
			} else {
				Log.e(getTag(), "writeToBuffer" + up + ">>> out buffer is full filled,need " + r + " remain "
						+ buffer.remaining() + " pause data read in.");
				updateOps(up,false,SelectionKey.OP_READ);
			}
		}

		return w;
	}

	/**
	 * encrypt data in src and relay to dest.
	 * 
	 * @param src
	 *            : the source data need be encrypted and relayed to dest.
	 * @param dest:
	 *            the destnation where data in src need be encrypted and relayed to.
	 * @return the bytes be relayed of src, possibile 0 if nothing be relayed or -1
	 *         if dest buffer is full filled.
	 */
	private int encryptRelay(ByteBuffer src, ByteBuffer dest) {
		if (src.position() <= 0) {
			Log.d(getTag(), "encryptRelay>>> not data in src,nothing need to relay.");
			return 0;
		}

		int len = src.position();
		int r = 0;
		ByteBuffer outBuffer = ByteBufferPool.obtain(mCipher.encryptLen(len));
		try {
			while(true) {
				if(len <= 0) {
					break;
				}
				
				int estl = mCipher.encryptLen(len);
				if(estl > dest.remaining()) {
					Log.e(getTag(), "encryptRelay>>> out buffer may be full filled: need " + estl + " remain " + dest.remaining());
					notifyRelayFailed(Error.E_S5_OUT_BUFFER_FULL_FILLED);
					break;
				}
				
				int el = mCipher.encrypt(src.array(), r, len,outBuffer);
				if (el > 0) {
					outBuffer.flip();
					int ll = outBuffer.remaining();
					if(dest.remaining() >= ll) {
						try {
							dest.put(outBuffer);
							outBuffer.clear();
							r += el;
							len -= el;
							
						}catch(Exception e) {
							ExceptionHandler.handleException(e);
							break;
						}
						
					}else {
						Log.e(getTag(), "encryptRelay>>> out buffer is full filled: need " + ll + " remain " + dest.remaining());
						notifyRelayFailed(Error.E_S5_OUT_BUFFER_FULL_FILLED);
						break;
					}
				}else {
					Log.e(getTag(), "encryptRelay>>> encrypt data failed.");
					notifyRelayFailed(Error.E_S5_RELAY_ENCRYPT_FAILED);
					break;
				}
			}
		}finally {
			ByteBufferPool.recycle(outBuffer);
		}
		
		if(r > 0) {
			cutBuffer(src, r);
		}
		
		return r;
	}

	/**
	 * decrypt data in src and relay to dest.
	 * 
	 * @param src
	 *            : the source data need be decrypted and relayed to dest.
	 * @param dest:
	 *            the destnation where data in src need be decrypted and relayed to.
	 * @return the bytes be relayed, possibile 0 if nothing be relayed or -1 if dest
	 *         buffer is full filled.
	 */
	private int decryptRelay(ByteBuffer src, ByteBuffer dest) {
		if (src.position() <= 0) {
			Log.d(getTag(), "decryptRelay>>> no data in src,nothing need to relay.");
			return 0;
		}

		int len = src.position();
		ByteBuffer decOutBuffer = ByteBufferPool.obtain(mCipher.decryptLen(len));
		int  r = 0;
		try {
			while(true) {
				if(len <= 0) {
					break;
				}
				
				if(dest.remaining() < Cipher.MAX_PARCEL_SIZE) {
					Log.e(getTag(), "decryptRelay>>> out buffer maybe full filled,need " + Cipher.MAX_PARCEL_SIZE + " remain " + dest.remaining());
					notifyRelayFailed(Error.E_S5_OUT_BUFFER_FULL_FILLED);
					break;
				}
				
				int dl = mCipher.decrypt(src.array(), r, len,decOutBuffer);
				if (dl > 0) {
					decOutBuffer.flip();
					final int ll = decOutBuffer.remaining();
					if (dest.remaining() >= ll) {
						dest.put(decOutBuffer);
						decOutBuffer.clear();
						r += dl;
						len -= dl;
					} else {
						Log.e(getTag(), "decryptRelay>>> out buffer is full filled,need " + ll + " remain " + dest.remaining());
						notifyRelayFailed(Error.E_S5_OUT_BUFFER_FULL_FILLED);
						break;
					}
				} else {
					Log.d(getTag(), "decryptRelay>>> decrypt packs failed.");
					notifyRelayFailed(Error.E_S5_RELAY_DECRYPT_FAILED);
					break;
				}
			}
		}finally {
			ByteBufferPool.recycle(decOutBuffer);
		}
		
		if(r > 0) {
			cutBuffer(src, r);
		}

		return r;
	}

	public int cutBuffer(ByteBuffer buffer, int len) {
		if (buffer != null && buffer.position() >= len) {
			Log.i(getTag(), "before cut " + len + " : " + buffer.position());
			buffer.flip();
			buffer.position(len);
			buffer.compact();
			Log.i(getTag(), "after cut " + len + " : " + buffer.position());
			return len;
		}

		return 0;
	}

	public ByteBuffer getSrcInBuffer() {
		return mUpStreamBufferIn;
	}

	public ByteBuffer getDestInBuffer() {
		return mDownStreamBufferIn;
	}

	public ByteBuffer getSrcOutBuffer() {
		return mUpStreamBufferOut;
	}

	public ByteBuffer getDestOutBuffer() {
		return mDownStreamBufferOut;
	}

	private SelectionKey registerOpts(AbstractSelectableChannel socketChannel, int ops) {
		if (socketChannel != null) {
			try {
				SelectionKey selKey = socketChannel.register(mSelector, ops);
				selKey.attach(this);
				return selKey;
			} catch (Throwable e) {
				ExceptionHandler.handleException(e);
			}
		}

		return null;
	}

	public void updateOps(boolean src, boolean add, int opts) {
		Log.i(getTag(), "updateOps " + (add?"enable ":"disable ") + (src?" src " :" dest ") + opts + ": " + NetUtils.getOpsDesc(opts));
		SelectionKey key = src ? mSourceKey : mDestKey;
		if (key != null && !key.isValid()) {
			return;
		}
		
		if(key != null) {
			int oldOps = key.interestOps();
			opts = add ? (opts | oldOps) : (oldOps & (~opts));
		}

		if (src) {
			if(mSourceKey != null && mSourceKey.isValid()) {				
				mSourceKey.interestOps(opts);
			}else {				
				mSourceKey = registerOpts(mSource, opts);
			}
		} else {
			if(mDestKey != null && mDestKey.isValid()) {
				mDestKey.interestOps(opts);
			}else {				
				mDestKey = registerOpts(mTCPDest==null?mUDPDest:mTCPDest, opts);
			}
		}
		
		notifyIntrestOpsUpdate(src);
	}
	
	private boolean hasOps(SelectionKey key,int intres) {
		return (key != null && key.isValid() && (key.interestOps()&intres) > 0);
	}
	
	private boolean checkAlive() {
		if(!mAlive) {
			return false;
		}
		
		if(mDestKey != null && (!mDestKey.isValid() || mDestKey.interestOps() == 0) 
				&& mDownStreamBufferIn.position() <= 0
				&& mDownStreamBufferOut.position() <= 0) {
			return false;
		}
		
		if(mSourceKey != null && (!mSourceKey.isValid() || mSourceKey.interestOps() == 0) 
				&& mUpStreamBufferIn.position() <= 0
				&& mUpStreamBufferOut.position() <= 0) {
			return false;
		}
		
		return true;
	}

	public synchronized void destroy() {
		Log.r(getTag(), "total>>> src>" + mSrcIn + ",src<" + mSrcOut + ",dest>" + mDestIn + ",dest<" + mDestOut);
		Log.r(getTag(), "mUpStreamBufferIn "+ mUpStreamBufferIn 
				+ " mDownStreamBufferIn " + mDownStreamBufferIn 
				+ " mUpStreamBufferOut " + mUpStreamBufferOut 
				+ " mDownStreamBufferOut " + mDownStreamBufferOut);
		
		mAlive = false;
		if (mDestKey != null) {
			mDestKey.cancel();
			mDestKey = null;
		}

		if (mSourceKey != null) {
			mSourceKey.cancel();
			mSourceKey = null;
		}

		IOUtils.safeClose(mTCPDest);
		IOUtils.safeClose(mUDPDest);
		IOUtils.safeClose(mSource);
		mTCPDest = mSource = null; mUDPDest = null;
		mConnId = -1;
		
		if (mUpStreamBufferIn != null) {
			ByteBufferPool.recycle(mUpStreamBufferIn);
			mUpStreamBufferIn = null;
		}
		if (mDownStreamBufferIn != null) {
			ByteBufferPool.recycle(mDownStreamBufferIn);
			mDownStreamBufferIn = null;
		}

		if (mUpStreamBufferOut != null) {
			ByteBufferPool.recycle(mUpStreamBufferOut);
			mUpStreamBufferOut = null;
		}

		if (mDownStreamBufferOut != null) {
			ByteBufferPool.recycle(mDownStreamBufferOut);
			mDownStreamBufferOut = null;
		}
	}

	private int read(SocketChannel socketChannel, ByteBuffer buffer) {
		try {
			Log.d(getTag(), "pre read,buffer remain " + buffer.remaining());
			int r = socketChannel.read(buffer);
			Log.d(getTag(), "read " + r + " bytes,total " + buffer.position());
			Log.i(getTag(), "read content: " + StringUtils.toRawString(buffer.array(), buffer.position() - r, r));
			return r;
		} catch (Throwable e) {
			Log.e(getTag(), "read socket channel failed. " + e.getMessage());
			ExceptionHandler.handleException(e);
		}

		return -1;
	}
	
	private int read(DatagramChannel socketChannel, ByteBuffer buffer) {
		try {
			Log.d(getTag(), "pre read,buffer remain " + buffer.remaining());
			int r = socketChannel.read(buffer);
			Log.d(getTag(), "read " + r + " bytes,total " + buffer.position());
			Log.i(getTag(), "read content: " + StringUtils.toRawString(buffer.array(), buffer.position() - r, r));
			return r;
		} catch (Throwable e) {
			Log.e(getTag(), "read socket channel failed. " + e.getMessage());
			ExceptionHandler.handleException(e);
		}

		return -1;
	}

	private int write(SocketChannel socketChannel, ByteBuffer buffer) {
		try {
			buffer.flip();
			int w = socketChannel.write(buffer);

			Log.d(getTag(), "write " + w + " bytes,remain " + buffer.remaining());
			Log.i(getTag(), "write content: " + StringUtils.toRawString(buffer.array(), 0, w));

			buffer.compact();
			return w;
		} catch (Throwable e) {
			Log.e(getTag(), "write socket channel failed." + e.getMessage());
			ExceptionHandler.handleException(e);
		}

		return -1;
	}
	
	private int write(DatagramChannel socketChannel, ByteBuffer buffer) {
		try {
			buffer.flip();
			int w = socketChannel.write(buffer);

			Log.d(getTag(), "write " + w + " bytes,remain " + buffer.remaining());
			Log.i(getTag(), "write content: " + StringUtils.toRawString(buffer.array(), 0, w));

			buffer.compact();
			return w;
		} catch (Throwable e) {
			Log.e(getTag(), "write socket channel failed." + e.getMessage());
			ExceptionHandler.handleException(e);
		}

		return -1;
	}
	
	@Override
	public void onPeriodicCheck(long timeout) {
		mTimeout += timeout;
		if(mTimeout >= mTimeoutLimit) {
			Log.e(getTag(), "timeout, close channel");
			this.notifySocketClosed(Error.E_S5_SOCKETCHANNEL_ZOMBIE);
		}
	}

	@Override
	public synchronized Error accept(SelectionKey selKey, int opts) {
		if (!mAlive || !selKey.isValid()) {
			Log.e(getTag(), "accept>>> channel has died.");
			return null;
		}
		
		mTimeout = 0;

		if (selKey == mSourceKey) {
			if (selKey.isValid() && selKey.isReadable()) {
				Log.d(getTag(), "src recv OP_READ");
				int r = read(mSource, mUpStreamBufferIn);
				if (r <= 0) {
					if(++mRetryTimesWhileReadNull > MAX_RETRY_FOR_READ) {
						Log.d(getTag(), "read data in src failed." + r + " block read in.");
						mSourceKey.cancel();
//						updateOps(true, false, SelectionKey.OP_READ);
					}else {
						updateOps(true, false, SelectionKey.OP_READ);
					}
				} else {
					Log.d(getTag(), "read frome src " + r + "bytes");
					mRetryTimesWhileReadNull = 0;
					onSrcIn(r);
				}
			}

			if (selKey.isValid() && selKey.isWritable()) {
				Log.d(getTag(), "src recv OP_WRITE");
				if (mDownStreamBufferOut != null && mDownStreamBufferOut.position() > 0) {
					int w = write(mSource, mDownStreamBufferOut);

					if (w > 0) {
						if (mDownStreamBufferOut.remaining() > (BUFFER_SIZE >> 1)
								&& (mConnCmd == CONN_CMD_TCP && mDestConnected && mTCPDest != null || (mConnCmd == CONN_CMD_UDP && mUDPDest != null)) 
								&& mDestKey != null && !hasOps(mDestKey, SelectionKey.OP_READ)) {
							Log.d(getTag(), "out buffer has enough remaining, open dest read in.");
							updateOps(false, true, SelectionKey.OP_READ);
						}

						onSrcOut(w);
					}else {
						Log.d(getTag(), "write to src failed," + w + " pause src write.");
						updateOps(true, false, SelectionKey.OP_WRITE);
					}
				}

				if (mDownStreamBufferOut == null || mDownStreamBufferOut.position() <= 0) {
					updateOps(true, false, SelectionKey.OP_WRITE);
				}
			}
			
			if(selKey.isValid()) {				
				notifySourceOps(opts);
			}

		} else if (selKey == mDestKey) {

			if (mConnCmd == CONN_CMD_TCP && selKey.isValid() && selKey.isConnectable()) {
				Log.i(getTag(), "dest receive connect ops.");
				try {
					if(mTCPDest != null && !mTCPDest.finishConnect()) {
						Log.e(getTag(), "finish connect failed.");
						notifySocketClosed(Error.E_S5_BIND_PROXY_FAILED);
						return null;
					}else {
						updateOps(false, false, SelectionKey.OP_CONNECT);
						updateOps(false, true, SelectionKey.OP_READ|SelectionKey.OP_WRITE);
						mDestConnected = true;
						Log.r(getTag(), "bind proxy success!");
					}
				} catch (Throwable e) {
					ExceptionHandler.handleException(e);
					Log.e(getTag(), "conn to proxy failed");
					notifySocketClosed(Error.E_S5_BIND_PROXY_FAILED);
					return null;
				}
			}

			if (selKey.isValid() && selKey.isReadable()) {
				Log.d(getTag(), "recv dest OP_READ");
				int r = 0;
				if(mConnCmd == CONN_CMD_TCP && mTCPDest != null) {
					r = read(mTCPDest, mDownStreamBufferIn);
				}else if(mConnCmd == CONN_CMD_UDP && mUDPDest != null){
					r = read(mUDPDest, mDownStreamBufferIn);
				}
				if (r <= 0) {
					if(++mRetryTimesWhileReadNull > MAX_RETRY_FOR_READ) {
						Log.d(getTag(), "read from dest failed," + r + " pause dest read.");
						mDestKey.cancel();
//						updateOps(false, false, SelectionKey.OP_READ);
					}else {
						updateOps(false, false, SelectionKey.OP_READ);
					}
				} else {	
					Log.d(getTag(), "read frome dest " + r + "bytes");
					mRetryTimesWhileReadNull = 0;
					onDestIn(r);
				}
			}

			if (selKey.isValid() && selKey.isWritable()) {// dest channel is writable now, lets check if anything need be relay
				Log.d(getTag(), "recv dest OP_WRITE");
				if (mUpStreamBufferOut != null && mUpStreamBufferOut.position() > 0) {
					int w = 0;
					if(mConnCmd == CONN_CMD_TCP && mTCPDest != null) {
						w = write(mTCPDest, mUpStreamBufferOut);
					}else if(mConnCmd == CONN_CMD_UDP && mUDPDest != null){
						w = write(mUDPDest, mUpStreamBufferOut);
					}
					if (w > 0) {
						if (mUpStreamBufferOut.remaining() > (BUFFER_SIZE >> 1) 
								&& mSource != null && mSourceKey != null && !hasOps(mSourceKey, SelectionKey.OP_READ)) {
							Log.d(getTag(), "out buffer has enough remaining, open src read in.");
							updateOps(true, true, SelectionKey.OP_READ);
						}

						onDestOut(w);
					}else {
						Log.d(getTag(), "write to dest failed," + w + " pause dest write.");
						updateOps(false, false, SelectionKey.OP_WRITE);
					}
				}

				if (mUpStreamBufferOut == null || mUpStreamBufferOut.position() <= 0) {// all data have been send,shutdown write event
					updateOps(false, false, SelectionKey.OP_WRITE);
				}
			}

			if(selKey.isValid()) {				
				notifyDestOps(opts);
			}
		}
		
		if(!checkAlive()) {
			Log.d(getTag(), "socket has died,channel will closed.");
			notifySocketClosed(Error.E_S5_CHANNEL_DEAD);
		}

		return null;
	}

	private void onSrcIn(int len) {
		mSrcIn += len;
		if(mTrafficListener != null) {
			mTrafficListener.onSrcIn(len,mSrcIn);
		}
	}

	private void onSrcOut(int len) {
		mSrcOut += len;
		if(mTrafficListener != null) {
			mTrafficListener.onSrcOut(len,mSrcOut);
		}
	}

	private void onDestIn(int len) {
		mDestIn += len;
		if(mTrafficListener != null) {
			mTrafficListener.onDestIn(len,mDestIn);
		}
	}

	private void onDestOut(int len) {
		mDestOut += len;
		if(mTrafficListener != null) {
			mTrafficListener.onDestOut(len,mDestOut);
		}
	}

	private void notifySourceOps(int ops) {
		if (mAlive && mListener != null) {
			mListener.onSourceOpts(ops);
		}
	}

	private void notifyDestOps(int ops) {
		if (mAlive && mListener != null) {
			mListener.onDestOpts(ops);
		}
	}

	private void notifySocketClosed(Error result) {
		if (mAlive && mListener != null) {
			mListener.onSocketBroken(result);
		}
	}

	private void notifyRelayFailed(Error result) {
		if (mAlive && mListener != null) {
			mListener.onRelayFailed(result);
		}
	}
	
	private void notifyIntrestOpsUpdate(boolean src) {
		
		if(mAlive && mListener != null) {
			if(src && mSourceKey != null) {
				int ops = mSourceKey.interestOps();
				Log.d(getTag(), "notifyIntrestOpsUpdate source " + ops);
				mListener.onSrcOpsUpdate(ops);
			}else if(!src && mDestKey != null){	
				int ops = mDestKey.interestOps();
				Log.d(getTag(), "notifyIntrestOpsUpdate dest " + ops);
				mListener.onDestOpsUpdate(ops);
			}
		}
	}

	public static interface IChannelEvent {

		void onSourceOpts(int opts);

		void onDestOpts(int opts);

		void onSocketBroken(Error result);

		void onRelayFailed(Error result);
		
		void onSrcOpsUpdate(int ops);
		
		void onDestOpsUpdate(int ops);
	}

	public static interface ITrafficEvent {
		void onSrcIn(int len,long total);

		void onSrcOut(int len,long total);

		void onDestIn(int len,long total);

		void onDestOut(int len,long total);
		
	}

}
