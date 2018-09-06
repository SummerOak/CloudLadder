package com.chedifier.ladder.socks5;

import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;

import com.chedifier.ladder.base.ExceptionHandler;
import com.chedifier.ladder.base.Log;
import com.chedifier.ladder.base.StringUtils;
import com.chedifier.ladder.cipher.Cipher;
import com.chedifier.ladder.iface.Error;
import com.chedifier.ladder.iface.SProxyIface;
import com.chedifier.ladder.memory.ByteBufferPool;

public class S5ConnStage extends AbsS5Stage{
	private ConnInfo mConnInfo = new ConnInfo();
	private Cipher mCipher = new Cipher();
	public S5ConnStage(AbsS5Stage stage) {
		super(stage);
		
	}
	
	@Override
	public void start() {
		Log.d(getTag(), "S5ConnStage start>>>");
		super.start();
		
		notifyState(SProxyIface.STATE.CONN);
	}

	@Override
	public AbsS5Stage next() {
		return new S5TransStage(this);
	}
	
	@Override
	public void onSourceOpts(int opts) {
		Log.d(getTag(), "onSourceOpts " + opts + " " + isLocal());
		if((opts&SelectionKey.OP_READ) > 0) {
			ByteBuffer buffer = getChannel().getSrcInBuffer();
			if(isLocal()) {
				Log.i(getTag(),"recv conn info: " + StringUtils.toRawString(buffer.array(), buffer.position()));
				int result = buildConnInfo(mConnInfo,buffer.array(), 0, buffer.position());
				if(result > 0){
					Log.d(getTag(), "recv conn info success. " + mConnInfo);
					notifyConnInfo();
					if((mConnInfo.connCmd&0xFF) != ConnInfo.CONN_CMD_TCP_STREAM 
							&& (mConnInfo.connCmd&0xFF) != ConnInfo.CONN_CMD_TCP_BIND 
							&& (mConnInfo.connCmd&0xFF) != ConnInfo.CONN_CMD_UDP) {
						Log.e(getTag(), "wrong connect command: " + mConnInfo.connCmd);
						notifyError(Error.E_S5_SOCKET_ERROR_CONN);
						return;
					}
					
					int estLen = mCipher.encryptLen(buffer.position());
					ByteBuffer outBuffer = ByteBufferPool.obtain(estLen);
					if(outBuffer != null && outBuffer.remaining() >= estLen) {
						if(mCipher.encrypt(buffer.array(), 0, buffer.position(),outBuffer) > 0) {
							outBuffer.flip();
							int l = outBuffer.remaining();
							if(getChannel().writeToBuffer(true, outBuffer) == l) {
								buffer.clear();
							}else {
								Log.e(getTag(), "send conn info to server failed.");
							}
						}else {
							Log.e(getTag(), "encrypt data failed.");
						}
					}else {
						Log.e(getTag(), "obtain out buffer for encrypt failed.");
					}
					ByteBufferPool.recycle(outBuffer);
				}else {
					Log.e(getTag(), "build conn info failed.");
					notifyError(Error.E_S5_CONN_BUILD_CONN_INFO_FAILED);
					return;
				}
			}else {
				Log.d(getTag(), "decrypt buffer: " + StringUtils.toRawString(buffer.array(),0,buffer.position()));
				ByteBuffer outBuffer = ByteBufferPool.obtain(mCipher.decryptLen(buffer.position()));
				if(outBuffer == null) {
					Log.e(getTag(), "obtain outBuffer failed");
					return ;
				}
				int dl = mCipher.decrypt(buffer.array(), 0, buffer.position(),outBuffer);
				if(dl > 0) {
					Log.i(getTag(),"recv conn info: " + StringUtils.toRawString(outBuffer.array(),0,outBuffer.position()));
					int buildConnInfoResult = buildConnInfo(mConnInfo,outBuffer.array(), 0, outBuffer.position());
					if(buildConnInfoResult > 0) {
						notifyConnInfo();
						Log.r(getTag(), "build conn info success. " + mConnInfo);
						InetSocketAddress remoteAddr = buildRemoteAddress(mConnInfo);
						Log.d(getTag(), "build remote address: " + remoteAddr);
						if(remoteAddr != null) {
							
							Log.d(getTag(), "bind to remote " + remoteAddr);
							boolean succ = false;
							if(mConnInfo.connCmd == ConnInfo.CONN_CMD_TCP_STREAM || mConnInfo.connCmd == ConnInfo.CONN_CMD_TCP_BIND) {
								SocketChannel tcpChannel = bindTCPServer(remoteAddr);
								if(tcpChannel != null) {
									getChannel().setDest(tcpChannel);
									succ = true;
								}
							}else if(mConnInfo.connCmd == ConnInfo.CONN_CMD_UDP){
								DatagramChannel udpChannel = bindUDPServer(remoteAddr);
								if(udpChannel != null) {
									getChannel().setDest(udpChannel);
									succ = true;
								}
							}
							
							Log.d(getTag(), "bind to remote return " + succ);
							if(succ) {
								mConnInfo.netAddr = remoteAddr;
								ByteBuffer rep = ByteBufferPool.obtain(256);
								byte addrType = mConnInfo.addrInfo.addrtp;
								rep.put(new byte[]{0x05,0x00,0x00,addrType});
								if(addrType == 0x03) {									
									rep.put((byte)(mConnInfo.addrInfo.addr.length&0xFF));
								}
								rep.put(mConnInfo.addrInfo.addr);
								rep.put(mConnInfo.addrInfo._port);
								
								int estLen = mCipher.encryptLen(rep.position());
								ByteBuffer outResult  = ByteBufferPool.obtain(estLen);
								if(outResult != null && outResult.remaining() >= estLen) {
									int el = mCipher.encrypt(rep.array(),0,rep.position(),outResult);
									if(el > 0) {
										outResult.flip();
										int l = outResult.remaining();
										if(getChannel().writeToBuffer(false, outResult) == l) {
											getChannel().cutBuffer(buffer, dl);
											forward();
										}else {
											Log.e(getTag(), "send conn feedback to local failed.");
										}
									}else {
										Log.e(getTag(),"decrypt failed.");
									}
									
								}else {
									Log.e(getTag(), "obtain out buffer for encrypt failed");
								}
								ByteBufferPool.recycle(outResult);
								ByteBufferPool.recycle(rep);
							}else {
								Log.e(getTag(), "bind remote failed: " + remoteAddr);
								notifyError(Error.E_S5_CONN_BIND_REMOTE);
							}
						}else {
							Log.e(getTag(), "receive wrong connect request.");
							notifyError(Error.E_S5_CONN_BIND_REMOTE);
						}
					}else if(buildConnInfoResult < 0) {
						Log.e(getTag(), "build conn info failed.");
						notifyError(Error.E_S5_CONN_BUILD_CONN_INFO_FAILED);
					}
				}
				
				ByteBufferPool.recycle(outBuffer);
			}
			
			return;
		}
		
//		Log.e(getTag(), "unexpected opts " + opts + " from src.");
	}
	
	private InetSocketAddress buildRemoteAddress(ConnInfo connInfo) {
		byte[] addr = connInfo.addrInfo.addr;
		int port = connInfo.addrInfo.port;
		if(port<0 || port > 65536) {
			Log.e(getTag(), "invalidate port " + port);
			return null;
		}
		InetSocketAddress netAddr = null;
		if(connInfo.addrInfo.addrtp == 0x03) {
			netAddr = new InetSocketAddress(StringUtils.toString(addr, addr.length), port);
		}else {
			try {
				netAddr = new InetSocketAddress(InetAddress.getByAddress(addr), port);
			} catch (Throwable e) {
				ExceptionHandler.handleException(e);
			}
		}
		return netAddr;
	}

	@Override
	public void onDestOpts(int opts) {
		if(isLocal()) {
			if((opts&SelectionKey.OP_READ) > 0) {
				ByteBuffer buffer = getChannel().getDestInBuffer();
				Log.i(getTag(),"recv conn from server: " + StringUtils.toRawString(buffer.array(), buffer.position()));
				ByteBuffer outBuffer = ByteBufferPool.obtain(mCipher.decryptLen(buffer.position()));
				if(outBuffer != null) {
					int dl = mCipher.decrypt(buffer.array(), 0, buffer.position(),outBuffer);
					if(dl > 0) {
						outBuffer.flip();
						int ll = outBuffer.remaining();
						if(getChannel().writeToBuffer(false, outBuffer) == ll) {
							getChannel().cutBuffer(buffer, dl);
							
							forward();
						}else {
							Log.e(getTag(), "write conn info to client failed");
						}
					}
				}else {
					Log.e(getTag(), "obtain out buffer for decrypt failed.");
				}
				
				ByteBufferPool.recycle(outBuffer);
				
				return;
			}
			
		}
		
//		Log.e(getTag(), "unexpected opts " + opts + " from src.");
	}
	
	@Override
	public void onSocketBroken(Error result) {
		notifyError(result);
	}

	private SocketChannel bindTCPServer(InetSocketAddress netAddr) {
		
		try {
			SocketChannel server = SocketChannel.open();
			server.configureBlocking(false);
			server.connect(netAddr);
			return server;
		} catch (Throwable e) {
			ExceptionHandler.handleException(e);
		}

		return null;
	}
	
	private DatagramChannel bindUDPServer(InetSocketAddress netAddr) {
		try {
			DatagramChannel channel = DatagramChannel.open();
			SocketAddress address = new InetSocketAddress(0);
			DatagramSocket socket = channel.socket();
		    socket.setSoTimeout(5000);
		    socket.bind(address);
		    channel.connect(netAddr);
		    return channel;
		} catch (Throwable e) {
			ExceptionHandler.handleException(e);
		}
		
		return null;
	}
	
	private int buildConnInfo(ConnInfo connInfo,byte[] data,int offset,int len) {
		int p = offset;
		
		p += 4;
		if(len > p) {
			if((data[0]&0xFF) != 0x05) {
				Log.e(getTag(), "not socks5 protocal");
				return -1;
			}
			
			AddrInfo addrInfo = null;
			
			byte connCmd = data[1];
			byte addrType = data[3];
			switch(addrType) {
				case ConnInfo.ADDR_IPV4:{
					if((len-p) == 4 + 2) {
						addrInfo = new AddrInfo();
						addrInfo.addrtp = 0x01;
						addrInfo.addr = new byte[4];
						
						System.arraycopy(data, 4, addrInfo.addr, 0, 4);
						p += 4;
						break;
					}
					return 0;
				}
				case ConnInfo.ADDR_DOMAIN:{
					if((len-p) > 1) {
						int domainL = data[p];
						p += 1;
						
						if((len-p) == domainL+2) {
							addrInfo = new AddrInfo();
							addrInfo.addrtp = 0x03;
							addrInfo.addr = new byte[domainL];
							System.arraycopy(data, p, addrInfo.addr, 0, domainL);
							p += domainL;
							break;
						}
					}
					
					return 0;
				}
				case ConnInfo.ADDR_IPV6:{
					if((len-p) == 6 + 2) {
						addrInfo = new AddrInfo();
						addrInfo.addrtp = 0x04;
						addrInfo.addr = new byte[6];
						
						System.arraycopy(data, 6, addrInfo.addr, 0, 6);
						p += 6;
						break;
					}
					return 0;
				}
				
				default:{
					Log.e(getTag(), "not supported address type: " + addrType);
					return -1;
				}
					
			}
			
			if(addrInfo != null && len == (p+2)) {
				byte[] _port = new byte[2];
				_port[0] = data[p];_port[1] = data[p+1];
				addrInfo._port = _port;
				addrInfo.port = ((data[p]&0xFF) << 8) | (data[p+1] & 0xFF);
				mConnInfo.addrInfo = addrInfo;
				mConnInfo.connCmd = connCmd;
				
				return 1;
			}
		}
		
		return 0;
	}
	
	private void notifyConnInfo() {
		ICallback callback = getCallback();
		if(callback != null && mConnInfo != null) {
			String domain = "";
			String ip = "";
			int port = 0;
			
			AddrInfo addrInfo = mConnInfo.addrInfo;
			if(addrInfo != null) {
				if(addrInfo.addrtp == ConnInfo.ADDR_DOMAIN) {					
					domain = StringUtils.toString(addrInfo.addr);
				}else {
					ip = StringUtils.bytes2IP(addrInfo.addrtp==1?4:6, addrInfo.addr);
				}
				
				port = mConnInfo.addrInfo.port;
			}
			
			if(mConnInfo.netAddr != null && !mConnInfo.netAddr.isUnresolved()) {
				if(StringUtils.isEmpty(domain)) {
					domain = mConnInfo.netAddr.getHostString();
				}
				
				if(StringUtils.isEmpty(ip) && mConnInfo.netAddr.getAddress() != null) {
					ip = mConnInfo.netAddr.getAddress().getHostAddress();
				}
			}
			callback.onConnInfo(ip, domain, port);
		}
	}

	private final class ConnInfo{
		private byte connCmd;
		private AddrInfo addrInfo;
		private InetSocketAddress netAddr;
		
		public static final int ADDR_DOMAIN 	= 0x03;
		public static final int ADDR_IPV4  	= 0x01;
		public static final int ADDR_IPV6 	= 0x04;
		
		private static final byte CONN_CMD_TCP_STREAM = 0x01;
		private static final byte CONN_CMD_TCP_BIND = 0x02;
		private static final byte CONN_CMD_UDP	= 0x03;
		
		@Override
		public String toString() {
			return "conn: " + (connCmd&0xFF) + " addr " + addrInfo + " resolved: " + netAddr;
		}
	}
	
	private final class AddrInfo{
		
		private byte[] addr;
		private byte addrtp;
		
		private int port;
		private byte[] _port;
		
		@Override
		public String toString() {
			return "ip: " + (addr == null? "null":
					(addrtp!=0x03?StringUtils.toRawString(addr, addr.length):
						StringUtils.toString(addr, addr.length))) + 
					" port " + port;
		}
	}
	
}
