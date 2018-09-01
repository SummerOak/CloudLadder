package com.chedifier.ladder.socks5;

import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import com.chedifier.ladder.base.DateUtils;
import com.chedifier.ladder.base.ExceptionHandler;
import com.chedifier.ladder.base.IOUtils;
import com.chedifier.ladder.base.Log;
import com.chedifier.ladder.base.ObjectPool;
import com.chedifier.ladder.base.ObjectPool.IConstructor;
import com.chedifier.ladder.base.Timer;
import com.chedifier.ladder.base.TimerTask;
import com.chedifier.ladder.iface.Error;
import com.chedifier.ladder.iface.IProxyListener;
import com.chedifier.ladder.iface.SProxyIface;
import com.chedifier.ladder.memory.ByteBufferPool;
import com.chedifier.ladder.memory.ByteBufferPool.IMemInfoListener;
import com.chedifier.ladder.socks5.AbsS5Stage.ICallback;
import com.chedifier.ladder.socks5.AcceptorWrapper.IAcceptor;
import com.chedifier.ladder.socks5.SSockChannel.ITrafficEvent;

public class SProxy implements IAcceptor,IMemInfoListener{

	private final String TAG;

	private static int sConnectionId;
	
	private final int mPort;
	private Selector mSelector;
	private ServerSocketChannel mSocketChannel = null;
	private boolean mIsLocal;
	
	private boolean mWorking = false;
	private String mProxyHost = null;
	private int mProxyPort;
	private InetSocketAddress mProxyAddress;
	
	private ObjectPool<Relayer> mRelayerPool;
	private static volatile long sMaxConcurrents = 0L;
	private static volatile long sAliveConnections = 0L;
	private static volatile long sMaxConnections = 0L;
	private Set<Relayer> mLivingRelayers = new HashSet<Relayer>();
	private IProxyListener mListener;
	
	private static final String BIRTH_TIME = DateUtils.getCurrentDate();
	public static final String getBirthDay() {
		return BIRTH_TIME;
	}
	
	public static SProxy createLocal(int port,String serverHost,int serverPort) {
		return new SProxy(port,true,serverHost,serverPort,null);
	}
	
	public static SProxy createServer(int port) {
		return new SProxy(port,false,"",0,null);
	}
	
	public static SProxy createLocal(int port,String serverHost,int serverPort,IProxyListener l) {
		return new SProxy(port,true,serverHost,serverPort,l);
	}
	
	public static SProxy createServer(int port,IProxyListener l) {
		return new SProxy(port,false,"",0,l);
	}

	private SProxy(int port,boolean isLocal,String serverHost,int serverPort,IProxyListener l) {
		TAG = "SProxy." + (isLocal?"local":"server");
		mPort = port;
		mIsLocal = isLocal;
		mListener = l;
		
		init();
		
		
		if(isLocal) {
			mProxyHost = serverHost;
			mProxyPort = serverPort;
			mProxyAddress = new InetSocketAddress(serverHost,serverPort);
		}
		
		mRelayerPool = new ObjectPool<Relayer>(new IConstructor<Relayer>() {

			@Override
			public Relayer newInstance(Object... params) {
				return new Relayer((SocketChannel)params[0]);
			}

			@Override
			public void initialize(Relayer e, Object... params) {
				e.init((SocketChannel)params[0]);
			}
		}, 20);
		
	}
	
	private void init() {
		AcceptorWrapper.init();
		ByteBufferPool.addListener(this);
	}
	
	private synchronized int generateConnectionId() {
		return sConnectionId = (++sConnectionId < 0? 0:sConnectionId);
	}

	public void start() {
		try {
			mSelector = Selector.open();
			mSocketChannel = ServerSocketChannel.open();
			mSocketChannel.configureBlocking(false);
			InetSocketAddress addr = new InetSocketAddress(mPort);
			mSocketChannel.bind(addr);
			SelectionKey selKey = mSocketChannel.register(mSelector, SelectionKey.OP_ACCEPT);
			selKey.attach(AcceptorWrapper.wrapper(this));
		}catch (Throwable t) {
			Log.e(TAG, "start failed." + t.getMessage());
			ExceptionHandler.handleException(t);
			IOUtils.safeClose(mSocketChannel);
			Messenger.notifyMessage(mListener, IProxyListener.ERROR, 0,Error.E_LOCAL_SOCKET_BUILD_FAILED);
			return;
		}
		
		mWorking = true;
		Messenger.notifyMessage(mListener, IProxyListener.PROXY_START, mIsLocal,mPort, mProxyHost,mProxyPort);
		
		long lastcheck = System.currentTimeMillis();
		Log.r(TAG, "start success >>> listening " + mPort);
		while(mWorking) {
			long now = System.currentTimeMillis();
			long cost = now;
			
			int sel = 0;
			try {
				Log.d(TAG, "select next ops...");
				final long TIMEOUT = 10*1000L;
				sel = mSelector.select(10*1000);
				
				if(System.currentTimeMillis() - lastcheck > TIMEOUT) {
					Log.d(TAG, "onPeriodicCheck " + TIMEOUT);
					Set<SelectionKey> regKeys = mSelector.keys();
		            Iterator<SelectionKey> it = regKeys.iterator();  
		            while (it.hasNext()) {
		            	SelectionKey key = it.next();
		            	if(key != null && key.attachment() instanceof IAcceptor) {
	            			((IAcceptor)key.attachment()).onPeriodicCheck(TIMEOUT);
	            		}
		            }
		            
		            lastcheck = System.currentTimeMillis();
				}
				
				if(sel == 0) {
					Log.d(TAG, "nothing to do,go next... " + mSelector.selectedKeys().size());
					continue;
				}
				Log.d(TAG, "selected ops: " + sel);
			} catch (Throwable t) {
				ExceptionHandler.handleException(t);
			}
			
			now = System.currentTimeMillis();
			
			Set<SelectionKey> regKeys = mSelector.selectedKeys();
            Iterator<SelectionKey> it = regKeys.iterator();  
            while (it.hasNext()) {
            		SelectionKey key = it.next();
            		it.remove();
            		if(!key.isValid()) {
            			continue;
            		}
            		
            		cost = System.currentTimeMillis();
            		if(key != null && key.attachment() instanceof IAcceptor) {
            			((IAcceptor)key.attachment()).accept(key,key.readyOps());
            		}
            		now = System.currentTimeMillis();
            		cost = now - cost;
//            		Log.t(TAG, "accept cost: "+cost);
            }
		}
		
		stopAllRelayer();
		
		Log.dumpBeforeExit(new Log.ICallback() {
			
			@Override
			public void onDumpFinish() {
				Messenger.notifyMessage(mListener, IProxyListener.PROXY_STOP, mIsLocal);
			}
		});
	}
	
	public void stop(String reason) {
		Log.r(TAG, "proxy is stopping, reason: " + reason);
		
		if(mWorking) {
			mWorking = false;
			
			if(mSelector != null) {			
				mSelector.wakeup();
			}
			
			new Timer().schedule(new TimerTask() {
				
				@Override
				public void run() {
					System.exit(1);
				}
			}, 5000);
		}
		
	}
	
	private void stopAllRelayer() {
		synchronized (mLivingRelayers) {
			Set<Relayer> rs = new HashSet<Relayer>(mLivingRelayers.size());
			rs.addAll(mLivingRelayers);
			
			Iterator<Relayer> itr = rs.iterator();
			while(itr.hasNext()) {
				itr.next().release();
			}
		}
	}
	
	private void incConnection(Relayer r) {
		synchronized (mLivingRelayers) {
			++sMaxConnections;
			++sAliveConnections;
			if(sAliveConnections > sMaxConcurrents) {
				sMaxConcurrents = sAliveConnections;
			}
			
			mLivingRelayers.add(r);
		}
		
//		Log.r(TAG, "inc " + sAliveConnections);
		Messenger.notifyMessage(mListener, IProxyListener.ALIVE_NUM, sAliveConnections);
	}
	
	private void decConnection(Relayer r) {
		
		synchronized (mLivingRelayers) {
			--sAliveConnections;
			mLivingRelayers.remove(r);
		}
		
//		Log.r(TAG, "dec " + sAliveConnections);
		Messenger.notifyMessage(mListener, IProxyListener.ALIVE_NUM, sAliveConnections);
	}
	
	@Override
	public Error accept(SelectionKey selKey,int opt) {
		if(selKey.isAcceptable()) {
			Log.d(TAG, "recv a connection...");
			try {
				SocketChannel sc = mSocketChannel.accept();
				if(sc != null) {		
					mRelayerPool.obtain(sc);
				}
			} catch (Throwable e) {
				ExceptionHandler.handleException(e);
			}
		}
		return null;
	}
	
	@Override
	public void onPeriodicCheck(long timeout) {
		
	}

	private class Relayer implements ICallback,ITrafficEvent{
		
		private SSockChannel mChannel;
		private int mConnId;
		private boolean mAlive;
		
		private Relayer(SocketChannel conn) {
			init(conn);
		}
		
		private final String getTag() {
			return "Relayer_c"+mConnId;
		}
		
		private void init(SocketChannel conn) {
			mConnId = generateConnectionId();
			String clientAddr = (conn.socket() != null && conn.socket().getInetAddress() != null)?conn.socket().getInetAddress().getHostAddress():"unknown";
			Log.d(getTag(), "receive an conntion " + clientAddr);
			
			Messenger.notifyMessage(mListener, IProxyListener.RECV_CONN,mConnId, clientAddr);
			
			incConnection(this);
			
			mChannel = new SSockChannel(mSelector);
			mChannel.setConnId(mConnId);
			mChannel.setSource(conn);
			mChannel.setTrafficListener(this);
			
			AbsS5Stage stage = new S5VerifyStage(mChannel, mIsLocal, this);
			stage.setConnId(mConnId);
			stage.start();
			
			if(mIsLocal) {
				try {
					SocketChannel sc = SocketChannel.open();
					mChannel.setDest(sc);
					sc.connect(mProxyAddress);
				} catch (Throwable e) {
					Log.e(getTag(), "failed to connect to proxy server.");
					ExceptionHandler.handleException(e);
					Messenger.notifyMessage(mListener, IProxyListener.ERROR,mConnId, Error.E_S5_BIND_PROXY_FAILED);
					release();
					return;
				}
			}
			
			mAlive = true;
		}
		
		private synchronized void release() {
			Log.d(TAG, "release conn " + mConnId);
			if(!mAlive) {
				return;
			}
			
			mAlive = false;
			
			mChannel.destroy();
			mChannel = null;
			
			decConnection(this);
			
			Messenger.notifyMessage(mListener, IProxyListener.STATE_UPDATE, mConnId, SProxyIface.STATE.TERMINATE);
			
			mConnId = -1;
			mRelayerPool.recycle(this);
		}
		
		@Override
		public void onStateChange(int newState, Object... params) {
			Messenger.notifyMessage(mListener, IProxyListener.STATE_UPDATE, mConnId, newState, params);
		}
		
		@Override
		public void onError(Error result) {
			Log.e(getTag(), result.getMessage());
			
			Messenger.notifyMessage(mListener,IProxyListener.ERROR,mConnId, result);
			
			release();
			
		}
		
		@Override
		public void onSrcIn(int len, long total) {
			Messenger.notifyMessage(mListener,IProxyListener.SRC_IN, mConnId, total);
		}

		@Override
		public void onSrcOut(int len, long total) {
			Messenger.notifyMessage(mListener,IProxyListener.SRC_OUT, mConnId, total);
		}

		@Override
		public void onDestIn(int len, long total) {
			Messenger.notifyMessage(mListener,IProxyListener.DEST_IN, mConnId, total);
		}

		@Override
		public void onDestOut(int len, long total) {
			Messenger.notifyMessage(mListener,IProxyListener.DEST_OUT, mConnId, total);
		}

		@Override
		public void onConnInfo(String ip, String domain, int port) {
			Messenger.notifyMessage(mListener,IProxyListener.CONN_INFO, mConnId, ip,domain,port);
		}

		@Override
		public void onSrcOpsUpdate(int ops) {
			Messenger.notifyMessage(mListener,IProxyListener.SRC_INTRS_OPS, mConnId, ops);
		}

		@Override
		public void onDestOpsUpdate(int ops) {
			Messenger.notifyMessage(mListener,IProxyListener.DEST_INTRS_OPS, mConnId, ops);
		}

	}
	
	public static final String dumpInfo() {
		StringBuilder sb = new StringBuilder(256);
		sb.append("living connections: " + sAliveConnections)
		.append(" , max concurrents: " + sMaxConcurrents)
		.append(" , total connections: " + sMaxConnections).append("\n");
		sb.append("using memory ").append(ByteBufferPool.getMemInUsing())
		.append(" , Total memory ").append(ByteBufferPool.getMemTotal());
		return sb.toString();
	}

	@Override
	public void onMemoryInfo(long inUsing, long total) {
		Messenger.notifyMessage(mListener, IProxyListener.MEMORY_INFO, inUsing,total);
	}

}
