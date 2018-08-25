package com.chedifier.ladder.socks5;

import java.nio.channels.SelectionKey;

import com.chedifier.ladder.base.ObjectPool;
import com.chedifier.ladder.base.ObjectPool.IConstructor;
import com.chedifier.ladder.iface.Error;

public class AcceptorWrapper {
	
	private static ObjectPool<AcceptorW> sWAcceptorPool;
	private static boolean sInited = false;
	
	public static synchronized void init() {
		if(sInited) {
			return;
		}
		sWAcceptorPool = new ObjectPool<AcceptorW>(new IConstructor<AcceptorW>() {
			
			@Override
			public AcceptorW newInstance(Object... params) {
				return new AcceptorW((IAcceptor)params[0]);
			}

			@Override
			public void initialize(AcceptorW e, Object... params) {
				e.mA = (IAcceptor)params[0];
			}
			
		}, 50);
		sInited = true;
	}
	
	public static IAcceptor wrapper(IAcceptor a) {
		return sWAcceptorPool.obtain(a);
	}
	
	private static class AcceptorW implements IAcceptor{
		private IAcceptor mA;
		
		private AcceptorW(IAcceptor acceptor) {
			this.mA = acceptor;
		}
		
		public Error accept(SelectionKey selKey,int opt) {
			Error res = mA.accept(selKey,opt);
			sWAcceptorPool.recycle(this);
			return res;
		}

		@Override
		public void onPeriodicCheck(long timeout) {
			mA.onPeriodicCheck(timeout);
			sWAcceptorPool.recycle(this);
		}
	}
	
	public static interface IAcceptor {
		public Error accept(SelectionKey selKey,int opts);
		public void onPeriodicCheck(long timeout);
	}
	
}
