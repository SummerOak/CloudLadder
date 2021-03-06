package com.chedifier.ladder.socks5;

import com.chedifier.ladder.base.Log;
import com.chedifier.ladder.base.NetUtils;
import com.chedifier.ladder.iface.Error;
import com.chedifier.ladder.socks5.SSockChannel.IChannelEvent;

public abstract class AbsS5Stage implements IChannelEvent{

	protected SSockChannel mChannel;
	private ICallback mCallback;
	private boolean mIsLocal;
	private int mConnId;
	
	public AbsS5Stage(SSockChannel context,boolean isLocal,ICallback callback) {
		mChannel = context;
		mIsLocal = isLocal;
		mCallback = callback;
		mChannel.setListener(this);
	}
	
	public AbsS5Stage(AbsS5Stage stage) {
		this.mChannel = stage.mChannel;
		this.mChannel.setListener(this);
		this.mCallback = stage.mCallback;
		this.mIsLocal = stage.mIsLocal;
		this.mConnId = stage.mConnId;
	}
	
	protected final String getTag() {
		return getClass().getName() + "_c"+mConnId;
	}
	
	public void setConnId(int id) {
		mConnId = id;
	}
	
	public int getConnId() {
		return mConnId;
	}
	
	protected boolean isLocal() {
		return mIsLocal;
	}
	
	protected int getSrcInDataSize() {
		return getChannel().getSrcInBuffer().position();
	}
	
	protected int getDestInData() {
		return getChannel().getDestInBuffer().position();
	}
	
	public void start() {
		
	}
	
	@Override
	public void onRelayFailed(Error result) {
		
	}
	
	@Override
	public void onSrcOpsUpdate(int ops) {
		Log.i(getTag(), "onSrcOpsUpdate " + ops + ": " + NetUtils.getOpsDesc(ops));
		if(mCallback != null) {
			mCallback.onSrcOpsUpdate(ops);
		}
	}
	
	@Override
	public void onDestOpsUpdate(int ops) {
		Log.i(getTag(), "onDestOpsUpdate " + ops + ": " + NetUtils.getOpsDesc(ops));
		if(mCallback != null) {
			mCallback.onDestOpsUpdate(ops);
		}
	}
	
	protected AbsS5Stage forward() {
		AbsS5Stage next = next();
		if(next != null) {
			next.start();
		}
		return next;
	}
	
	public abstract AbsS5Stage next();

	protected SSockChannel getChannel() {
		return mChannel;
	}
	
	protected ICallback getCallback() {
		return mCallback;
	}
	
	@Override
	public void onSocketBroken(Error result) {
		notifyError(result);
	}
	
	protected void notifyState(int newState,Object... params) {
		if(mCallback != null) {
			mCallback.onStateChange(newState, params);
		}
	}

	protected void notifyError(Error result) {
		if(mCallback != null) {
			mCallback.onError(result);
		}
	}
	
	public static interface ICallback{
		void onStateChange(int newState,Object... params);
		void onError(Error result);
		void onConnInfo(String ip,String domain,int port);
		void onSrcOpsUpdate(int ops);
		void onDestOpsUpdate(int ops);
	}
}
