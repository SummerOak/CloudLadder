package com.chedifier.ladder.socks5;

import java.nio.channels.SelectionKey;

import com.chedifier.ladder.base.Log;
import com.chedifier.ladder.iface.Error;
import com.chedifier.ladder.iface.SProxyIface;

public class S5TransStage extends AbsS5Stage{
	
	
	public S5TransStage(AbsS5Stage stage) {
		super(stage);
		
	}
	
	@Override
	public void start() {
		Log.d(getTag(), "S5TransStage start>>>");
		super.start();
		if(getChannel().getConnType() == SSockChannel.CONN_CMD_TCP) {
			getChannel().setTimeout(3600*1000);
		}
		
		notifyState(SProxyIface.STATE.TRANS);
	}

	@Override
	public AbsS5Stage next() {
		return null;
	}

	@Override
	public void onSourceOpts(int opts) {
		if((opts&SelectionKey.OP_READ) > 0) {
			getChannel().relay(true, isLocal());
		}else if((opts&SelectionKey.OP_WRITE) > 0) {
			getChannel().relay(false, !isLocal());
		}
	}
	
	@Override
	public void onDestOpts(int opts) {
		if((opts&SelectionKey.OP_READ) > 0) {
			getChannel().relay(false, !isLocal());
		}else if((opts&SelectionKey.OP_READ) > 0){
			getChannel().relay(true, isLocal());
		}
		
	}

	@Override
	public void onSocketBroken(Error result) {
		notifyError(result);
	}

}
