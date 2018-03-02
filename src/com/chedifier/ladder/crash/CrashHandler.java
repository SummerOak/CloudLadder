package com.chedifier.ladder.crash;

import java.lang.Thread.UncaughtExceptionHandler;

import com.chedifier.ladder.base.ExceptionHandler;
import com.chedifier.ladder.base.Log;
import com.chedifier.ladder.base.Log.ICallback;
import com.chedifier.ladder.socks5.SProxy;

public class CrashHandler {
	private static final String TAG = "CrashHandler";
	
	public static final void init() {
		Thread.setDefaultUncaughtExceptionHandler(new UncaughtExceptionHandler() {
			
			@Override
			public void uncaughtException(Thread t, Throwable e) {
				Log.e(TAG, "FATAL died, thread: " + (t==null?"":t.getName()) 
						+ " reason: " + (e==null?"":e.getMessage()) 
						+ " stack: " + ExceptionHandler.getStackTraceString(e));
				
				Log.dumpBeforeExit(new ICallback() {
					
					@Override
					public void onDumpFinish() {
						System.exit(1);
					}
				});
			}
		});
	}

}
