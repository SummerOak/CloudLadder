package com.chedifier.ladder.socks5;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Properties;

import com.chedifier.ladder.base.ExceptionHandler;
import com.chedifier.ladder.base.IOUtils;
import com.chedifier.ladder.base.Log;
import com.chedifier.ladder.base.StringUtils;

public class Configuration {
	private static final String TAG = "Configuration";
	private static Properties sConfig;
	
	public static final String IS_SERVER 	= "is_server";
	public static final String SERVER_ADDR 	= "server_address";
	public static final String SERVER_PORT 	= "server_port";
	public static final String LOCAL_PORT 	= "local_port";
	public static final String COMMAND_PORT 	= "command_port";
	
	public static final String LOG_PATH 		= "log_directory";
	public static final String LOG_LEVL 		= "log_level";
	
	
	private static final String SETTING_PATH = "./settings.txt";
	
	public static final String DEFAULT_LOG_PATH = "./log";
	
	public synchronized static boolean init() {
		InputStream input = null;
		try {
			if (null == sConfig) {
				File configFile = new File(SETTING_PATH);
				if (configFile.exists() && configFile.isFile() && configFile.canRead()) {
					input = new FileInputStream(configFile);
					sConfig = new Properties();
					sConfig.load(input);
					return true;
				}else {
					Log.e(TAG, "load settings.txt file failed.");
				}
			}
		} catch (Exception e) {
			ExceptionHandler.handleFatalException(e);
		}finally {
			IOUtils.safeClose(input);
		}
		
		return false;
	}

	public static synchronized int getConfigInt(String key,int def) {
		if(sConfig == null) {
			return 0;
		}
		
		return StringUtils.parseInt(sConfig.getProperty(key), def);
	}
	
	public static synchronized String getConfig(String key,String def) {
		if(sConfig == null) {
			return null;
		}
		
		return sConfig.getProperty(key,def);
	}
}
