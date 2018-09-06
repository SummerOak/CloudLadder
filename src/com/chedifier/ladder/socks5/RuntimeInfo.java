package com.chedifier.ladder.socks5;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import com.chedifier.ladder.base.FileUtils;
import com.chedifier.ladder.base.JobScheduler;
import com.chedifier.ladder.base.JobScheduler.Job;

public class RuntimeInfo {
	
	int port;
	boolean isLocal;
	String proxyHost = null;
	int proxyPort;
	volatile long maxConcurrents = 0L;
	volatile long aliveConnections = 0L;
	volatile long maxConnections = 0L;
	Map<String, Client> clients = new HashMap();
	
	private long mLastDumpTime;
	private static long DUMP_INTERVAL = 5L;
	
	public RuntimeInfo() {
		
	}
	
	void onConnect(String client) {
		++maxConnections;
		++aliveConnections;
		if(aliveConnections > maxConcurrents) {
			maxConcurrents = aliveConnections;
		}
		
		if(client != null) {
			Client c = clients.get(client);
			if(c == null) {
				c = new Client();
				c.total = c.concurrent = c.alive = 1L;
				clients.put(client, c);
			}else {
				++c.alive; ++c.total;
				if(c.alive > c.concurrent) {
					c.concurrent = c.alive;
				}
			}
		}
		
	}
	
	void onConnDisconnect(String client) {
		--aliveConnections;
		
		if(client != null) {
			Client c = clients.get(client);
			if(c != null) {
				--c.alive;
			}
		}
	}
	
	void dump() {
		long now = System.currentTimeMillis();
		if(now > mLastDumpTime + DUMP_INTERVAL) {
			mLastDumpTime = now;
			JobScheduler.schedule(mDumper);
		}
	}
	
	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder(128);
		
		sb.append("port: ").append(port).append("\n\r");
		if(isLocal) {			
			sb.append("server: ").append(proxyHost).append("/").append(proxyPort).append("\n\r");
		}
		sb.append("alive: ").append(aliveConnections).append(" concurrent: ").append(maxConcurrents).append(" total: ").append(maxConnections).append("\n\r");
		
		sb.append("clients:").append("\n\r");
		
		Iterator<Map.Entry<String, Client>> itr = clients.entrySet().iterator();
		while(itr.hasNext()) {
			Map.Entry<String, Client> entry = itr.next();
			Client c = entry.getValue();
			sb.append(entry.getKey()).append(": ")
			.append(" alive ").append(c.alive)
			.append(" concurrent ").append(c.concurrent)
			.append(" total ").append(c.total)
			.append("\n\r");
		}
		
		return sb.toString();
	}
	
	private Job mDumper = new Job("run-time_dumper") {

		@Override
		public void run() {
			FileUtils.writeString2File("status.rt", RuntimeInfo.this.toString(), false);
		}
		
	};
	
	private class Client{
		long alive;
		long total;
		long concurrent;
	}

}
