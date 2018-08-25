package com.chedifier.ladder.external;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;

import com.chedifier.ladder.base.ExceptionHandler;
import com.chedifier.ladder.base.IOUtils;
import com.chedifier.ladder.base.Log;
import com.chedifier.ladder.base.StringUtils;
import com.chedifier.ladder.cipher.Cipher;
import com.chedifier.ladder.iface.CmdId;
import com.chedifier.ladder.iface.Error;
import com.chedifier.ladder.iface.SProxyIface;
import com.chedifier.ladder.memory.ByteBufferPool;
import com.chedifier.ladder.socks5.Configuration;
import com.chedifier.ladder.socks5.version.Parcel;
import com.chedifier.ladder.socks5.version.Parcel.Parcelable;

public class ExternalCmdHandler {
	private static final String TAG = "ExternalCmdHandler";
	
	public static final int MAX_COMMAND_LEN = 1024;
	
	private Cipher mCipher = new Cipher();
	private static class Holder{
		public static ExternalCmdHandler sInstance = new ExternalCmdHandler();
	}
	
	private static ExternalCmdHandler getInstance() {
		return Holder.sInstance;
	}
	
	public static void start() {
		new Thread() {
			@Override
			public void run() {
				getInstance().accept();
				
				SProxyIface.stop("external cmd service failed.");
			}
		}.start();
	}
	
	private void accept() {
		int port = Configuration.getConfigInt(Configuration.COMMAND_PORT, 0);
		ServerSocket socket = null;
		byte[] rawCmd = new byte[MAX_COMMAND_LEN];
		ByteBuffer decrypt = ByteBufferPool.obtain(mCipher.decryptLen(rawCmd.length));
		int r = 0;
		try {
			socket = new ServerSocket(port);
			
			while(true) {
				Socket client = socket.accept();
				InputStream is = client.getInputStream();
				if((r=is.read(rawCmd)) > 0){
					Command command = new Command();
					decrypt.clear();
					int dl = mCipher.decrypt(rawCmd, 0, r, decrypt);
					if(dl > 0) {
						Error checkResult = parseExternalCmd(decrypt.array(),0,decrypt.position(),command);
						Log.d(TAG, "parseCommand " + checkResult);
						if(checkResult == Error.SUCCESS) {
							processCommand(command);
						}
					}else {
						Log.e(TAG, "decrypt command failed.");
					}
				}
				
			}
			
		} catch (Throwable t) {
			ExceptionHandler.handleException(t);
		}finally {
			IOUtils.safeClose(socket);
			ByteBufferPool.recycle(decrypt);
		}
	}
	
	public static void sendCommand(boolean isLocal,int cmd,String params,String user,String password) {
		getInstance().sendCommandInternal(isLocal, cmd, params, user, password);
	}
	
	private void sendCommandInternal(boolean isLocal,int cmd,String params,String user,String password) {
		String host = "127.0.0.1";;
		int port = Configuration.getConfigInt(Configuration.COMMAND_PORT, 0);;
		
		if (StringUtils.isEmpty(host) || port == 0) {
			Log.e(TAG, "can not find server addr/port");
			return;
		}
		
		Socket socket = null;
		OutputStream os = null;
		try {
			socket = new Socket(host, port);
			os = socket.getOutputStream();
			
			Command command = new Command(cmd,params,user,password);
			byte[] origin = command.parcel().getBytes();
			
			if(origin != null && origin.length > 0) {
				ByteBuffer outBuffer = ByteBufferPool.obtain(mCipher.encryptLen(origin.length));
				int el = mCipher.encrypt(origin, outBuffer);
				if(el > 0) {
					os.write(outBuffer.array(),0,outBuffer.position());
					Log.r(TAG, "send command " + host + "/" + port + " success.");
				}
				
				ByteBufferPool.recycle(outBuffer);
				
				return;
			}
		} catch (Throwable e) {
//			ExceptionHandler.handleException(e);
		}finally {
			IOUtils.safeClose(os);
			IOUtils.safeClose(socket);
		}
		
		Log.r(TAG, "send command " + host + "/" + port + " failed.");
	}
	
	public static void processCommand(Command command) {
		Log.r(TAG, "recv external command: " + command.cmd + " user " + command.user);
		if(command != null) {
			switch(command.cmd) {
				case CmdId.STOP:{
					SProxyIface.stop("external command");
					break;
				}
			}
		}
	}
	
	private static Error parseExternalCmd(byte[] raw,int offset,int len,Command command) {
		Log.r(TAG, "parseExternalCmd: " + StringUtils.toRawString(raw));
		if(command == null || raw == null || raw.length <= 0) {
			return null;
		}
		
		Parcel parcel = Parcel.createParcelWithData(raw, offset, len);
		if(parcel == null) {
			return Error.E_S5_EXTERNAL_CMD_CHECK_FAILED;
		}
		
		if(command.parcel(parcel) == command) {
			return Error.SUCCESS;
		}
		
		return Error.E_S5_EXTERNAL_CMD_CHECK_FAILED;
	}
	
	public static class Command implements Parcelable{
		public int DATA_TYPE = Parcel.DATA_TYPE.COMMAND;
		
		public int cmd;
		public String params = null;
		
		public String user = null;
		public String password = null;
		
		public Command() {
			
		}
		
		public Command(int cmd,String params,String user,String password) {
			this.cmd = cmd;
			this.params = params;
			this.user = user;
			this.password = password;
		}
		
		@Override
		public Parcel parcel() {
			Parcel parcel = Parcel.createEmptyParcel();
			parcel.writeInt(DATA_TYPE);
			parcel.writeInt(cmd);
			parcel.writeString(params);
			parcel.writeString(user);
			parcel.writeString(password);
			int sign = hashCode();
			parcel.writeInt(sign);
			return parcel;
		}
		@Override
		public Parcelable parcel(Parcel parcel) {
			if(parcel == null) {
				return null;
			}
			
			parcel.flip();
			this.DATA_TYPE = parcel.readInt(-1);
			this.cmd = parcel.readInt(-1);
			this.params = parcel.readString("");
			this.user = parcel.readString("");
			this.password = parcel.readString("");
			int sign = parcel.readInt(1);
			if(DATA_TYPE == Parcel.DATA_TYPE.COMMAND && sign == this.hashCode()) {
				return this;
			}
			
			return null;
		}
		
		@Override
		public int hashCode() {
			return cmd + (user==null?0:user.hashCode()) + (password==null?0:password.hashCode()) + (params==null?0:params.hashCode());
		}
	}

}
