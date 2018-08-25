package com.chedifier.ladder.base;

import java.util.Iterator;
import java.util.LinkedList;

public class ObjectPool<T> {
	private static final String TAG = "ObjectPool";
	private LinkedList<T> mPool;
	private LinkedList<T> mUsing;
	private IConstructor<T> mConstructor;
	private int mSize;
	
	public ObjectPool(IConstructor<T> constructor,int size) {
		mPool = new LinkedList<>();
		mUsing = new LinkedList<>();
		mConstructor = constructor;
		mSize = size;
	}
	
	public int getPoolSize() {
		synchronized (mPool) {
			return mPool.size();
		}
	}

	public T obtain(Object... params) {
		if(mConstructor == null) {
			return null;
		}
		
		synchronized (mPool) {
			T e = null;
			if(mPool.isEmpty()) {
				e = mConstructor.newInstance(params);
//				Log.d(TAG,"obtain-create " + System.identityHashCode(e));
			}else{
				e = mPool.removeFirst();
				mConstructor.initialize(e,params);
//				Log.d(TAG,"obtain-reuse " + System.identityHashCode(e));
			}
			
			mUsing.add(e);
			
			return e;
		}
	}
	
	/**
	 * recycle action will choose one of those 2 operations:
	 * 1. put object o back to pool;
	 * 2. ignore object if the pool exceeded size limitation;
	 * @param o 
	 * @return 
	 */
	public int recycle(T o) {
		if(o != null) {
			synchronized (mPool) {
				for(T t:mPool) {
					if(t == o) {
						return 0;//already in pool
					}
				}
				
				boolean inUsing = false;
				for(Iterator<T> itr = mUsing.iterator(); itr.hasNext();) {
					if(itr.next() == o) {
						inUsing = true;
						itr.remove();
						break;
					}
				}
				
				if(getPoolSize() < mSize) {
					return mPool.add(o)? 1:2;
				}else if(inUsing) {
					return 2;
				}
				
			}
		}
		return 0;
	}
	
	public static interface IConstructor<T>{
		T newInstance(Object... params);
		void initialize(T e,Object... params);
	}
	
}
