package android.support.v4.p010e;

import android.os.AsyncTask;

/* renamed from: android.support.v4.e.b */
class C0093b {
    static void m573a(AsyncTask asyncTask, Object... objArr) {
        asyncTask.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, objArr);
    }
}
