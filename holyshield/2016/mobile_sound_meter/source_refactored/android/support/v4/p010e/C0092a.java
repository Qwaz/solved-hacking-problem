package android.support.v4.p010e;

import android.os.AsyncTask;
import android.os.Build.VERSION;

/* renamed from: android.support.v4.e.a */
public final class C0092a {
    public static AsyncTask m572a(AsyncTask asyncTask, Object... objArr) {
        if (asyncTask == null) {
            throw new IllegalArgumentException("task can not be null");
        }
        if (VERSION.SDK_INT >= 11) {
            C0093b.m573a(asyncTask, objArr);
        } else {
            asyncTask.execute(objArr);
        }
        return asyncTask;
    }
}
