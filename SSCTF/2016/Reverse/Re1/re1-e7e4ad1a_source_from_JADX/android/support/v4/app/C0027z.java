package android.support.v4.app;

import android.os.Bundle;
import android.support.v4.p000a.C0000a;
import android.support.v4.p000a.C0001b;
import android.support.v4.p002c.C0033a;
import android.util.Log;
import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.lang.reflect.Modifier;

/* renamed from: android.support.v4.app.z */
final class C0027z implements C0001b {
    final int f172a;
    final Bundle f173b;
    C0025x f174c;
    C0000a f175d;
    boolean f176e;
    boolean f177f;
    Object f178g;
    boolean f179h;
    boolean f180i;
    boolean f181j;
    boolean f182k;
    boolean f183l;
    boolean f184m;
    C0027z f185n;
    final /* synthetic */ C0026y f186o;

    void m190a() {
        if (this.f180i && this.f181j) {
            this.f179h = true;
        } else if (!this.f179h) {
            this.f179h = true;
            if (C0026y.f165a) {
                Log.v("LoaderManager", "  Starting: " + this);
            }
            if (this.f175d == null && this.f174c != null) {
                this.f175d = this.f174c.m177a(this.f172a, this.f173b);
            }
            if (this.f175d == null) {
                return;
            }
            if (!this.f175d.getClass().isMemberClass() || Modifier.isStatic(this.f175d.getClass().getModifiers())) {
                if (!this.f184m) {
                    this.f175d.m2a(this.f172a, this);
                    this.f184m = true;
                }
                this.f175d.m1a();
                return;
            }
            throw new IllegalArgumentException("Object returned from onCreateLoader must not be a non-static inner member class: " + this.f175d);
        }
    }

    void m191a(C0000a c0000a, Object obj) {
        String str;
        if (this.f174c != null) {
            if (this.f186o.f169e != null) {
                String str2 = this.f186o.f169e.f111b.f153u;
                this.f186o.f169e.f111b.f153u = "onLoadFinished";
                str = str2;
            } else {
                str = null;
            }
            try {
                if (C0026y.f165a) {
                    Log.v("LoaderManager", "  onLoadFinished in " + c0000a + ": " + c0000a.m0a(obj));
                }
                this.f174c.m179a(c0000a, obj);
                this.f177f = true;
            } finally {
                if (this.f186o.f169e != null) {
                    this.f186o.f169e.f111b.f153u = str;
                }
            }
        }
    }

    public void m192a(String str, FileDescriptor fileDescriptor, PrintWriter printWriter, String[] strArr) {
        printWriter.print(str);
        printWriter.print("mId=");
        printWriter.print(this.f172a);
        printWriter.print(" mArgs=");
        printWriter.println(this.f173b);
        printWriter.print(str);
        printWriter.print("mCallbacks=");
        printWriter.println(this.f174c);
        printWriter.print(str);
        printWriter.print("mLoader=");
        printWriter.println(this.f175d);
        if (this.f175d != null) {
            this.f175d.m4a(str + "  ", fileDescriptor, printWriter, strArr);
        }
        if (this.f176e || this.f177f) {
            printWriter.print(str);
            printWriter.print("mHaveData=");
            printWriter.print(this.f176e);
            printWriter.print("  mDeliveredData=");
            printWriter.println(this.f177f);
            printWriter.print(str);
            printWriter.print("mData=");
            printWriter.println(this.f178g);
        }
        printWriter.print(str);
        printWriter.print("mStarted=");
        printWriter.print(this.f179h);
        printWriter.print(" mReportNextStart=");
        printWriter.print(this.f182k);
        printWriter.print(" mDestroyed=");
        printWriter.println(this.f183l);
        printWriter.print(str);
        printWriter.print("mRetaining=");
        printWriter.print(this.f180i);
        printWriter.print(" mRetainingStarted=");
        printWriter.print(this.f181j);
        printWriter.print(" mListenerRegistered=");
        printWriter.println(this.f184m);
        if (this.f185n != null) {
            printWriter.print(str);
            printWriter.println("Pending Loader ");
            printWriter.print(this.f185n);
            printWriter.println(":");
            this.f185n.m192a(str + "  ", fileDescriptor, printWriter, strArr);
        }
    }

    void m193b() {
        if (C0026y.f165a) {
            Log.v("LoaderManager", "  Retaining: " + this);
        }
        this.f180i = true;
        this.f181j = this.f179h;
        this.f179h = false;
        this.f174c = null;
    }

    void m194c() {
        if (this.f180i) {
            if (C0026y.f165a) {
                Log.v("LoaderManager", "  Finished Retaining: " + this);
            }
            this.f180i = false;
            if (!(this.f179h == this.f181j || this.f179h)) {
                m196e();
            }
        }
        if (this.f179h && this.f176e && !this.f182k) {
            m191a(this.f175d, this.f178g);
        }
    }

    void m195d() {
        if (this.f179h && this.f182k) {
            this.f182k = false;
            if (this.f176e) {
                m191a(this.f175d, this.f178g);
            }
        }
    }

    void m196e() {
        if (C0026y.f165a) {
            Log.v("LoaderManager", "  Stopping: " + this);
        }
        this.f179h = false;
        if (!this.f180i && this.f175d != null && this.f184m) {
            this.f184m = false;
            this.f175d.m3a((C0001b) this);
            this.f175d.m6c();
        }
    }

    void m197f() {
        String str;
        C0025x c0025x = null;
        if (C0026y.f165a) {
            Log.v("LoaderManager", "  Destroying: " + this);
        }
        this.f183l = true;
        boolean z = this.f177f;
        this.f177f = false;
        if (this.f174c != null && this.f175d != null && this.f176e && z) {
            if (C0026y.f165a) {
                Log.v("LoaderManager", "  Reseting: " + this);
            }
            if (this.f186o.f169e != null) {
                String str2 = this.f186o.f169e.f111b.f153u;
                this.f186o.f169e.f111b.f153u = "onLoaderReset";
                str = str2;
            } else {
                str = null;
            }
            try {
                this.f174c.m178a(this.f175d);
            } finally {
                c0025x = this.f186o.f169e;
                if (c0025x != null) {
                    c0025x = this.f186o.f169e.f111b;
                    c0025x.f153u = str;
                }
            }
        }
        this.f174c = c0025x;
        this.f178g = c0025x;
        this.f176e = false;
        if (this.f175d != null) {
            if (this.f184m) {
                this.f184m = false;
                this.f175d.m3a((C0001b) this);
            }
            this.f175d.m8e();
        }
        if (this.f185n != null) {
            this.f185n.m197f();
        }
    }

    public String toString() {
        StringBuilder stringBuilder = new StringBuilder(64);
        stringBuilder.append("LoaderInfo{");
        stringBuilder.append(Integer.toHexString(System.identityHashCode(this)));
        stringBuilder.append(" #");
        stringBuilder.append(this.f172a);
        stringBuilder.append(" : ");
        C0033a.m202a(this.f175d, stringBuilder);
        stringBuilder.append("}}");
        return stringBuilder.toString();
    }
}
