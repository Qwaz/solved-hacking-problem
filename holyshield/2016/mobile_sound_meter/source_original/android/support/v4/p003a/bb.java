package android.support.v4.p003a;

import android.os.Bundle;
import android.support.v4.p002b.C0023l;
import android.support.v4.p002b.C0024m;
import android.support.v4.p002b.C0060k;
import android.support.v4.p012g.C0111d;
import android.util.Log;
import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.lang.reflect.Modifier;

/* renamed from: android.support.v4.a.bb */
final class bb implements C0023l, C0024m {
    final int f182a;
    final Bundle f183b;
    az f184c;
    C0060k f185d;
    boolean f186e;
    boolean f187f;
    Object f188g;
    boolean f189h;
    boolean f190i;
    boolean f191j;
    boolean f192k;
    boolean f193l;
    boolean f194m;
    bb f195n;
    final /* synthetic */ ba f196o;

    void m248a() {
        if (this.f190i && this.f191j) {
            this.f189h = true;
        } else if (!this.f189h) {
            this.f189h = true;
            if (ba.f175a) {
                Log.v("LoaderManager", "  Starting: " + this);
            }
            if (this.f185d == null && this.f184c != null) {
                this.f185d = this.f184c.m233a(this.f182a, this.f183b);
            }
            if (this.f185d == null) {
                return;
            }
            if (!this.f185d.getClass().isMemberClass() || Modifier.isStatic(this.f185d.getClass().getModifiers())) {
                if (!this.f194m) {
                    this.f185d.m442a(this.f182a, this);
                    this.f185d.m443a((C0023l) this);
                    this.f194m = true;
                }
                this.f185d.m441a();
                return;
            }
            throw new IllegalArgumentException("Object returned from onCreateLoader must not be a non-static inner member class: " + this.f185d);
        }
    }

    void m249a(C0060k c0060k, Object obj) {
        String str;
        if (this.f184c != null) {
            if (this.f196o.f181g != null) {
                String str2 = this.f196o.f181g.f93d.f125v;
                this.f196o.f181g.f93d.f125v = "onLoadFinished";
                str = str2;
            } else {
                str = null;
            }
            try {
                if (ba.f175a) {
                    Log.v("LoaderManager", "  onLoadFinished in " + c0060k + ": " + c0060k.m440a(obj));
                }
                this.f184c.m235a(c0060k, obj);
                this.f187f = true;
            } finally {
                if (this.f196o.f181g != null) {
                    this.f196o.f181g.f93d.f125v = str;
                }
            }
        }
    }

    public void m250a(String str, FileDescriptor fileDescriptor, PrintWriter printWriter, String[] strArr) {
        printWriter.print(str);
        printWriter.print("mId=");
        printWriter.print(this.f182a);
        printWriter.print(" mArgs=");
        printWriter.println(this.f183b);
        printWriter.print(str);
        printWriter.print("mCallbacks=");
        printWriter.println(this.f184c);
        printWriter.print(str);
        printWriter.print("mLoader=");
        printWriter.println(this.f185d);
        if (this.f185d != null) {
            this.f185d.m445a(str + "  ", fileDescriptor, printWriter, strArr);
        }
        if (this.f186e || this.f187f) {
            printWriter.print(str);
            printWriter.print("mHaveData=");
            printWriter.print(this.f186e);
            printWriter.print("  mDeliveredData=");
            printWriter.println(this.f187f);
            printWriter.print(str);
            printWriter.print("mData=");
            printWriter.println(this.f188g);
        }
        printWriter.print(str);
        printWriter.print("mStarted=");
        printWriter.print(this.f189h);
        printWriter.print(" mReportNextStart=");
        printWriter.print(this.f192k);
        printWriter.print(" mDestroyed=");
        printWriter.println(this.f193l);
        printWriter.print(str);
        printWriter.print("mRetaining=");
        printWriter.print(this.f190i);
        printWriter.print(" mRetainingStarted=");
        printWriter.print(this.f191j);
        printWriter.print(" mListenerRegistered=");
        printWriter.println(this.f194m);
        if (this.f195n != null) {
            printWriter.print(str);
            printWriter.println("Pending Loader ");
            printWriter.print(this.f195n);
            printWriter.println(":");
            this.f195n.m250a(str + "  ", fileDescriptor, printWriter, strArr);
        }
    }

    void m251b() {
        if (ba.f175a) {
            Log.v("LoaderManager", "  Retaining: " + this);
        }
        this.f190i = true;
        this.f191j = this.f189h;
        this.f189h = false;
        this.f184c = null;
    }

    void m252c() {
        if (this.f190i) {
            if (ba.f175a) {
                Log.v("LoaderManager", "  Finished Retaining: " + this);
            }
            this.f190i = false;
            if (!(this.f189h == this.f191j || this.f189h)) {
                m254e();
            }
        }
        if (this.f189h && this.f186e && !this.f192k) {
            m249a(this.f185d, this.f188g);
        }
    }

    void m253d() {
        if (this.f189h && this.f192k) {
            this.f192k = false;
            if (this.f186e) {
                m249a(this.f185d, this.f188g);
            }
        }
    }

    void m254e() {
        if (ba.f175a) {
            Log.v("LoaderManager", "  Stopping: " + this);
        }
        this.f189h = false;
        if (!this.f190i && this.f185d != null && this.f194m) {
            this.f194m = false;
            this.f185d.m444a((C0024m) this);
            this.f185d.m447b(this);
            this.f185d.m448c();
        }
    }

    void m255f() {
        String str;
        az azVar = null;
        if (ba.f175a) {
            Log.v("LoaderManager", "  Destroying: " + this);
        }
        this.f193l = true;
        boolean z = this.f187f;
        this.f187f = false;
        if (this.f184c != null && this.f185d != null && this.f186e && z) {
            if (ba.f175a) {
                Log.v("LoaderManager", "  Reseting: " + this);
            }
            if (this.f196o.f181g != null) {
                String str2 = this.f196o.f181g.f93d.f125v;
                this.f196o.f181g.f93d.f125v = "onLoaderReset";
                str = str2;
            } else {
                str = null;
            }
            try {
                this.f184c.m234a(this.f185d);
            } finally {
                azVar = this.f196o.f181g;
                if (azVar != null) {
                    azVar = this.f196o.f181g.f93d;
                    azVar.f125v = str;
                }
            }
        }
        this.f184c = azVar;
        this.f188g = azVar;
        this.f186e = false;
        if (this.f185d != null) {
            if (this.f194m) {
                this.f194m = false;
                this.f185d.m444a((C0024m) this);
                this.f185d.m447b(this);
            }
            this.f185d.m450e();
        }
        if (this.f195n != null) {
            this.f195n.m255f();
        }
    }

    public String toString() {
        StringBuilder stringBuilder = new StringBuilder(64);
        stringBuilder.append("LoaderInfo{");
        stringBuilder.append(Integer.toHexString(System.identityHashCode(this)));
        stringBuilder.append(" #");
        stringBuilder.append(this.f182a);
        stringBuilder.append(" : ");
        C0111d.m636a(this.f185d, stringBuilder);
        stringBuilder.append("}}");
        return stringBuilder.toString();
    }
}
