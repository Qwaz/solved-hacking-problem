package android.support.v4.p003a;

import android.support.v4.p012g.C0111d;
import android.support.v4.p012g.C0120o;
import android.util.Log;
import java.io.FileDescriptor;
import java.io.PrintWriter;

/* renamed from: android.support.v4.a.ba */
class ba extends ay {
    static boolean f175a;
    final C0120o f176b;
    final C0120o f177c;
    final String f178d;
    boolean f179e;
    boolean f180f;
    private ac f181g;

    static {
        f175a = false;
    }

    ba(String str, ac acVar, boolean z) {
        this.f176b = new C0120o();
        this.f177c = new C0120o();
        this.f178d = str;
        this.f181g = acVar;
        this.f179e = z;
    }

    void m238a(ac acVar) {
        this.f181g = acVar;
    }

    public void m239a(String str, FileDescriptor fileDescriptor, PrintWriter printWriter, String[] strArr) {
        int i = 0;
        if (this.f176b.m660b() > 0) {
            printWriter.print(str);
            printWriter.println("Active Loaders:");
            String str2 = str + "    ";
            for (int i2 = 0; i2 < this.f176b.m660b(); i2++) {
                bb bbVar = (bb) this.f176b.m666e(i2);
                printWriter.print(str);
                printWriter.print("  #");
                printWriter.print(this.f176b.m665d(i2));
                printWriter.print(": ");
                printWriter.println(bbVar.toString());
                bbVar.m250a(str2, fileDescriptor, printWriter, strArr);
            }
        }
        if (this.f177c.m660b() > 0) {
            printWriter.print(str);
            printWriter.println("Inactive Loaders:");
            String str3 = str + "    ";
            while (i < this.f177c.m660b()) {
                bbVar = (bb) this.f177c.m666e(i);
                printWriter.print(str);
                printWriter.print("  #");
                printWriter.print(this.f177c.m665d(i));
                printWriter.print(": ");
                printWriter.println(bbVar.toString());
                bbVar.m250a(str3, fileDescriptor, printWriter, strArr);
                i++;
            }
        }
    }

    public boolean m240a() {
        int b = this.f176b.m660b();
        boolean z = false;
        for (int i = 0; i < b; i++) {
            bb bbVar = (bb) this.f176b.m666e(i);
            int i2 = (!bbVar.f189h || bbVar.f187f) ? 0 : 1;
            z |= i2;
        }
        return z;
    }

    void m241b() {
        if (f175a) {
            Log.v("LoaderManager", "Starting in " + this);
        }
        if (this.f179e) {
            Throwable runtimeException = new RuntimeException("here");
            runtimeException.fillInStackTrace();
            Log.w("LoaderManager", "Called doStart when already started: " + this, runtimeException);
            return;
        }
        this.f179e = true;
        for (int b = this.f176b.m660b() - 1; b >= 0; b--) {
            ((bb) this.f176b.m666e(b)).m248a();
        }
    }

    void m242c() {
        if (f175a) {
            Log.v("LoaderManager", "Stopping in " + this);
        }
        if (this.f179e) {
            for (int b = this.f176b.m660b() - 1; b >= 0; b--) {
                ((bb) this.f176b.m666e(b)).m254e();
            }
            this.f179e = false;
            return;
        }
        Throwable runtimeException = new RuntimeException("here");
        runtimeException.fillInStackTrace();
        Log.w("LoaderManager", "Called doStop when not started: " + this, runtimeException);
    }

    void m243d() {
        if (f175a) {
            Log.v("LoaderManager", "Retaining in " + this);
        }
        if (this.f179e) {
            this.f180f = true;
            this.f179e = false;
            for (int b = this.f176b.m660b() - 1; b >= 0; b--) {
                ((bb) this.f176b.m666e(b)).m251b();
            }
            return;
        }
        Throwable runtimeException = new RuntimeException("here");
        runtimeException.fillInStackTrace();
        Log.w("LoaderManager", "Called doRetain when not started: " + this, runtimeException);
    }

    void m244e() {
        if (this.f180f) {
            if (f175a) {
                Log.v("LoaderManager", "Finished Retaining in " + this);
            }
            this.f180f = false;
            for (int b = this.f176b.m660b() - 1; b >= 0; b--) {
                ((bb) this.f176b.m666e(b)).m252c();
            }
        }
    }

    void m245f() {
        for (int b = this.f176b.m660b() - 1; b >= 0; b--) {
            ((bb) this.f176b.m666e(b)).f192k = true;
        }
    }

    void m246g() {
        for (int b = this.f176b.m660b() - 1; b >= 0; b--) {
            ((bb) this.f176b.m666e(b)).m253d();
        }
    }

    void m247h() {
        int b;
        if (!this.f180f) {
            if (f175a) {
                Log.v("LoaderManager", "Destroying Active in " + this);
            }
            for (b = this.f176b.m660b() - 1; b >= 0; b--) {
                ((bb) this.f176b.m666e(b)).m255f();
            }
            this.f176b.m663c();
        }
        if (f175a) {
            Log.v("LoaderManager", "Destroying Inactive in " + this);
        }
        for (b = this.f177c.m660b() - 1; b >= 0; b--) {
            ((bb) this.f177c.m666e(b)).m255f();
        }
        this.f177c.m663c();
    }

    public String toString() {
        StringBuilder stringBuilder = new StringBuilder(128);
        stringBuilder.append("LoaderManager{");
        stringBuilder.append(Integer.toHexString(System.identityHashCode(this)));
        stringBuilder.append(" in ");
        C0111d.m636a(this.f181g, stringBuilder);
        stringBuilder.append("}}");
        return stringBuilder.toString();
    }
}
