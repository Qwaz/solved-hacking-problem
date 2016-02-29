package android.support.v4.app;

import android.support.v4.p002c.C0033a;
import android.support.v4.p002c.C0035c;
import android.util.Log;
import java.io.FileDescriptor;
import java.io.PrintWriter;

/* renamed from: android.support.v4.app.y */
class C0026y extends C0024w {
    static boolean f165a;
    final C0035c f166b;
    final C0035c f167c;
    final String f168d;
    C0011h f169e;
    boolean f170f;
    boolean f171g;

    static {
        f165a = false;
    }

    C0026y(String str, C0011h c0011h, boolean z) {
        this.f166b = new C0035c();
        this.f167c = new C0035c();
        this.f168d = str;
        this.f169e = c0011h;
        this.f170f = z;
    }

    void m180a(C0011h c0011h) {
        this.f169e = c0011h;
    }

    public void m181a(String str, FileDescriptor fileDescriptor, PrintWriter printWriter, String[] strArr) {
        int i = 0;
        if (this.f166b.m207a() > 0) {
            printWriter.print(str);
            printWriter.println("Active Loaders:");
            String str2 = str + "    ";
            for (int i2 = 0; i2 < this.f166b.m207a(); i2++) {
                C0027z c0027z = (C0027z) this.f166b.m209b(i2);
                printWriter.print(str);
                printWriter.print("  #");
                printWriter.print(this.f166b.m208a(i2));
                printWriter.print(": ");
                printWriter.println(c0027z.toString());
                c0027z.m192a(str2, fileDescriptor, printWriter, strArr);
            }
        }
        if (this.f167c.m207a() > 0) {
            printWriter.print(str);
            printWriter.println("Inactive Loaders:");
            String str3 = str + "    ";
            while (i < this.f167c.m207a()) {
                c0027z = (C0027z) this.f167c.m209b(i);
                printWriter.print(str);
                printWriter.print("  #");
                printWriter.print(this.f167c.m208a(i));
                printWriter.print(": ");
                printWriter.println(c0027z.toString());
                c0027z.m192a(str3, fileDescriptor, printWriter, strArr);
                i++;
            }
        }
    }

    public boolean m182a() {
        int a = this.f166b.m207a();
        boolean z = false;
        for (int i = 0; i < a; i++) {
            C0027z c0027z = (C0027z) this.f166b.m209b(i);
            int i2 = (!c0027z.f179h || c0027z.f177f) ? 0 : 1;
            z |= i2;
        }
        return z;
    }

    void m183b() {
        if (f165a) {
            Log.v("LoaderManager", "Starting in " + this);
        }
        if (this.f170f) {
            Throwable runtimeException = new RuntimeException("here");
            runtimeException.fillInStackTrace();
            Log.w("LoaderManager", "Called doStart when already started: " + this, runtimeException);
            return;
        }
        this.f170f = true;
        for (int a = this.f166b.m207a() - 1; a >= 0; a--) {
            ((C0027z) this.f166b.m209b(a)).m190a();
        }
    }

    void m184c() {
        if (f165a) {
            Log.v("LoaderManager", "Stopping in " + this);
        }
        if (this.f170f) {
            for (int a = this.f166b.m207a() - 1; a >= 0; a--) {
                ((C0027z) this.f166b.m209b(a)).m196e();
            }
            this.f170f = false;
            return;
        }
        Throwable runtimeException = new RuntimeException("here");
        runtimeException.fillInStackTrace();
        Log.w("LoaderManager", "Called doStop when not started: " + this, runtimeException);
    }

    void m185d() {
        if (f165a) {
            Log.v("LoaderManager", "Retaining in " + this);
        }
        if (this.f170f) {
            this.f171g = true;
            this.f170f = false;
            for (int a = this.f166b.m207a() - 1; a >= 0; a--) {
                ((C0027z) this.f166b.m209b(a)).m193b();
            }
            return;
        }
        Throwable runtimeException = new RuntimeException("here");
        runtimeException.fillInStackTrace();
        Log.w("LoaderManager", "Called doRetain when not started: " + this, runtimeException);
    }

    void m186e() {
        if (this.f171g) {
            if (f165a) {
                Log.v("LoaderManager", "Finished Retaining in " + this);
            }
            this.f171g = false;
            for (int a = this.f166b.m207a() - 1; a >= 0; a--) {
                ((C0027z) this.f166b.m209b(a)).m194c();
            }
        }
    }

    void m187f() {
        for (int a = this.f166b.m207a() - 1; a >= 0; a--) {
            ((C0027z) this.f166b.m209b(a)).f182k = true;
        }
    }

    void m188g() {
        for (int a = this.f166b.m207a() - 1; a >= 0; a--) {
            ((C0027z) this.f166b.m209b(a)).m195d();
        }
    }

    void m189h() {
        int a;
        if (!this.f171g) {
            if (f165a) {
                Log.v("LoaderManager", "Destroying Active in " + this);
            }
            for (a = this.f166b.m207a() - 1; a >= 0; a--) {
                ((C0027z) this.f166b.m209b(a)).m197f();
            }
            this.f166b.m210b();
        }
        if (f165a) {
            Log.v("LoaderManager", "Destroying Inactive in " + this);
        }
        for (a = this.f167c.m207a() - 1; a >= 0; a--) {
            ((C0027z) this.f167c.m209b(a)).m197f();
        }
        this.f167c.m210b();
    }

    public String toString() {
        StringBuilder stringBuilder = new StringBuilder(128);
        stringBuilder.append("LoaderManager{");
        stringBuilder.append(Integer.toHexString(System.identityHashCode(this)));
        stringBuilder.append(" in ");
        C0033a.m202a(this.f169e, stringBuilder);
        stringBuilder.append("}}");
        return stringBuilder.toString();
    }
}
