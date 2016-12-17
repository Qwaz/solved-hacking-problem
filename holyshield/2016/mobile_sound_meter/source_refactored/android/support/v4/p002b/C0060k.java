package android.support.v4.p002b;

import android.support.v4.p012g.C0111d;
import java.io.FileDescriptor;
import java.io.PrintWriter;

/* renamed from: android.support.v4.b.k */
public class C0060k {
    int f335a;
    C0024m f336b;
    C0023l f337c;
    boolean f338d;
    boolean f339e;
    boolean f340f;
    boolean f341g;
    boolean f342h;

    public String m440a(Object obj) {
        StringBuilder stringBuilder = new StringBuilder(64);
        C0111d.m636a(obj, stringBuilder);
        stringBuilder.append("}");
        return stringBuilder.toString();
    }

    public final void m441a() {
        this.f338d = true;
        this.f340f = false;
        this.f339e = false;
        m446b();
    }

    public void m442a(int i, C0024m c0024m) {
        if (this.f336b != null) {
            throw new IllegalStateException("There is already a listener registered");
        }
        this.f336b = c0024m;
        this.f335a = i;
    }

    public void m443a(C0023l c0023l) {
        if (this.f337c != null) {
            throw new IllegalStateException("There is already a listener registered");
        }
        this.f337c = c0023l;
    }

    public void m444a(C0024m c0024m) {
        if (this.f336b == null) {
            throw new IllegalStateException("No listener register");
        } else if (this.f336b != c0024m) {
            throw new IllegalArgumentException("Attempting to unregister the wrong listener");
        } else {
            this.f336b = null;
        }
    }

    public void m445a(String str, FileDescriptor fileDescriptor, PrintWriter printWriter, String[] strArr) {
        printWriter.print(str);
        printWriter.print("mId=");
        printWriter.print(this.f335a);
        printWriter.print(" mListener=");
        printWriter.println(this.f336b);
        if (this.f338d || this.f341g || this.f342h) {
            printWriter.print(str);
            printWriter.print("mStarted=");
            printWriter.print(this.f338d);
            printWriter.print(" mContentChanged=");
            printWriter.print(this.f341g);
            printWriter.print(" mProcessingChange=");
            printWriter.println(this.f342h);
        }
        if (this.f339e || this.f340f) {
            printWriter.print(str);
            printWriter.print("mAbandoned=");
            printWriter.print(this.f339e);
            printWriter.print(" mReset=");
            printWriter.println(this.f340f);
        }
    }

    protected void m446b() {
    }

    public void m447b(C0023l c0023l) {
        if (this.f337c == null) {
            throw new IllegalStateException("No listener register");
        } else if (this.f337c != c0023l) {
            throw new IllegalArgumentException("Attempting to unregister the wrong listener");
        } else {
            this.f337c = null;
        }
    }

    public void m448c() {
        this.f338d = false;
        m449d();
    }

    protected void m449d() {
    }

    public void m450e() {
        m451f();
        this.f340f = true;
        this.f338d = false;
        this.f339e = false;
        this.f341g = false;
        this.f342h = false;
    }

    protected void m451f() {
    }

    public String toString() {
        StringBuilder stringBuilder = new StringBuilder(64);
        C0111d.m636a(this, stringBuilder);
        stringBuilder.append(" id=");
        stringBuilder.append(this.f335a);
        stringBuilder.append("}");
        return stringBuilder.toString();
    }
}
