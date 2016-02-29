package android.support.v4.p000a;

import android.support.v4.p002c.C0033a;
import java.io.FileDescriptor;
import java.io.PrintWriter;

/* renamed from: android.support.v4.a.a */
public class C0000a {
    int f0a;
    C0001b f1b;
    boolean f2c;
    boolean f3d;
    boolean f4e;
    boolean f5f;
    boolean f6g;

    public String m0a(Object obj) {
        StringBuilder stringBuilder = new StringBuilder(64);
        C0033a.m202a(obj, stringBuilder);
        stringBuilder.append("}");
        return stringBuilder.toString();
    }

    public final void m1a() {
        this.f2c = true;
        this.f4e = false;
        this.f3d = false;
        m5b();
    }

    public void m2a(int i, C0001b c0001b) {
        if (this.f1b != null) {
            throw new IllegalStateException("There is already a listener registered");
        }
        this.f1b = c0001b;
        this.f0a = i;
    }

    public void m3a(C0001b c0001b) {
        if (this.f1b == null) {
            throw new IllegalStateException("No listener register");
        } else if (this.f1b != c0001b) {
            throw new IllegalArgumentException("Attempting to unregister the wrong listener");
        } else {
            this.f1b = null;
        }
    }

    public void m4a(String str, FileDescriptor fileDescriptor, PrintWriter printWriter, String[] strArr) {
        printWriter.print(str);
        printWriter.print("mId=");
        printWriter.print(this.f0a);
        printWriter.print(" mListener=");
        printWriter.println(this.f1b);
        if (this.f2c || this.f5f || this.f6g) {
            printWriter.print(str);
            printWriter.print("mStarted=");
            printWriter.print(this.f2c);
            printWriter.print(" mContentChanged=");
            printWriter.print(this.f5f);
            printWriter.print(" mProcessingChange=");
            printWriter.println(this.f6g);
        }
        if (this.f3d || this.f4e) {
            printWriter.print(str);
            printWriter.print("mAbandoned=");
            printWriter.print(this.f3d);
            printWriter.print(" mReset=");
            printWriter.println(this.f4e);
        }
    }

    protected void m5b() {
    }

    public void m6c() {
        this.f2c = false;
        m7d();
    }

    protected void m7d() {
    }

    public void m8e() {
        m9f();
        this.f4e = true;
        this.f2c = false;
        this.f3d = false;
        this.f5f = false;
        this.f6g = false;
    }

    protected void m9f() {
    }

    public String toString() {
        StringBuilder stringBuilder = new StringBuilder(64);
        C0033a.m202a(this, stringBuilder);
        stringBuilder.append(" id=");
        stringBuilder.append(this.f0a);
        stringBuilder.append("}");
        return stringBuilder.toString();
    }
}
