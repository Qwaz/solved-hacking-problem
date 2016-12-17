package android.support.v7.p014a;

import android.content.Context;
import android.content.res.Configuration;
import android.support.v7.view.C0208c;
import android.support.v7.view.C0212b;
import android.view.KeyEvent;

/* renamed from: android.support.v7.a.a */
public abstract class C0200a {
    public abstract int m1599a();

    public C0212b m1600a(C0208c c0208c) {
        return null;
    }

    public void m1601a(float f) {
        if (f != 0.0f) {
            throw new UnsupportedOperationException("Setting a non-zero elevation is not supported in this action bar configuration.");
        }
    }

    public void m1602a(Configuration configuration) {
    }

    public void m1603a(CharSequence charSequence) {
    }

    public void m1604a(boolean z) {
    }

    public boolean m1605a(int i, KeyEvent keyEvent) {
        return false;
    }

    public void m1606b(boolean z) {
        if (z) {
            throw new UnsupportedOperationException("Hide on content scroll is not supported in this action bar configuration.");
        }
    }

    public abstract boolean m1607b();

    public Context m1608c() {
        return null;
    }

    public void m1609c(boolean z) {
    }

    public int m1610d() {
        return 0;
    }

    public void m1611d(boolean z) {
    }

    public void m1612e(boolean z) {
    }

    public boolean m1613e() {
        return false;
    }

    public boolean m1614f() {
        return false;
    }

    boolean m1615g() {
        return false;
    }

    void m1616h() {
    }
}
