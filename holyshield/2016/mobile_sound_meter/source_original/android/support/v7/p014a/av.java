package android.support.v7.p014a;

import android.content.Context;
import android.content.res.Configuration;
import android.support.v4.p004h.bu;
import android.support.v7.view.menu.C0264i;
import android.support.v7.widget.bs;
import android.view.KeyCharacterMap;
import android.view.KeyEvent;
import android.view.Menu;
import android.view.ViewGroup;
import android.view.Window.Callback;
import java.util.ArrayList;

/* renamed from: android.support.v7.a.av */
class av extends C0200a {
    private bs f665a;
    private Callback f666b;
    private boolean f667c;
    private boolean f668d;
    private ArrayList f669e;
    private final Runnable f670f;

    private Menu m1793j() {
        if (!this.f667c) {
            this.f665a.m2606a(new ax(), new ay());
            this.f667c = true;
        }
        return this.f665a.m2631r();
    }

    public int m1794a() {
        return this.f665a.m2628o();
    }

    public void m1795a(float f) {
        bu.m994c(this.f665a.m2603a(), f);
    }

    public void m1796a(Configuration configuration) {
        super.m1602a(configuration);
    }

    public void m1797a(CharSequence charSequence) {
        this.f665a.m2610a(charSequence);
    }

    public void m1798a(boolean z) {
    }

    public boolean m1799a(int i, KeyEvent keyEvent) {
        Menu j = m1793j();
        if (j != null) {
            j.setQwertyMode(KeyCharacterMap.load(keyEvent != null ? keyEvent.getDeviceId() : -1).getKeyboardType() != 1);
            j.performShortcut(i, keyEvent, 0);
        }
        return true;
    }

    public boolean m1800b() {
        return this.f665a.m2630q() == 0;
    }

    public Context m1801c() {
        return this.f665a.m2612b();
    }

    public void m1802c(boolean z) {
    }

    public void m1803d(boolean z) {
    }

    public void m1804e(boolean z) {
        if (z != this.f668d) {
            this.f668d = z;
            int size = this.f669e.size();
            for (int i = 0; i < size; i++) {
                ((C0213c) this.f669e.get(i)).m1911a(z);
            }
        }
    }

    public boolean m1805e() {
        this.f665a.m2603a().removeCallbacks(this.f670f);
        bu.m986a(this.f665a.m2603a(), this.f670f);
        return true;
    }

    public boolean m1806f() {
        if (!this.f665a.m2616c()) {
            return false;
        }
        this.f665a.m2617d();
        return true;
    }

    public boolean m1807g() {
        ViewGroup a = this.f665a.m2603a();
        if (a == null || a.hasFocus()) {
            return false;
        }
        a.requestFocus();
        return true;
    }

    void m1808h() {
        this.f665a.m2603a().removeCallbacks(this.f670f);
    }

    void m1809i() {
        Menu j = m1793j();
        C0264i c0264i = j instanceof C0264i ? (C0264i) j : null;
        if (c0264i != null) {
            c0264i.m2133g();
        }
        try {
            j.clear();
            if (!(this.f666b.onCreatePanelMenu(0, j) && this.f666b.onPreparePanel(0, null, j))) {
                j.clear();
            }
            if (c0264i != null) {
                c0264i.m2134h();
            }
        } catch (Throwable th) {
            if (c0264i != null) {
                c0264i.m2134h();
            }
        }
    }
}
