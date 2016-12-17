package android.support.v7.p014a;

import android.content.Context;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.os.Bundle;
import android.support.v7.p015b.C0243l;
import android.view.Window;
import android.view.Window.Callback;

/* renamed from: android.support.v7.a.aa */
class aa extends C0204z {
    private static ba f606r;
    private int f607s;
    private boolean f608t;
    private boolean f609u;

    aa(Context context, Window window, C0209v c0209v) {
        super(context, window, c0209v);
        this.f607s = -100;
        this.f609u = true;
    }

    private boolean m1732e(int i) {
        Resources resources = this.a.getResources();
        Configuration configuration = resources.getConfiguration();
        int i2 = configuration.uiMode & 48;
        int i3 = i == 2 ? 32 : 16;
        if (i2 == i3) {
            return false;
        }
        configuration.uiMode = i3 | (configuration.uiMode & -49);
        resources.updateConfiguration(configuration, null);
        return true;
    }

    private ba m1733r() {
        if (f606r == null) {
            f606r = new ba(this.a.getApplicationContext());
        }
        return f606r;
    }

    Callback m1734a(Callback callback) {
        return new ab(this, callback);
    }

    public void m1735a(Bundle bundle) {
        super.m1705a(bundle);
        if (bundle != null && this.f607s == -100) {
            this.f607s = bundle.getInt("appcompat:local_night_mode", -100);
        }
    }

    public void m1736c(Bundle bundle) {
        super.m1650c(bundle);
        if (this.f607s != -100) {
            bundle.putInt("appcompat:local_night_mode", this.f607s);
        }
    }

    int m1737d(int i) {
        switch (i) {
            case -100:
                return -1;
            case C0243l.View_android_theme /*0*/:
                return m1733r().m1820a() ? 2 : 1;
            default:
                return i;
        }
    }

    public boolean m1738h() {
        this.f608t = true;
        int d = m1737d(this.f607s == -100 ? C0201w.m1620i() : this.f607s);
        return d != -1 ? m1732e(d) : false;
    }

    public boolean m1739m() {
        return this.f609u;
    }
}
