package android.support.v4.widget;

import android.view.View;

/* renamed from: android.support.v4.widget.d */
class C0065d extends aa {
    final /* synthetic */ DrawerLayout f316a;
    private final int f317b;
    private C0086y f318c;
    private final Runnable f319d;

    private void m449b() {
        int i = 3;
        if (this.f317b == 3) {
            i = 5;
        }
        View a = this.f316a.m397a(i);
        if (a != null) {
            this.f316a.m412i(a);
        }
    }

    public int m450a(View view) {
        return view.getWidth();
    }

    public int m451a(View view, int i, int i2) {
        if (this.f316a.m402a(view, 3)) {
            return Math.max(-view.getWidth(), Math.min(i, 0));
        }
        int width = this.f316a.getWidth();
        return Math.max(width - view.getWidth(), Math.min(i, width));
    }

    public void m452a() {
        this.f316a.removeCallbacks(this.f319d);
    }

    public void m453a(int i) {
        this.f316a.m399a(this.f317b, i, this.f318c.m569c());
    }

    public void m454a(int i, int i2) {
        this.f316a.postDelayed(this.f319d, 160);
    }

    public void m455a(View view, float f, float f2) {
        int i;
        float d = this.f316a.m407d(view);
        int width = view.getWidth();
        if (this.f316a.m402a(view, 3)) {
            i = (f > 0.0f || (f == 0.0f && d > 0.5f)) ? 0 : -width;
        } else {
            i = this.f316a.getWidth();
            if (f < 0.0f || (f == 0.0f && d < 0.5f)) {
                i -= width;
            }
        }
        this.f318c.m559a(i, view.getTop());
        this.f316a.invalidate();
    }

    public void m456a(View view, int i, int i2, int i3, int i4) {
        int width = view.getWidth();
        float width2 = this.f316a.m402a(view, 3) ? ((float) (width + i)) / ((float) width) : ((float) (this.f316a.getWidth() - i)) / ((float) width);
        this.f316a.m405b(view, width2);
        view.setVisibility(width2 == 0.0f ? 4 : 0);
        this.f316a.invalidate();
    }

    public boolean m457a(View view, int i) {
        return this.f316a.m410g(view) && this.f316a.m402a(view, this.f317b) && this.f316a.m395a(view) == 0;
    }

    public int m458b(View view, int i, int i2) {
        return view.getTop();
    }

    public void m459b(int i, int i2) {
        View a = (i & 1) == 1 ? this.f316a.m397a(3) : this.f316a.m397a(5);
        if (a != null && this.f316a.m395a(a) == 0) {
            this.f318c.m557a(a, i2);
        }
    }

    public void m460b(View view, int i) {
        ((C0063b) view.getLayoutParams()).f314c = false;
        m449b();
    }

    public boolean m461b(int i) {
        return false;
    }
}
