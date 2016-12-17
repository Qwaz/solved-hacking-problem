package android.support.v7.view;

import android.view.Menu;
import android.view.MenuInflater;
import android.view.View;

/* renamed from: android.support.v7.view.b */
public abstract class C0212b {
    private Object f727a;
    private boolean f728b;

    public abstract MenuInflater m1877a();

    public abstract void m1878a(int i);

    public abstract void m1879a(View view);

    public abstract void m1880a(CharSequence charSequence);

    public void m1881a(Object obj) {
        this.f727a = obj;
    }

    public void m1882a(boolean z) {
        this.f728b = z;
    }

    public abstract Menu m1883b();

    public abstract void m1884b(int i);

    public abstract void m1885b(CharSequence charSequence);

    public abstract void m1886c();

    public abstract void m1887d();

    public abstract CharSequence m1888f();

    public abstract CharSequence m1889g();

    public boolean m1890h() {
        return false;
    }

    public abstract View m1891i();

    public Object m1892j() {
        return this.f727a;
    }

    public boolean m1893k() {
        return this.f728b;
    }
}
