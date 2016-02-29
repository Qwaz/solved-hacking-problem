package android.support.v4.view;

import android.database.DataSetObservable;
import android.database.DataSetObserver;
import android.os.Parcelable;
import android.view.View;
import android.view.ViewGroup;

/* renamed from: android.support.v4.view.r */
public abstract class C0055r {
    private DataSetObservable f264a;

    public float m351a(int i) {
        return 1.0f;
    }

    public abstract int m352a();

    public int m353a(Object obj) {
        return -1;
    }

    public Object m354a(View view, int i) {
        throw new UnsupportedOperationException("Required method instantiateItem was not overridden");
    }

    public Object m355a(ViewGroup viewGroup, int i) {
        return m354a((View) viewGroup, i);
    }

    public void m356a(DataSetObserver dataSetObserver) {
        this.f264a.registerObserver(dataSetObserver);
    }

    public void m357a(Parcelable parcelable, ClassLoader classLoader) {
    }

    public void m358a(View view) {
    }

    public void m359a(View view, int i, Object obj) {
        throw new UnsupportedOperationException("Required method destroyItem was not overridden");
    }

    public void m360a(ViewGroup viewGroup) {
        m358a((View) viewGroup);
    }

    public void m361a(ViewGroup viewGroup, int i, Object obj) {
        m359a((View) viewGroup, i, obj);
    }

    public abstract boolean m362a(View view, Object obj);

    public Parcelable m363b() {
        return null;
    }

    public void m364b(DataSetObserver dataSetObserver) {
        this.f264a.unregisterObserver(dataSetObserver);
    }

    public void m365b(View view) {
    }

    public void m366b(View view, int i, Object obj) {
    }

    public void m367b(ViewGroup viewGroup) {
        m365b((View) viewGroup);
    }

    public void m368b(ViewGroup viewGroup, int i, Object obj) {
        m366b((View) viewGroup, i, obj);
    }
}
