package android.support.v4.p012g;

import java.util.Collection;
import java.util.Iterator;
import java.util.Set;

/* renamed from: android.support.v4.g.k */
final class C0117k implements Set {
    final /* synthetic */ C0108h f402a;

    C0117k(C0108h c0108h) {
        this.f402a = c0108h;
    }

    public boolean add(Object obj) {
        throw new UnsupportedOperationException();
    }

    public boolean addAll(Collection collection) {
        throw new UnsupportedOperationException();
    }

    public void clear() {
        this.f402a.m617c();
    }

    public boolean contains(Object obj) {
        return this.f402a.m608a(obj) >= 0;
    }

    public boolean containsAll(Collection collection) {
        return C0108h.m603a(this.f402a.m615b(), collection);
    }

    public boolean equals(Object obj) {
        return C0108h.m604a((Set) this, obj);
    }

    public int hashCode() {
        int i = 0;
        for (int a = this.f402a.m607a() - 1; a >= 0; a--) {
            Object a2 = this.f402a.m609a(a, 0);
            i += a2 == null ? 0 : a2.hashCode();
        }
        return i;
    }

    public boolean isEmpty() {
        return this.f402a.m607a() == 0;
    }

    public Iterator iterator() {
        return new C0115i(this.f402a, 0);
    }

    public boolean remove(Object obj) {
        int a = this.f402a.m608a(obj);
        if (a < 0) {
            return false;
        }
        this.f402a.m611a(a);
        return true;
    }

    public boolean removeAll(Collection collection) {
        return C0108h.m605b(this.f402a.m615b(), collection);
    }

    public boolean retainAll(Collection collection) {
        return C0108h.m606c(this.f402a.m615b(), collection);
    }

    public int size() {
        return this.f402a.m607a();
    }

    public Object[] toArray() {
        return this.f402a.m616b(0);
    }

    public Object[] toArray(Object[] objArr) {
        return this.f402a.m613a(objArr, 0);
    }
}
