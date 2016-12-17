package android.support.v4.p012g;

import java.util.Collection;
import java.util.Iterator;
import java.util.Map.Entry;
import java.util.Set;

/* renamed from: android.support.v4.g.j */
final class C0116j implements Set {
    final /* synthetic */ C0108h f401a;

    C0116j(C0108h c0108h) {
        this.f401a = c0108h;
    }

    public boolean m654a(Entry entry) {
        throw new UnsupportedOperationException();
    }

    public /* synthetic */ boolean add(Object obj) {
        return m654a((Entry) obj);
    }

    public boolean addAll(Collection collection) {
        int a = this.f401a.m607a();
        for (Entry entry : collection) {
            this.f401a.m612a(entry.getKey(), entry.getValue());
        }
        return a != this.f401a.m607a();
    }

    public void clear() {
        this.f401a.m617c();
    }

    public boolean contains(Object obj) {
        if (!(obj instanceof Entry)) {
            return false;
        }
        Entry entry = (Entry) obj;
        int a = this.f401a.m608a(entry.getKey());
        return a >= 0 ? C0110c.m633a(this.f401a.m609a(a, 1), entry.getValue()) : false;
    }

    public boolean containsAll(Collection collection) {
        for (Object contains : collection) {
            if (!contains(contains)) {
                return false;
            }
        }
        return true;
    }

    public boolean equals(Object obj) {
        return C0108h.m604a((Set) this, obj);
    }

    public int hashCode() {
        int a = this.f401a.m607a() - 1;
        int i = 0;
        while (a >= 0) {
            Object a2 = this.f401a.m609a(a, 0);
            Object a3 = this.f401a.m609a(a, 1);
            a--;
            i += (a3 == null ? 0 : a3.hashCode()) ^ (a2 == null ? 0 : a2.hashCode());
        }
        return i;
    }

    public boolean isEmpty() {
        return this.f401a.m607a() == 0;
    }

    public Iterator iterator() {
        return new C0118l(this.f401a);
    }

    public boolean remove(Object obj) {
        throw new UnsupportedOperationException();
    }

    public boolean removeAll(Collection collection) {
        throw new UnsupportedOperationException();
    }

    public boolean retainAll(Collection collection) {
        throw new UnsupportedOperationException();
    }

    public int size() {
        return this.f401a.m607a();
    }

    public Object[] toArray() {
        throw new UnsupportedOperationException();
    }

    public Object[] toArray(Object[] objArr) {
        throw new UnsupportedOperationException();
    }
}
