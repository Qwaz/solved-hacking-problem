package android.support.v4.p012g;

import java.util.Collection;
import java.util.Iterator;

/* renamed from: android.support.v4.g.m */
final class C0119m implements Collection {
    final /* synthetic */ C0108h f407a;

    C0119m(C0108h c0108h) {
        this.f407a = c0108h;
    }

    public boolean add(Object obj) {
        throw new UnsupportedOperationException();
    }

    public boolean addAll(Collection collection) {
        throw new UnsupportedOperationException();
    }

    public void clear() {
        this.f407a.m617c();
    }

    public boolean contains(Object obj) {
        return this.f407a.m614b(obj) >= 0;
    }

    public boolean containsAll(Collection collection) {
        for (Object contains : collection) {
            if (!contains(contains)) {
                return false;
            }
        }
        return true;
    }

    public boolean isEmpty() {
        return this.f407a.m607a() == 0;
    }

    public Iterator iterator() {
        return new C0115i(this.f407a, 1);
    }

    public boolean remove(Object obj) {
        int b = this.f407a.m614b(obj);
        if (b < 0) {
            return false;
        }
        this.f407a.m611a(b);
        return true;
    }

    public boolean removeAll(Collection collection) {
        int i = 0;
        int a = this.f407a.m607a();
        boolean z = false;
        while (i < a) {
            if (collection.contains(this.f407a.m609a(i, 1))) {
                this.f407a.m611a(i);
                i--;
                a--;
                z = true;
            }
            i++;
        }
        return z;
    }

    public boolean retainAll(Collection collection) {
        int i = 0;
        int a = this.f407a.m607a();
        boolean z = false;
        while (i < a) {
            if (!collection.contains(this.f407a.m609a(i, 1))) {
                this.f407a.m611a(i);
                i--;
                a--;
                z = true;
            }
            i++;
        }
        return z;
    }

    public int size() {
        return this.f407a.m607a();
    }

    public Object[] toArray() {
        return this.f407a.m616b(1);
    }

    public Object[] toArray(Object[] objArr) {
        return this.f407a.m613a(objArr, 1);
    }
}
