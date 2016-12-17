package android.support.v4.p012g;

import java.lang.reflect.Array;
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

/* renamed from: android.support.v4.g.h */
abstract class C0108h {
    C0116j f374b;
    C0117k f375c;
    C0119m f376d;

    C0108h() {
    }

    public static boolean m603a(Map map, Collection collection) {
        for (Object containsKey : collection) {
            if (!map.containsKey(containsKey)) {
                return false;
            }
        }
        return true;
    }

    public static boolean m604a(Set set, Object obj) {
        boolean z = true;
        if (set == obj) {
            return true;
        }
        if (!(obj instanceof Set)) {
            return false;
        }
        Set set2 = (Set) obj;
        try {
            if (!(set.size() == set2.size() && set.containsAll(set2))) {
                z = false;
            }
            return z;
        } catch (NullPointerException e) {
            return false;
        } catch (ClassCastException e2) {
            return false;
        }
    }

    public static boolean m605b(Map map, Collection collection) {
        int size = map.size();
        for (Object remove : collection) {
            map.remove(remove);
        }
        return size != map.size();
    }

    public static boolean m606c(Map map, Collection collection) {
        int size = map.size();
        Iterator it = map.keySet().iterator();
        while (it.hasNext()) {
            if (!collection.contains(it.next())) {
                it.remove();
            }
        }
        return size != map.size();
    }

    protected abstract int m607a();

    protected abstract int m608a(Object obj);

    protected abstract Object m609a(int i, int i2);

    protected abstract Object m610a(int i, Object obj);

    protected abstract void m611a(int i);

    protected abstract void m612a(Object obj, Object obj2);

    public Object[] m613a(Object[] objArr, int i) {
        int a = m607a();
        Object[] objArr2 = objArr.length < a ? (Object[]) Array.newInstance(objArr.getClass().getComponentType(), a) : objArr;
        for (int i2 = 0; i2 < a; i2++) {
            objArr2[i2] = m609a(i2, i);
        }
        if (objArr2.length > a) {
            objArr2[a] = null;
        }
        return objArr2;
    }

    protected abstract int m614b(Object obj);

    protected abstract Map m615b();

    public Object[] m616b(int i) {
        int a = m607a();
        Object[] objArr = new Object[a];
        for (int i2 = 0; i2 < a; i2++) {
            objArr[i2] = m609a(i2, i);
        }
        return objArr;
    }

    protected abstract void m617c();

    public Set m618d() {
        if (this.f374b == null) {
            this.f374b = new C0116j(this);
        }
        return this.f374b;
    }

    public Set m619e() {
        if (this.f375c == null) {
            this.f375c = new C0117k(this);
        }
        return this.f375c;
    }

    public Collection m620f() {
        if (this.f376d == null) {
            this.f376d = new C0119m(this);
        }
        return this.f376d;
    }
}
