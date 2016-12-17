package android.support.v4.p003a;

import android.os.Build.VERSION;
import android.support.v4.p012g.C0107a;
import android.support.v4.p012g.C0112e;
import android.support.v7.p015b.C0243l;
import android.util.Log;
import android.util.SparseArray;
import android.view.View;
import android.view.ViewGroup;
import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Map;

/* renamed from: android.support.v4.a.j */
final class C0032j extends aq implements Runnable {
    static final boolean f203a;
    final af f204b;
    C0036n f205c;
    C0036n f206d;
    int f207e;
    int f208f;
    int f209g;
    int f210h;
    int f211i;
    int f212j;
    int f213k;
    boolean f214l;
    boolean f215m;
    String f216n;
    boolean f217o;
    int f218p;
    int f219q;
    CharSequence f220r;
    int f221s;
    CharSequence f222t;
    ArrayList f223u;
    ArrayList f224v;

    static {
        f203a = VERSION.SDK_INT >= 21;
    }

    public C0032j(af afVar) {
        this.f215m = true;
        this.f218p = -1;
        this.f204b = afVar;
    }

    private C0037o m300a(SparseArray sparseArray, SparseArray sparseArray2, boolean z) {
        int i = 0;
        m318a(sparseArray2);
        C0037o c0037o = new C0037o(this);
        c0037o.f252d = new View(this.f204b.f119o.m127g());
        int i2 = 0;
        int i3 = 0;
        while (i2 < sparseArray.size()) {
            int i4 = m321a(sparseArray.keyAt(i2), c0037o, z, sparseArray, sparseArray2) ? 1 : i3;
            i2++;
            i3 = i4;
        }
        while (i < sparseArray2.size()) {
            i4 = sparseArray2.keyAt(i);
            if (sparseArray.get(i4) == null && m321a(i4, c0037o, z, sparseArray, sparseArray2)) {
                i3 = 1;
            }
            i++;
        }
        return i3 == 0 ? null : c0037o;
    }

    private C0107a m302a(C0037o c0037o, C0042t c0042t, boolean z) {
        C0107a c0107a = new C0107a();
        if (this.f223u != null) {
            ar.m222a((Map) c0107a, c0042t.m386g());
            if (z) {
                c0107a.m602a(this.f224v);
            } else {
                c0107a = C0032j.m304a(this.f223u, this.f224v, c0107a);
            }
        }
        if (z) {
            if (c0042t.f290X != null) {
                c0042t.f290X.m281a(this.f224v, c0107a);
            }
            m313a(c0037o, c0107a, false);
        } else {
            if (c0042t.f291Y != null) {
                c0042t.f291Y.m281a(this.f224v, c0107a);
            }
            m324b(c0037o, c0107a, false);
        }
        return c0107a;
    }

    private C0107a m303a(C0037o c0037o, boolean z, C0042t c0042t) {
        C0107a b = m322b(c0037o, c0042t, z);
        if (z) {
            if (c0042t.f291Y != null) {
                c0042t.f291Y.m281a(this.f224v, b);
            }
            m313a(c0037o, b, true);
        } else {
            if (c0042t.f290X != null) {
                c0042t.f290X.m281a(this.f224v, b);
            }
            m324b(c0037o, b, true);
        }
        return b;
    }

    private static C0107a m304a(ArrayList arrayList, ArrayList arrayList2, C0107a c0107a) {
        if (c0107a.isEmpty()) {
            return c0107a;
        }
        C0107a c0107a2 = new C0107a();
        int size = arrayList.size();
        for (int i = 0; i < size; i++) {
            View view = (View) c0107a.get(arrayList.get(i));
            if (view != null) {
                c0107a2.put(arrayList2.get(i), view);
            }
        }
        return c0107a2;
    }

    private static Object m305a(C0042t c0042t, C0042t c0042t2, boolean z) {
        if (c0042t == null || c0042t2 == null) {
            return null;
        }
        return ar.m227b(z ? c0042t2.m404v() : c0042t.m403u());
    }

    private static Object m306a(C0042t c0042t, boolean z) {
        if (c0042t == null) {
            return null;
        }
        return ar.m208a(z ? c0042t.m402t() : c0042t.m399q());
    }

    private static Object m307a(Object obj, C0042t c0042t, ArrayList arrayList, C0107a c0107a, View view) {
        return obj != null ? ar.m209a(obj, c0042t.m386g(), arrayList, c0107a, view) : obj;
    }

    private void m311a(C0037o c0037o, int i, Object obj) {
        if (this.f204b.f111g != null) {
            for (int i2 = 0; i2 < this.f204b.f111g.size(); i2++) {
                C0042t c0042t = (C0042t) this.f204b.f111g.get(i2);
                if (!(c0042t.f275I == null || c0042t.f274H == null || c0042t.f314x != i)) {
                    if (!c0042t.f316z) {
                        ar.m217a(obj, c0042t.f275I, false);
                        c0037o.f250b.remove(c0042t.f275I);
                    } else if (!c0037o.f250b.contains(c0042t.f275I)) {
                        ar.m217a(obj, c0042t.f275I, true);
                        c0037o.f250b.add(c0042t.f275I);
                    }
                }
            }
        }
    }

    private void m312a(C0037o c0037o, C0042t c0042t, C0042t c0042t2, boolean z, C0107a c0107a) {
        bi biVar = z ? c0042t2.f290X : c0042t.f290X;
        if (biVar != null) {
            biVar.m282b(new ArrayList(c0107a.keySet()), new ArrayList(c0107a.values()), null);
        }
    }

    private void m313a(C0037o c0037o, C0107a c0107a, boolean z) {
        int size = this.f224v == null ? 0 : this.f224v.size();
        for (int i = 0; i < size; i++) {
            String str = (String) this.f223u.get(i);
            View view = (View) c0107a.get((String) this.f224v.get(i));
            if (view != null) {
                String a = ar.m211a(view);
                if (z) {
                    C0032j.m317a(c0037o.f249a, str, a);
                } else {
                    C0032j.m317a(c0037o.f249a, a, str);
                }
            }
        }
    }

    private void m314a(C0037o c0037o, View view, Object obj, C0042t c0042t, C0042t c0042t2, boolean z, ArrayList arrayList) {
        view.getViewTreeObserver().addOnPreDrawListener(new C0034l(this, view, obj, arrayList, c0037o, z, c0042t, c0042t2));
    }

    private static void m315a(C0037o c0037o, ArrayList arrayList, ArrayList arrayList2) {
        if (arrayList != null) {
            for (int i = 0; i < arrayList.size(); i++) {
                C0032j.m317a(c0037o.f249a, (String) arrayList.get(i), (String) arrayList2.get(i));
            }
        }
    }

    private void m316a(C0107a c0107a, C0037o c0037o) {
        if (this.f224v != null && !c0107a.isEmpty()) {
            View view = (View) c0107a.get(this.f224v.get(0));
            if (view != null) {
                c0037o.f251c.f174a = view;
            }
        }
    }

    private static void m317a(C0107a c0107a, String str, String str2) {
        if (str != null && str2 != null) {
            for (int i = 0; i < c0107a.size(); i++) {
                if (str.equals(c0107a.m599c(i))) {
                    c0107a.m595a(i, (Object) str2);
                    return;
                }
            }
            c0107a.put(str, str2);
        }
    }

    private void m318a(SparseArray sparseArray) {
        int size = sparseArray.size();
        for (int i = 0; i < size; i++) {
            C0042t c0042t = (C0042t) sparseArray.valueAt(i);
            if (c0042t.f292b < 1) {
                this.f204b.m179c(c0042t);
                this.f204b.m163a(c0042t, 1, 0, 0, false);
            }
        }
    }

    private static void m319a(SparseArray sparseArray, SparseArray sparseArray2, C0042t c0042t) {
        if (c0042t != null) {
            int i = c0042t.f314x;
            if (i != 0 && !c0042t.m385f()) {
                if (c0042t.m383e() && c0042t.m386g() != null && sparseArray.get(i) == null) {
                    sparseArray.put(i, c0042t);
                }
                if (sparseArray2.get(i) == c0042t) {
                    sparseArray2.remove(i);
                }
            }
        }
    }

    private void m320a(View view, C0037o c0037o, int i, Object obj) {
        view.getViewTreeObserver().addOnPreDrawListener(new C0035m(this, view, c0037o, i, obj));
    }

    private boolean m321a(int i, C0037o c0037o, boolean z, SparseArray sparseArray, SparseArray sparseArray2) {
        View view = (ViewGroup) this.f204b.f120p.m78a(i);
        if (view == null) {
            return false;
        }
        Object obj;
        ArrayList arrayList;
        Object a;
        View view2;
        ax c0033k;
        ArrayList arrayList2;
        Map c0107a;
        boolean z2;
        Object a2;
        C0042t c0042t = (C0042t) sparseArray2.get(i);
        C0042t c0042t2 = (C0042t) sparseArray.get(i);
        Object a3 = C0032j.m306a(c0042t, z);
        Object a4 = C0032j.m305a(c0042t, c0042t2, z);
        Object b = C0032j.m323b(c0042t2, z);
        Map map = null;
        ArrayList arrayList3 = new ArrayList();
        if (a4 != null) {
            map = m302a(c0037o, c0042t2, z);
            if (map.isEmpty()) {
                map = null;
                obj = null;
                if (a3 != null && obj == null && b == null) {
                    return false;
                }
                arrayList = new ArrayList();
                a = C0032j.m307a(b, c0042t2, arrayList, (C0107a) map, c0037o.f252d);
                if (!(this.f224v == null || map == null)) {
                    view2 = (View) map.get(this.f224v.get(0));
                    if (view2 != null) {
                        if (a != null) {
                            ar.m215a(a, view2);
                        }
                        if (obj != null) {
                            ar.m215a(obj, view2);
                        }
                    }
                }
                c0033k = new C0033k(this, c0042t);
                arrayList2 = new ArrayList();
                c0107a = new C0107a();
                z2 = true;
                if (c0042t != null) {
                    z2 = z ? c0042t.m406x() : c0042t.m405w();
                }
                a2 = ar.m210a(a3, a, obj, z2);
                if (a2 != null) {
                    ar.m218a(a3, obj, view, c0033k, c0037o.f252d, c0037o.f251c, c0037o.f249a, arrayList2, map, c0107a, arrayList3);
                    m320a(view, c0037o, i, a2);
                    ar.m217a(a2, c0037o.f252d, true);
                    m311a(c0037o, i, a2);
                    ar.m214a((ViewGroup) view, a2);
                    ar.m213a(view, c0037o.f252d, a3, arrayList2, a, arrayList, obj, arrayList3, a2, c0037o.f250b, c0107a);
                }
                return a2 == null;
            } else {
                bi biVar = z ? c0042t2.f290X : c0042t.f290X;
                if (biVar != null) {
                    biVar.m280a(new ArrayList(map.keySet()), new ArrayList(map.values()), null);
                }
                m314a(c0037o, view, a4, c0042t, c0042t2, z, arrayList3);
            }
        }
        obj = a4;
        if (a3 != null) {
        }
        arrayList = new ArrayList();
        a = C0032j.m307a(b, c0042t2, arrayList, (C0107a) map, c0037o.f252d);
        view2 = (View) map.get(this.f224v.get(0));
        if (view2 != null) {
            if (a != null) {
                ar.m215a(a, view2);
            }
            if (obj != null) {
                ar.m215a(obj, view2);
            }
        }
        c0033k = new C0033k(this, c0042t);
        arrayList2 = new ArrayList();
        c0107a = new C0107a();
        z2 = true;
        if (c0042t != null) {
            if (z) {
            }
        }
        a2 = ar.m210a(a3, a, obj, z2);
        if (a2 != null) {
            ar.m218a(a3, obj, view, c0033k, c0037o.f252d, c0037o.f251c, c0037o.f249a, arrayList2, map, c0107a, arrayList3);
            m320a(view, c0037o, i, a2);
            ar.m217a(a2, c0037o.f252d, true);
            m311a(c0037o, i, a2);
            ar.m214a((ViewGroup) view, a2);
            ar.m213a(view, c0037o.f252d, a3, arrayList2, a, arrayList, obj, arrayList3, a2, c0037o.f250b, c0107a);
        }
        if (a2 == null) {
        }
    }

    private C0107a m322b(C0037o c0037o, C0042t c0042t, boolean z) {
        C0107a c0107a = new C0107a();
        View g = c0042t.m386g();
        if (g == null || this.f223u == null) {
            return c0107a;
        }
        ar.m222a((Map) c0107a, g);
        if (z) {
            return C0032j.m304a(this.f223u, this.f224v, c0107a);
        }
        c0107a.m602a(this.f224v);
        return c0107a;
    }

    private static Object m323b(C0042t c0042t, boolean z) {
        if (c0042t == null) {
            return null;
        }
        return ar.m208a(z ? c0042t.m400r() : c0042t.m401s());
    }

    private void m324b(C0037o c0037o, C0107a c0107a, boolean z) {
        int size = c0107a.size();
        for (int i = 0; i < size; i++) {
            String str = (String) c0107a.m598b(i);
            String a = ar.m211a((View) c0107a.m599c(i));
            if (z) {
                C0032j.m317a(c0037o.f249a, str, a);
            } else {
                C0032j.m317a(c0037o.f249a, a, str);
            }
        }
    }

    private void m325b(SparseArray sparseArray, SparseArray sparseArray2) {
        if (this.f204b.f120p.m79a()) {
            for (C0036n c0036n = this.f205c; c0036n != null; c0036n = c0036n.f240a) {
                switch (c0036n.f242c) {
                    case C0243l.View_android_focusable /*1*/:
                        m326b(sparseArray, sparseArray2, c0036n.f243d);
                        break;
                    case C0243l.View_paddingStart /*2*/:
                        C0042t c0042t = c0036n.f243d;
                        if (this.f204b.f111g != null) {
                            C0042t c0042t2 = c0042t;
                            for (int i = 0; i < this.f204b.f111g.size(); i++) {
                                C0042t c0042t3 = (C0042t) this.f204b.f111g.get(i);
                                if (c0042t2 == null || c0042t3.f314x == c0042t2.f314x) {
                                    if (c0042t3 == c0042t2) {
                                        c0042t2 = null;
                                        sparseArray2.remove(c0042t3.f314x);
                                    } else {
                                        C0032j.m319a(sparseArray, sparseArray2, c0042t3);
                                    }
                                }
                            }
                        }
                        m326b(sparseArray, sparseArray2, c0036n.f243d);
                        break;
                    case C0243l.View_paddingEnd /*3*/:
                        C0032j.m319a(sparseArray, sparseArray2, c0036n.f243d);
                        break;
                    case C0243l.View_theme /*4*/:
                        C0032j.m319a(sparseArray, sparseArray2, c0036n.f243d);
                        break;
                    case C0243l.Toolbar_contentInsetStart /*5*/:
                        m326b(sparseArray, sparseArray2, c0036n.f243d);
                        break;
                    case C0243l.Toolbar_contentInsetEnd /*6*/:
                        C0032j.m319a(sparseArray, sparseArray2, c0036n.f243d);
                        break;
                    case C0243l.Toolbar_contentInsetLeft /*7*/:
                        m326b(sparseArray, sparseArray2, c0036n.f243d);
                        break;
                    default:
                        break;
                }
            }
        }
    }

    private void m326b(SparseArray sparseArray, SparseArray sparseArray2, C0042t c0042t) {
        if (c0042t != null) {
            int i = c0042t.f314x;
            if (i != 0) {
                if (!c0042t.m383e()) {
                    sparseArray2.put(i, c0042t);
                }
                if (sparseArray.get(i) == c0042t) {
                    sparseArray.remove(i);
                }
            }
        }
    }

    public C0037o m327a(boolean z, C0037o c0037o, SparseArray sparseArray, SparseArray sparseArray2) {
        if (af.f104a) {
            Log.v("FragmentManager", "popFromBackStack: " + this);
            m332a("  ", null, new PrintWriter(new C0112e("FragmentManager")), null);
        }
        if (f203a) {
            if (c0037o == null) {
                if (!(sparseArray.size() == 0 && sparseArray2.size() == 0)) {
                    c0037o = m300a(sparseArray, sparseArray2, true);
                }
            } else if (!z) {
                C0032j.m315a(c0037o, this.f224v, this.f223u);
            }
        }
        m329a(-1);
        int i = c0037o != null ? 0 : this.f213k;
        int i2 = c0037o != null ? 0 : this.f212j;
        C0036n c0036n = this.f206d;
        while (c0036n != null) {
            int i3 = c0037o != null ? 0 : c0036n.f246g;
            int i4 = c0037o != null ? 0 : c0036n.f247h;
            C0042t c0042t;
            C0042t c0042t2;
            switch (c0036n.f242c) {
                case C0243l.View_android_focusable /*1*/:
                    c0042t = c0036n.f243d;
                    c0042t.f273G = i4;
                    this.f204b.m162a(c0042t, af.m146c(i2), i);
                    break;
                case C0243l.View_paddingStart /*2*/:
                    c0042t = c0036n.f243d;
                    if (c0042t != null) {
                        c0042t.f273G = i4;
                        this.f204b.m162a(c0042t, af.m146c(i2), i);
                    }
                    if (c0036n.f248i == null) {
                        break;
                    }
                    for (int i5 = 0; i5 < c0036n.f248i.size(); i5++) {
                        c0042t2 = (C0042t) c0036n.f248i.get(i5);
                        c0042t2.f273G = i3;
                        this.f204b.m164a(c0042t2, false);
                    }
                    break;
                case C0243l.View_paddingEnd /*3*/:
                    c0042t2 = c0036n.f243d;
                    c0042t2.f273G = i3;
                    this.f204b.m164a(c0042t2, false);
                    break;
                case C0243l.View_theme /*4*/:
                    c0042t2 = c0036n.f243d;
                    c0042t2.f273G = i3;
                    this.f204b.m180c(c0042t2, af.m146c(i2), i);
                    break;
                case C0243l.Toolbar_contentInsetStart /*5*/:
                    c0042t = c0036n.f243d;
                    c0042t.f273G = i4;
                    this.f204b.m174b(c0042t, af.m146c(i2), i);
                    break;
                case C0243l.Toolbar_contentInsetEnd /*6*/:
                    c0042t2 = c0036n.f243d;
                    c0042t2.f273G = i3;
                    this.f204b.m186e(c0042t2, af.m146c(i2), i);
                    break;
                case C0243l.Toolbar_contentInsetLeft /*7*/:
                    c0042t2 = c0036n.f243d;
                    c0042t2.f273G = i3;
                    this.f204b.m182d(c0042t2, af.m146c(i2), i);
                    break;
                default:
                    throw new IllegalArgumentException("Unknown cmd: " + c0036n.f242c);
            }
            c0036n = c0036n.f241b;
        }
        if (z) {
            this.f204b.m153a(this.f204b.f118n, af.m146c(i2), i, true);
            c0037o = null;
        }
        if (this.f218p >= 0) {
            this.f204b.m172b(this.f218p);
            this.f218p = -1;
        }
        return c0037o;
    }

    public String m328a() {
        return this.f216n;
    }

    void m329a(int i) {
        if (this.f214l) {
            if (af.f104a) {
                Log.v("FragmentManager", "Bump nesting in " + this + " by " + i);
            }
            for (C0036n c0036n = this.f205c; c0036n != null; c0036n = c0036n.f240a) {
                C0042t c0042t;
                if (c0036n.f243d != null) {
                    c0042t = c0036n.f243d;
                    c0042t.f308r += i;
                    if (af.f104a) {
                        Log.v("FragmentManager", "Bump nesting of " + c0036n.f243d + " to " + c0036n.f243d.f308r);
                    }
                }
                if (c0036n.f248i != null) {
                    for (int size = c0036n.f248i.size() - 1; size >= 0; size--) {
                        c0042t = (C0042t) c0036n.f248i.get(size);
                        c0042t.f308r += i;
                        if (af.f104a) {
                            Log.v("FragmentManager", "Bump nesting of " + c0042t + " to " + c0042t.f308r);
                        }
                    }
                }
            }
        }
    }

    void m330a(C0036n c0036n) {
        if (this.f205c == null) {
            this.f206d = c0036n;
            this.f205c = c0036n;
        } else {
            c0036n.f241b = this.f206d;
            this.f206d.f240a = c0036n;
            this.f206d = c0036n;
        }
        c0036n.f244e = this.f208f;
        c0036n.f245f = this.f209g;
        c0036n.f246g = this.f210h;
        c0036n.f247h = this.f211i;
        this.f207e++;
    }

    public void m331a(SparseArray sparseArray, SparseArray sparseArray2) {
        if (this.f204b.f120p.m79a()) {
            for (C0036n c0036n = this.f206d; c0036n != null; c0036n = c0036n.f241b) {
                switch (c0036n.f242c) {
                    case C0243l.View_android_focusable /*1*/:
                        C0032j.m319a(sparseArray, sparseArray2, c0036n.f243d);
                        break;
                    case C0243l.View_paddingStart /*2*/:
                        if (c0036n.f248i != null) {
                            for (int size = c0036n.f248i.size() - 1; size >= 0; size--) {
                                m326b(sparseArray, sparseArray2, (C0042t) c0036n.f248i.get(size));
                            }
                        }
                        C0032j.m319a(sparseArray, sparseArray2, c0036n.f243d);
                        break;
                    case C0243l.View_paddingEnd /*3*/:
                        m326b(sparseArray, sparseArray2, c0036n.f243d);
                        break;
                    case C0243l.View_theme /*4*/:
                        m326b(sparseArray, sparseArray2, c0036n.f243d);
                        break;
                    case C0243l.Toolbar_contentInsetStart /*5*/:
                        C0032j.m319a(sparseArray, sparseArray2, c0036n.f243d);
                        break;
                    case C0243l.Toolbar_contentInsetEnd /*6*/:
                        m326b(sparseArray, sparseArray2, c0036n.f243d);
                        break;
                    case C0243l.Toolbar_contentInsetLeft /*7*/:
                        C0032j.m319a(sparseArray, sparseArray2, c0036n.f243d);
                        break;
                    default:
                        break;
                }
            }
        }
    }

    public void m332a(String str, FileDescriptor fileDescriptor, PrintWriter printWriter, String[] strArr) {
        m333a(str, printWriter, true);
    }

    public void m333a(String str, PrintWriter printWriter, boolean z) {
        if (z) {
            printWriter.print(str);
            printWriter.print("mName=");
            printWriter.print(this.f216n);
            printWriter.print(" mIndex=");
            printWriter.print(this.f218p);
            printWriter.print(" mCommitted=");
            printWriter.println(this.f217o);
            if (this.f212j != 0) {
                printWriter.print(str);
                printWriter.print("mTransition=#");
                printWriter.print(Integer.toHexString(this.f212j));
                printWriter.print(" mTransitionStyle=#");
                printWriter.println(Integer.toHexString(this.f213k));
            }
            if (!(this.f208f == 0 && this.f209g == 0)) {
                printWriter.print(str);
                printWriter.print("mEnterAnim=#");
                printWriter.print(Integer.toHexString(this.f208f));
                printWriter.print(" mExitAnim=#");
                printWriter.println(Integer.toHexString(this.f209g));
            }
            if (!(this.f210h == 0 && this.f211i == 0)) {
                printWriter.print(str);
                printWriter.print("mPopEnterAnim=#");
                printWriter.print(Integer.toHexString(this.f210h));
                printWriter.print(" mPopExitAnim=#");
                printWriter.println(Integer.toHexString(this.f211i));
            }
            if (!(this.f219q == 0 && this.f220r == null)) {
                printWriter.print(str);
                printWriter.print("mBreadCrumbTitleRes=#");
                printWriter.print(Integer.toHexString(this.f219q));
                printWriter.print(" mBreadCrumbTitleText=");
                printWriter.println(this.f220r);
            }
            if (!(this.f221s == 0 && this.f222t == null)) {
                printWriter.print(str);
                printWriter.print("mBreadCrumbShortTitleRes=#");
                printWriter.print(Integer.toHexString(this.f221s));
                printWriter.print(" mBreadCrumbShortTitleText=");
                printWriter.println(this.f222t);
            }
        }
        if (this.f205c != null) {
            printWriter.print(str);
            printWriter.println("Operations:");
            String str2 = str + "    ";
            int i = 0;
            C0036n c0036n = this.f205c;
            while (c0036n != null) {
                String str3;
                switch (c0036n.f242c) {
                    case C0243l.View_android_theme /*0*/:
                        str3 = "NULL";
                        break;
                    case C0243l.View_android_focusable /*1*/:
                        str3 = "ADD";
                        break;
                    case C0243l.View_paddingStart /*2*/:
                        str3 = "REPLACE";
                        break;
                    case C0243l.View_paddingEnd /*3*/:
                        str3 = "REMOVE";
                        break;
                    case C0243l.View_theme /*4*/:
                        str3 = "HIDE";
                        break;
                    case C0243l.Toolbar_contentInsetStart /*5*/:
                        str3 = "SHOW";
                        break;
                    case C0243l.Toolbar_contentInsetEnd /*6*/:
                        str3 = "DETACH";
                        break;
                    case C0243l.Toolbar_contentInsetLeft /*7*/:
                        str3 = "ATTACH";
                        break;
                    default:
                        str3 = "cmd=" + c0036n.f242c;
                        break;
                }
                printWriter.print(str);
                printWriter.print("  Op #");
                printWriter.print(i);
                printWriter.print(": ");
                printWriter.print(str3);
                printWriter.print(" ");
                printWriter.println(c0036n.f243d);
                if (z) {
                    if (!(c0036n.f244e == 0 && c0036n.f245f == 0)) {
                        printWriter.print(str);
                        printWriter.print("enterAnim=#");
                        printWriter.print(Integer.toHexString(c0036n.f244e));
                        printWriter.print(" exitAnim=#");
                        printWriter.println(Integer.toHexString(c0036n.f245f));
                    }
                    if (!(c0036n.f246g == 0 && c0036n.f247h == 0)) {
                        printWriter.print(str);
                        printWriter.print("popEnterAnim=#");
                        printWriter.print(Integer.toHexString(c0036n.f246g));
                        printWriter.print(" popExitAnim=#");
                        printWriter.println(Integer.toHexString(c0036n.f247h));
                    }
                }
                if (c0036n.f248i != null && c0036n.f248i.size() > 0) {
                    for (int i2 = 0; i2 < c0036n.f248i.size(); i2++) {
                        printWriter.print(str2);
                        if (c0036n.f248i.size() == 1) {
                            printWriter.print("Removed: ");
                        } else {
                            if (i2 == 0) {
                                printWriter.println("Removed:");
                            }
                            printWriter.print(str2);
                            printWriter.print("  #");
                            printWriter.print(i2);
                            printWriter.print(": ");
                        }
                        printWriter.println(c0036n.f248i.get(i2));
                    }
                }
                c0036n = c0036n.f240a;
                i++;
            }
        }
    }

    public void run() {
        if (af.f104a) {
            Log.v("FragmentManager", "Run: " + this);
        }
        if (!this.f214l || this.f218p >= 0) {
            C0037o a;
            m329a(1);
            if (f203a) {
                SparseArray sparseArray = new SparseArray();
                SparseArray sparseArray2 = new SparseArray();
                m325b(sparseArray, sparseArray2);
                a = m300a(sparseArray, sparseArray2, false);
            } else {
                a = null;
            }
            int i = a != null ? 0 : this.f213k;
            int i2 = a != null ? 0 : this.f212j;
            C0036n c0036n = this.f205c;
            while (c0036n != null) {
                int i3 = a != null ? 0 : c0036n.f244e;
                int i4 = a != null ? 0 : c0036n.f245f;
                C0042t c0042t;
                switch (c0036n.f242c) {
                    case C0243l.View_android_focusable /*1*/:
                        c0042t = c0036n.f243d;
                        c0042t.f273G = i3;
                        this.f204b.m164a(c0042t, false);
                        break;
                    case C0243l.View_paddingStart /*2*/:
                        C0042t c0042t2 = c0036n.f243d;
                        int i5 = c0042t2.f314x;
                        if (this.f204b.f111g != null) {
                            int size = this.f204b.f111g.size() - 1;
                            while (size >= 0) {
                                c0042t = (C0042t) this.f204b.f111g.get(size);
                                if (af.f104a) {
                                    Log.v("FragmentManager", "OP_REPLACE: adding=" + c0042t2 + " old=" + c0042t);
                                }
                                if (c0042t.f314x == i5) {
                                    if (c0042t == c0042t2) {
                                        c0042t = null;
                                        c0036n.f243d = null;
                                        size--;
                                        c0042t2 = c0042t;
                                    } else {
                                        if (c0036n.f248i == null) {
                                            c0036n.f248i = new ArrayList();
                                        }
                                        c0036n.f248i.add(c0042t);
                                        c0042t.f273G = i4;
                                        if (this.f214l) {
                                            c0042t.f308r++;
                                            if (af.f104a) {
                                                Log.v("FragmentManager", "Bump nesting of " + c0042t + " to " + c0042t.f308r);
                                            }
                                        }
                                        this.f204b.m162a(c0042t, i2, i);
                                    }
                                }
                                c0042t = c0042t2;
                                size--;
                                c0042t2 = c0042t;
                            }
                        }
                        if (c0042t2 == null) {
                            break;
                        }
                        c0042t2.f273G = i3;
                        this.f204b.m164a(c0042t2, false);
                        break;
                    case C0243l.View_paddingEnd /*3*/:
                        c0042t = c0036n.f243d;
                        c0042t.f273G = i4;
                        this.f204b.m162a(c0042t, i2, i);
                        break;
                    case C0243l.View_theme /*4*/:
                        c0042t = c0036n.f243d;
                        c0042t.f273G = i4;
                        this.f204b.m174b(c0042t, i2, i);
                        break;
                    case C0243l.Toolbar_contentInsetStart /*5*/:
                        c0042t = c0036n.f243d;
                        c0042t.f273G = i3;
                        this.f204b.m180c(c0042t, i2, i);
                        break;
                    case C0243l.Toolbar_contentInsetEnd /*6*/:
                        c0042t = c0036n.f243d;
                        c0042t.f273G = i4;
                        this.f204b.m182d(c0042t, i2, i);
                        break;
                    case C0243l.Toolbar_contentInsetLeft /*7*/:
                        c0042t = c0036n.f243d;
                        c0042t.f273G = i3;
                        this.f204b.m186e(c0042t, i2, i);
                        break;
                    default:
                        throw new IllegalArgumentException("Unknown cmd: " + c0036n.f242c);
                }
                c0036n = c0036n.f240a;
            }
            this.f204b.m153a(this.f204b.f118n, i2, i, true);
            if (this.f214l) {
                this.f204b.m160a(this);
                return;
            }
            return;
        }
        throw new IllegalStateException("addToBackStack() called after commit()");
    }

    public String toString() {
        StringBuilder stringBuilder = new StringBuilder(128);
        stringBuilder.append("BackStackEntry{");
        stringBuilder.append(Integer.toHexString(System.identityHashCode(this)));
        if (this.f218p >= 0) {
            stringBuilder.append(" #");
            stringBuilder.append(this.f218p);
        }
        if (this.f216n != null) {
            stringBuilder.append(" ");
            stringBuilder.append(this.f216n);
        }
        stringBuilder.append("}");
        return stringBuilder.toString();
    }
}
