package android.support.v7.view.menu;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.content.res.Resources;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.support.v4.p002b.C0020a;
import android.support.v4.p004h.C0161n;
import android.support.v4.p004h.ar;
import android.support.v4.p008d.p009a.C0089a;
import android.support.v7.p015b.C0234c;
import android.util.SparseArray;
import android.view.ContextMenu.ContextMenuInfo;
import android.view.KeyCharacterMap.KeyData;
import android.view.KeyEvent;
import android.view.MenuItem;
import android.view.SubMenu;
import android.view.View;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/* renamed from: android.support.v7.view.menu.i */
public class C0264i implements C0089a {
    private static final int[] f957d;
    CharSequence f958a;
    Drawable f959b;
    View f960c;
    private final Context f961e;
    private final Resources f962f;
    private boolean f963g;
    private boolean f964h;
    private C0203j f965i;
    private ArrayList f966j;
    private ArrayList f967k;
    private boolean f968l;
    private ArrayList f969m;
    private ArrayList f970n;
    private boolean f971o;
    private int f972p;
    private ContextMenuInfo f973q;
    private boolean f974r;
    private boolean f975s;
    private boolean f976t;
    private boolean f977u;
    private ArrayList f978v;
    private CopyOnWriteArrayList f979w;
    private C0272m f980x;
    private boolean f981y;

    static {
        f957d = new int[]{1, 4, 5, 3, 2, 0};
    }

    public C0264i(Context context) {
        this.f972p = 0;
        this.f974r = false;
        this.f975s = false;
        this.f976t = false;
        this.f977u = false;
        this.f978v = new ArrayList();
        this.f979w = new CopyOnWriteArrayList();
        this.f961e = context;
        this.f962f = context.getResources();
        this.f966j = new ArrayList();
        this.f967k = new ArrayList();
        this.f968l = true;
        this.f969m = new ArrayList();
        this.f970n = new ArrayList();
        this.f971o = true;
        m2099e(true);
    }

    private static int m2092a(ArrayList arrayList, int i) {
        for (int size = arrayList.size() - 1; size >= 0; size--) {
            if (((C0272m) arrayList.get(size)).m2224c() <= i) {
                return size + 1;
            }
        }
        return 0;
    }

    private C0272m m2093a(int i, int i2, int i3, int i4, CharSequence charSequence, int i5) {
        return new C0272m(this, i, i2, i3, i4, charSequence, i5);
    }

    private void m2094a(int i, CharSequence charSequence, int i2, Drawable drawable, View view) {
        Resources d = m2129d();
        if (view != null) {
            this.f960c = view;
            this.f958a = null;
            this.f959b = null;
        } else {
            if (i > 0) {
                this.f958a = d.getText(i);
            } else if (charSequence != null) {
                this.f958a = charSequence;
            }
            if (i2 > 0) {
                this.f959b = C0020a.m74a(m2131e(), i2);
            } else if (drawable != null) {
                this.f959b = drawable;
            }
            this.f960c = null;
        }
        m2123b(false);
    }

    private void m2095a(int i, boolean z) {
        if (i >= 0 && i < this.f966j.size()) {
            this.f966j.remove(i);
            if (z) {
                m2123b(true);
            }
        }
    }

    private boolean m2096a(ad adVar, C0267x c0267x) {
        boolean z = false;
        if (this.f979w.isEmpty()) {
            return false;
        }
        if (c0267x != null) {
            z = c0267x.m2172a(adVar);
        }
        Iterator it = this.f979w.iterator();
        boolean z2 = z;
        while (it.hasNext()) {
            WeakReference weakReference = (WeakReference) it.next();
            C0267x c0267x2 = (C0267x) weakReference.get();
            if (c0267x2 == null) {
                this.f979w.remove(weakReference);
                z = z2;
            } else {
                z = !z2 ? c0267x2.m2172a(adVar) : z2;
            }
            z2 = z;
        }
        return z2;
    }

    private static int m2097d(int i) {
        int i2 = (-65536 & i) >> 16;
        if (i2 >= 0 && i2 < f957d.length) {
            return (f957d[i2] << 16) | (65535 & i);
        }
        throw new IllegalArgumentException("order does not contain a valid category.");
    }

    private void m2098d(boolean z) {
        if (!this.f979w.isEmpty()) {
            m2133g();
            Iterator it = this.f979w.iterator();
            while (it.hasNext()) {
                WeakReference weakReference = (WeakReference) it.next();
                C0267x c0267x = (C0267x) weakReference.get();
                if (c0267x == null) {
                    this.f979w.remove(weakReference);
                } else {
                    c0267x.m2174b(z);
                }
            }
            m2134h();
        }
    }

    private void m2099e(boolean z) {
        boolean z2 = true;
        if (!(z && this.f962f.getConfiguration().keyboard != 1 && this.f962f.getBoolean(C0234c.abc_config_showMenuShortcutsWhenKeyboardPresent))) {
            z2 = false;
        }
        this.f964h = z2;
    }

    public int m2100a(int i, int i2) {
        int size = size();
        if (i2 < 0) {
            i2 = 0;
        }
        for (int i3 = i2; i3 < size; i3++) {
            if (((C0272m) this.f966j.get(i3)).getGroupId() == i) {
                return i3;
            }
        }
        return -1;
    }

    public C0264i m2101a(int i) {
        this.f972p = i;
        return this;
    }

    protected C0264i m2102a(Drawable drawable) {
        m2094a(0, null, 0, drawable, null);
        return this;
    }

    protected C0264i m2103a(View view) {
        m2094a(0, null, 0, null, view);
        return this;
    }

    protected C0264i m2104a(CharSequence charSequence) {
        m2094a(0, charSequence, 0, null, null);
        return this;
    }

    C0272m m2105a(int i, KeyEvent keyEvent) {
        List list = this.f978v;
        list.clear();
        m2114a(list, i, keyEvent);
        if (list.isEmpty()) {
            return null;
        }
        int metaState = keyEvent.getMetaState();
        KeyData keyData = new KeyData();
        keyEvent.getKeyData(keyData);
        int size = list.size();
        if (size == 1) {
            return (C0272m) list.get(0);
        }
        boolean b = m2124b();
        for (int i2 = 0; i2 < size; i2++) {
            C0272m c0272m = (C0272m) list.get(i2);
            char alphabeticShortcut = b ? c0272m.getAlphabeticShortcut() : c0272m.getNumericShortcut();
            if (alphabeticShortcut == keyData.meta[0] && (metaState & 2) == 0) {
                return c0272m;
            }
            if (alphabeticShortcut == keyData.meta[2] && (metaState & 2) != 0) {
                return c0272m;
            }
            if (b && alphabeticShortcut == '\b' && i == 67) {
                return c0272m;
            }
        }
        return null;
    }

    protected MenuItem m2106a(int i, int i2, int i3, CharSequence charSequence) {
        int d = C0264i.m2097d(i3);
        MenuItem a = m2093a(i, i2, i3, d, charSequence, this.f972p);
        if (this.f973q != null) {
            a.m2219a(this.f973q);
        }
        this.f966j.add(C0264i.m2092a(this.f966j, d), a);
        m2123b(true);
        return a;
    }

    protected String m2107a() {
        return "android:menu:actionviewstates";
    }

    public void m2108a(Bundle bundle) {
        int size = size();
        int i = 0;
        SparseArray sparseArray = null;
        while (i < size) {
            MenuItem item = getItem(i);
            View a = ar.m862a(item);
            if (!(a == null || a.getId() == -1)) {
                if (sparseArray == null) {
                    sparseArray = new SparseArray();
                }
                a.saveHierarchyState(sparseArray);
                if (ar.m866c(item)) {
                    bundle.putInt("android:menu:expandedactionview", item.getItemId());
                }
            }
            SparseArray sparseArray2 = sparseArray;
            if (item.hasSubMenu()) {
                ((ad) item.getSubMenu()).m2108a(bundle);
            }
            i++;
            sparseArray = sparseArray2;
        }
        if (sparseArray != null) {
            bundle.putSparseParcelableArray(m2107a(), sparseArray);
        }
    }

    public void m2109a(C0203j c0203j) {
        this.f965i = c0203j;
    }

    void m2110a(C0272m c0272m) {
        this.f968l = true;
        m2123b(true);
    }

    public void m2111a(C0267x c0267x) {
        m2112a(c0267x, this.f961e);
    }

    public void m2112a(C0267x c0267x, Context context) {
        this.f979w.add(new WeakReference(c0267x));
        c0267x.m2170a(context, this);
        this.f971o = true;
    }

    void m2113a(MenuItem menuItem) {
        int groupId = menuItem.getGroupId();
        int size = this.f966j.size();
        for (int i = 0; i < size; i++) {
            MenuItem menuItem2 = (C0272m) this.f966j.get(i);
            if (menuItem2.getGroupId() == groupId && menuItem2.m2231g() && menuItem2.isCheckable()) {
                menuItem2.m2222b(menuItem2 == menuItem);
            }
        }
    }

    void m2114a(List list, int i, KeyEvent keyEvent) {
        boolean b = m2124b();
        int metaState = keyEvent.getMetaState();
        KeyData keyData = new KeyData();
        if (keyEvent.getKeyData(keyData) || i == 67) {
            int size = this.f966j.size();
            for (int i2 = 0; i2 < size; i2++) {
                C0272m c0272m = (C0272m) this.f966j.get(i2);
                if (c0272m.hasSubMenu()) {
                    ((C0264i) c0272m.getSubMenu()).m2114a(list, i, keyEvent);
                }
                char alphabeticShortcut = b ? c0272m.getAlphabeticShortcut() : c0272m.getNumericShortcut();
                if ((metaState & 5) == 0 && alphabeticShortcut != '\u0000' && ((alphabeticShortcut == keyData.meta[0] || alphabeticShortcut == keyData.meta[2] || (b && alphabeticShortcut == '\b' && i == 67)) && c0272m.isEnabled())) {
                    list.add(c0272m);
                }
            }
        }
    }

    public final void m2115a(boolean z) {
        if (!this.f977u) {
            this.f977u = true;
            Iterator it = this.f979w.iterator();
            while (it.hasNext()) {
                WeakReference weakReference = (WeakReference) it.next();
                C0267x c0267x = (C0267x) weakReference.get();
                if (c0267x == null) {
                    this.f979w.remove(weakReference);
                } else {
                    c0267x.m2171a(this, z);
                }
            }
            this.f977u = false;
        }
    }

    boolean m2116a(C0264i c0264i, MenuItem menuItem) {
        return this.f965i != null && this.f965i.m1661a(c0264i, menuItem);
    }

    public boolean m2117a(MenuItem menuItem, int i) {
        return m2118a(menuItem, null, i);
    }

    public boolean m2118a(MenuItem menuItem, C0267x c0267x, int i) {
        C0272m c0272m = (C0272m) menuItem;
        if (c0272m == null || !c0272m.isEnabled()) {
            return false;
        }
        boolean b = c0272m.m2223b();
        C0161n a = c0272m.m2216a();
        boolean z = a != null && a.m1343e();
        boolean expandActionView;
        if (c0272m.m2238n()) {
            expandActionView = c0272m.expandActionView() | b;
            if (!expandActionView) {
                return expandActionView;
            }
            m2115a(true);
            return expandActionView;
        } else if (c0272m.hasSubMenu() || z) {
            m2115a(false);
            if (!c0272m.hasSubMenu()) {
                c0272m.m2218a(new ad(m2131e(), this, c0272m));
            }
            ad adVar = (ad) c0272m.getSubMenu();
            if (z) {
                a.m1338a((SubMenu) adVar);
            }
            expandActionView = m2096a(adVar, c0267x) | b;
            if (expandActionView) {
                return expandActionView;
            }
            m2115a(true);
            return expandActionView;
        } else {
            if ((i & 1) == 0) {
                m2115a(true);
            }
            return b;
        }
    }

    public MenuItem add(int i) {
        return m2106a(0, 0, 0, this.f962f.getString(i));
    }

    public MenuItem add(int i, int i2, int i3, int i4) {
        return m2106a(i, i2, i3, this.f962f.getString(i4));
    }

    public MenuItem add(int i, int i2, int i3, CharSequence charSequence) {
        return m2106a(i, i2, i3, charSequence);
    }

    public MenuItem add(CharSequence charSequence) {
        return m2106a(0, 0, 0, charSequence);
    }

    public int addIntentOptions(int i, int i2, int i3, ComponentName componentName, Intent[] intentArr, Intent intent, int i4, MenuItem[] menuItemArr) {
        PackageManager packageManager = this.f961e.getPackageManager();
        List queryIntentActivityOptions = packageManager.queryIntentActivityOptions(componentName, intentArr, intent, 0);
        int size = queryIntentActivityOptions != null ? queryIntentActivityOptions.size() : 0;
        if ((i4 & 1) == 0) {
            removeGroup(i);
        }
        for (int i5 = 0; i5 < size; i5++) {
            ResolveInfo resolveInfo = (ResolveInfo) queryIntentActivityOptions.get(i5);
            Intent intent2 = new Intent(resolveInfo.specificIndex < 0 ? intent : intentArr[resolveInfo.specificIndex]);
            intent2.setComponent(new ComponentName(resolveInfo.activityInfo.applicationInfo.packageName, resolveInfo.activityInfo.name));
            MenuItem intent3 = add(i, i2, i3, resolveInfo.loadLabel(packageManager)).setIcon(resolveInfo.loadIcon(packageManager)).setIntent(intent2);
            if (menuItemArr != null && resolveInfo.specificIndex >= 0) {
                menuItemArr[resolveInfo.specificIndex] = intent3;
            }
        }
        return size;
    }

    public SubMenu addSubMenu(int i) {
        return addSubMenu(0, 0, 0, this.f962f.getString(i));
    }

    public SubMenu addSubMenu(int i, int i2, int i3, int i4) {
        return addSubMenu(i, i2, i3, this.f962f.getString(i4));
    }

    public SubMenu addSubMenu(int i, int i2, int i3, CharSequence charSequence) {
        C0272m c0272m = (C0272m) m2106a(i, i2, i3, charSequence);
        ad adVar = new ad(this.f961e, this, c0272m);
        c0272m.m2218a(adVar);
        return adVar;
    }

    public SubMenu addSubMenu(CharSequence charSequence) {
        return addSubMenu(0, 0, 0, charSequence);
    }

    public int m2119b(int i) {
        int size = size();
        for (int i2 = 0; i2 < size; i2++) {
            if (((C0272m) this.f966j.get(i2)).getItemId() == i) {
                return i2;
            }
        }
        return -1;
    }

    public void m2120b(Bundle bundle) {
        if (bundle != null) {
            MenuItem item;
            SparseArray sparseParcelableArray = bundle.getSparseParcelableArray(m2107a());
            int size = size();
            for (int i = 0; i < size; i++) {
                item = getItem(i);
                View a = ar.m862a(item);
                if (!(a == null || a.getId() == -1)) {
                    a.restoreHierarchyState(sparseParcelableArray);
                }
                if (item.hasSubMenu()) {
                    ((ad) item.getSubMenu()).m2120b(bundle);
                }
            }
            int i2 = bundle.getInt("android:menu:expandedactionview");
            if (i2 > 0) {
                item = findItem(i2);
                if (item != null) {
                    ar.m865b(item);
                }
            }
        }
    }

    void m2121b(C0272m c0272m) {
        this.f971o = true;
        m2123b(true);
    }

    public void m2122b(C0267x c0267x) {
        Iterator it = this.f979w.iterator();
        while (it.hasNext()) {
            WeakReference weakReference = (WeakReference) it.next();
            C0267x c0267x2 = (C0267x) weakReference.get();
            if (c0267x2 == null || c0267x2 == c0267x) {
                this.f979w.remove(weakReference);
            }
        }
    }

    public void m2123b(boolean z) {
        if (this.f974r) {
            this.f975s = true;
            return;
        }
        if (z) {
            this.f968l = true;
            this.f971o = true;
        }
        m2098d(z);
    }

    boolean m2124b() {
        return this.f963g;
    }

    public int m2125c(int i) {
        return m2100a(i, 0);
    }

    public void m2126c(boolean z) {
        this.f981y = z;
    }

    public boolean m2127c() {
        return this.f964h;
    }

    public boolean m2128c(C0272m c0272m) {
        boolean z = false;
        if (!this.f979w.isEmpty()) {
            m2133g();
            Iterator it = this.f979w.iterator();
            boolean z2 = false;
            while (it.hasNext()) {
                WeakReference weakReference = (WeakReference) it.next();
                C0267x c0267x = (C0267x) weakReference.get();
                if (c0267x == null) {
                    this.f979w.remove(weakReference);
                    z = z2;
                } else {
                    z = c0267x.m2173a(this, c0272m);
                    if (z) {
                        break;
                    }
                }
                z2 = z;
            }
            z = z2;
            m2134h();
            if (z) {
                this.f980x = c0272m;
            }
        }
        return z;
    }

    public void clear() {
        if (this.f980x != null) {
            m2130d(this.f980x);
        }
        this.f966j.clear();
        m2123b(true);
    }

    public void clearHeader() {
        this.f959b = null;
        this.f958a = null;
        this.f960c = null;
        m2123b(false);
    }

    public void close() {
        m2115a(true);
    }

    Resources m2129d() {
        return this.f962f;
    }

    public boolean m2130d(C0272m c0272m) {
        boolean z = false;
        if (!this.f979w.isEmpty() && this.f980x == c0272m) {
            m2133g();
            Iterator it = this.f979w.iterator();
            boolean z2 = false;
            while (it.hasNext()) {
                WeakReference weakReference = (WeakReference) it.next();
                C0267x c0267x = (C0267x) weakReference.get();
                if (c0267x == null) {
                    this.f979w.remove(weakReference);
                    z = z2;
                } else {
                    z = c0267x.m2176b(this, c0272m);
                    if (z) {
                        break;
                    }
                }
                z2 = z;
            }
            z = z2;
            m2134h();
            if (z) {
                this.f980x = null;
            }
        }
        return z;
    }

    public Context m2131e() {
        return this.f961e;
    }

    public void m2132f() {
        if (this.f965i != null) {
            this.f965i.m1660a(this);
        }
    }

    public MenuItem findItem(int i) {
        int size = size();
        for (int i2 = 0; i2 < size; i2++) {
            C0272m c0272m = (C0272m) this.f966j.get(i2);
            if (c0272m.getItemId() == i) {
                return c0272m;
            }
            if (c0272m.hasSubMenu()) {
                MenuItem findItem = c0272m.getSubMenu().findItem(i);
                if (findItem != null) {
                    return findItem;
                }
            }
        }
        return null;
    }

    public void m2133g() {
        if (!this.f974r) {
            this.f974r = true;
            this.f975s = false;
        }
    }

    public MenuItem getItem(int i) {
        return (MenuItem) this.f966j.get(i);
    }

    public void m2134h() {
        this.f974r = false;
        if (this.f975s) {
            this.f975s = false;
            m2123b(true);
        }
    }

    public boolean hasVisibleItems() {
        if (this.f981y) {
            return true;
        }
        int size = size();
        for (int i = 0; i < size; i++) {
            if (((C0272m) this.f966j.get(i)).isVisible()) {
                return true;
            }
        }
        return false;
    }

    public ArrayList m2135i() {
        if (!this.f968l) {
            return this.f967k;
        }
        this.f967k.clear();
        int size = this.f966j.size();
        for (int i = 0; i < size; i++) {
            C0272m c0272m = (C0272m) this.f966j.get(i);
            if (c0272m.isVisible()) {
                this.f967k.add(c0272m);
            }
        }
        this.f968l = false;
        this.f971o = true;
        return this.f967k;
    }

    public boolean isShortcutKey(int i, KeyEvent keyEvent) {
        return m2105a(i, keyEvent) != null;
    }

    public void m2136j() {
        ArrayList i = m2135i();
        if (this.f971o) {
            Iterator it = this.f979w.iterator();
            int i2 = 0;
            while (it.hasNext()) {
                int i3;
                WeakReference weakReference = (WeakReference) it.next();
                C0267x c0267x = (C0267x) weakReference.get();
                if (c0267x == null) {
                    this.f979w.remove(weakReference);
                    i3 = i2;
                } else {
                    i3 = c0267x.m2175b() | i2;
                }
                i2 = i3;
            }
            if (i2 != 0) {
                this.f969m.clear();
                this.f970n.clear();
                i2 = i.size();
                for (int i4 = 0; i4 < i2; i4++) {
                    C0272m c0272m = (C0272m) i.get(i4);
                    if (c0272m.m2234j()) {
                        this.f969m.add(c0272m);
                    } else {
                        this.f970n.add(c0272m);
                    }
                }
            } else {
                this.f969m.clear();
                this.f970n.clear();
                this.f970n.addAll(m2135i());
            }
            this.f971o = false;
        }
    }

    public ArrayList m2137k() {
        m2136j();
        return this.f969m;
    }

    public ArrayList m2138l() {
        m2136j();
        return this.f970n;
    }

    public CharSequence m2139m() {
        return this.f958a;
    }

    public Drawable m2140n() {
        return this.f959b;
    }

    public View m2141o() {
        return this.f960c;
    }

    public C0264i m2142p() {
        return this;
    }

    public boolean performIdentifierAction(int i, int i2) {
        return m2117a(findItem(i), i2);
    }

    public boolean performShortcut(int i, KeyEvent keyEvent, int i2) {
        MenuItem a = m2105a(i, keyEvent);
        boolean z = false;
        if (a != null) {
            z = m2117a(a, i2);
        }
        if ((i2 & 2) != 0) {
            m2115a(true);
        }
        return z;
    }

    boolean m2143q() {
        return this.f976t;
    }

    public C0272m m2144r() {
        return this.f980x;
    }

    /* JADX WARNING: inconsistent code. */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public void removeGroup(int r6) {
        /*
        r5 = this;
        r1 = 0;
        r3 = r5.m2125c(r6);
        if (r3 < 0) goto L_0x002b;
    L_0x0007:
        r0 = r5.f966j;
        r0 = r0.size();
        r4 = r0 - r3;
        r0 = r1;
    L_0x0010:
        r2 = r0 + 1;
        if (r0 >= r4) goto L_0x0027;
    L_0x0014:
        r0 = r5.f966j;
        r0 = r0.get(r3);
        r0 = (android.support.v7.view.menu.C0272m) r0;
        r0 = r0.getGroupId();
        if (r0 != r6) goto L_0x0027;
    L_0x0022:
        r5.m2095a(r3, r1);
        r0 = r2;
        goto L_0x0010;
    L_0x0027:
        r0 = 1;
        r5.m2123b(r0);
    L_0x002b:
        return;
        */
        throw new UnsupportedOperationException("Method not decompiled: android.support.v7.view.menu.i.removeGroup(int):void");
    }

    public void removeItem(int i) {
        m2095a(m2119b(i), true);
    }

    public void setGroupCheckable(int i, boolean z, boolean z2) {
        int size = this.f966j.size();
        for (int i2 = 0; i2 < size; i2++) {
            C0272m c0272m = (C0272m) this.f966j.get(i2);
            if (c0272m.getGroupId() == i) {
                c0272m.m2220a(z2);
                c0272m.setCheckable(z);
            }
        }
    }

    public void setGroupEnabled(int i, boolean z) {
        int size = this.f966j.size();
        for (int i2 = 0; i2 < size; i2++) {
            C0272m c0272m = (C0272m) this.f966j.get(i2);
            if (c0272m.getGroupId() == i) {
                c0272m.setEnabled(z);
            }
        }
    }

    public void setGroupVisible(int i, boolean z) {
        int size = this.f966j.size();
        int i2 = 0;
        boolean z2 = false;
        while (i2 < size) {
            C0272m c0272m = (C0272m) this.f966j.get(i2);
            boolean z3 = (c0272m.getGroupId() == i && c0272m.m2225c(z)) ? true : z2;
            i2++;
            z2 = z3;
        }
        if (z2) {
            m2123b(true);
        }
    }

    public void setQwertyMode(boolean z) {
        this.f963g = z;
        m2123b(false);
    }

    public int size() {
        return this.f966j.size();
    }
}
