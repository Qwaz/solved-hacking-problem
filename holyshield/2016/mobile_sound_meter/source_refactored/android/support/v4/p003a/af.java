package android.support.v4.p003a;

import android.content.Context;
import android.content.res.Configuration;
import android.content.res.TypedArray;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.os.Parcelable;
import android.support.v4.p004h.al;
import android.support.v4.p004h.bu;
import android.support.v4.p012g.C0111d;
import android.support.v4.p012g.C0112e;
import android.support.v7.p015b.C0243l;
import android.util.AttributeSet;
import android.util.Log;
import android.util.SparseArray;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.animation.AccelerateInterpolator;
import android.view.animation.AlphaAnimation;
import android.view.animation.Animation;
import android.view.animation.Animation.AnimationListener;
import android.view.animation.AnimationSet;
import android.view.animation.AnimationUtils;
import android.view.animation.DecelerateInterpolator;
import android.view.animation.Interpolator;
import android.view.animation.ScaleAnimation;
import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/* renamed from: android.support.v4.a.af */
final class af extends ad implements al {
    static final Interpolator f100A;
    static final Interpolator f101B;
    static final Interpolator f102C;
    static final Interpolator f103D;
    static boolean f104a;
    static final boolean f105b;
    static Field f106r;
    ArrayList f107c;
    Runnable[] f108d;
    boolean f109e;
    ArrayList f110f;
    ArrayList f111g;
    ArrayList f112h;
    ArrayList f113i;
    ArrayList f114j;
    ArrayList f115k;
    ArrayList f116l;
    ArrayList f117m;
    int f118n;
    ac f119o;
    aa f120p;
    C0042t f121q;
    boolean f122s;
    boolean f123t;
    boolean f124u;
    String f125v;
    boolean f126w;
    Bundle f127x;
    SparseArray f128y;
    Runnable f129z;

    static {
        boolean z = false;
        f104a = false;
        if (VERSION.SDK_INT >= 11) {
            z = true;
        }
        f105b = z;
        f106r = null;
        f100A = new DecelerateInterpolator(2.5f);
        f101B = new DecelerateInterpolator(1.5f);
        f102C = new AccelerateInterpolator(2.5f);
        f103D = new AccelerateInterpolator(1.5f);
    }

    af() {
        this.f118n = 0;
        this.f127x = null;
        this.f128y = null;
        this.f129z = new ag(this);
    }

    static Animation m139a(Context context, float f, float f2) {
        Animation alphaAnimation = new AlphaAnimation(f, f2);
        alphaAnimation.setInterpolator(f101B);
        alphaAnimation.setDuration(220);
        return alphaAnimation;
    }

    static Animation m140a(Context context, float f, float f2, float f3, float f4) {
        Animation animationSet = new AnimationSet(false);
        Animation scaleAnimation = new ScaleAnimation(f, f2, f, f2, 1, 0.5f, 1, 0.5f);
        scaleAnimation.setInterpolator(f100A);
        scaleAnimation.setDuration(220);
        animationSet.addAnimation(scaleAnimation);
        scaleAnimation = new AlphaAnimation(f3, f4);
        scaleAnimation.setInterpolator(f101B);
        scaleAnimation.setDuration(220);
        animationSet.addAnimation(scaleAnimation);
        return animationSet;
    }

    private void m141a(RuntimeException runtimeException) {
        Log.e("FragmentManager", runtimeException.getMessage());
        Log.e("FragmentManager", "Activity state:");
        PrintWriter printWriter = new PrintWriter(new C0112e("FragmentManager"));
        if (this.f119o != null) {
            try {
                this.f119o.m116a("  ", null, printWriter, new String[0]);
            } catch (Throwable e) {
                Log.e("FragmentManager", "Failed dumping state", e);
            }
        } else {
            try {
                m165a("  ", null, printWriter, new String[0]);
            } catch (Throwable e2) {
                Log.e("FragmentManager", "Failed dumping state", e2);
            }
        }
        throw runtimeException;
    }

    static boolean m142a(View view, Animation animation) {
        return VERSION.SDK_INT >= 19 && bu.m993c(view) == 0 && bu.m1004m(view) && af.m143a(animation);
    }

    static boolean m143a(Animation animation) {
        if (animation instanceof AlphaAnimation) {
            return true;
        }
        if (!(animation instanceof AnimationSet)) {
            return false;
        }
        List animations = ((AnimationSet) animation).getAnimations();
        for (int i = 0; i < animations.size(); i++) {
            if (animations.get(i) instanceof AlphaAnimation) {
                return true;
            }
        }
        return false;
    }

    public static int m144b(int i, boolean z) {
        switch (i) {
            case 4097:
                return z ? 1 : 2;
            case 4099:
                return z ? 5 : 6;
            case 8194:
                return z ? 3 : 4;
            default:
                return -1;
        }
    }

    private void m145b(View view, Animation animation) {
        if (view != null && animation != null && af.m142a(view, animation)) {
            AnimationListener animationListener;
            try {
                if (f106r == null) {
                    f106r = Animation.class.getDeclaredField("mListener");
                    f106r.setAccessible(true);
                }
                animationListener = (AnimationListener) f106r.get(animation);
            } catch (Throwable e) {
                Log.e("FragmentManager", "No field with the name mListener is found in Animation class", e);
                animationListener = null;
            } catch (Throwable e2) {
                Log.e("FragmentManager", "Cannot access Animation's mListener field", e2);
                animationListener = null;
            }
            animation.setAnimationListener(new ai(view, animation, animationListener));
        }
    }

    public static int m146c(int i) {
        switch (i) {
            case 4097:
                return 8194;
            case 4099:
                return 4099;
            case 8194:
                return 4097;
            default:
                return 0;
        }
    }

    private void m147t() {
        if (this.f123t) {
            throw new IllegalStateException("Can not perform this action after onSaveInstanceState");
        } else if (this.f125v != null) {
            throw new IllegalStateException("Can not perform this action inside of " + this.f125v);
        }
    }

    public C0042t m148a(int i) {
        int size;
        C0042t c0042t;
        if (this.f111g != null) {
            for (size = this.f111g.size() - 1; size >= 0; size--) {
                c0042t = (C0042t) this.f111g.get(size);
                if (c0042t != null && c0042t.f313w == i) {
                    return c0042t;
                }
            }
        }
        if (this.f110f != null) {
            for (size = this.f110f.size() - 1; size >= 0; size--) {
                c0042t = (C0042t) this.f110f.get(size);
                if (c0042t != null && c0042t.f313w == i) {
                    return c0042t;
                }
            }
        }
        return null;
    }

    public C0042t m149a(Bundle bundle, String str) {
        int i = bundle.getInt(str, -1);
        if (i == -1) {
            return null;
        }
        if (i >= this.f110f.size()) {
            m141a(new IllegalStateException("Fragment no longer exists for key " + str + ": index " + i));
        }
        C0042t c0042t = (C0042t) this.f110f.get(i);
        if (c0042t != null) {
            return c0042t;
        }
        m141a(new IllegalStateException("Fragment no longer exists for key " + str + ": index " + i));
        return c0042t;
    }

    public C0042t m150a(String str) {
        int size;
        C0042t c0042t;
        if (!(this.f111g == null || str == null)) {
            for (size = this.f111g.size() - 1; size >= 0; size--) {
                c0042t = (C0042t) this.f111g.get(size);
                if (c0042t != null && str.equals(c0042t.f315y)) {
                    return c0042t;
                }
            }
        }
        if (!(this.f110f == null || str == null)) {
            for (size = this.f110f.size() - 1; size >= 0; size--) {
                c0042t = (C0042t) this.f110f.get(size);
                if (c0042t != null && str.equals(c0042t.f315y)) {
                    return c0042t;
                }
            }
        }
        return null;
    }

    public View m151a(View view, String str, Context context, AttributeSet attributeSet) {
        if (!"fragment".equals(str)) {
            return null;
        }
        String attributeValue = attributeSet.getAttributeValue(null, "class");
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, al.f138a);
        String string = attributeValue == null ? obtainStyledAttributes.getString(0) : attributeValue;
        int resourceId = obtainStyledAttributes.getResourceId(1, -1);
        String string2 = obtainStyledAttributes.getString(2);
        obtainStyledAttributes.recycle();
        if (!C0042t.m341b(this.f119o.m127g(), string)) {
            return null;
        }
        int id = view != null ? view.getId() : 0;
        if (id == -1 && resourceId == -1 && string2 == null) {
            throw new IllegalArgumentException(attributeSet.getPositionDescription() + ": Must specify unique android:id, android:tag, or have a parent with an id for " + string);
        }
        C0042t c0042t;
        C0042t a = resourceId != -1 ? m148a(resourceId) : null;
        if (a == null && string2 != null) {
            a = m150a(string2);
        }
        if (a == null && id != -1) {
            a = m148a(id);
        }
        if (f104a) {
            Log.v("FragmentManager", "onCreateView: id=0x" + Integer.toHexString(resourceId) + " fname=" + string + " existing=" + a);
        }
        if (a == null) {
            C0042t a2 = C0042t.m339a(context, string);
            a2.f305o = true;
            a2.f313w = resourceId != 0 ? resourceId : id;
            a2.f314x = id;
            a2.f315y = string2;
            a2.f306p = true;
            a2.f309s = this;
            a2.f310t = this.f119o;
            a2.m358a(this.f119o.m127g(), attributeSet, a2.f295e);
            m164a(a2, true);
            c0042t = a2;
        } else if (a.f306p) {
            throw new IllegalArgumentException(attributeSet.getPositionDescription() + ": Duplicate id 0x" + Integer.toHexString(resourceId) + ", tag " + string2 + ", or parent id 0x" + Integer.toHexString(id) + " with another fragment for " + string);
        } else {
            a.f306p = true;
            a.f310t = this.f119o;
            if (!a.f269C) {
                a.m358a(this.f119o.m127g(), attributeSet, a.f295e);
            }
            c0042t = a;
        }
        if (this.f118n >= 1 || !c0042t.f305o) {
            m173b(c0042t);
        } else {
            m163a(c0042t, 1, 0, 0, false);
        }
        if (c0042t.f275I == null) {
            throw new IllegalStateException("Fragment " + string + " did not create a view.");
        }
        if (resourceId != 0) {
            c0042t.f275I.setId(resourceId);
        }
        if (c0042t.f275I.getTag() == null) {
            c0042t.f275I.setTag(string2);
        }
        return c0042t.f275I;
    }

    Animation m152a(C0042t c0042t, int i, boolean z, int i2) {
        Animation a = c0042t.m351a(i, z, c0042t.f273G);
        if (a != null) {
            return a;
        }
        if (c0042t.f273G != 0) {
            a = AnimationUtils.loadAnimation(this.f119o.m127g(), c0042t.f273G);
            if (a != null) {
                return a;
            }
        }
        if (i == 0) {
            return null;
        }
        int b = af.m144b(i, z);
        if (b < 0) {
            return null;
        }
        switch (b) {
            case C0243l.View_android_focusable /*1*/:
                return af.m140a(this.f119o.m127g(), 1.125f, 1.0f, 0.0f, 1.0f);
            case C0243l.View_paddingStart /*2*/:
                return af.m140a(this.f119o.m127g(), 1.0f, 0.975f, 1.0f, 0.0f);
            case C0243l.View_paddingEnd /*3*/:
                return af.m140a(this.f119o.m127g(), 0.975f, 1.0f, 0.0f, 1.0f);
            case C0243l.View_theme /*4*/:
                return af.m140a(this.f119o.m127g(), 1.0f, 1.075f, 1.0f, 0.0f);
            case C0243l.Toolbar_contentInsetStart /*5*/:
                return af.m139a(this.f119o.m127g(), 0.0f, 1.0f);
            case C0243l.Toolbar_contentInsetEnd /*6*/:
                return af.m139a(this.f119o.m127g(), 1.0f, 0.0f);
            default:
                if (i2 == 0 && this.f119o.m124d()) {
                    i2 = this.f119o.m125e();
                }
                return i2 == 0 ? null : null;
        }
    }

    void m153a(int i, int i2, int i3, boolean z) {
        if (this.f119o == null && i != 0) {
            throw new IllegalStateException("No host");
        } else if (z || this.f118n != i) {
            this.f118n = i;
            if (this.f110f != null) {
                int i4 = 0;
                int i5 = 0;
                while (i4 < this.f110f.size()) {
                    int a;
                    C0042t c0042t = (C0042t) this.f110f.get(i4);
                    if (c0042t != null) {
                        m163a(c0042t, i, i2, i3, false);
                        if (c0042t.f279M != null) {
                            a = i5 | c0042t.f279M.m240a();
                            i4++;
                            i5 = a;
                        }
                    }
                    a = i5;
                    i4++;
                    i5 = a;
                }
                if (i5 == 0) {
                    m178c();
                }
                if (this.f122s && this.f119o != null && this.f118n == 5) {
                    this.f119o.m123c();
                    this.f122s = false;
                }
            }
        }
    }

    public void m154a(int i, C0032j c0032j) {
        synchronized (this) {
            if (this.f115k == null) {
                this.f115k = new ArrayList();
            }
            int size = this.f115k.size();
            if (i < size) {
                if (f104a) {
                    Log.v("FragmentManager", "Setting back stack index " + i + " to " + c0032j);
                }
                this.f115k.set(i, c0032j);
            } else {
                while (size < i) {
                    this.f115k.add(null);
                    if (this.f116l == null) {
                        this.f116l = new ArrayList();
                    }
                    if (f104a) {
                        Log.v("FragmentManager", "Adding available back stack index " + size);
                    }
                    this.f116l.add(Integer.valueOf(size));
                    size++;
                }
                if (f104a) {
                    Log.v("FragmentManager", "Adding back stack index " + i + " with " + c0032j);
                }
                this.f115k.add(c0032j);
            }
        }
    }

    void m155a(int i, boolean z) {
        m153a(i, 0, 0, z);
    }

    public void m156a(Configuration configuration) {
        if (this.f111g != null) {
            for (int i = 0; i < this.f111g.size(); i++) {
                C0042t c0042t = (C0042t) this.f111g.get(i);
                if (c0042t != null) {
                    c0042t.m359a(configuration);
                }
            }
        }
    }

    public void m157a(Bundle bundle, String str, C0042t c0042t) {
        if (c0042t.f297g < 0) {
            m141a(new IllegalStateException("Fragment " + c0042t + " is not currently in the FragmentManager"));
        }
        bundle.putInt(str, c0042t.f297g);
    }

    void m158a(Parcelable parcelable, List list) {
        if (parcelable != null) {
            am amVar = (am) parcelable;
            if (amVar.f139a != null) {
                int i;
                C0042t c0042t;
                int i2;
                if (list != null) {
                    for (i = 0; i < list.size(); i++) {
                        c0042t = (C0042t) list.get(i);
                        if (f104a) {
                            Log.v("FragmentManager", "restoreAllState: re-attaching retained " + c0042t);
                        }
                        ao aoVar = amVar.f139a[c0042t.f297g];
                        aoVar.f152k = c0042t;
                        c0042t.f296f = null;
                        c0042t.f308r = 0;
                        c0042t.f306p = false;
                        c0042t.f303m = false;
                        c0042t.f300j = null;
                        if (aoVar.f151j != null) {
                            aoVar.f151j.setClassLoader(this.f119o.m127g().getClassLoader());
                            c0042t.f296f = aoVar.f151j.getSparseParcelableArray("android:view_state");
                            c0042t.f295e = aoVar.f151j;
                        }
                    }
                }
                this.f110f = new ArrayList(amVar.f139a.length);
                if (this.f112h != null) {
                    this.f112h.clear();
                }
                for (i2 = 0; i2 < amVar.f139a.length; i2++) {
                    ao aoVar2 = amVar.f139a[i2];
                    if (aoVar2 != null) {
                        C0042t a = aoVar2.m205a(this.f119o, this.f121q);
                        if (f104a) {
                            Log.v("FragmentManager", "restoreAllState: active #" + i2 + ": " + a);
                        }
                        this.f110f.add(a);
                        aoVar2.f152k = null;
                    } else {
                        this.f110f.add(null);
                        if (this.f112h == null) {
                            this.f112h = new ArrayList();
                        }
                        if (f104a) {
                            Log.v("FragmentManager", "restoreAllState: avail #" + i2);
                        }
                        this.f112h.add(Integer.valueOf(i2));
                    }
                }
                if (list != null) {
                    for (int i3 = 0; i3 < list.size(); i3++) {
                        c0042t = (C0042t) list.get(i3);
                        if (c0042t.f301k >= 0) {
                            if (c0042t.f301k < this.f110f.size()) {
                                c0042t.f300j = (C0042t) this.f110f.get(c0042t.f301k);
                            } else {
                                Log.w("FragmentManager", "Re-attaching retained fragment " + c0042t + " target no longer exists: " + c0042t.f301k);
                                c0042t.f300j = null;
                            }
                        }
                    }
                }
                if (amVar.f140b != null) {
                    this.f111g = new ArrayList(amVar.f140b.length);
                    for (i = 0; i < amVar.f140b.length; i++) {
                        c0042t = (C0042t) this.f110f.get(amVar.f140b[i]);
                        if (c0042t == null) {
                            m141a(new IllegalStateException("No instantiated fragment for index #" + amVar.f140b[i]));
                        }
                        c0042t.f303m = true;
                        if (f104a) {
                            Log.v("FragmentManager", "restoreAllState: added #" + i + ": " + c0042t);
                        }
                        if (this.f111g.contains(c0042t)) {
                            throw new IllegalStateException("Already added!");
                        }
                        this.f111g.add(c0042t);
                    }
                } else {
                    this.f111g = null;
                }
                if (amVar.f141c != null) {
                    this.f113i = new ArrayList(amVar.f141c.length);
                    for (i2 = 0; i2 < amVar.f141c.length; i2++) {
                        C0032j a2 = amVar.f141c[i2].m335a(this);
                        if (f104a) {
                            Log.v("FragmentManager", "restoreAllState: back stack #" + i2 + " (index " + a2.f218p + "): " + a2);
                            a2.m333a("  ", new PrintWriter(new C0112e("FragmentManager")), false);
                        }
                        this.f113i.add(a2);
                        if (a2.f218p >= 0) {
                            m154a(a2.f218p, a2);
                        }
                    }
                    return;
                }
                this.f113i = null;
            }
        }
    }

    public void m159a(ac acVar, aa aaVar, C0042t c0042t) {
        if (this.f119o != null) {
            throw new IllegalStateException("Already attached");
        }
        this.f119o = acVar;
        this.f120p = aaVar;
        this.f121q = c0042t;
    }

    void m160a(C0032j c0032j) {
        if (this.f113i == null) {
            this.f113i = new ArrayList();
        }
        this.f113i.add(c0032j);
        m184e();
    }

    public void m161a(C0042t c0042t) {
        if (!c0042t.f277K) {
            return;
        }
        if (this.f109e) {
            this.f126w = true;
            return;
        }
        c0042t.f277K = false;
        m163a(c0042t, this.f118n, 0, 0, false);
    }

    public void m162a(C0042t c0042t, int i, int i2) {
        if (f104a) {
            Log.v("FragmentManager", "remove: " + c0042t + " nesting=" + c0042t.f308r);
        }
        boolean z = !c0042t.m366a();
        if (!c0042t.f267A || z) {
            if (this.f111g != null) {
                this.f111g.remove(c0042t);
            }
            if (c0042t.f270D && c0042t.f271E) {
                this.f122s = true;
            }
            c0042t.f303m = false;
            c0042t.f304n = true;
            m163a(c0042t, z ? 0 : 1, i, i2, false);
        }
    }

    /* JADX WARNING: inconsistent code. */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    void m163a(android.support.v4.p003a.C0042t r11, int r12, int r13, int r14, boolean r15) {
        /*
        r10 = this;
        r9 = 4;
        r6 = 3;
        r5 = 1;
        r3 = 0;
        r7 = 0;
        r0 = r11.f303m;
        if (r0 == 0) goto L_0x000d;
    L_0x0009:
        r0 = r11.f267A;
        if (r0 == 0) goto L_0x0010;
    L_0x000d:
        if (r12 <= r5) goto L_0x0010;
    L_0x000f:
        r12 = r5;
    L_0x0010:
        r0 = r11.f304n;
        if (r0 == 0) goto L_0x001a;
    L_0x0014:
        r0 = r11.f292b;
        if (r12 <= r0) goto L_0x001a;
    L_0x0018:
        r12 = r11.f292b;
    L_0x001a:
        r0 = r11.f277K;
        if (r0 == 0) goto L_0x0025;
    L_0x001e:
        r0 = r11.f292b;
        if (r0 >= r9) goto L_0x0025;
    L_0x0022:
        if (r12 <= r6) goto L_0x0025;
    L_0x0024:
        r12 = r6;
    L_0x0025:
        r0 = r11.f292b;
        if (r0 >= r12) goto L_0x02aa;
    L_0x0029:
        r0 = r11.f305o;
        if (r0 == 0) goto L_0x0032;
    L_0x002d:
        r0 = r11.f306p;
        if (r0 != 0) goto L_0x0032;
    L_0x0031:
        return;
    L_0x0032:
        r0 = r11.f293c;
        if (r0 == 0) goto L_0x0040;
    L_0x0036:
        r11.f293c = r7;
        r2 = r11.f294d;
        r0 = r10;
        r1 = r11;
        r4 = r3;
        r0.m163a(r1, r2, r3, r4, r5);
    L_0x0040:
        r0 = r11.f292b;
        switch(r0) {
            case 0: goto L_0x0080;
            case 1: goto L_0x0176;
            case 2: goto L_0x0247;
            case 3: goto L_0x0247;
            case 4: goto L_0x0268;
            default: goto L_0x0045;
        };
    L_0x0045:
        r0 = r11.f292b;
        if (r0 == r12) goto L_0x0031;
    L_0x0049:
        r0 = "FragmentManager";
        r1 = new java.lang.StringBuilder;
        r1.<init>();
        r2 = "moveToState: Fragment state for ";
        r1 = r1.append(r2);
        r1 = r1.append(r11);
        r2 = " not updated inline; ";
        r1 = r1.append(r2);
        r2 = "expected state ";
        r1 = r1.append(r2);
        r1 = r1.append(r12);
        r2 = " found ";
        r1 = r1.append(r2);
        r2 = r11.f292b;
        r1 = r1.append(r2);
        r1 = r1.toString();
        android.util.Log.w(r0, r1);
        r11.f292b = r12;
        goto L_0x0031;
    L_0x0080:
        r0 = f104a;
        if (r0 == 0) goto L_0x009c;
    L_0x0084:
        r0 = "FragmentManager";
        r1 = new java.lang.StringBuilder;
        r1.<init>();
        r2 = "moveto CREATED: ";
        r1 = r1.append(r2);
        r1 = r1.append(r11);
        r1 = r1.toString();
        android.util.Log.v(r0, r1);
    L_0x009c:
        r0 = r11.f295e;
        if (r0 == 0) goto L_0x00e4;
    L_0x00a0:
        r0 = r11.f295e;
        r1 = r10.f119o;
        r1 = r1.m127g();
        r1 = r1.getClassLoader();
        r0.setClassLoader(r1);
        r0 = r11.f295e;
        r1 = "android:view_state";
        r0 = r0.getSparseParcelableArray(r1);
        r11.f296f = r0;
        r0 = r11.f295e;
        r1 = "android:target_state";
        r0 = r10.m149a(r0, r1);
        r11.f300j = r0;
        r0 = r11.f300j;
        if (r0 == 0) goto L_0x00d1;
    L_0x00c7:
        r0 = r11.f295e;
        r1 = "android:target_req_state";
        r0 = r0.getInt(r1, r3);
        r11.f302l = r0;
    L_0x00d1:
        r0 = r11.f295e;
        r1 = "android:user_visible_hint";
        r0 = r0.getBoolean(r1, r5);
        r11.f278L = r0;
        r0 = r11.f278L;
        if (r0 != 0) goto L_0x00e4;
    L_0x00df:
        r11.f277K = r5;
        if (r12 <= r6) goto L_0x00e4;
    L_0x00e3:
        r12 = r6;
    L_0x00e4:
        r0 = r10.f119o;
        r11.f310t = r0;
        r0 = r10.f121q;
        r11.f312v = r0;
        r0 = r10.f121q;
        if (r0 == 0) goto L_0x0124;
    L_0x00f0:
        r0 = r10.f121q;
        r0 = r0.f311u;
    L_0x00f4:
        r11.f309s = r0;
        r11.f272F = r3;
        r0 = r10.f119o;
        r0 = r0.m127g();
        r11.m357a(r0);
        r0 = r11.f272F;
        if (r0 != 0) goto L_0x012b;
    L_0x0105:
        r0 = new android.support.v4.a.bj;
        r1 = new java.lang.StringBuilder;
        r1.<init>();
        r2 = "Fragment ";
        r1 = r1.append(r2);
        r1 = r1.append(r11);
        r2 = " did not call through to super.onAttach()";
        r1 = r1.append(r2);
        r1 = r1.toString();
        r0.<init>(r1);
        throw r0;
    L_0x0124:
        r0 = r10.f119o;
        r0 = r0.m129i();
        goto L_0x00f4;
    L_0x012b:
        r0 = r11.f312v;
        if (r0 != 0) goto L_0x0134;
    L_0x012f:
        r0 = r10.f119o;
        r0.m121b(r11);
    L_0x0134:
        r0 = r11.f269C;
        if (r0 != 0) goto L_0x013d;
    L_0x0138:
        r0 = r11.f295e;
        r11.m387g(r0);
    L_0x013d:
        r11.f269C = r3;
        r0 = r11.f305o;
        if (r0 == 0) goto L_0x0176;
    L_0x0143:
        r0 = r11.f295e;
        r0 = r11.m369b(r0);
        r1 = r11.f295e;
        r0 = r11.m370b(r0, r7, r1);
        r11.f275I = r0;
        r0 = r11.f275I;
        if (r0 == 0) goto L_0x0299;
    L_0x0155:
        r0 = r11.f275I;
        r11.f276J = r0;
        r0 = android.os.Build.VERSION.SDK_INT;
        r1 = 11;
        if (r0 < r1) goto L_0x028f;
    L_0x015f:
        r0 = r11.f275I;
        android.support.v4.p004h.bu.m988a(r0, r3);
    L_0x0164:
        r0 = r11.f316z;
        if (r0 == 0) goto L_0x016f;
    L_0x0168:
        r0 = r11.f275I;
        r1 = 8;
        r0.setVisibility(r1);
    L_0x016f:
        r0 = r11.f275I;
        r1 = r11.f295e;
        r11.m363a(r0, r1);
    L_0x0176:
        if (r12 <= r5) goto L_0x0247;
    L_0x0178:
        r0 = f104a;
        if (r0 == 0) goto L_0x0194;
    L_0x017c:
        r0 = "FragmentManager";
        r1 = new java.lang.StringBuilder;
        r1.<init>();
        r2 = "moveto ACTIVITY_CREATED: ";
        r1 = r1.append(r2);
        r1 = r1.append(r11);
        r1 = r1.toString();
        android.util.Log.v(r0, r1);
    L_0x0194:
        r0 = r11.f305o;
        if (r0 != 0) goto L_0x0237;
    L_0x0198:
        r0 = r11.f314x;
        if (r0 == 0) goto L_0x0408;
    L_0x019c:
        r0 = r10.f120p;
        r1 = r11.f314x;
        r0 = r0.m78a(r1);
        r0 = (android.view.ViewGroup) r0;
        if (r0 != 0) goto L_0x01eb;
    L_0x01a8:
        r1 = r11.f307q;
        if (r1 != 0) goto L_0x01eb;
    L_0x01ac:
        r1 = new java.lang.IllegalArgumentException;
        r2 = new java.lang.StringBuilder;
        r2.<init>();
        r4 = "No view found for id 0x";
        r2 = r2.append(r4);
        r4 = r11.f314x;
        r4 = java.lang.Integer.toHexString(r4);
        r2 = r2.append(r4);
        r4 = " (";
        r2 = r2.append(r4);
        r4 = r11.m374c();
        r8 = r11.f314x;
        r4 = r4.getResourceName(r8);
        r2 = r2.append(r4);
        r4 = ") for fragment ";
        r2 = r2.append(r4);
        r2 = r2.append(r11);
        r2 = r2.toString();
        r1.<init>(r2);
        r10.m141a(r1);
    L_0x01eb:
        r11.f274H = r0;
        r1 = r11.f295e;
        r1 = r11.m369b(r1);
        r2 = r11.f295e;
        r1 = r11.m370b(r1, r0, r2);
        r11.f275I = r1;
        r1 = r11.f275I;
        if (r1 == 0) goto L_0x02a7;
    L_0x01ff:
        r1 = r11.f275I;
        r11.f276J = r1;
        r1 = android.os.Build.VERSION.SDK_INT;
        r2 = 11;
        if (r1 < r2) goto L_0x029d;
    L_0x0209:
        r1 = r11.f275I;
        android.support.v4.p004h.bu.m988a(r1, r3);
    L_0x020e:
        if (r0 == 0) goto L_0x0225;
    L_0x0210:
        r1 = r10.m152a(r11, r13, r5, r14);
        if (r1 == 0) goto L_0x0220;
    L_0x0216:
        r2 = r11.f275I;
        r10.m145b(r2, r1);
        r2 = r11.f275I;
        r2.startAnimation(r1);
    L_0x0220:
        r1 = r11.f275I;
        r0.addView(r1);
    L_0x0225:
        r0 = r11.f316z;
        if (r0 == 0) goto L_0x0230;
    L_0x0229:
        r0 = r11.f275I;
        r1 = 8;
        r0.setVisibility(r1);
    L_0x0230:
        r0 = r11.f275I;
        r1 = r11.f295e;
        r11.m363a(r0, r1);
    L_0x0237:
        r0 = r11.f295e;
        r11.m389h(r0);
        r0 = r11.f275I;
        if (r0 == 0) goto L_0x0245;
    L_0x0240:
        r0 = r11.f295e;
        r11.m360a(r0);
    L_0x0245:
        r11.f295e = r7;
    L_0x0247:
        if (r12 <= r6) goto L_0x0268;
    L_0x0249:
        r0 = f104a;
        if (r0 == 0) goto L_0x0265;
    L_0x024d:
        r0 = "FragmentManager";
        r1 = new java.lang.StringBuilder;
        r1.<init>();
        r2 = "moveto STARTED: ";
        r1 = r1.append(r2);
        r1 = r1.append(r11);
        r1 = r1.toString();
        android.util.Log.v(r0, r1);
    L_0x0265:
        r11.m408z();
    L_0x0268:
        if (r12 <= r9) goto L_0x0045;
    L_0x026a:
        r0 = f104a;
        if (r0 == 0) goto L_0x0286;
    L_0x026e:
        r0 = "FragmentManager";
        r1 = new java.lang.StringBuilder;
        r1.<init>();
        r2 = "moveto RESUMED: ";
        r1 = r1.append(r2);
        r1 = r1.append(r11);
        r1 = r1.toString();
        android.util.Log.v(r0, r1);
    L_0x0286:
        r11.m342A();
        r11.f295e = r7;
        r11.f296f = r7;
        goto L_0x0045;
    L_0x028f:
        r0 = r11.f275I;
        r0 = android.support.v4.p003a.bh.m279a(r0);
        r11.f275I = r0;
        goto L_0x0164;
    L_0x0299:
        r11.f276J = r7;
        goto L_0x0176;
    L_0x029d:
        r1 = r11.f275I;
        r1 = android.support.v4.p003a.bh.m279a(r1);
        r11.f275I = r1;
        goto L_0x020e;
    L_0x02a7:
        r11.f276J = r7;
        goto L_0x0237;
    L_0x02aa:
        r0 = r11.f292b;
        if (r0 <= r12) goto L_0x0045;
    L_0x02ae:
        r0 = r11.f292b;
        switch(r0) {
            case 1: goto L_0x02b5;
            case 2: goto L_0x0333;
            case 3: goto L_0x0312;
            case 4: goto L_0x02f1;
            case 5: goto L_0x02cf;
            default: goto L_0x02b3;
        };
    L_0x02b3:
        goto L_0x0045;
    L_0x02b5:
        if (r12 >= r5) goto L_0x0045;
    L_0x02b7:
        r0 = r10.f124u;
        if (r0 == 0) goto L_0x02c6;
    L_0x02bb:
        r0 = r11.f293c;
        if (r0 == 0) goto L_0x02c6;
    L_0x02bf:
        r0 = r11.f293c;
        r11.f293c = r7;
        r0.clearAnimation();
    L_0x02c6:
        r0 = r11.f293c;
        if (r0 == 0) goto L_0x03a2;
    L_0x02ca:
        r11.f294d = r12;
        r12 = r5;
        goto L_0x0045;
    L_0x02cf:
        r0 = 5;
        if (r12 >= r0) goto L_0x02f1;
    L_0x02d2:
        r0 = f104a;
        if (r0 == 0) goto L_0x02ee;
    L_0x02d6:
        r0 = "FragmentManager";
        r1 = new java.lang.StringBuilder;
        r1.<init>();
        r2 = "movefrom RESUMED: ";
        r1 = r1.append(r2);
        r1 = r1.append(r11);
        r1 = r1.toString();
        android.util.Log.v(r0, r1);
    L_0x02ee:
        r11.m344C();
    L_0x02f1:
        if (r12 >= r9) goto L_0x0312;
    L_0x02f3:
        r0 = f104a;
        if (r0 == 0) goto L_0x030f;
    L_0x02f7:
        r0 = "FragmentManager";
        r1 = new java.lang.StringBuilder;
        r1.<init>();
        r2 = "movefrom STARTED: ";
        r1 = r1.append(r2);
        r1 = r1.append(r11);
        r1 = r1.toString();
        android.util.Log.v(r0, r1);
    L_0x030f:
        r11.m345D();
    L_0x0312:
        if (r12 >= r6) goto L_0x0333;
    L_0x0314:
        r0 = f104a;
        if (r0 == 0) goto L_0x0330;
    L_0x0318:
        r0 = "FragmentManager";
        r1 = new java.lang.StringBuilder;
        r1.<init>();
        r2 = "movefrom STOPPED: ";
        r1 = r1.append(r2);
        r1 = r1.append(r11);
        r1 = r1.toString();
        android.util.Log.v(r0, r1);
    L_0x0330:
        r11.m346E();
    L_0x0333:
        r0 = 2;
        if (r12 >= r0) goto L_0x02b5;
    L_0x0336:
        r0 = f104a;
        if (r0 == 0) goto L_0x0352;
    L_0x033a:
        r0 = "FragmentManager";
        r1 = new java.lang.StringBuilder;
        r1.<init>();
        r2 = "movefrom ACTIVITY_CREATED: ";
        r1 = r1.append(r2);
        r1 = r1.append(r11);
        r1 = r1.toString();
        android.util.Log.v(r0, r1);
    L_0x0352:
        r0 = r11.f275I;
        if (r0 == 0) goto L_0x0365;
    L_0x0356:
        r0 = r10.f119o;
        r0 = r0.m119a(r11);
        if (r0 == 0) goto L_0x0365;
    L_0x035e:
        r0 = r11.f296f;
        if (r0 != 0) goto L_0x0365;
    L_0x0362:
        r10.m185e(r11);
    L_0x0365:
        r11.m347F();
        r0 = r11.f275I;
        if (r0 == 0) goto L_0x039a;
    L_0x036c:
        r0 = r11.f274H;
        if (r0 == 0) goto L_0x039a;
    L_0x0370:
        r0 = r10.f118n;
        if (r0 <= 0) goto L_0x0405;
    L_0x0374:
        r0 = r10.f124u;
        if (r0 != 0) goto L_0x0405;
    L_0x0378:
        r0 = r10.m152a(r11, r13, r3, r14);
    L_0x037c:
        if (r0 == 0) goto L_0x0393;
    L_0x037e:
        r1 = r11.f275I;
        r11.f293c = r1;
        r11.f294d = r12;
        r1 = r11.f275I;
        r2 = new android.support.v4.a.ah;
        r2.<init>(r10, r1, r0, r11);
        r0.setAnimationListener(r2);
        r1 = r11.f275I;
        r1.startAnimation(r0);
    L_0x0393:
        r0 = r11.f274H;
        r1 = r11.f275I;
        r0.removeView(r1);
    L_0x039a:
        r11.f274H = r7;
        r11.f275I = r7;
        r11.f276J = r7;
        goto L_0x02b5;
    L_0x03a2:
        r0 = f104a;
        if (r0 == 0) goto L_0x03be;
    L_0x03a6:
        r0 = "FragmentManager";
        r1 = new java.lang.StringBuilder;
        r1.<init>();
        r2 = "movefrom CREATED: ";
        r1 = r1.append(r2);
        r1 = r1.append(r11);
        r1 = r1.toString();
        android.util.Log.v(r0, r1);
    L_0x03be:
        r0 = r11.f269C;
        if (r0 != 0) goto L_0x03ed;
    L_0x03c2:
        r11.m348G();
    L_0x03c5:
        r11.f272F = r3;
        r11.m397o();
        r0 = r11.f272F;
        if (r0 != 0) goto L_0x03f0;
    L_0x03ce:
        r0 = new android.support.v4.a.bj;
        r1 = new java.lang.StringBuilder;
        r1.<init>();
        r2 = "Fragment ";
        r1 = r1.append(r2);
        r1 = r1.append(r11);
        r2 = " did not call through to super.onDetach()";
        r1 = r1.append(r2);
        r1 = r1.toString();
        r0.<init>(r1);
        throw r0;
    L_0x03ed:
        r11.f292b = r3;
        goto L_0x03c5;
    L_0x03f0:
        if (r15 != 0) goto L_0x0045;
    L_0x03f2:
        r0 = r11.f269C;
        if (r0 != 0) goto L_0x03fb;
    L_0x03f6:
        r10.m181d(r11);
        goto L_0x0045;
    L_0x03fb:
        r11.f310t = r7;
        r11.f312v = r7;
        r11.f309s = r7;
        r11.f311u = r7;
        goto L_0x0045;
    L_0x0405:
        r0 = r7;
        goto L_0x037c;
    L_0x0408:
        r0 = r7;
        goto L_0x01eb;
        */
        throw new UnsupportedOperationException("Method not decompiled: android.support.v4.a.af.a(android.support.v4.a.t, int, int, int, boolean):void");
    }

    public void m164a(C0042t c0042t, boolean z) {
        if (this.f111g == null) {
            this.f111g = new ArrayList();
        }
        if (f104a) {
            Log.v("FragmentManager", "add: " + c0042t);
        }
        m179c(c0042t);
        if (!c0042t.f267A) {
            if (this.f111g.contains(c0042t)) {
                throw new IllegalStateException("Fragment already added: " + c0042t);
            }
            this.f111g.add(c0042t);
            c0042t.f303m = true;
            c0042t.f304n = false;
            if (c0042t.f270D && c0042t.f271E) {
                this.f122s = true;
            }
            if (z) {
                m173b(c0042t);
            }
        }
    }

    public void m165a(String str, FileDescriptor fileDescriptor, PrintWriter printWriter, String[] strArr) {
        int size;
        int i;
        C0042t c0042t;
        int i2 = 0;
        String str2 = str + "    ";
        if (this.f110f != null) {
            size = this.f110f.size();
            if (size > 0) {
                printWriter.print(str);
                printWriter.print("Active Fragments in ");
                printWriter.print(Integer.toHexString(System.identityHashCode(this)));
                printWriter.println(":");
                for (i = 0; i < size; i++) {
                    c0042t = (C0042t) this.f110f.get(i);
                    printWriter.print(str);
                    printWriter.print("  #");
                    printWriter.print(i);
                    printWriter.print(": ");
                    printWriter.println(c0042t);
                    if (c0042t != null) {
                        c0042t.m364a(str2, fileDescriptor, printWriter, strArr);
                    }
                }
            }
        }
        if (this.f111g != null) {
            size = this.f111g.size();
            if (size > 0) {
                printWriter.print(str);
                printWriter.println("Added Fragments:");
                for (i = 0; i < size; i++) {
                    c0042t = (C0042t) this.f111g.get(i);
                    printWriter.print(str);
                    printWriter.print("  #");
                    printWriter.print(i);
                    printWriter.print(": ");
                    printWriter.println(c0042t.toString());
                }
            }
        }
        if (this.f114j != null) {
            size = this.f114j.size();
            if (size > 0) {
                printWriter.print(str);
                printWriter.println("Fragments Created Menus:");
                for (i = 0; i < size; i++) {
                    c0042t = (C0042t) this.f114j.get(i);
                    printWriter.print(str);
                    printWriter.print("  #");
                    printWriter.print(i);
                    printWriter.print(": ");
                    printWriter.println(c0042t.toString());
                }
            }
        }
        if (this.f113i != null) {
            size = this.f113i.size();
            if (size > 0) {
                printWriter.print(str);
                printWriter.println("Back Stack:");
                for (i = 0; i < size; i++) {
                    C0032j c0032j = (C0032j) this.f113i.get(i);
                    printWriter.print(str);
                    printWriter.print("  #");
                    printWriter.print(i);
                    printWriter.print(": ");
                    printWriter.println(c0032j.toString());
                    c0032j.m332a(str2, fileDescriptor, printWriter, strArr);
                }
            }
        }
        synchronized (this) {
            if (this.f115k != null) {
                int size2 = this.f115k.size();
                if (size2 > 0) {
                    printWriter.print(str);
                    printWriter.println("Back Stack Indices:");
                    for (i = 0; i < size2; i++) {
                        c0032j = (C0032j) this.f115k.get(i);
                        printWriter.print(str);
                        printWriter.print("  #");
                        printWriter.print(i);
                        printWriter.print(": ");
                        printWriter.println(c0032j);
                    }
                }
            }
            if (this.f116l != null && this.f116l.size() > 0) {
                printWriter.print(str);
                printWriter.print("mAvailBackStackIndices: ");
                printWriter.println(Arrays.toString(this.f116l.toArray()));
            }
        }
        if (this.f107c != null) {
            i = this.f107c.size();
            if (i > 0) {
                printWriter.print(str);
                printWriter.println("Pending Actions:");
                while (i2 < i) {
                    Runnable runnable = (Runnable) this.f107c.get(i2);
                    printWriter.print(str);
                    printWriter.print("  #");
                    printWriter.print(i2);
                    printWriter.print(": ");
                    printWriter.println(runnable);
                    i2++;
                }
            }
        }
        printWriter.print(str);
        printWriter.println("FragmentManager misc state:");
        printWriter.print(str);
        printWriter.print("  mHost=");
        printWriter.println(this.f119o);
        printWriter.print(str);
        printWriter.print("  mContainer=");
        printWriter.println(this.f120p);
        if (this.f121q != null) {
            printWriter.print(str);
            printWriter.print("  mParent=");
            printWriter.println(this.f121q);
        }
        printWriter.print(str);
        printWriter.print("  mCurState=");
        printWriter.print(this.f118n);
        printWriter.print(" mStateSaved=");
        printWriter.print(this.f123t);
        printWriter.print(" mDestroyed=");
        printWriter.println(this.f124u);
        if (this.f122s) {
            printWriter.print(str);
            printWriter.print("  mNeedMenuInvalidate=");
            printWriter.println(this.f122s);
        }
        if (this.f125v != null) {
            printWriter.print(str);
            printWriter.print("  mNoTransactionsBecause=");
            printWriter.println(this.f125v);
        }
        if (this.f112h != null && this.f112h.size() > 0) {
            printWriter.print(str);
            printWriter.print("  mAvailIndices: ");
            printWriter.println(Arrays.toString(this.f112h.toArray()));
        }
    }

    public boolean m166a() {
        m147t();
        m176b();
        return m167a(this.f119o.m128h(), null, -1, 0);
    }

    /* JADX WARNING: inconsistent code. */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    boolean m167a(android.os.Handler r12, java.lang.String r13, int r14, int r15) {
        /*
        r11 = this;
        r4 = 0;
        r2 = 1;
        r3 = 0;
        r0 = r11.f113i;
        if (r0 != 0) goto L_0x0008;
    L_0x0007:
        return r3;
    L_0x0008:
        if (r13 != 0) goto L_0x0037;
    L_0x000a:
        if (r14 >= 0) goto L_0x0037;
    L_0x000c:
        r0 = r15 & 1;
        if (r0 != 0) goto L_0x0037;
    L_0x0010:
        r0 = r11.f113i;
        r0 = r0.size();
        r0 = r0 + -1;
        if (r0 < 0) goto L_0x0007;
    L_0x001a:
        r1 = r11.f113i;
        r0 = r1.remove(r0);
        r0 = (android.support.v4.p003a.C0032j) r0;
        r1 = new android.util.SparseArray;
        r1.<init>();
        r3 = new android.util.SparseArray;
        r3.<init>();
        r0.m331a(r1, r3);
        r0.m327a(r2, r4, r1, r3);
        r11.m184e();
    L_0x0035:
        r3 = r2;
        goto L_0x0007;
    L_0x0037:
        r0 = -1;
        if (r13 != 0) goto L_0x003c;
    L_0x003a:
        if (r14 < 0) goto L_0x008b;
    L_0x003c:
        r0 = r11.f113i;
        r0 = r0.size();
        r1 = r0 + -1;
    L_0x0044:
        if (r1 < 0) goto L_0x005a;
    L_0x0046:
        r0 = r11.f113i;
        r0 = r0.get(r1);
        r0 = (android.support.v4.p003a.C0032j) r0;
        if (r13 == 0) goto L_0x0081;
    L_0x0050:
        r5 = r0.m328a();
        r5 = r13.equals(r5);
        if (r5 == 0) goto L_0x0081;
    L_0x005a:
        if (r1 < 0) goto L_0x0007;
    L_0x005c:
        r0 = r15 & 1;
        if (r0 == 0) goto L_0x008a;
    L_0x0060:
        r1 = r1 + -1;
    L_0x0062:
        if (r1 < 0) goto L_0x008a;
    L_0x0064:
        r0 = r11.f113i;
        r0 = r0.get(r1);
        r0 = (android.support.v4.p003a.C0032j) r0;
        if (r13 == 0) goto L_0x0078;
    L_0x006e:
        r5 = r0.m328a();
        r5 = r13.equals(r5);
        if (r5 != 0) goto L_0x007e;
    L_0x0078:
        if (r14 < 0) goto L_0x008a;
    L_0x007a:
        r0 = r0.f218p;
        if (r14 != r0) goto L_0x008a;
    L_0x007e:
        r1 = r1 + -1;
        goto L_0x0062;
    L_0x0081:
        if (r14 < 0) goto L_0x0087;
    L_0x0083:
        r0 = r0.f218p;
        if (r14 == r0) goto L_0x005a;
    L_0x0087:
        r1 = r1 + -1;
        goto L_0x0044;
    L_0x008a:
        r0 = r1;
    L_0x008b:
        r1 = r11.f113i;
        r1 = r1.size();
        r1 = r1 + -1;
        if (r0 == r1) goto L_0x0007;
    L_0x0095:
        r6 = new java.util.ArrayList;
        r6.<init>();
        r1 = r11.f113i;
        r1 = r1.size();
        r1 = r1 + -1;
    L_0x00a2:
        if (r1 <= r0) goto L_0x00b0;
    L_0x00a4:
        r5 = r11.f113i;
        r5 = r5.remove(r1);
        r6.add(r5);
        r1 = r1 + -1;
        goto L_0x00a2;
    L_0x00b0:
        r0 = r6.size();
        r7 = r0 + -1;
        r8 = new android.util.SparseArray;
        r8.<init>();
        r9 = new android.util.SparseArray;
        r9.<init>();
        r1 = r3;
    L_0x00c1:
        if (r1 > r7) goto L_0x00d0;
    L_0x00c3:
        r0 = r6.get(r1);
        r0 = (android.support.v4.p003a.C0032j) r0;
        r0.m331a(r8, r9);
        r0 = r1 + 1;
        r1 = r0;
        goto L_0x00c1;
    L_0x00d0:
        r5 = r4;
        r4 = r3;
    L_0x00d2:
        if (r4 > r7) goto L_0x0108;
    L_0x00d4:
        r0 = f104a;
        if (r0 == 0) goto L_0x00f4;
    L_0x00d8:
        r0 = "FragmentManager";
        r1 = new java.lang.StringBuilder;
        r1.<init>();
        r10 = "Popping back stack state: ";
        r1 = r1.append(r10);
        r10 = r6.get(r4);
        r1 = r1.append(r10);
        r1 = r1.toString();
        android.util.Log.v(r0, r1);
    L_0x00f4:
        r0 = r6.get(r4);
        r0 = (android.support.v4.p003a.C0032j) r0;
        if (r4 != r7) goto L_0x0106;
    L_0x00fc:
        r1 = r2;
    L_0x00fd:
        r1 = r0.m327a(r1, r5, r8, r9);
        r0 = r4 + 1;
        r4 = r0;
        r5 = r1;
        goto L_0x00d2;
    L_0x0106:
        r1 = r3;
        goto L_0x00fd;
    L_0x0108:
        r11.m184e();
        goto L_0x0035;
        */
        throw new UnsupportedOperationException("Method not decompiled: android.support.v4.a.af.a(android.os.Handler, java.lang.String, int, int):boolean");
    }

    public boolean m168a(Menu menu) {
        if (this.f111g == null) {
            return false;
        }
        boolean z = false;
        for (int i = 0; i < this.f111g.size(); i++) {
            C0042t c0042t = (C0042t) this.f111g.get(i);
            if (c0042t != null && c0042t.m376c(menu)) {
                z = true;
            }
        }
        return z;
    }

    public boolean m169a(Menu menu, MenuInflater menuInflater) {
        boolean z;
        C0042t c0042t;
        int i = 0;
        ArrayList arrayList = null;
        if (this.f111g != null) {
            int i2 = 0;
            z = false;
            while (i2 < this.f111g.size()) {
                c0042t = (C0042t) this.f111g.get(i2);
                if (c0042t != null && c0042t.m372b(menu, menuInflater)) {
                    z = true;
                    if (arrayList == null) {
                        arrayList = new ArrayList();
                    }
                    arrayList.add(c0042t);
                }
                i2++;
                z = z;
            }
        } else {
            z = false;
        }
        if (this.f114j != null) {
            while (i < this.f114j.size()) {
                c0042t = (C0042t) this.f114j.get(i);
                if (arrayList == null || !arrayList.contains(c0042t)) {
                    c0042t.m398p();
                }
                i++;
            }
        }
        this.f114j = arrayList;
        return z;
    }

    public boolean m170a(MenuItem menuItem) {
        if (this.f111g == null) {
            return false;
        }
        for (int i = 0; i < this.f111g.size(); i++) {
            C0042t c0042t = (C0042t) this.f111g.get(i);
            if (c0042t != null && c0042t.m377c(menuItem)) {
                return true;
            }
        }
        return false;
    }

    public C0042t m171b(String str) {
        if (!(this.f110f == null || str == null)) {
            for (int size = this.f110f.size() - 1; size >= 0; size--) {
                C0042t c0042t = (C0042t) this.f110f.get(size);
                if (c0042t != null) {
                    c0042t = c0042t.m349a(str);
                    if (c0042t != null) {
                        return c0042t;
                    }
                }
            }
        }
        return null;
    }

    public void m172b(int i) {
        synchronized (this) {
            this.f115k.set(i, null);
            if (this.f116l == null) {
                this.f116l = new ArrayList();
            }
            if (f104a) {
                Log.v("FragmentManager", "Freeing back stack index " + i);
            }
            this.f116l.add(Integer.valueOf(i));
        }
    }

    void m173b(C0042t c0042t) {
        m163a(c0042t, this.f118n, 0, 0, false);
    }

    public void m174b(C0042t c0042t, int i, int i2) {
        if (f104a) {
            Log.v("FragmentManager", "hide: " + c0042t);
        }
        if (!c0042t.f316z) {
            c0042t.f316z = true;
            if (c0042t.f275I != null) {
                Animation a = m152a(c0042t, i, false, i2);
                if (a != null) {
                    m145b(c0042t.f275I, a);
                    c0042t.f275I.startAnimation(a);
                }
                c0042t.f275I.setVisibility(8);
            }
            if (c0042t.f303m && c0042t.f270D && c0042t.f271E) {
                this.f122s = true;
            }
            c0042t.m365a(true);
        }
    }

    public void m175b(Menu menu) {
        if (this.f111g != null) {
            for (int i = 0; i < this.f111g.size(); i++) {
                C0042t c0042t = (C0042t) this.f111g.get(i);
                if (c0042t != null) {
                    c0042t.m380d(menu);
                }
            }
        }
    }

    public boolean m176b() {
        return m183d();
    }

    public boolean m177b(MenuItem menuItem) {
        if (this.f111g == null) {
            return false;
        }
        for (int i = 0; i < this.f111g.size(); i++) {
            C0042t c0042t = (C0042t) this.f111g.get(i);
            if (c0042t != null && c0042t.m381d(menuItem)) {
                return true;
            }
        }
        return false;
    }

    void m178c() {
        if (this.f110f != null) {
            for (int i = 0; i < this.f110f.size(); i++) {
                C0042t c0042t = (C0042t) this.f110f.get(i);
                if (c0042t != null) {
                    m161a(c0042t);
                }
            }
        }
    }

    void m179c(C0042t c0042t) {
        if (c0042t.f297g < 0) {
            if (this.f112h == null || this.f112h.size() <= 0) {
                if (this.f110f == null) {
                    this.f110f = new ArrayList();
                }
                c0042t.m353a(this.f110f.size(), this.f121q);
                this.f110f.add(c0042t);
            } else {
                c0042t.m353a(((Integer) this.f112h.remove(this.f112h.size() - 1)).intValue(), this.f121q);
                this.f110f.set(c0042t.f297g, c0042t);
            }
            if (f104a) {
                Log.v("FragmentManager", "Allocated fragment index " + c0042t);
            }
        }
    }

    public void m180c(C0042t c0042t, int i, int i2) {
        if (f104a) {
            Log.v("FragmentManager", "show: " + c0042t);
        }
        if (c0042t.f316z) {
            c0042t.f316z = false;
            if (c0042t.f275I != null) {
                Animation a = m152a(c0042t, i, true, i2);
                if (a != null) {
                    m145b(c0042t.f275I, a);
                    c0042t.f275I.startAnimation(a);
                }
                c0042t.f275I.setVisibility(0);
            }
            if (c0042t.f303m && c0042t.f270D && c0042t.f271E) {
                this.f122s = true;
            }
            c0042t.m365a(false);
        }
    }

    void m181d(C0042t c0042t) {
        if (c0042t.f297g >= 0) {
            if (f104a) {
                Log.v("FragmentManager", "Freeing fragment index " + c0042t);
            }
            this.f110f.set(c0042t.f297g, null);
            if (this.f112h == null) {
                this.f112h = new ArrayList();
            }
            this.f112h.add(Integer.valueOf(c0042t.f297g));
            this.f119o.m115a(c0042t.f298h);
            c0042t.m396n();
        }
    }

    public void m182d(C0042t c0042t, int i, int i2) {
        if (f104a) {
            Log.v("FragmentManager", "detach: " + c0042t);
        }
        if (!c0042t.f267A) {
            c0042t.f267A = true;
            if (c0042t.f303m) {
                if (this.f111g != null) {
                    if (f104a) {
                        Log.v("FragmentManager", "remove from detach: " + c0042t);
                    }
                    this.f111g.remove(c0042t);
                }
                if (c0042t.f270D && c0042t.f271E) {
                    this.f122s = true;
                }
                c0042t.f303m = false;
                m163a(c0042t, 1, i, i2, false);
            }
        }
    }

    /* JADX WARNING: inconsistent code. */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public boolean m183d() {
        /*
        r6 = this;
        r0 = 1;
        r2 = 0;
        r1 = r6.f109e;
        if (r1 == 0) goto L_0x000e;
    L_0x0006:
        r0 = new java.lang.IllegalStateException;
        r1 = "Recursive entry to executePendingTransactions";
        r0.<init>(r1);
        throw r0;
    L_0x000e:
        r1 = android.os.Looper.myLooper();
        r3 = r6.f119o;
        r3 = r3.m128h();
        r3 = r3.getLooper();
        if (r1 == r3) goto L_0x0026;
    L_0x001e:
        r0 = new java.lang.IllegalStateException;
        r1 = "Must be called from main thread of process";
        r0.<init>(r1);
        throw r0;
    L_0x0026:
        r1 = r2;
    L_0x0027:
        monitor-enter(r6);
        r3 = r6.f107c;	 Catch:{ all -> 0x009b }
        if (r3 == 0) goto L_0x0034;
    L_0x002c:
        r3 = r6.f107c;	 Catch:{ all -> 0x009b }
        r3 = r3.size();	 Catch:{ all -> 0x009b }
        if (r3 != 0) goto L_0x005c;
    L_0x0034:
        monitor-exit(r6);	 Catch:{ all -> 0x009b }
        r0 = r6.f126w;
        if (r0 == 0) goto L_0x00a9;
    L_0x0039:
        r3 = r2;
        r4 = r2;
    L_0x003b:
        r0 = r6.f110f;
        r0 = r0.size();
        if (r3 >= r0) goto L_0x00a2;
    L_0x0043:
        r0 = r6.f110f;
        r0 = r0.get(r3);
        r0 = (android.support.v4.p003a.C0042t) r0;
        if (r0 == 0) goto L_0x0058;
    L_0x004d:
        r5 = r0.f279M;
        if (r5 == 0) goto L_0x0058;
    L_0x0051:
        r0 = r0.f279M;
        r0 = r0.m240a();
        r4 = r4 | r0;
    L_0x0058:
        r0 = r3 + 1;
        r3 = r0;
        goto L_0x003b;
    L_0x005c:
        r1 = r6.f107c;	 Catch:{ all -> 0x009b }
        r3 = r1.size();	 Catch:{ all -> 0x009b }
        r1 = r6.f108d;	 Catch:{ all -> 0x009b }
        if (r1 == 0) goto L_0x006b;
    L_0x0066:
        r1 = r6.f108d;	 Catch:{ all -> 0x009b }
        r1 = r1.length;	 Catch:{ all -> 0x009b }
        if (r1 >= r3) goto L_0x006f;
    L_0x006b:
        r1 = new java.lang.Runnable[r3];	 Catch:{ all -> 0x009b }
        r6.f108d = r1;	 Catch:{ all -> 0x009b }
    L_0x006f:
        r1 = r6.f107c;	 Catch:{ all -> 0x009b }
        r4 = r6.f108d;	 Catch:{ all -> 0x009b }
        r1.toArray(r4);	 Catch:{ all -> 0x009b }
        r1 = r6.f107c;	 Catch:{ all -> 0x009b }
        r1.clear();	 Catch:{ all -> 0x009b }
        r1 = r6.f119o;	 Catch:{ all -> 0x009b }
        r1 = r1.m128h();	 Catch:{ all -> 0x009b }
        r4 = r6.f129z;	 Catch:{ all -> 0x009b }
        r1.removeCallbacks(r4);	 Catch:{ all -> 0x009b }
        monitor-exit(r6);	 Catch:{ all -> 0x009b }
        r6.f109e = r0;
        r1 = r2;
    L_0x008a:
        if (r1 >= r3) goto L_0x009e;
    L_0x008c:
        r4 = r6.f108d;
        r4 = r4[r1];
        r4.run();
        r4 = r6.f108d;
        r5 = 0;
        r4[r1] = r5;
        r1 = r1 + 1;
        goto L_0x008a;
    L_0x009b:
        r0 = move-exception;
        monitor-exit(r6);	 Catch:{ all -> 0x009b }
        throw r0;
    L_0x009e:
        r6.f109e = r2;
        r1 = r0;
        goto L_0x0027;
    L_0x00a2:
        if (r4 != 0) goto L_0x00a9;
    L_0x00a4:
        r6.f126w = r2;
        r6.m178c();
    L_0x00a9:
        return r1;
        */
        throw new UnsupportedOperationException("Method not decompiled: android.support.v4.a.af.d():boolean");
    }

    void m184e() {
        if (this.f117m != null) {
            for (int i = 0; i < this.f117m.size(); i++) {
                ((ae) this.f117m.get(i)).m137a();
            }
        }
    }

    void m185e(C0042t c0042t) {
        if (c0042t.f276J != null) {
            if (this.f128y == null) {
                this.f128y = new SparseArray();
            } else {
                this.f128y.clear();
            }
            c0042t.f276J.saveHierarchyState(this.f128y);
            if (this.f128y.size() > 0) {
                c0042t.f296f = this.f128y;
                this.f128y = null;
            }
        }
    }

    public void m186e(C0042t c0042t, int i, int i2) {
        if (f104a) {
            Log.v("FragmentManager", "attach: " + c0042t);
        }
        if (c0042t.f267A) {
            c0042t.f267A = false;
            if (!c0042t.f303m) {
                if (this.f111g == null) {
                    this.f111g = new ArrayList();
                }
                if (this.f111g.contains(c0042t)) {
                    throw new IllegalStateException("Fragment already added: " + c0042t);
                }
                if (f104a) {
                    Log.v("FragmentManager", "add from attach: " + c0042t);
                }
                this.f111g.add(c0042t);
                c0042t.f303m = true;
                if (c0042t.f270D && c0042t.f271E) {
                    this.f122s = true;
                }
                m163a(c0042t, this.f118n, i, i2, false);
            }
        }
    }

    Bundle m187f(C0042t c0042t) {
        Bundle bundle;
        if (this.f127x == null) {
            this.f127x = new Bundle();
        }
        c0042t.m391i(this.f127x);
        if (this.f127x.isEmpty()) {
            bundle = null;
        } else {
            bundle = this.f127x;
            this.f127x = null;
        }
        if (c0042t.f275I != null) {
            m185e(c0042t);
        }
        if (c0042t.f296f != null) {
            if (bundle == null) {
                bundle = new Bundle();
            }
            bundle.putSparseParcelableArray("android:view_state", c0042t.f296f);
        }
        if (!c0042t.f278L) {
            if (bundle == null) {
                bundle = new Bundle();
            }
            bundle.putBoolean("android:user_visible_hint", c0042t.f278L);
        }
        return bundle;
    }

    ArrayList m188f() {
        ArrayList arrayList = null;
        if (this.f110f != null) {
            for (int i = 0; i < this.f110f.size(); i++) {
                C0042t c0042t = (C0042t) this.f110f.get(i);
                if (c0042t != null && c0042t.f268B) {
                    if (arrayList == null) {
                        arrayList = new ArrayList();
                    }
                    arrayList.add(c0042t);
                    c0042t.f269C = true;
                    c0042t.f301k = c0042t.f300j != null ? c0042t.f300j.f297g : -1;
                    if (f104a) {
                        Log.v("FragmentManager", "retainNonConfig: keeping retained " + c0042t);
                    }
                }
            }
        }
        return arrayList;
    }

    Parcelable m189g() {
        C0038p[] c0038pArr = null;
        m183d();
        if (f105b) {
            this.f123t = true;
        }
        if (this.f110f == null || this.f110f.size() <= 0) {
            return null;
        }
        int size = this.f110f.size();
        ao[] aoVarArr = new ao[size];
        int i = 0;
        boolean z = false;
        while (i < size) {
            boolean z2;
            C0042t c0042t = (C0042t) this.f110f.get(i);
            if (c0042t != null) {
                if (c0042t.f297g < 0) {
                    m141a(new IllegalStateException("Failure saving state: active " + c0042t + " has cleared index: " + c0042t.f297g));
                }
                ao aoVar = new ao(c0042t);
                aoVarArr[i] = aoVar;
                if (c0042t.f292b <= 0 || aoVar.f151j != null) {
                    aoVar.f151j = c0042t.f295e;
                } else {
                    aoVar.f151j = m187f(c0042t);
                    if (c0042t.f300j != null) {
                        if (c0042t.f300j.f297g < 0) {
                            m141a(new IllegalStateException("Failure saving state: " + c0042t + " has target not in fragment manager: " + c0042t.f300j));
                        }
                        if (aoVar.f151j == null) {
                            aoVar.f151j = new Bundle();
                        }
                        m157a(aoVar.f151j, "android:target_state", c0042t.f300j);
                        if (c0042t.f302l != 0) {
                            aoVar.f151j.putInt("android:target_req_state", c0042t.f302l);
                        }
                    }
                }
                if (f104a) {
                    Log.v("FragmentManager", "Saved state of " + c0042t + ": " + aoVar.f151j);
                }
                z2 = true;
            } else {
                z2 = z;
            }
            i++;
            z = z2;
        }
        if (z) {
            int[] iArr;
            int i2;
            am amVar;
            if (this.f111g != null) {
                i = this.f111g.size();
                if (i > 0) {
                    iArr = new int[i];
                    for (i2 = 0; i2 < i; i2++) {
                        iArr[i2] = ((C0042t) this.f111g.get(i2)).f297g;
                        if (iArr[i2] < 0) {
                            m141a(new IllegalStateException("Failure saving state: active " + this.f111g.get(i2) + " has cleared index: " + iArr[i2]));
                        }
                        if (f104a) {
                            Log.v("FragmentManager", "saveAllState: adding fragment #" + i2 + ": " + this.f111g.get(i2));
                        }
                    }
                    if (this.f113i != null) {
                        i = this.f113i.size();
                        if (i > 0) {
                            c0038pArr = new C0038p[i];
                            for (i2 = 0; i2 < i; i2++) {
                                c0038pArr[i2] = new C0038p((C0032j) this.f113i.get(i2));
                                if (f104a) {
                                    Log.v("FragmentManager", "saveAllState: adding back stack #" + i2 + ": " + this.f113i.get(i2));
                                }
                            }
                        }
                    }
                    amVar = new am();
                    amVar.f139a = aoVarArr;
                    amVar.f140b = iArr;
                    amVar.f141c = c0038pArr;
                    return amVar;
                }
            }
            iArr = null;
            if (this.f113i != null) {
                i = this.f113i.size();
                if (i > 0) {
                    c0038pArr = new C0038p[i];
                    for (i2 = 0; i2 < i; i2++) {
                        c0038pArr[i2] = new C0038p((C0032j) this.f113i.get(i2));
                        if (f104a) {
                            Log.v("FragmentManager", "saveAllState: adding back stack #" + i2 + ": " + this.f113i.get(i2));
                        }
                    }
                }
            }
            amVar = new am();
            amVar.f139a = aoVarArr;
            amVar.f140b = iArr;
            amVar.f141c = c0038pArr;
            return amVar;
        } else if (!f104a) {
            return null;
        } else {
            Log.v("FragmentManager", "saveAllState: no fragments!");
            return null;
        }
    }

    public void m190h() {
        this.f123t = false;
    }

    public void m191i() {
        this.f123t = false;
        m155a(1, false);
    }

    public void m192j() {
        this.f123t = false;
        m155a(2, false);
    }

    public void m193k() {
        this.f123t = false;
        m155a(4, false);
    }

    public void m194l() {
        this.f123t = false;
        m155a(5, false);
    }

    public void m195m() {
        m155a(4, false);
    }

    public void m196n() {
        this.f123t = true;
        m155a(3, false);
    }

    public void m197o() {
        m155a(2, false);
    }

    public void m198p() {
        m155a(1, false);
    }

    public void m199q() {
        this.f124u = true;
        m183d();
        m155a(0, false);
        this.f119o = null;
        this.f120p = null;
        this.f121q = null;
    }

    public void m200r() {
        if (this.f111g != null) {
            for (int i = 0; i < this.f111g.size(); i++) {
                C0042t c0042t = (C0042t) this.f111g.get(i);
                if (c0042t != null) {
                    c0042t.m343B();
                }
            }
        }
    }

    al m201s() {
        return this;
    }

    public String toString() {
        StringBuilder stringBuilder = new StringBuilder(128);
        stringBuilder.append("FragmentManager{");
        stringBuilder.append(Integer.toHexString(System.identityHashCode(this)));
        stringBuilder.append(" in ");
        if (this.f121q != null) {
            C0111d.m636a(this.f121q, stringBuilder);
        } else {
            C0111d.m636a(this.f119o, stringBuilder);
        }
        stringBuilder.append("}}");
        return stringBuilder.toString();
    }
}
