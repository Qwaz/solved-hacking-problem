package android.support.v4.app;

import android.content.Context;
import android.content.res.Configuration;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.os.Parcelable;
import android.support.v4.p002c.C0033a;
import android.support.v4.p002c.C0034b;
import android.util.Log;
import android.util.SparseArray;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.animation.AccelerateInterpolator;
import android.view.animation.AlphaAnimation;
import android.view.animation.Animation;
import android.view.animation.AnimationSet;
import android.view.animation.AnimationUtils;
import android.view.animation.DecelerateInterpolator;
import android.view.animation.Interpolator;
import android.view.animation.ScaleAnimation;
import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;

/* renamed from: android.support.v4.app.n */
final class C0016n extends C0014l {
    static final Interpolator f129A;
    static final Interpolator f130B;
    static final Interpolator f131C;
    static boolean f132a;
    static final boolean f133b;
    static final Interpolator f134z;
    ArrayList f135c;
    Runnable[] f136d;
    boolean f137e;
    ArrayList f138f;
    ArrayList f139g;
    ArrayList f140h;
    ArrayList f141i;
    ArrayList f142j;
    ArrayList f143k;
    ArrayList f144l;
    ArrayList f145m;
    int f146n;
    C0011h f147o;
    C0007k f148p;
    Fragment f149q;
    boolean f150r;
    boolean f151s;
    boolean f152t;
    String f153u;
    boolean f154v;
    Bundle f155w;
    SparseArray f156x;
    Runnable f157y;

    static {
        boolean z = false;
        f132a = false;
        if (VERSION.SDK_INT >= 11) {
            z = true;
        }
        f133b = z;
        f134z = new DecelerateInterpolator(2.5f);
        f129A = new DecelerateInterpolator(1.5f);
        f130B = new AccelerateInterpolator(2.5f);
        f131C = new AccelerateInterpolator(1.5f);
    }

    C0016n() {
        this.f146n = 0;
        this.f155w = null;
        this.f156x = null;
        this.f157y = new C0017o(this);
    }

    static Animation m105a(Context context, float f, float f2) {
        Animation alphaAnimation = new AlphaAnimation(f, f2);
        alphaAnimation.setInterpolator(f129A);
        alphaAnimation.setDuration(220);
        return alphaAnimation;
    }

    static Animation m106a(Context context, float f, float f2, float f3, float f4) {
        Animation animationSet = new AnimationSet(false);
        Animation scaleAnimation = new ScaleAnimation(f, f2, f, f2, 1, 0.5f, 1, 0.5f);
        scaleAnimation.setInterpolator(f134z);
        scaleAnimation.setDuration(220);
        animationSet.addAnimation(scaleAnimation);
        scaleAnimation = new AlphaAnimation(f3, f4);
        scaleAnimation.setInterpolator(f129A);
        scaleAnimation.setDuration(220);
        animationSet.addAnimation(scaleAnimation);
        return animationSet;
    }

    private void m107a(RuntimeException runtimeException) {
        Log.e("FragmentManager", runtimeException.getMessage());
        Log.e("FragmentManager", "Activity state:");
        PrintWriter printWriter = new PrintWriter(new C0034b("FragmentManager"));
        if (this.f147o != null) {
            try {
                this.f147o.dump("  ", null, printWriter, new String[0]);
            } catch (Throwable e) {
                Log.e("FragmentManager", "Failed dumping state", e);
            }
        } else {
            try {
                m129a("  ", null, printWriter, new String[0]);
            } catch (Throwable e2) {
                Log.e("FragmentManager", "Failed dumping state", e2);
            }
        }
        throw runtimeException;
    }

    public static int m108b(int i, boolean z) {
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

    public static int m109c(int i) {
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

    private void m110t() {
        if (this.f151s) {
            throw new IllegalStateException("Can not perform this action after onSaveInstanceState");
        } else if (this.f153u != null) {
            throw new IllegalStateException("Can not perform this action inside of " + this.f153u);
        }
    }

    public int m111a(C0004b c0004b) {
        int size;
        synchronized (this) {
            if (this.f144l == null || this.f144l.size() <= 0) {
                if (this.f143k == null) {
                    this.f143k = new ArrayList();
                }
                size = this.f143k.size();
                if (f132a) {
                    Log.v("FragmentManager", "Setting back stack index " + size + " to " + c0004b);
                }
                this.f143k.add(c0004b);
            } else {
                size = ((Integer) this.f144l.remove(this.f144l.size() - 1)).intValue();
                if (f132a) {
                    Log.v("FragmentManager", "Adding back stack index " + size + " with " + c0004b);
                }
                this.f143k.set(size, c0004b);
            }
        }
        return size;
    }

    public Fragment m112a(int i) {
        int size;
        Fragment fragment;
        if (this.f139g != null) {
            for (size = this.f139g.size() - 1; size >= 0; size--) {
                fragment = (Fragment) this.f139g.get(size);
                if (fragment != null && fragment.f55w == i) {
                    return fragment;
                }
            }
        }
        if (this.f138f != null) {
            for (size = this.f138f.size() - 1; size >= 0; size--) {
                fragment = (Fragment) this.f138f.get(size);
                if (fragment != null && fragment.f55w == i) {
                    return fragment;
                }
            }
        }
        return null;
    }

    public Fragment m113a(Bundle bundle, String str) {
        int i = bundle.getInt(str, -1);
        if (i == -1) {
            return null;
        }
        if (i >= this.f138f.size()) {
            m107a(new IllegalStateException("Fragement no longer exists for key " + str + ": index " + i));
        }
        Fragment fragment = (Fragment) this.f138f.get(i);
        if (fragment != null) {
            return fragment;
        }
        m107a(new IllegalStateException("Fragement no longer exists for key " + str + ": index " + i));
        return fragment;
    }

    public Fragment m114a(String str) {
        int size;
        Fragment fragment;
        if (!(this.f139g == null || str == null)) {
            for (size = this.f139g.size() - 1; size >= 0; size--) {
                fragment = (Fragment) this.f139g.get(size);
                if (fragment != null && str.equals(fragment.f57y)) {
                    return fragment;
                }
            }
        }
        if (!(this.f138f == null || str == null)) {
            for (size = this.f138f.size() - 1; size >= 0; size--) {
                fragment = (Fragment) this.f138f.get(size);
                if (fragment != null && str.equals(fragment.f57y)) {
                    return fragment;
                }
            }
        }
        return null;
    }

    public C0003v m115a() {
        return new C0004b(this);
    }

    Animation m116a(Fragment fragment, int i, boolean z, int i2) {
        Animation a = fragment.m14a(i, z, fragment.f24G);
        if (a != null) {
            return a;
        }
        if (fragment.f24G != 0) {
            a = AnimationUtils.loadAnimation(this.f147o, fragment.f24G);
            if (a != null) {
                return a;
            }
        }
        if (i == 0) {
            return null;
        }
        int b = C0016n.m108b(i, z);
        if (b < 0) {
            return null;
        }
        switch (b) {
            case 1:
                return C0016n.m106a(this.f147o, 1.125f, 1.0f, 0.0f, 1.0f);
            case 2:
                return C0016n.m106a(this.f147o, 1.0f, 0.975f, 1.0f, 0.0f);
            case 3:
                return C0016n.m106a(this.f147o, 0.975f, 1.0f, 0.0f, 1.0f);
            case 4:
                return C0016n.m106a(this.f147o, 1.0f, 1.075f, 1.0f, 0.0f);
            case 5:
                return C0016n.m105a(this.f147o, 0.0f, 1.0f);
            case 6:
                return C0016n.m105a(this.f147o, 1.0f, 0.0f);
            default:
                if (i2 == 0 && this.f147o.getWindow() != null) {
                    i2 = this.f147o.getWindow().getAttributes().windowAnimations;
                }
                return i2 == 0 ? null : null;
        }
    }

    void m117a(int i, int i2, int i3, boolean z) {
        if (this.f147o == null && i != 0) {
            throw new IllegalStateException("No activity");
        } else if (z || this.f146n != i) {
            this.f146n = i;
            if (this.f138f != null) {
                int i4 = 0;
                int i5 = 0;
                while (i4 < this.f138f.size()) {
                    int a;
                    Fragment fragment = (Fragment) this.f138f.get(i4);
                    if (fragment != null) {
                        m125a(fragment, i, i2, i3, false);
                        if (fragment.f30M != null) {
                            a = i5 | fragment.f30M.m182a();
                            i4++;
                            i5 = a;
                        }
                    }
                    a = i5;
                    i4++;
                    i5 = a;
                }
                if (i5 == 0) {
                    m144d();
                }
                if (this.f150r && this.f147o != null && this.f146n == 5) {
                    this.f147o.m99c();
                    this.f150r = false;
                }
            }
        }
    }

    public void m118a(int i, C0004b c0004b) {
        synchronized (this) {
            if (this.f143k == null) {
                this.f143k = new ArrayList();
            }
            int size = this.f143k.size();
            if (i < size) {
                if (f132a) {
                    Log.v("FragmentManager", "Setting back stack index " + i + " to " + c0004b);
                }
                this.f143k.set(i, c0004b);
            } else {
                while (size < i) {
                    this.f143k.add(null);
                    if (this.f144l == null) {
                        this.f144l = new ArrayList();
                    }
                    if (f132a) {
                        Log.v("FragmentManager", "Adding available back stack index " + size);
                    }
                    this.f144l.add(Integer.valueOf(size));
                    size++;
                }
                if (f132a) {
                    Log.v("FragmentManager", "Adding back stack index " + i + " with " + c0004b);
                }
                this.f143k.add(c0004b);
            }
        }
    }

    void m119a(int i, boolean z) {
        m117a(i, 0, 0, z);
    }

    public void m120a(Configuration configuration) {
        if (this.f139g != null) {
            for (int i = 0; i < this.f139g.size(); i++) {
                Fragment fragment = (Fragment) this.f139g.get(i);
                if (fragment != null) {
                    fragment.m19a(configuration);
                }
            }
        }
    }

    public void m121a(Bundle bundle, String str, Fragment fragment) {
        if (fragment.f38f < 0) {
            m107a(new IllegalStateException("Fragment " + fragment + " is not currently in the FragmentManager"));
        }
        bundle.putInt(str, fragment.f38f);
    }

    void m122a(Parcelable parcelable, ArrayList arrayList) {
        if (parcelable != null) {
            FragmentManagerState fragmentManagerState = (FragmentManagerState) parcelable;
            if (fragmentManagerState.f59a != null) {
                int i;
                Fragment fragment;
                int i2;
                if (arrayList != null) {
                    for (i = 0; i < arrayList.size(); i++) {
                        fragment = (Fragment) arrayList.get(i);
                        if (f132a) {
                            Log.v("FragmentManager", "restoreAllState: re-attaching retained " + fragment);
                        }
                        FragmentState fragmentState = fragmentManagerState.f59a[fragment.f38f];
                        fragmentState.f72k = fragment;
                        fragment.f37e = null;
                        fragment.f50r = 0;
                        fragment.f48p = false;
                        fragment.f44l = false;
                        fragment.f41i = null;
                        if (fragmentState.f71j != null) {
                            fragmentState.f71j.setClassLoader(this.f147o.getClassLoader());
                            fragment.f37e = fragmentState.f71j.getSparseParcelableArray("android:view_state");
                        }
                    }
                }
                this.f138f = new ArrayList(fragmentManagerState.f59a.length);
                if (this.f140h != null) {
                    this.f140h.clear();
                }
                for (i2 = 0; i2 < fragmentManagerState.f59a.length; i2++) {
                    FragmentState fragmentState2 = fragmentManagerState.f59a[i2];
                    if (fragmentState2 != null) {
                        Fragment a = fragmentState2.m65a(this.f147o, this.f149q);
                        if (f132a) {
                            Log.v("FragmentManager", "restoreAllState: active #" + i2 + ": " + a);
                        }
                        this.f138f.add(a);
                        fragmentState2.f72k = null;
                    } else {
                        this.f138f.add(null);
                        if (this.f140h == null) {
                            this.f140h = new ArrayList();
                        }
                        if (f132a) {
                            Log.v("FragmentManager", "restoreAllState: avail #" + i2);
                        }
                        this.f140h.add(Integer.valueOf(i2));
                    }
                }
                if (arrayList != null) {
                    for (int i3 = 0; i3 < arrayList.size(); i3++) {
                        fragment = (Fragment) arrayList.get(i3);
                        if (fragment.f42j >= 0) {
                            if (fragment.f42j < this.f138f.size()) {
                                fragment.f41i = (Fragment) this.f138f.get(fragment.f42j);
                            } else {
                                Log.w("FragmentManager", "Re-attaching retained fragment " + fragment + " target no longer exists: " + fragment.f42j);
                                fragment.f41i = null;
                            }
                        }
                    }
                }
                if (fragmentManagerState.f60b != null) {
                    this.f139g = new ArrayList(fragmentManagerState.f60b.length);
                    for (i = 0; i < fragmentManagerState.f60b.length; i++) {
                        fragment = (Fragment) this.f138f.get(fragmentManagerState.f60b[i]);
                        if (fragment == null) {
                            m107a(new IllegalStateException("No instantiated fragment for index #" + fragmentManagerState.f60b[i]));
                        }
                        fragment.f44l = true;
                        if (f132a) {
                            Log.v("FragmentManager", "restoreAllState: added #" + i + ": " + fragment);
                        }
                        if (this.f139g.contains(fragment)) {
                            throw new IllegalStateException("Already added!");
                        }
                        this.f139g.add(fragment);
                    }
                } else {
                    this.f139g = null;
                }
                if (fragmentManagerState.f61c != null) {
                    this.f141i = new ArrayList(fragmentManagerState.f61c.length);
                    for (i2 = 0; i2 < fragmentManagerState.f61c.length; i2++) {
                        C0004b a2 = fragmentManagerState.f61c[i2].m10a(this);
                        if (f132a) {
                            Log.v("FragmentManager", "restoreAllState: back stack #" + i2 + " (index " + a2.f95o + "): " + a2);
                            a2.m81a("  ", new PrintWriter(new C0034b("FragmentManager")), false);
                        }
                        this.f141i.add(a2);
                        if (a2.f95o >= 0) {
                            m118a(a2.f95o, a2);
                        }
                    }
                    return;
                }
                this.f141i = null;
            }
        }
    }

    public void m123a(Fragment fragment) {
        if (!fragment.f28K) {
            return;
        }
        if (this.f137e) {
            this.f154v = true;
            return;
        }
        fragment.f28K = false;
        m125a(fragment, this.f146n, 0, 0, false);
    }

    public void m124a(Fragment fragment, int i, int i2) {
        if (f132a) {
            Log.v("FragmentManager", "remove: " + fragment + " nesting=" + fragment.f50r);
        }
        boolean z = !fragment.m26a();
        if (!fragment.f18A || z) {
            if (this.f139g != null) {
                this.f139g.remove(fragment);
            }
            if (fragment.f21D && fragment.f22E) {
                this.f150r = true;
            }
            fragment.f44l = false;
            fragment.f45m = true;
            m125a(fragment, z ? 0 : 1, i, i2, false);
        }
    }

    /* JADX WARNING: inconsistent code. */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    void m125a(android.support.v4.app.Fragment r10, int r11, int r12, int r13, boolean r14) {
        /*
        r9 = this;
        r8 = 4;
        r6 = 3;
        r3 = 0;
        r5 = 1;
        r7 = 0;
        r0 = r10.f44l;
        if (r0 == 0) goto L_0x000d;
    L_0x0009:
        r0 = r10.f18A;
        if (r0 == 0) goto L_0x0010;
    L_0x000d:
        if (r11 <= r5) goto L_0x0010;
    L_0x000f:
        r11 = r5;
    L_0x0010:
        r0 = r10.f45m;
        if (r0 == 0) goto L_0x001a;
    L_0x0014:
        r0 = r10.f33a;
        if (r11 <= r0) goto L_0x001a;
    L_0x0018:
        r11 = r10.f33a;
    L_0x001a:
        r0 = r10.f28K;
        if (r0 == 0) goto L_0x0025;
    L_0x001e:
        r0 = r10.f33a;
        if (r0 >= r8) goto L_0x0025;
    L_0x0022:
        if (r11 <= r6) goto L_0x0025;
    L_0x0024:
        r11 = r6;
    L_0x0025:
        r0 = r10.f33a;
        if (r0 >= r11) goto L_0x0240;
    L_0x0029:
        r0 = r10.f47o;
        if (r0 == 0) goto L_0x0032;
    L_0x002d:
        r0 = r10.f48p;
        if (r0 != 0) goto L_0x0032;
    L_0x0031:
        return;
    L_0x0032:
        r0 = r10.f34b;
        if (r0 == 0) goto L_0x0040;
    L_0x0036:
        r10.f34b = r7;
        r2 = r10.f35c;
        r0 = r9;
        r1 = r10;
        r4 = r3;
        r0.m125a(r1, r2, r3, r4, r5);
    L_0x0040:
        r0 = r10.f33a;
        switch(r0) {
            case 0: goto L_0x0048;
            case 1: goto L_0x0126;
            case 2: goto L_0x01ef;
            case 3: goto L_0x01ef;
            case 4: goto L_0x0210;
            default: goto L_0x0045;
        };
    L_0x0045:
        r10.f33a = r11;
        goto L_0x0031;
    L_0x0048:
        r0 = f132a;
        if (r0 == 0) goto L_0x0064;
    L_0x004c:
        r0 = "FragmentManager";
        r1 = new java.lang.StringBuilder;
        r1.<init>();
        r2 = "moveto CREATED: ";
        r1 = r1.append(r2);
        r1 = r1.append(r10);
        r1 = r1.toString();
        android.util.Log.v(r0, r1);
    L_0x0064:
        r0 = r10.f36d;
        if (r0 == 0) goto L_0x009d;
    L_0x0068:
        r0 = r10.f36d;
        r1 = "android:view_state";
        r0 = r0.getSparseParcelableArray(r1);
        r10.f37e = r0;
        r0 = r10.f36d;
        r1 = "android:target_state";
        r0 = r9.m113a(r0, r1);
        r10.f41i = r0;
        r0 = r10.f41i;
        if (r0 == 0) goto L_0x008a;
    L_0x0080:
        r0 = r10.f36d;
        r1 = "android:target_req_state";
        r0 = r0.getInt(r1, r3);
        r10.f43k = r0;
    L_0x008a:
        r0 = r10.f36d;
        r1 = "android:user_visible_hint";
        r0 = r0.getBoolean(r1, r5);
        r10.f29L = r0;
        r0 = r10.f29L;
        if (r0 != 0) goto L_0x009d;
    L_0x0098:
        r10.f28K = r5;
        if (r11 <= r6) goto L_0x009d;
    L_0x009c:
        r11 = r6;
    L_0x009d:
        r0 = r9.f147o;
        r10.f52t = r0;
        r0 = r9.f149q;
        r10.f54v = r0;
        r0 = r9.f149q;
        if (r0 == 0) goto L_0x00d9;
    L_0x00a9:
        r0 = r9.f149q;
        r0 = r0.f53u;
    L_0x00ad:
        r10.f51s = r0;
        r10.f23F = r3;
        r0 = r9.f147o;
        r10.m17a(r0);
        r0 = r10.f23F;
        if (r0 != 0) goto L_0x00de;
    L_0x00ba:
        r0 = new android.support.v4.app.ab;
        r1 = new java.lang.StringBuilder;
        r1.<init>();
        r2 = "Fragment ";
        r1 = r1.append(r2);
        r1 = r1.append(r10);
        r2 = " did not call through to super.onAttach()";
        r1 = r1.append(r2);
        r1 = r1.toString();
        r0.<init>(r1);
        throw r0;
    L_0x00d9:
        r0 = r9.f147o;
        r0 = r0.f111b;
        goto L_0x00ad;
    L_0x00de:
        r0 = r10.f54v;
        if (r0 != 0) goto L_0x00e7;
    L_0x00e2:
        r0 = r9.f147o;
        r0.m95a(r10);
    L_0x00e7:
        r0 = r10.f20C;
        if (r0 != 0) goto L_0x00f0;
    L_0x00eb:
        r0 = r10.f36d;
        r10.m47g(r0);
    L_0x00f0:
        r10.f20C = r3;
        r0 = r10.f47o;
        if (r0 == 0) goto L_0x0126;
    L_0x00f6:
        r0 = r10.f36d;
        r0 = r10.m29b(r0);
        r1 = r10.f36d;
        r0 = r10.m30b(r0, r7, r1);
        r10.f26I = r0;
        r0 = r10.f26I;
        if (r0 == 0) goto L_0x0239;
    L_0x0108:
        r0 = r10.f26I;
        r10.f27J = r0;
        r0 = r10.f26I;
        r0 = android.support.v4.app.aa.m68a(r0);
        r10.f26I = r0;
        r0 = r10.f58z;
        if (r0 == 0) goto L_0x011f;
    L_0x0118:
        r0 = r10.f26I;
        r1 = 8;
        r0.setVisibility(r1);
    L_0x011f:
        r0 = r10.f26I;
        r1 = r10.f36d;
        r10.m23a(r0, r1);
    L_0x0126:
        if (r11 <= r5) goto L_0x01ef;
    L_0x0128:
        r0 = f132a;
        if (r0 == 0) goto L_0x0144;
    L_0x012c:
        r0 = "FragmentManager";
        r1 = new java.lang.StringBuilder;
        r1.<init>();
        r2 = "moveto ACTIVITY_CREATED: ";
        r1 = r1.append(r2);
        r1 = r1.append(r10);
        r1 = r1.toString();
        android.util.Log.v(r0, r1);
    L_0x0144:
        r0 = r10.f47o;
        if (r0 != 0) goto L_0x01df;
    L_0x0148:
        r0 = r10.f56x;
        if (r0 == 0) goto L_0x0397;
    L_0x014c:
        r0 = r9.f148p;
        r1 = r10.f56x;
        r0 = r0.m87a(r1);
        r0 = (android.view.ViewGroup) r0;
        if (r0 != 0) goto L_0x019b;
    L_0x0158:
        r1 = r10.f49q;
        if (r1 != 0) goto L_0x019b;
    L_0x015c:
        r1 = new java.lang.IllegalArgumentException;
        r2 = new java.lang.StringBuilder;
        r2.<init>();
        r3 = "No view found for id 0x";
        r2 = r2.append(r3);
        r3 = r10.f56x;
        r3 = java.lang.Integer.toHexString(r3);
        r2 = r2.append(r3);
        r3 = " (";
        r2 = r2.append(r3);
        r3 = r10.m34c();
        r4 = r10.f56x;
        r3 = r3.getResourceName(r4);
        r2 = r2.append(r3);
        r3 = ") for fragment ";
        r2 = r2.append(r3);
        r2 = r2.append(r10);
        r2 = r2.toString();
        r1.<init>(r2);
        r9.m107a(r1);
    L_0x019b:
        r10.f25H = r0;
        r1 = r10.f36d;
        r1 = r10.m29b(r1);
        r2 = r10.f36d;
        r1 = r10.m30b(r1, r0, r2);
        r10.f26I = r1;
        r1 = r10.f26I;
        if (r1 == 0) goto L_0x023d;
    L_0x01af:
        r1 = r10.f26I;
        r10.f27J = r1;
        r1 = r10.f26I;
        r1 = android.support.v4.app.aa.m68a(r1);
        r10.f26I = r1;
        if (r0 == 0) goto L_0x01cd;
    L_0x01bd:
        r1 = r9.m116a(r10, r12, r5, r13);
        if (r1 == 0) goto L_0x01c8;
    L_0x01c3:
        r2 = r10.f26I;
        r2.startAnimation(r1);
    L_0x01c8:
        r1 = r10.f26I;
        r0.addView(r1);
    L_0x01cd:
        r0 = r10.f58z;
        if (r0 == 0) goto L_0x01d8;
    L_0x01d1:
        r0 = r10.f26I;
        r1 = 8;
        r0.setVisibility(r1);
    L_0x01d8:
        r0 = r10.f26I;
        r1 = r10.f36d;
        r10.m23a(r0, r1);
    L_0x01df:
        r0 = r10.f36d;
        r10.m49h(r0);
        r0 = r10.f26I;
        if (r0 == 0) goto L_0x01ed;
    L_0x01e8:
        r0 = r10.f36d;
        r10.m20a(r0);
    L_0x01ed:
        r10.f36d = r7;
    L_0x01ef:
        if (r11 <= r6) goto L_0x0210;
    L_0x01f1:
        r0 = f132a;
        if (r0 == 0) goto L_0x020d;
    L_0x01f5:
        r0 = "FragmentManager";
        r1 = new java.lang.StringBuilder;
        r1.<init>();
        r2 = "moveto STARTED: ";
        r1 = r1.append(r2);
        r1 = r1.append(r10);
        r1 = r1.toString();
        android.util.Log.v(r0, r1);
    L_0x020d:
        r10.m57o();
    L_0x0210:
        if (r11 <= r8) goto L_0x0045;
    L_0x0212:
        r0 = f132a;
        if (r0 == 0) goto L_0x022e;
    L_0x0216:
        r0 = "FragmentManager";
        r1 = new java.lang.StringBuilder;
        r1.<init>();
        r2 = "moveto RESUMED: ";
        r1 = r1.append(r2);
        r1 = r1.append(r10);
        r1 = r1.toString();
        android.util.Log.v(r0, r1);
    L_0x022e:
        r10.f46n = r5;
        r10.m58p();
        r10.f36d = r7;
        r10.f37e = r7;
        goto L_0x0045;
    L_0x0239:
        r10.f27J = r7;
        goto L_0x0126;
    L_0x023d:
        r10.f27J = r7;
        goto L_0x01df;
    L_0x0240:
        r0 = r10.f33a;
        if (r0 <= r11) goto L_0x0045;
    L_0x0244:
        r0 = r10.f33a;
        switch(r0) {
            case 1: goto L_0x024b;
            case 2: goto L_0x02cb;
            case 3: goto L_0x02aa;
            case 4: goto L_0x0289;
            case 5: goto L_0x0265;
            default: goto L_0x0249;
        };
    L_0x0249:
        goto L_0x0045;
    L_0x024b:
        if (r11 >= r5) goto L_0x0045;
    L_0x024d:
        r0 = r9.f152t;
        if (r0 == 0) goto L_0x025c;
    L_0x0251:
        r0 = r10.f34b;
        if (r0 == 0) goto L_0x025c;
    L_0x0255:
        r0 = r10.f34b;
        r10.f34b = r7;
        r0.clearAnimation();
    L_0x025c:
        r0 = r10.f34b;
        if (r0 == 0) goto L_0x0338;
    L_0x0260:
        r10.f35c = r11;
        r11 = r5;
        goto L_0x0045;
    L_0x0265:
        r0 = 5;
        if (r11 >= r0) goto L_0x0289;
    L_0x0268:
        r0 = f132a;
        if (r0 == 0) goto L_0x0284;
    L_0x026c:
        r0 = "FragmentManager";
        r1 = new java.lang.StringBuilder;
        r1.<init>();
        r2 = "movefrom RESUMED: ";
        r1 = r1.append(r2);
        r1 = r1.append(r10);
        r1 = r1.toString();
        android.util.Log.v(r0, r1);
    L_0x0284:
        r10.m60r();
        r10.f46n = r3;
    L_0x0289:
        if (r11 >= r8) goto L_0x02aa;
    L_0x028b:
        r0 = f132a;
        if (r0 == 0) goto L_0x02a7;
    L_0x028f:
        r0 = "FragmentManager";
        r1 = new java.lang.StringBuilder;
        r1.<init>();
        r2 = "movefrom STARTED: ";
        r1 = r1.append(r2);
        r1 = r1.append(r10);
        r1 = r1.toString();
        android.util.Log.v(r0, r1);
    L_0x02a7:
        r10.m61s();
    L_0x02aa:
        if (r11 >= r6) goto L_0x02cb;
    L_0x02ac:
        r0 = f132a;
        if (r0 == 0) goto L_0x02c8;
    L_0x02b0:
        r0 = "FragmentManager";
        r1 = new java.lang.StringBuilder;
        r1.<init>();
        r2 = "movefrom STOPPED: ";
        r1 = r1.append(r2);
        r1 = r1.append(r10);
        r1 = r1.toString();
        android.util.Log.v(r0, r1);
    L_0x02c8:
        r10.m62t();
    L_0x02cb:
        r0 = 2;
        if (r11 >= r0) goto L_0x024b;
    L_0x02ce:
        r0 = f132a;
        if (r0 == 0) goto L_0x02ea;
    L_0x02d2:
        r0 = "FragmentManager";
        r1 = new java.lang.StringBuilder;
        r1.<init>();
        r2 = "movefrom ACTIVITY_CREATED: ";
        r1 = r1.append(r2);
        r1 = r1.append(r10);
        r1 = r1.toString();
        android.util.Log.v(r0, r1);
    L_0x02ea:
        r0 = r10.f26I;
        if (r0 == 0) goto L_0x02fd;
    L_0x02ee:
        r0 = r9.f147o;
        r0 = r0.isFinishing();
        if (r0 != 0) goto L_0x02fd;
    L_0x02f6:
        r0 = r10.f37e;
        if (r0 != 0) goto L_0x02fd;
    L_0x02fa:
        r9.m147e(r10);
    L_0x02fd:
        r10.m63u();
        r0 = r10.f26I;
        if (r0 == 0) goto L_0x0330;
    L_0x0304:
        r0 = r10.f25H;
        if (r0 == 0) goto L_0x0330;
    L_0x0308:
        r0 = r9.f146n;
        if (r0 <= 0) goto L_0x0394;
    L_0x030c:
        r0 = r9.f152t;
        if (r0 != 0) goto L_0x0394;
    L_0x0310:
        r0 = r9.m116a(r10, r12, r3, r13);
    L_0x0314:
        if (r0 == 0) goto L_0x0329;
    L_0x0316:
        r1 = r10.f26I;
        r10.f34b = r1;
        r10.f35c = r11;
        r1 = new android.support.v4.app.p;
        r1.<init>(r9, r10);
        r0.setAnimationListener(r1);
        r1 = r10.f26I;
        r1.startAnimation(r0);
    L_0x0329:
        r0 = r10.f25H;
        r1 = r10.f26I;
        r0.removeView(r1);
    L_0x0330:
        r10.f25H = r7;
        r10.f26I = r7;
        r10.f27J = r7;
        goto L_0x024b;
    L_0x0338:
        r0 = f132a;
        if (r0 == 0) goto L_0x0354;
    L_0x033c:
        r0 = "FragmentManager";
        r1 = new java.lang.StringBuilder;
        r1.<init>();
        r2 = "movefrom CREATED: ";
        r1 = r1.append(r2);
        r1 = r1.append(r10);
        r1 = r1.toString();
        android.util.Log.v(r0, r1);
    L_0x0354:
        r0 = r10.f20C;
        if (r0 != 0) goto L_0x035b;
    L_0x0358:
        r10.m64v();
    L_0x035b:
        r10.f23F = r3;
        r10.m54l();
        r0 = r10.f23F;
        if (r0 != 0) goto L_0x0383;
    L_0x0364:
        r0 = new android.support.v4.app.ab;
        r1 = new java.lang.StringBuilder;
        r1.<init>();
        r2 = "Fragment ";
        r1 = r1.append(r2);
        r1 = r1.append(r10);
        r2 = " did not call through to super.onDetach()";
        r1 = r1.append(r2);
        r1 = r1.toString();
        r0.<init>(r1);
        throw r0;
    L_0x0383:
        if (r14 != 0) goto L_0x0045;
    L_0x0385:
        r0 = r10.f20C;
        if (r0 != 0) goto L_0x038e;
    L_0x0389:
        r9.m145d(r10);
        goto L_0x0045;
    L_0x038e:
        r10.f52t = r7;
        r10.f51s = r7;
        goto L_0x0045;
    L_0x0394:
        r0 = r7;
        goto L_0x0314;
    L_0x0397:
        r0 = r7;
        goto L_0x019b;
        */
        throw new UnsupportedOperationException("Method not decompiled: android.support.v4.app.n.a(android.support.v4.app.Fragment, int, int, int, boolean):void");
    }

    public void m126a(Fragment fragment, boolean z) {
        if (this.f139g == null) {
            this.f139g = new ArrayList();
        }
        if (f132a) {
            Log.v("FragmentManager", "add: " + fragment);
        }
        m141c(fragment);
        if (!fragment.f18A) {
            if (this.f139g.contains(fragment)) {
                throw new IllegalStateException("Fragment already added: " + fragment);
            }
            this.f139g.add(fragment);
            fragment.f44l = true;
            fragment.f45m = false;
            if (fragment.f21D && fragment.f22E) {
                this.f150r = true;
            }
            if (z) {
                m135b(fragment);
            }
        }
    }

    public void m127a(C0011h c0011h, C0007k c0007k, Fragment fragment) {
        if (this.f147o != null) {
            throw new IllegalStateException("Already attached");
        }
        this.f147o = c0011h;
        this.f148p = c0007k;
        this.f149q = fragment;
    }

    public void m128a(Runnable runnable, boolean z) {
        if (!z) {
            m110t();
        }
        synchronized (this) {
            if (this.f147o == null) {
                throw new IllegalStateException("Activity has been destroyed");
            }
            if (this.f135c == null) {
                this.f135c = new ArrayList();
            }
            this.f135c.add(runnable);
            if (this.f135c.size() == 1) {
                this.f147o.f110a.removeCallbacks(this.f157y);
                this.f147o.f110a.post(this.f157y);
            }
        }
    }

    public void m129a(String str, FileDescriptor fileDescriptor, PrintWriter printWriter, String[] strArr) {
        int size;
        int i;
        Fragment fragment;
        int i2 = 0;
        String str2 = str + "    ";
        if (this.f138f != null) {
            size = this.f138f.size();
            if (size > 0) {
                printWriter.print(str);
                printWriter.print("Active Fragments in ");
                printWriter.print(Integer.toHexString(System.identityHashCode(this)));
                printWriter.println(":");
                for (i = 0; i < size; i++) {
                    fragment = (Fragment) this.f138f.get(i);
                    printWriter.print(str);
                    printWriter.print("  #");
                    printWriter.print(i);
                    printWriter.print(": ");
                    printWriter.println(fragment);
                    if (fragment != null) {
                        fragment.m24a(str2, fileDescriptor, printWriter, strArr);
                    }
                }
            }
        }
        if (this.f139g != null) {
            size = this.f139g.size();
            if (size > 0) {
                printWriter.print(str);
                printWriter.println("Added Fragments:");
                for (i = 0; i < size; i++) {
                    fragment = (Fragment) this.f139g.get(i);
                    printWriter.print(str);
                    printWriter.print("  #");
                    printWriter.print(i);
                    printWriter.print(": ");
                    printWriter.println(fragment.toString());
                }
            }
        }
        if (this.f142j != null) {
            size = this.f142j.size();
            if (size > 0) {
                printWriter.print(str);
                printWriter.println("Fragments Created Menus:");
                for (i = 0; i < size; i++) {
                    fragment = (Fragment) this.f142j.get(i);
                    printWriter.print(str);
                    printWriter.print("  #");
                    printWriter.print(i);
                    printWriter.print(": ");
                    printWriter.println(fragment.toString());
                }
            }
        }
        if (this.f141i != null) {
            size = this.f141i.size();
            if (size > 0) {
                printWriter.print(str);
                printWriter.println("Back Stack:");
                for (i = 0; i < size; i++) {
                    C0004b c0004b = (C0004b) this.f141i.get(i);
                    printWriter.print(str);
                    printWriter.print("  #");
                    printWriter.print(i);
                    printWriter.print(": ");
                    printWriter.println(c0004b.toString());
                    c0004b.m80a(str2, fileDescriptor, printWriter, strArr);
                }
            }
        }
        synchronized (this) {
            if (this.f143k != null) {
                int size2 = this.f143k.size();
                if (size2 > 0) {
                    printWriter.print(str);
                    printWriter.println("Back Stack Indices:");
                    for (i = 0; i < size2; i++) {
                        c0004b = (C0004b) this.f143k.get(i);
                        printWriter.print(str);
                        printWriter.print("  #");
                        printWriter.print(i);
                        printWriter.print(": ");
                        printWriter.println(c0004b);
                    }
                }
            }
            if (this.f144l != null && this.f144l.size() > 0) {
                printWriter.print(str);
                printWriter.print("mAvailBackStackIndices: ");
                printWriter.println(Arrays.toString(this.f144l.toArray()));
            }
        }
        if (this.f135c != null) {
            i = this.f135c.size();
            if (i > 0) {
                printWriter.print(str);
                printWriter.println("Pending Actions:");
                while (i2 < i) {
                    Runnable runnable = (Runnable) this.f135c.get(i2);
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
        printWriter.print("  mActivity=");
        printWriter.println(this.f147o);
        printWriter.print(str);
        printWriter.print("  mContainer=");
        printWriter.println(this.f148p);
        if (this.f149q != null) {
            printWriter.print(str);
            printWriter.print("  mParent=");
            printWriter.println(this.f149q);
        }
        printWriter.print(str);
        printWriter.print("  mCurState=");
        printWriter.print(this.f146n);
        printWriter.print(" mStateSaved=");
        printWriter.print(this.f151s);
        printWriter.print(" mDestroyed=");
        printWriter.println(this.f152t);
        if (this.f150r) {
            printWriter.print(str);
            printWriter.print("  mNeedMenuInvalidate=");
            printWriter.println(this.f150r);
        }
        if (this.f153u != null) {
            printWriter.print(str);
            printWriter.print("  mNoTransactionsBecause=");
            printWriter.println(this.f153u);
        }
        if (this.f140h != null && this.f140h.size() > 0) {
            printWriter.print(str);
            printWriter.print("  mAvailIndices: ");
            printWriter.println(Arrays.toString(this.f140h.toArray()));
        }
    }

    /* JADX WARNING: inconsistent code. */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    boolean m130a(android.os.Handler r9, java.lang.String r10, int r11, int r12) {
        /*
        r8 = this;
        r2 = 1;
        r3 = 0;
        r0 = r8.f141i;
        if (r0 != 0) goto L_0x0007;
    L_0x0006:
        return r3;
    L_0x0007:
        if (r10 != 0) goto L_0x0029;
    L_0x0009:
        if (r11 >= 0) goto L_0x0029;
    L_0x000b:
        r0 = r12 & 1;
        if (r0 != 0) goto L_0x0029;
    L_0x000f:
        r0 = r8.f141i;
        r0 = r0.size();
        r0 = r0 + -1;
        if (r0 < 0) goto L_0x0006;
    L_0x0019:
        r1 = r8.f141i;
        r0 = r1.remove(r0);
        r0 = (android.support.v4.app.C0004b) r0;
        r0.m84b(r2);
        r8.m151f();
    L_0x0027:
        r3 = r2;
        goto L_0x0006;
    L_0x0029:
        r0 = -1;
        if (r10 != 0) goto L_0x002e;
    L_0x002c:
        if (r11 < 0) goto L_0x007d;
    L_0x002e:
        r0 = r8.f141i;
        r0 = r0.size();
        r1 = r0 + -1;
    L_0x0036:
        if (r1 < 0) goto L_0x004c;
    L_0x0038:
        r0 = r8.f141i;
        r0 = r0.get(r1);
        r0 = (android.support.v4.app.C0004b) r0;
        if (r10 == 0) goto L_0x0073;
    L_0x0042:
        r4 = r0.m83b();
        r4 = r10.equals(r4);
        if (r4 == 0) goto L_0x0073;
    L_0x004c:
        if (r1 < 0) goto L_0x0006;
    L_0x004e:
        r0 = r12 & 1;
        if (r0 == 0) goto L_0x007c;
    L_0x0052:
        r1 = r1 + -1;
    L_0x0054:
        if (r1 < 0) goto L_0x007c;
    L_0x0056:
        r0 = r8.f141i;
        r0 = r0.get(r1);
        r0 = (android.support.v4.app.C0004b) r0;
        if (r10 == 0) goto L_0x006a;
    L_0x0060:
        r4 = r0.m83b();
        r4 = r10.equals(r4);
        if (r4 != 0) goto L_0x0070;
    L_0x006a:
        if (r11 < 0) goto L_0x007c;
    L_0x006c:
        r0 = r0.f95o;
        if (r11 != r0) goto L_0x007c;
    L_0x0070:
        r1 = r1 + -1;
        goto L_0x0054;
    L_0x0073:
        if (r11 < 0) goto L_0x0079;
    L_0x0075:
        r0 = r0.f95o;
        if (r11 == r0) goto L_0x004c;
    L_0x0079:
        r1 = r1 + -1;
        goto L_0x0036;
    L_0x007c:
        r0 = r1;
    L_0x007d:
        r1 = r8.f141i;
        r1 = r1.size();
        r1 = r1 + -1;
        if (r0 == r1) goto L_0x0006;
    L_0x0087:
        r5 = new java.util.ArrayList;
        r5.<init>();
        r1 = r8.f141i;
        r1 = r1.size();
        r1 = r1 + -1;
    L_0x0094:
        if (r1 <= r0) goto L_0x00a2;
    L_0x0096:
        r4 = r8.f141i;
        r4 = r4.remove(r1);
        r5.add(r4);
        r1 = r1 + -1;
        goto L_0x0094;
    L_0x00a2:
        r0 = r5.size();
        r6 = r0 + -1;
        r4 = r3;
    L_0x00a9:
        if (r4 > r6) goto L_0x00dd;
    L_0x00ab:
        r0 = f132a;
        if (r0 == 0) goto L_0x00cb;
    L_0x00af:
        r0 = "FragmentManager";
        r1 = new java.lang.StringBuilder;
        r1.<init>();
        r7 = "Popping back stack state: ";
        r1 = r1.append(r7);
        r7 = r5.get(r4);
        r1 = r1.append(r7);
        r1 = r1.toString();
        android.util.Log.v(r0, r1);
    L_0x00cb:
        r0 = r5.get(r4);
        r0 = (android.support.v4.app.C0004b) r0;
        if (r4 != r6) goto L_0x00db;
    L_0x00d3:
        r1 = r2;
    L_0x00d4:
        r0.m84b(r1);
        r0 = r4 + 1;
        r4 = r0;
        goto L_0x00a9;
    L_0x00db:
        r1 = r3;
        goto L_0x00d4;
    L_0x00dd:
        r8.m151f();
        goto L_0x0027;
        */
        throw new UnsupportedOperationException("Method not decompiled: android.support.v4.app.n.a(android.os.Handler, java.lang.String, int, int):boolean");
    }

    public boolean m131a(Menu menu) {
        if (this.f139g == null) {
            return false;
        }
        boolean z = false;
        for (int i = 0; i < this.f139g.size(); i++) {
            Fragment fragment = (Fragment) this.f139g.get(i);
            if (fragment != null && fragment.m36c(menu)) {
                z = true;
            }
        }
        return z;
    }

    public boolean m132a(Menu menu, MenuInflater menuInflater) {
        boolean z;
        Fragment fragment;
        int i = 0;
        ArrayList arrayList = null;
        if (this.f139g != null) {
            int i2 = 0;
            z = false;
            while (i2 < this.f139g.size()) {
                fragment = (Fragment) this.f139g.get(i2);
                if (fragment != null && fragment.m32b(menu, menuInflater)) {
                    z = true;
                    if (arrayList == null) {
                        arrayList = new ArrayList();
                    }
                    arrayList.add(fragment);
                }
                i2++;
                z = z;
            }
        } else {
            z = false;
        }
        if (this.f142j != null) {
            while (i < this.f142j.size()) {
                fragment = (Fragment) this.f142j.get(i);
                if (arrayList == null || !arrayList.contains(fragment)) {
                    fragment.m55m();
                }
                i++;
            }
        }
        this.f142j = arrayList;
        return z;
    }

    public boolean m133a(MenuItem menuItem) {
        if (this.f139g == null) {
            return false;
        }
        for (int i = 0; i < this.f139g.size(); i++) {
            Fragment fragment = (Fragment) this.f139g.get(i);
            if (fragment != null && fragment.m37c(menuItem)) {
                return true;
            }
        }
        return false;
    }

    public void m134b(int i) {
        synchronized (this) {
            this.f143k.set(i, null);
            if (this.f144l == null) {
                this.f144l = new ArrayList();
            }
            if (f132a) {
                Log.v("FragmentManager", "Freeing back stack index " + i);
            }
            this.f144l.add(Integer.valueOf(i));
        }
    }

    void m135b(Fragment fragment) {
        m125a(fragment, this.f146n, 0, 0, false);
    }

    public void m136b(Fragment fragment, int i, int i2) {
        if (f132a) {
            Log.v("FragmentManager", "hide: " + fragment);
        }
        if (!fragment.f58z) {
            fragment.f58z = true;
            if (fragment.f26I != null) {
                Animation a = m116a(fragment, i, true, i2);
                if (a != null) {
                    fragment.f26I.startAnimation(a);
                }
                fragment.f26I.setVisibility(8);
            }
            if (fragment.f44l && fragment.f21D && fragment.f22E) {
                this.f150r = true;
            }
            fragment.m25a(true);
        }
    }

    void m137b(C0004b c0004b) {
        if (this.f141i == null) {
            this.f141i = new ArrayList();
        }
        this.f141i.add(c0004b);
        m151f();
    }

    public void m138b(Menu menu) {
        if (this.f139g != null) {
            for (int i = 0; i < this.f139g.size(); i++) {
                Fragment fragment = (Fragment) this.f139g.get(i);
                if (fragment != null) {
                    fragment.m39d(menu);
                }
            }
        }
    }

    public boolean m139b() {
        return m149e();
    }

    public boolean m140b(MenuItem menuItem) {
        if (this.f139g == null) {
            return false;
        }
        for (int i = 0; i < this.f139g.size(); i++) {
            Fragment fragment = (Fragment) this.f139g.get(i);
            if (fragment != null && fragment.m41d(menuItem)) {
                return true;
            }
        }
        return false;
    }

    void m141c(Fragment fragment) {
        if (fragment.f38f < 0) {
            if (this.f140h == null || this.f140h.size() <= 0) {
                if (this.f138f == null) {
                    this.f138f = new ArrayList();
                }
                fragment.m16a(this.f138f.size(), this.f149q);
                this.f138f.add(fragment);
            } else {
                fragment.m16a(((Integer) this.f140h.remove(this.f140h.size() - 1)).intValue(), this.f149q);
                this.f138f.set(fragment.f38f, fragment);
            }
            if (f132a) {
                Log.v("FragmentManager", "Allocated fragment index " + fragment);
            }
        }
    }

    public void m142c(Fragment fragment, int i, int i2) {
        if (f132a) {
            Log.v("FragmentManager", "show: " + fragment);
        }
        if (fragment.f58z) {
            fragment.f58z = false;
            if (fragment.f26I != null) {
                Animation a = m116a(fragment, i, true, i2);
                if (a != null) {
                    fragment.f26I.startAnimation(a);
                }
                fragment.f26I.setVisibility(0);
            }
            if (fragment.f44l && fragment.f21D && fragment.f22E) {
                this.f150r = true;
            }
            fragment.m25a(false);
        }
    }

    public boolean m143c() {
        m110t();
        m139b();
        return m130a(this.f147o.f110a, null, -1, 0);
    }

    void m144d() {
        if (this.f138f != null) {
            for (int i = 0; i < this.f138f.size(); i++) {
                Fragment fragment = (Fragment) this.f138f.get(i);
                if (fragment != null) {
                    m123a(fragment);
                }
            }
        }
    }

    void m145d(Fragment fragment) {
        if (fragment.f38f >= 0) {
            if (f132a) {
                Log.v("FragmentManager", "Freeing fragment index " + fragment);
            }
            this.f138f.set(fragment.f38f, null);
            if (this.f140h == null) {
                this.f140h = new ArrayList();
            }
            this.f140h.add(Integer.valueOf(fragment.f38f));
            this.f147o.m96a(fragment.f39g);
            fragment.m53k();
        }
    }

    public void m146d(Fragment fragment, int i, int i2) {
        if (f132a) {
            Log.v("FragmentManager", "detach: " + fragment);
        }
        if (!fragment.f18A) {
            fragment.f18A = true;
            if (fragment.f44l) {
                if (this.f139g != null) {
                    if (f132a) {
                        Log.v("FragmentManager", "remove from detach: " + fragment);
                    }
                    this.f139g.remove(fragment);
                }
                if (fragment.f21D && fragment.f22E) {
                    this.f150r = true;
                }
                fragment.f44l = false;
                m125a(fragment, 1, i, i2, false);
            }
        }
    }

    void m147e(Fragment fragment) {
        if (fragment.f27J != null) {
            if (this.f156x == null) {
                this.f156x = new SparseArray();
            } else {
                this.f156x.clear();
            }
            fragment.f27J.saveHierarchyState(this.f156x);
            if (this.f156x.size() > 0) {
                fragment.f37e = this.f156x;
                this.f156x = null;
            }
        }
    }

    public void m148e(Fragment fragment, int i, int i2) {
        if (f132a) {
            Log.v("FragmentManager", "attach: " + fragment);
        }
        if (fragment.f18A) {
            fragment.f18A = false;
            if (!fragment.f44l) {
                if (this.f139g == null) {
                    this.f139g = new ArrayList();
                }
                if (this.f139g.contains(fragment)) {
                    throw new IllegalStateException("Fragment already added: " + fragment);
                }
                if (f132a) {
                    Log.v("FragmentManager", "add from attach: " + fragment);
                }
                this.f139g.add(fragment);
                fragment.f44l = true;
                if (fragment.f21D && fragment.f22E) {
                    this.f150r = true;
                }
                m125a(fragment, this.f146n, i, i2, false);
            }
        }
    }

    /* JADX WARNING: inconsistent code. */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public boolean m149e() {
        /*
        r6 = this;
        r0 = 1;
        r2 = 0;
        r1 = r6.f137e;
        if (r1 == 0) goto L_0x000e;
    L_0x0006:
        r0 = new java.lang.IllegalStateException;
        r1 = "Recursive entry to executePendingTransactions";
        r0.<init>(r1);
        throw r0;
    L_0x000e:
        r1 = android.os.Looper.myLooper();
        r3 = r6.f147o;
        r3 = r3.f110a;
        r3 = r3.getLooper();
        if (r1 == r3) goto L_0x0024;
    L_0x001c:
        r0 = new java.lang.IllegalStateException;
        r1 = "Must be called from main thread of process";
        r0.<init>(r1);
        throw r0;
    L_0x0024:
        r1 = r2;
    L_0x0025:
        monitor-enter(r6);
        r3 = r6.f135c;	 Catch:{ all -> 0x0097 }
        if (r3 == 0) goto L_0x0032;
    L_0x002a:
        r3 = r6.f135c;	 Catch:{ all -> 0x0097 }
        r3 = r3.size();	 Catch:{ all -> 0x0097 }
        if (r3 != 0) goto L_0x005a;
    L_0x0032:
        monitor-exit(r6);	 Catch:{ all -> 0x0097 }
        r0 = r6.f154v;
        if (r0 == 0) goto L_0x00a5;
    L_0x0037:
        r3 = r2;
        r4 = r2;
    L_0x0039:
        r0 = r6.f138f;
        r0 = r0.size();
        if (r3 >= r0) goto L_0x009e;
    L_0x0041:
        r0 = r6.f138f;
        r0 = r0.get(r3);
        r0 = (android.support.v4.app.Fragment) r0;
        if (r0 == 0) goto L_0x0056;
    L_0x004b:
        r5 = r0.f30M;
        if (r5 == 0) goto L_0x0056;
    L_0x004f:
        r0 = r0.f30M;
        r0 = r0.m182a();
        r4 = r4 | r0;
    L_0x0056:
        r0 = r3 + 1;
        r3 = r0;
        goto L_0x0039;
    L_0x005a:
        r1 = r6.f135c;	 Catch:{ all -> 0x0097 }
        r3 = r1.size();	 Catch:{ all -> 0x0097 }
        r1 = r6.f136d;	 Catch:{ all -> 0x0097 }
        if (r1 == 0) goto L_0x0069;
    L_0x0064:
        r1 = r6.f136d;	 Catch:{ all -> 0x0097 }
        r1 = r1.length;	 Catch:{ all -> 0x0097 }
        if (r1 >= r3) goto L_0x006d;
    L_0x0069:
        r1 = new java.lang.Runnable[r3];	 Catch:{ all -> 0x0097 }
        r6.f136d = r1;	 Catch:{ all -> 0x0097 }
    L_0x006d:
        r1 = r6.f135c;	 Catch:{ all -> 0x0097 }
        r4 = r6.f136d;	 Catch:{ all -> 0x0097 }
        r1.toArray(r4);	 Catch:{ all -> 0x0097 }
        r1 = r6.f135c;	 Catch:{ all -> 0x0097 }
        r1.clear();	 Catch:{ all -> 0x0097 }
        r1 = r6.f147o;	 Catch:{ all -> 0x0097 }
        r1 = r1.f110a;	 Catch:{ all -> 0x0097 }
        r4 = r6.f157y;	 Catch:{ all -> 0x0097 }
        r1.removeCallbacks(r4);	 Catch:{ all -> 0x0097 }
        monitor-exit(r6);	 Catch:{ all -> 0x0097 }
        r6.f137e = r0;
        r1 = r2;
    L_0x0086:
        if (r1 >= r3) goto L_0x009a;
    L_0x0088:
        r4 = r6.f136d;
        r4 = r4[r1];
        r4.run();
        r4 = r6.f136d;
        r5 = 0;
        r4[r1] = r5;
        r1 = r1 + 1;
        goto L_0x0086;
    L_0x0097:
        r0 = move-exception;
        monitor-exit(r6);	 Catch:{ all -> 0x0097 }
        throw r0;
    L_0x009a:
        r6.f137e = r2;
        r1 = r0;
        goto L_0x0025;
    L_0x009e:
        if (r4 != 0) goto L_0x00a5;
    L_0x00a0:
        r6.f154v = r2;
        r6.m144d();
    L_0x00a5:
        return r1;
        */
        throw new UnsupportedOperationException("Method not decompiled: android.support.v4.app.n.e():boolean");
    }

    Bundle m150f(Fragment fragment) {
        Bundle bundle;
        if (this.f155w == null) {
            this.f155w = new Bundle();
        }
        fragment.m51i(this.f155w);
        if (this.f155w.isEmpty()) {
            bundle = null;
        } else {
            bundle = this.f155w;
            this.f155w = null;
        }
        if (fragment.f26I != null) {
            m147e(fragment);
        }
        if (fragment.f37e != null) {
            if (bundle == null) {
                bundle = new Bundle();
            }
            bundle.putSparseParcelableArray("android:view_state", fragment.f37e);
        }
        if (!fragment.f29L) {
            if (bundle == null) {
                bundle = new Bundle();
            }
            bundle.putBoolean("android:user_visible_hint", fragment.f29L);
        }
        return bundle;
    }

    void m151f() {
        if (this.f145m != null) {
            for (int i = 0; i < this.f145m.size(); i++) {
                ((C0015m) this.f145m.get(i)).m104a();
            }
        }
    }

    ArrayList m152g() {
        ArrayList arrayList = null;
        if (this.f138f != null) {
            for (int i = 0; i < this.f138f.size(); i++) {
                Fragment fragment = (Fragment) this.f138f.get(i);
                if (fragment != null && fragment.f19B) {
                    if (arrayList == null) {
                        arrayList = new ArrayList();
                    }
                    arrayList.add(fragment);
                    fragment.f20C = true;
                    fragment.f42j = fragment.f41i != null ? fragment.f41i.f38f : -1;
                    if (f132a) {
                        Log.v("FragmentManager", "retainNonConfig: keeping retained " + fragment);
                    }
                }
            }
        }
        return arrayList;
    }

    Parcelable m153h() {
        BackStackState[] backStackStateArr = null;
        m149e();
        if (f133b) {
            this.f151s = true;
        }
        if (this.f138f == null || this.f138f.size() <= 0) {
            return null;
        }
        int size = this.f138f.size();
        FragmentState[] fragmentStateArr = new FragmentState[size];
        int i = 0;
        boolean z = false;
        while (i < size) {
            boolean z2;
            Fragment fragment = (Fragment) this.f138f.get(i);
            if (fragment != null) {
                if (fragment.f38f < 0) {
                    m107a(new IllegalStateException("Failure saving state: active " + fragment + " has cleared index: " + fragment.f38f));
                }
                FragmentState fragmentState = new FragmentState(fragment);
                fragmentStateArr[i] = fragmentState;
                if (fragment.f33a <= 0 || fragmentState.f71j != null) {
                    fragmentState.f71j = fragment.f36d;
                } else {
                    fragmentState.f71j = m150f(fragment);
                    if (fragment.f41i != null) {
                        if (fragment.f41i.f38f < 0) {
                            m107a(new IllegalStateException("Failure saving state: " + fragment + " has target not in fragment manager: " + fragment.f41i));
                        }
                        if (fragmentState.f71j == null) {
                            fragmentState.f71j = new Bundle();
                        }
                        m121a(fragmentState.f71j, "android:target_state", fragment.f41i);
                        if (fragment.f43k != 0) {
                            fragmentState.f71j.putInt("android:target_req_state", fragment.f43k);
                        }
                    }
                }
                if (f132a) {
                    Log.v("FragmentManager", "Saved state of " + fragment + ": " + fragmentState.f71j);
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
            FragmentManagerState fragmentManagerState;
            if (this.f139g != null) {
                i = this.f139g.size();
                if (i > 0) {
                    iArr = new int[i];
                    for (i2 = 0; i2 < i; i2++) {
                        iArr[i2] = ((Fragment) this.f139g.get(i2)).f38f;
                        if (iArr[i2] < 0) {
                            m107a(new IllegalStateException("Failure saving state: active " + this.f139g.get(i2) + " has cleared index: " + iArr[i2]));
                        }
                        if (f132a) {
                            Log.v("FragmentManager", "saveAllState: adding fragment #" + i2 + ": " + this.f139g.get(i2));
                        }
                    }
                    if (this.f141i != null) {
                        i = this.f141i.size();
                        if (i > 0) {
                            backStackStateArr = new BackStackState[i];
                            for (i2 = 0; i2 < i; i2++) {
                                backStackStateArr[i2] = new BackStackState(this, (C0004b) this.f141i.get(i2));
                                if (f132a) {
                                    Log.v("FragmentManager", "saveAllState: adding back stack #" + i2 + ": " + this.f141i.get(i2));
                                }
                            }
                        }
                    }
                    fragmentManagerState = new FragmentManagerState();
                    fragmentManagerState.f59a = fragmentStateArr;
                    fragmentManagerState.f60b = iArr;
                    fragmentManagerState.f61c = backStackStateArr;
                    return fragmentManagerState;
                }
            }
            iArr = null;
            if (this.f141i != null) {
                i = this.f141i.size();
                if (i > 0) {
                    backStackStateArr = new BackStackState[i];
                    for (i2 = 0; i2 < i; i2++) {
                        backStackStateArr[i2] = new BackStackState(this, (C0004b) this.f141i.get(i2));
                        if (f132a) {
                            Log.v("FragmentManager", "saveAllState: adding back stack #" + i2 + ": " + this.f141i.get(i2));
                        }
                    }
                }
            }
            fragmentManagerState = new FragmentManagerState();
            fragmentManagerState.f59a = fragmentStateArr;
            fragmentManagerState.f60b = iArr;
            fragmentManagerState.f61c = backStackStateArr;
            return fragmentManagerState;
        } else if (!f132a) {
            return null;
        } else {
            Log.v("FragmentManager", "saveAllState: no fragments!");
            return null;
        }
    }

    public void m154i() {
        this.f151s = false;
    }

    public void m155j() {
        this.f151s = false;
        m119a(1, false);
    }

    public void m156k() {
        this.f151s = false;
        m119a(2, false);
    }

    public void m157l() {
        this.f151s = false;
        m119a(4, false);
    }

    public void m158m() {
        this.f151s = false;
        m119a(5, false);
    }

    public void m159n() {
        m119a(4, false);
    }

    public void m160o() {
        this.f151s = true;
        m119a(3, false);
    }

    public void m161p() {
        m119a(2, false);
    }

    public void m162q() {
        m119a(1, false);
    }

    public void m163r() {
        this.f152t = true;
        m149e();
        m119a(0, false);
        this.f147o = null;
        this.f148p = null;
        this.f149q = null;
    }

    public void m164s() {
        if (this.f139g != null) {
            for (int i = 0; i < this.f139g.size(); i++) {
                Fragment fragment = (Fragment) this.f139g.get(i);
                if (fragment != null) {
                    fragment.m59q();
                }
            }
        }
    }

    public String toString() {
        StringBuilder stringBuilder = new StringBuilder(128);
        stringBuilder.append("FragmentManager{");
        stringBuilder.append(Integer.toHexString(System.identityHashCode(this)));
        stringBuilder.append(" in ");
        if (this.f149q != null) {
            C0033a.m202a(this.f149q, stringBuilder);
        } else {
            C0033a.m202a(this.f147o, stringBuilder);
        }
        stringBuilder.append("}}");
        return stringBuilder.toString();
    }
}
