package android.support.v7.p014a;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.content.res.Configuration;
import android.content.res.Resources.Theme;
import android.content.res.TypedArray;
import android.graphics.Rect;
import android.media.AudioManager;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.support.v4.p003a.bc;
import android.support.v4.p004h.ab;
import android.support.v4.p004h.al;
import android.support.v4.p004h.bu;
import android.support.v4.p004h.ct;
import android.support.v4.p004h.dh;
import android.support.v4.widget.ah;
import android.support.v7.p015b.C0233b;
import android.support.v7.p015b.C0235d;
import android.support.v7.p015b.C0238g;
import android.support.v7.p015b.C0240i;
import android.support.v7.p015b.C0243l;
import android.support.v7.view.C0208c;
import android.support.v7.view.C0212b;
import android.support.v7.view.C0249e;
import android.support.v7.view.C0250f;
import android.support.v7.view.menu.C0203j;
import android.support.v7.view.menu.C0264i;
import android.support.v7.widget.ActionBarContextView;
import android.support.v7.widget.ContentFrameLayout;
import android.support.v7.widget.ViewStubCompat;
import android.support.v7.widget.br;
import android.support.v7.widget.du;
import android.text.TextUtils;
import android.util.AndroidRuntimeException;
import android.util.AttributeSet;
import android.util.Log;
import android.util.TypedValue;
import android.view.KeyCharacterMap;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.LayoutInflater.Factory;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewConfiguration;
import android.view.ViewGroup;
import android.view.ViewGroup.LayoutParams;
import android.view.ViewGroup.MarginLayoutParams;
import android.view.ViewParent;
import android.view.Window;
import android.view.Window.Callback;
import android.view.WindowManager;
import android.widget.FrameLayout;
import android.widget.PopupWindow;
import android.widget.TextView;

/* renamed from: android.support.v7.a.ae */
class ae extends C0202x implements al, C0203j {
    private boolean f581A;
    private aq[] f582B;
    private aq f583C;
    private boolean f584D;
    private boolean f585E;
    private int f586F;
    private final Runnable f587G;
    private boolean f588H;
    private Rect f589I;
    private Rect f590J;
    private at f591K;
    C0212b f592m;
    ActionBarContextView f593n;
    PopupWindow f594o;
    Runnable f595p;
    dh f596q;
    private br f597r;
    private am f598s;
    private ar f599t;
    private boolean f600u;
    private ViewGroup f601v;
    private TextView f602w;
    private View f603x;
    private boolean f604y;
    private boolean f605z;

    ae(Context context, Window window, C0209v c0209v) {
        super(context, window, c0209v);
        this.f596q = null;
        this.f587G = new af(this);
    }

    private aq m1663a(int i, boolean z) {
        Object obj = this.f582B;
        if (obj == null || obj.length <= i) {
            Object obj2 = new aq[(i + 1)];
            if (obj != null) {
                System.arraycopy(obj, 0, obj2, 0, obj.length);
            }
            this.f582B = obj2;
            obj = obj2;
        }
        aq aqVar = obj[i];
        if (aqVar != null) {
            return aqVar;
        }
        aqVar = new aq(i);
        obj[i] = aqVar;
        return aqVar;
    }

    private aq m1665a(Menu menu) {
        aq[] aqVarArr = this.f582B;
        int length = aqVarArr != null ? aqVarArr.length : 0;
        for (int i = 0; i < length; i++) {
            aq aqVar = aqVarArr[i];
            if (aqVar != null && aqVar.f644j == menu) {
                return aqVar;
            }
        }
        return null;
    }

    private void m1666a(int i, aq aqVar, Menu menu) {
        if (menu == null) {
            if (aqVar == null && i >= 0 && i < this.f582B.length) {
                aqVar = this.f582B[i];
            }
            if (aqVar != null) {
                menu = aqVar.f644j;
            }
        }
        if ((aqVar == null || aqVar.f649o) && !m1657n()) {
            this.c.onPanelClosed(i, menu);
        }
    }

    /* JADX WARNING: inconsistent code. */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    private void m1671a(android.support.v7.p014a.aq r11, android.view.KeyEvent r12) {
        /*
        r10 = this;
        r1 = -1;
        r3 = 0;
        r9 = 1;
        r2 = -2;
        r0 = r11.f649o;
        if (r0 != 0) goto L_0x000e;
    L_0x0008:
        r0 = r10.m1657n();
        if (r0 == 0) goto L_0x000f;
    L_0x000e:
        return;
    L_0x000f:
        r0 = r11.f635a;
        if (r0 != 0) goto L_0x0034;
    L_0x0013:
        r4 = r10.a;
        r0 = r4.getResources();
        r0 = r0.getConfiguration();
        r0 = r0.screenLayout;
        r0 = r0 & 15;
        r5 = 4;
        if (r0 != r5) goto L_0x0048;
    L_0x0024:
        r0 = r9;
    L_0x0025:
        r4 = r4.getApplicationInfo();
        r4 = r4.targetSdkVersion;
        r5 = 11;
        if (r4 < r5) goto L_0x004a;
    L_0x002f:
        r4 = r9;
    L_0x0030:
        if (r0 == 0) goto L_0x0034;
    L_0x0032:
        if (r4 != 0) goto L_0x000e;
    L_0x0034:
        r0 = r10.m1658o();
        if (r0 == 0) goto L_0x004c;
    L_0x003a:
        r4 = r11.f635a;
        r5 = r11.f644j;
        r0 = r0.onMenuOpened(r4, r5);
        if (r0 != 0) goto L_0x004c;
    L_0x0044:
        r10.m1672a(r11, r9);
        goto L_0x000e;
    L_0x0048:
        r0 = r3;
        goto L_0x0025;
    L_0x004a:
        r4 = r3;
        goto L_0x0030;
    L_0x004c:
        r0 = r10.a;
        r4 = "window";
        r0 = r0.getSystemService(r4);
        r8 = r0;
        r8 = (android.view.WindowManager) r8;
        if (r8 == 0) goto L_0x000e;
    L_0x0059:
        r0 = r10.m1682b(r11, r12);
        if (r0 == 0) goto L_0x000e;
    L_0x005f:
        r0 = r11.f641g;
        if (r0 == 0) goto L_0x0067;
    L_0x0063:
        r0 = r11.f651q;
        if (r0 == 0) goto L_0x00f1;
    L_0x0067:
        r0 = r11.f641g;
        if (r0 != 0) goto L_0x00df;
    L_0x006b:
        r0 = r10.m1675a(r11);
        if (r0 == 0) goto L_0x000e;
    L_0x0071:
        r0 = r11.f641g;
        if (r0 == 0) goto L_0x000e;
    L_0x0075:
        r0 = r10.m1685c(r11);
        if (r0 == 0) goto L_0x000e;
    L_0x007b:
        r0 = r11.m1773a();
        if (r0 == 0) goto L_0x000e;
    L_0x0081:
        r0 = r11.f642h;
        r0 = r0.getLayoutParams();
        if (r0 != 0) goto L_0x0103;
    L_0x0089:
        r0 = new android.view.ViewGroup$LayoutParams;
        r0.<init>(r2, r2);
        r1 = r0;
    L_0x008f:
        r0 = r11.f636b;
        r4 = r11.f641g;
        r4.setBackgroundResource(r0);
        r0 = r11.f642h;
        r0 = r0.getParent();
        if (r0 == 0) goto L_0x00a9;
    L_0x009e:
        r4 = r0 instanceof android.view.ViewGroup;
        if (r4 == 0) goto L_0x00a9;
    L_0x00a2:
        r0 = (android.view.ViewGroup) r0;
        r4 = r11.f642h;
        r0.removeView(r4);
    L_0x00a9:
        r0 = r11.f641g;
        r4 = r11.f642h;
        r0.addView(r4, r1);
        r0 = r11.f642h;
        r0 = r0.hasFocus();
        if (r0 != 0) goto L_0x00bd;
    L_0x00b8:
        r0 = r11.f642h;
        r0.requestFocus();
    L_0x00bd:
        r1 = r2;
    L_0x00be:
        r11.f648n = r3;
        r0 = new android.view.WindowManager$LayoutParams;
        r3 = r11.f638d;
        r4 = r11.f639e;
        r5 = 1002; // 0x3ea float:1.404E-42 double:4.95E-321;
        r6 = 8519680; // 0x820000 float:1.1938615E-38 double:4.209281E-317;
        r7 = -3;
        r0.<init>(r1, r2, r3, r4, r5, r6, r7);
        r1 = r11.f637c;
        r0.gravity = r1;
        r1 = r11.f640f;
        r0.windowAnimations = r1;
        r1 = r11.f641g;
        r8.addView(r1, r0);
        r11.f649o = r9;
        goto L_0x000e;
    L_0x00df:
        r0 = r11.f651q;
        if (r0 == 0) goto L_0x0075;
    L_0x00e3:
        r0 = r11.f641g;
        r0 = r0.getChildCount();
        if (r0 <= 0) goto L_0x0075;
    L_0x00eb:
        r0 = r11.f641g;
        r0.removeAllViews();
        goto L_0x0075;
    L_0x00f1:
        r0 = r11.f643i;
        if (r0 == 0) goto L_0x0101;
    L_0x00f5:
        r0 = r11.f643i;
        r0 = r0.getLayoutParams();
        if (r0 == 0) goto L_0x0101;
    L_0x00fd:
        r0 = r0.width;
        if (r0 == r1) goto L_0x00be;
    L_0x0101:
        r1 = r2;
        goto L_0x00be;
    L_0x0103:
        r1 = r0;
        goto L_0x008f;
        */
        throw new UnsupportedOperationException("Method not decompiled: android.support.v7.a.ae.a(android.support.v7.a.aq, android.view.KeyEvent):void");
    }

    private void m1672a(aq aqVar, boolean z) {
        if (z && aqVar.f635a == 0 && this.f597r != null && this.f597r.m2298e()) {
            m1680b(aqVar.f644j);
            return;
        }
        WindowManager windowManager = (WindowManager) this.a.getSystemService("window");
        if (!(windowManager == null || !aqVar.f649o || aqVar.f641g == null)) {
            windowManager.removeView(aqVar.f641g);
            if (z) {
                m1666a(aqVar.f635a, aqVar, null);
            }
        }
        aqVar.f647m = false;
        aqVar.f648n = false;
        aqVar.f649o = false;
        aqVar.f642h = null;
        aqVar.f651q = true;
        if (this.f583C == aqVar) {
            this.f583C = null;
        }
    }

    private void m1673a(C0264i c0264i, boolean z) {
        if (this.f597r == null || !this.f597r.m2297d() || (ct.m1177a(ViewConfiguration.get(this.a)) && !this.f597r.m2299f())) {
            aq a = m1663a(0, true);
            a.f651q = true;
            m1672a(a, false);
            m1671a(a, null);
            return;
        }
        Callback o = m1658o();
        if (this.f597r.m2298e() && z) {
            this.f597r.m2301h();
            if (!m1657n()) {
                o.onPanelClosed(C0243l.AppCompatTheme_ratingBarStyleSmall, m1663a(0, true).f644j);
            }
        } else if (o != null && !m1657n()) {
            if (this.f585E && (this.f586F & 1) != 0) {
                this.b.getDecorView().removeCallbacks(this.f587G);
                this.f587G.run();
            }
            aq a2 = m1663a(0, true);
            if (a2.f644j != null && !a2.f652r && o.onPreparePanel(0, a2.f643i, a2.f644j)) {
                o.onMenuOpened(C0243l.AppCompatTheme_ratingBarStyleSmall, a2.f644j);
                this.f597r.m2300g();
            }
        }
    }

    private boolean m1675a(aq aqVar) {
        aqVar.m1771a(m1655l());
        aqVar.f641g = new ap(this, aqVar.f646l);
        aqVar.f637c = 81;
        return true;
    }

    private boolean m1676a(aq aqVar, int i, KeyEvent keyEvent, int i2) {
        boolean z = false;
        if (!keyEvent.isSystem()) {
            if ((aqVar.f647m || m1682b(aqVar, keyEvent)) && aqVar.f644j != null) {
                z = aqVar.f644j.performShortcut(i, keyEvent, i2);
            }
            if (z && (i2 & 1) == 0 && this.f597r == null) {
                m1672a(aqVar, true);
            }
        }
        return z;
    }

    private boolean m1677a(ViewParent viewParent) {
        if (viewParent == null) {
            return false;
        }
        ViewParent decorView = this.b.getDecorView();
        ViewParent viewParent2 = viewParent;
        while (viewParent2 != null) {
            if (viewParent2 == decorView || !(viewParent2 instanceof View) || bu.m1009r((View) viewParent2)) {
                return false;
            }
            viewParent2 = viewParent2.getParent();
        }
        return true;
    }

    private void m1680b(C0264i c0264i) {
        if (!this.f581A) {
            this.f581A = true;
            this.f597r.m2303j();
            Callback o = m1658o();
            if (!(o == null || m1657n())) {
                o.onPanelClosed(C0243l.AppCompatTheme_ratingBarStyleSmall, c0264i);
            }
            this.f581A = false;
        }
    }

    private boolean m1681b(aq aqVar) {
        Context c0249e;
        C0264i c0264i;
        Context context = this.a;
        if ((aqVar.f635a == 0 || aqVar.f635a == C0243l.AppCompatTheme_ratingBarStyleSmall) && this.f597r != null) {
            TypedValue typedValue = new TypedValue();
            Theme theme = context.getTheme();
            theme.resolveAttribute(C0233b.actionBarTheme, typedValue, true);
            Theme theme2 = null;
            if (typedValue.resourceId != 0) {
                theme2 = context.getResources().newTheme();
                theme2.setTo(theme);
                theme2.applyStyle(typedValue.resourceId, true);
                theme2.resolveAttribute(C0233b.actionBarWidgetTheme, typedValue, true);
            } else {
                theme.resolveAttribute(C0233b.actionBarWidgetTheme, typedValue, true);
            }
            if (typedValue.resourceId != 0) {
                if (theme2 == null) {
                    theme2 = context.getResources().newTheme();
                    theme2.setTo(theme);
                }
                theme2.applyStyle(typedValue.resourceId, true);
            }
            Theme theme3 = theme2;
            if (theme3 != null) {
                c0249e = new C0249e(context, 0);
                c0249e.getTheme().setTo(theme3);
                c0264i = new C0264i(c0249e);
                c0264i.m2109a((C0203j) this);
                aqVar.m1772a(c0264i);
                return true;
            }
        }
        c0249e = context;
        c0264i = new C0264i(c0249e);
        c0264i.m2109a((C0203j) this);
        aqVar.m1772a(c0264i);
        return true;
    }

    private boolean m1682b(aq aqVar, KeyEvent keyEvent) {
        if (m1657n()) {
            return false;
        }
        if (aqVar.f647m) {
            return true;
        }
        if (!(this.f583C == null || this.f583C == aqVar)) {
            m1672a(this.f583C, false);
        }
        Callback o = m1658o();
        if (o != null) {
            aqVar.f643i = o.onCreatePanelView(aqVar.f635a);
        }
        boolean z = aqVar.f635a == 0 || aqVar.f635a == C0243l.AppCompatTheme_ratingBarStyleSmall;
        if (z && this.f597r != null) {
            this.f597r.m2302i();
        }
        if (aqVar.f643i == null && !(z && (m1654k() instanceof av))) {
            if (aqVar.f644j == null || aqVar.f652r) {
                if (aqVar.f644j == null && (!m1681b(aqVar) || aqVar.f644j == null)) {
                    return false;
                }
                if (z && this.f597r != null) {
                    if (this.f598s == null) {
                        this.f598s = new am();
                    }
                    this.f597r.m2296a(aqVar.f644j, this.f598s);
                }
                aqVar.f644j.m2133g();
                if (o.onCreatePanelMenu(aqVar.f635a, aqVar.f644j)) {
                    aqVar.f652r = false;
                } else {
                    aqVar.m1772a(null);
                    if (!z || this.f597r == null) {
                        return false;
                    }
                    this.f597r.m2296a(null, this.f598s);
                    return false;
                }
            }
            aqVar.f644j.m2133g();
            if (aqVar.f653s != null) {
                aqVar.f644j.m2120b(aqVar.f653s);
                aqVar.f653s = null;
            }
            if (o.onPreparePanel(0, aqVar.f643i, aqVar.f644j)) {
                aqVar.f650p = KeyCharacterMap.load(keyEvent != null ? keyEvent.getDeviceId() : -1).getKeyboardType() != 1;
                aqVar.f644j.setQwertyMode(aqVar.f650p);
                aqVar.f644j.m2134h();
            } else {
                if (z && this.f597r != null) {
                    this.f597r.m2296a(null, this.f598s);
                }
                aqVar.f644j.m2134h();
                return false;
            }
        }
        aqVar.f647m = true;
        aqVar.f648n = false;
        this.f583C = aqVar;
        return true;
    }

    private boolean m1685c(aq aqVar) {
        if (aqVar.f643i != null) {
            aqVar.f642h = aqVar.f643i;
            return true;
        } else if (aqVar.f644j == null) {
            return false;
        } else {
            if (this.f599t == null) {
                this.f599t = new ar();
            }
            aqVar.f642h = (View) aqVar.m1770a(this.f599t);
            return aqVar.f642h != null;
        }
    }

    private void m1686d(int i) {
        m1672a(m1663a(i, true), true);
    }

    private boolean m1688d(int i, KeyEvent keyEvent) {
        if (keyEvent.getRepeatCount() == 0) {
            aq a = m1663a(i, true);
            if (!a.f649o) {
                return m1682b(a, keyEvent);
            }
        }
        return false;
    }

    private void m1689e(int i) {
        this.f586F |= 1 << i;
        if (!this.f585E) {
            bu.m986a(this.b.getDecorView(), this.f587G);
            this.f585E = true;
        }
    }

    private boolean m1690e(int i, KeyEvent keyEvent) {
        boolean z = true;
        if (this.f592m != null) {
            return false;
        }
        aq a = m1663a(i, true);
        if (i != 0 || this.f597r == null || !this.f597r.m2297d() || ct.m1177a(ViewConfiguration.get(this.a))) {
            boolean z2;
            if (a.f649o || a.f648n) {
                z2 = a.f649o;
                m1672a(a, true);
                z = z2;
            } else {
                if (a.f647m) {
                    if (a.f652r) {
                        a.f647m = false;
                        z2 = m1682b(a, keyEvent);
                    } else {
                        z2 = true;
                    }
                    if (z2) {
                        m1671a(a, keyEvent);
                    }
                }
                z = false;
            }
        } else if (this.f597r.m2298e()) {
            z = this.f597r.m2301h();
        } else {
            if (!m1657n() && m1682b(a, keyEvent)) {
                z = this.f597r.m2300g();
            }
            z = false;
        }
        if (z) {
            AudioManager audioManager = (AudioManager) this.a.getSystemService("audio");
            if (audioManager != null) {
                audioManager.playSoundEffect(0);
            } else {
                Log.w("AppCompatDelegate", "Couldn't get audio manager");
            }
        }
        return z;
    }

    private void m1691f(int i) {
        aq a = m1663a(i, true);
        if (a.f644j != null) {
            Bundle bundle = new Bundle();
            a.f644j.m2108a(bundle);
            if (bundle.size() > 0) {
                a.f653s = bundle;
            }
            a.f644j.m2133g();
            a.f644j.clear();
        }
        a.f652r = true;
        a.f651q = true;
        if ((i == C0243l.AppCompatTheme_ratingBarStyleSmall || i == 0) && this.f597r != null) {
            a = m1663a(0, false);
            if (a != null) {
                a.f647m = false;
                m1682b(a, null);
            }
        }
    }

    private int m1692g(int i) {
        int i2;
        int i3 = 1;
        int i4 = 0;
        if (this.f593n == null || !(this.f593n.getLayoutParams() instanceof MarginLayoutParams)) {
            i2 = 0;
        } else {
            int i5;
            MarginLayoutParams marginLayoutParams = (MarginLayoutParams) this.f593n.getLayoutParams();
            if (this.f593n.isShown()) {
                if (this.f589I == null) {
                    this.f589I = new Rect();
                    this.f590J = new Rect();
                }
                Rect rect = this.f589I;
                Rect rect2 = this.f590J;
                rect.set(0, i, 0, 0);
                du.m2793a(this.f601v, rect, rect2);
                if (marginLayoutParams.topMargin != (rect2.top == 0 ? i : 0)) {
                    marginLayoutParams.topMargin = i;
                    if (this.f603x == null) {
                        this.f603x = new View(this.a);
                        this.f603x.setBackgroundColor(this.a.getResources().getColor(C0235d.abc_input_method_navigation_guard));
                        this.f601v.addView(this.f603x, -1, new LayoutParams(-1, i));
                        i5 = 1;
                    } else {
                        LayoutParams layoutParams = this.f603x.getLayoutParams();
                        if (layoutParams.height != i) {
                            layoutParams.height = i;
                            this.f603x.setLayoutParams(layoutParams);
                        }
                        i5 = 1;
                    }
                } else {
                    i5 = 0;
                }
                if (this.f603x == null) {
                    i3 = 0;
                }
                if (!(this.j || i3 == 0)) {
                    i = 0;
                }
                int i6 = i5;
                i5 = i3;
                i3 = i6;
            } else if (marginLayoutParams.topMargin != 0) {
                marginLayoutParams.topMargin = 0;
                i5 = 0;
            } else {
                i3 = 0;
                i5 = 0;
            }
            if (i3 != 0) {
                this.f593n.setLayoutParams(marginLayoutParams);
            }
            i2 = i5;
        }
        if (this.f603x != null) {
            View view = this.f603x;
            if (i2 == 0) {
                i4 = 8;
            }
            view.setVisibility(i4);
        }
        return i;
    }

    private int m1693h(int i) {
        if (i == 8) {
            Log.i("AppCompatDelegate", "You should now use the AppCompatDelegate.FEATURE_SUPPORT_ACTION_BAR id when requesting this feature.");
            return C0243l.AppCompatTheme_ratingBarStyleSmall;
        } else if (i != 9) {
            return i;
        } else {
            Log.i("AppCompatDelegate", "You should now use the AppCompatDelegate.FEATURE_SUPPORT_ACTION_BAR_OVERLAY id when requesting this feature.");
            return C0243l.AppCompatTheme_seekBarStyle;
        }
    }

    private void m1694r() {
        if (!this.f600u) {
            this.f601v = m1695s();
            CharSequence p = m1659p();
            if (!TextUtils.isEmpty(p)) {
                m1718b(p);
            }
            m1696t();
            m1709a(this.f601v);
            this.f600u = true;
            aq a = m1663a(0, false);
            if (!m1657n()) {
                if (a == null || a.f644j == null) {
                    m1689e(C0243l.AppCompatTheme_ratingBarStyleSmall);
                }
            }
        }
    }

    private ViewGroup m1695s() {
        TypedArray obtainStyledAttributes = this.a.obtainStyledAttributes(C0243l.AppCompatTheme);
        if (obtainStyledAttributes.hasValue(C0243l.AppCompatTheme_windowActionBar)) {
            View view;
            if (obtainStyledAttributes.getBoolean(C0243l.AppCompatTheme_windowNoTitle, false)) {
                m1723c(1);
            } else if (obtainStyledAttributes.getBoolean(C0243l.AppCompatTheme_windowActionBar, false)) {
                m1723c((int) C0243l.AppCompatTheme_ratingBarStyleSmall);
            }
            if (obtainStyledAttributes.getBoolean(C0243l.AppCompatTheme_windowActionBarOverlay, false)) {
                m1723c((int) C0243l.AppCompatTheme_seekBarStyle);
            }
            if (obtainStyledAttributes.getBoolean(C0243l.AppCompatTheme_windowActionModeOverlay, false)) {
                m1723c(10);
            }
            this.k = obtainStyledAttributes.getBoolean(C0243l.AppCompatTheme_android_windowIsFloating, false);
            obtainStyledAttributes.recycle();
            LayoutInflater from = LayoutInflater.from(this.a);
            if (this.l) {
                View view2 = this.j ? (ViewGroup) from.inflate(C0240i.abc_screen_simple_overlay_action_mode, null) : (ViewGroup) from.inflate(C0240i.abc_screen_simple, null);
                if (VERSION.SDK_INT >= 21) {
                    bu.m985a(view2, new ag(this));
                    view = view2;
                } else {
                    ((android.support.v7.widget.bu) view2).setOnFitSystemWindowsListener(new ah(this));
                    view = view2;
                }
            } else if (this.k) {
                r0 = (ViewGroup) from.inflate(C0240i.abc_dialog_title_material, null);
                this.i = false;
                this.h = false;
                view = r0;
            } else if (this.h) {
                TypedValue typedValue = new TypedValue();
                this.a.getTheme().resolveAttribute(C0233b.actionBarTheme, typedValue, true);
                r0 = (ViewGroup) LayoutInflater.from(typedValue.resourceId != 0 ? new C0249e(this.a, typedValue.resourceId) : this.a).inflate(C0240i.abc_screen_toolbar, null);
                this.f597r = (br) r0.findViewById(C0238g.decor_content_parent);
                this.f597r.setWindowCallback(m1658o());
                if (this.i) {
                    this.f597r.m2295a(C0243l.AppCompatTheme_seekBarStyle);
                }
                if (this.f604y) {
                    this.f597r.m2295a(2);
                }
                if (this.f605z) {
                    this.f597r.m2295a(5);
                }
                view = r0;
            } else {
                view = null;
            }
            if (view == null) {
                throw new IllegalArgumentException("AppCompat does not support the current theme features: { windowActionBar: " + this.h + ", windowActionBarOverlay: " + this.i + ", android:windowIsFloating: " + this.k + ", windowActionModeOverlay: " + this.j + ", windowNoTitle: " + this.l + " }");
            }
            if (this.f597r == null) {
                this.f602w = (TextView) view.findViewById(C0238g.title);
            }
            du.m2795b(view);
            ViewGroup viewGroup = (ViewGroup) this.b.findViewById(16908290);
            ContentFrameLayout contentFrameLayout = (ContentFrameLayout) view.findViewById(C0238g.action_bar_activity_content);
            while (viewGroup.getChildCount() > 0) {
                View childAt = viewGroup.getChildAt(0);
                viewGroup.removeViewAt(0);
                contentFrameLayout.addView(childAt);
            }
            this.b.setContentView(view);
            viewGroup.setId(-1);
            contentFrameLayout.setId(16908290);
            if (viewGroup instanceof FrameLayout) {
                ((FrameLayout) viewGroup).setForeground(null);
            }
            contentFrameLayout.setAttachListener(new ai(this));
            return view;
        }
        obtainStyledAttributes.recycle();
        throw new IllegalStateException("You need to use a Theme.AppCompat theme (or descendant) with this activity.");
    }

    private void m1696t() {
        ContentFrameLayout contentFrameLayout = (ContentFrameLayout) this.f601v.findViewById(16908290);
        View decorView = this.b.getDecorView();
        contentFrameLayout.m1767a(decorView.getPaddingLeft(), decorView.getPaddingTop(), decorView.getPaddingRight(), decorView.getPaddingBottom());
        TypedArray obtainStyledAttributes = this.a.obtainStyledAttributes(C0243l.AppCompatTheme);
        obtainStyledAttributes.getValue(C0243l.AppCompatTheme_windowMinWidthMajor, contentFrameLayout.getMinWidthMajor());
        obtainStyledAttributes.getValue(C0243l.AppCompatTheme_windowMinWidthMinor, contentFrameLayout.getMinWidthMinor());
        if (obtainStyledAttributes.hasValue(C0243l.AppCompatTheme_windowFixedWidthMajor)) {
            obtainStyledAttributes.getValue(C0243l.AppCompatTheme_windowFixedWidthMajor, contentFrameLayout.getFixedWidthMajor());
        }
        if (obtainStyledAttributes.hasValue(C0243l.AppCompatTheme_windowFixedWidthMinor)) {
            obtainStyledAttributes.getValue(C0243l.AppCompatTheme_windowFixedWidthMinor, contentFrameLayout.getFixedWidthMinor());
        }
        if (obtainStyledAttributes.hasValue(C0243l.AppCompatTheme_windowFixedHeightMajor)) {
            obtainStyledAttributes.getValue(C0243l.AppCompatTheme_windowFixedHeightMajor, contentFrameLayout.getFixedHeightMajor());
        }
        if (obtainStyledAttributes.hasValue(C0243l.AppCompatTheme_windowFixedHeightMinor)) {
            obtainStyledAttributes.getValue(C0243l.AppCompatTheme_windowFixedHeightMinor, contentFrameLayout.getFixedHeightMinor());
        }
        obtainStyledAttributes.recycle();
        contentFrameLayout.requestLayout();
    }

    private void m1697u() {
        if (this.f596q != null) {
            this.f596q.m1232b();
        }
    }

    private void m1698v() {
        if (this.f600u) {
            throw new AndroidRuntimeException("Window feature must be requested before adding content");
        }
    }

    private void m1699w() {
        if (this.f597r != null) {
            this.f597r.m2303j();
        }
        if (this.f594o != null) {
            this.b.getDecorView().removeCallbacks(this.f595p);
            if (this.f594o.isShowing()) {
                try {
                    this.f594o.dismiss();
                } catch (IllegalArgumentException e) {
                }
            }
            this.f594o = null;
        }
        m1697u();
        aq a = m1663a(0, false);
        if (a != null && a.f644j != null) {
            a.f644j.close();
        }
    }

    C0212b m1700a(C0208c c0208c) {
        C0212b c0212b;
        m1697u();
        if (this.f592m != null) {
            this.f592m.m1886c();
        }
        C0208c anVar = new an(this, c0208c);
        if (this.e == null || m1657n()) {
            c0212b = null;
        } else {
            try {
                c0212b = this.e.m1776a(anVar);
            } catch (AbstractMethodError e) {
                c0212b = null;
            }
        }
        if (c0212b != null) {
            this.f592m = c0212b;
        } else {
            if (this.f593n == null) {
                if (this.k) {
                    Context c0249e;
                    TypedValue typedValue = new TypedValue();
                    Theme theme = this.a.getTheme();
                    theme.resolveAttribute(C0233b.actionBarTheme, typedValue, true);
                    if (typedValue.resourceId != 0) {
                        Theme newTheme = this.a.getResources().newTheme();
                        newTheme.setTo(theme);
                        newTheme.applyStyle(typedValue.resourceId, true);
                        c0249e = new C0249e(this.a, 0);
                        c0249e.getTheme().setTo(newTheme);
                    } else {
                        c0249e = this.a;
                    }
                    this.f593n = new ActionBarContextView(c0249e);
                    this.f594o = new PopupWindow(c0249e, null, C0233b.actionModePopupWindowStyle);
                    ah.m1432a(this.f594o, 2);
                    this.f594o.setContentView(this.f593n);
                    this.f594o.setWidth(-1);
                    c0249e.getTheme().resolveAttribute(C0233b.actionBarSize, typedValue, true);
                    this.f593n.setContentHeight(TypedValue.complexToDimensionPixelSize(typedValue.data, c0249e.getResources().getDisplayMetrics()));
                    this.f594o.setHeight(-2);
                    this.f595p = new aj(this);
                } else {
                    ViewStubCompat viewStubCompat = (ViewStubCompat) this.f601v.findViewById(C0238g.action_mode_bar_stub);
                    if (viewStubCompat != null) {
                        viewStubCompat.setLayoutInflater(LayoutInflater.from(m1655l()));
                        this.f593n = (ActionBarContextView) viewStubCompat.m2457a();
                    }
                }
            }
            if (this.f593n != null) {
                m1697u();
                this.f593n.m2293c();
                C0212b c0250f = new C0250f(this.f593n.getContext(), this.f593n, anVar, this.f594o == null);
                if (c0208c.m1759a(c0250f, c0250f.m1883b())) {
                    c0250f.m1887d();
                    this.f593n.m2290a(c0250f);
                    this.f592m = c0250f;
                    bu.m991b(this.f593n, 0.0f);
                    this.f596q = bu.m1000i(this.f593n).m1225a(1.0f);
                    this.f596q.m1227a(new al(this));
                    if (this.f594o != null) {
                        this.b.getDecorView().post(this.f595p);
                    }
                } else {
                    this.f592m = null;
                }
            }
        }
        if (!(this.f592m == null || this.e == null)) {
            this.e.m1777a(this.f592m);
        }
        return this.f592m;
    }

    public View m1701a(int i) {
        m1694r();
        return this.b.findViewById(i);
    }

    public final View m1702a(View view, String str, Context context, AttributeSet attributeSet) {
        View b = m1714b(view, str, context, attributeSet);
        return b != null ? b : m1721c(view, str, context, attributeSet);
    }

    void m1703a(int i, Menu menu) {
        if (i == C0243l.AppCompatTheme_ratingBarStyleSmall) {
            C0200a a = m1640a();
            if (a != null) {
                a.m1612e(false);
            }
        } else if (i == 0) {
            aq a2 = m1663a(i, true);
            if (a2.f649o) {
                m1672a(a2, false);
            }
        }
    }

    public void m1704a(Configuration configuration) {
        if (this.h && this.f600u) {
            C0200a a = m1640a();
            if (a != null) {
                a.m1602a(configuration);
            }
        }
    }

    public void m1705a(Bundle bundle) {
        if ((this.c instanceof Activity) && bc.m259b((Activity) this.c) != null) {
            C0200a k = m1654k();
            if (k == null) {
                this.f588H = true;
            } else {
                k.m1609c(true);
            }
        }
    }

    public void m1706a(C0264i c0264i) {
        m1673a(c0264i, true);
    }

    public void m1707a(View view) {
        m1694r();
        ViewGroup viewGroup = (ViewGroup) this.f601v.findViewById(16908290);
        viewGroup.removeAllViews();
        viewGroup.addView(view);
        this.c.onContentChanged();
    }

    public void m1708a(View view, LayoutParams layoutParams) {
        m1694r();
        ViewGroup viewGroup = (ViewGroup) this.f601v.findViewById(16908290);
        viewGroup.removeAllViews();
        viewGroup.addView(view, layoutParams);
        this.c.onContentChanged();
    }

    void m1709a(ViewGroup viewGroup) {
    }

    boolean m1710a(int i, KeyEvent keyEvent) {
        C0200a a = m1640a();
        if (a != null && a.m1605a(i, keyEvent)) {
            return true;
        }
        if (this.f583C == null || !m1676a(this.f583C, keyEvent.getKeyCode(), keyEvent, 1)) {
            if (this.f583C == null) {
                aq a2 = m1663a(0, true);
                m1682b(a2, keyEvent);
                boolean a3 = m1676a(a2, keyEvent.getKeyCode(), keyEvent, 1);
                a2.f647m = false;
                if (a3) {
                    return true;
                }
            }
            return false;
        } else if (this.f583C == null) {
            return true;
        } else {
            this.f583C.f648n = true;
            return true;
        }
    }

    public boolean m1711a(C0264i c0264i, MenuItem menuItem) {
        Callback o = m1658o();
        if (!(o == null || m1657n())) {
            aq a = m1665a(c0264i.m2142p());
            if (a != null) {
                return o.onMenuItemSelected(a.f635a, menuItem);
            }
        }
        return false;
    }

    boolean m1712a(KeyEvent keyEvent) {
        boolean z = true;
        if (keyEvent.getKeyCode() == 82 && this.c.dispatchKeyEvent(keyEvent)) {
            return true;
        }
        int keyCode = keyEvent.getKeyCode();
        if (keyEvent.getAction() != 0) {
            z = false;
        }
        return z ? m1724c(keyCode, keyEvent) : m1719b(keyCode, keyEvent);
    }

    public C0212b m1713b(C0208c c0208c) {
        if (c0208c == null) {
            throw new IllegalArgumentException("ActionMode callback can not be null.");
        }
        if (this.f592m != null) {
            this.f592m.m1886c();
        }
        C0208c anVar = new an(this, c0208c);
        C0200a a = m1640a();
        if (a != null) {
            this.f592m = a.m1600a(anVar);
            if (!(this.f592m == null || this.e == null)) {
                this.e.m1777a(this.f592m);
            }
        }
        if (this.f592m == null) {
            this.f592m = m1700a(anVar);
        }
        return this.f592m;
    }

    View m1714b(View view, String str, Context context, AttributeSet attributeSet) {
        if (this.c instanceof Factory) {
            View onCreateView = ((Factory) this.c).onCreateView(str, context, attributeSet);
            if (onCreateView != null) {
                return onCreateView;
            }
        }
        return null;
    }

    public void m1715b(int i) {
        m1694r();
        ViewGroup viewGroup = (ViewGroup) this.f601v.findViewById(16908290);
        viewGroup.removeAllViews();
        LayoutInflater.from(this.a).inflate(i, viewGroup);
        this.c.onContentChanged();
    }

    public void m1716b(Bundle bundle) {
        m1694r();
    }

    public void m1717b(View view, LayoutParams layoutParams) {
        m1694r();
        ((ViewGroup) this.f601v.findViewById(16908290)).addView(view, layoutParams);
        this.c.onContentChanged();
    }

    void m1718b(CharSequence charSequence) {
        if (this.f597r != null) {
            this.f597r.setWindowTitle(charSequence);
        } else if (m1654k() != null) {
            m1654k().m1603a(charSequence);
        } else if (this.f602w != null) {
            this.f602w.setText(charSequence);
        }
    }

    boolean m1719b(int i, KeyEvent keyEvent) {
        switch (i) {
            case C0243l.View_theme /*4*/:
                boolean z = this.f584D;
                this.f584D = false;
                aq a = m1663a(0, false);
                if (a == null || !a.f649o) {
                    if (m1730q()) {
                        return true;
                    }
                } else if (z) {
                    return true;
                } else {
                    m1672a(a, true);
                    return true;
                }
                break;
            case C0243l.AppCompatTheme_colorPrimary /*82*/:
                m1690e(0, keyEvent);
                return true;
        }
        return false;
    }

    boolean m1720b(int i, Menu menu) {
        if (i != C0243l.AppCompatTheme_ratingBarStyleSmall) {
            return false;
        }
        C0200a a = m1640a();
        if (a == null) {
            return true;
        }
        a.m1612e(true);
        return true;
    }

    public View m1721c(View view, String str, Context context, AttributeSet attributeSet) {
        boolean z = VERSION.SDK_INT < 21;
        if (this.f591K == null) {
            this.f591K = new at();
        }
        boolean z2 = z && m1677a((ViewParent) view);
        return this.f591K.m1789a(view, str, context, attributeSet, z2, z, true);
    }

    public void m1722c() {
        C0200a a = m1640a();
        if (a != null) {
            a.m1611d(false);
        }
    }

    public boolean m1723c(int i) {
        int h = m1693h(i);
        if (this.l && h == C0243l.AppCompatTheme_ratingBarStyleSmall) {
            return false;
        }
        if (this.h && h == 1) {
            this.h = false;
        }
        switch (h) {
            case C0243l.View_android_focusable /*1*/:
                m1698v();
                this.l = true;
                return true;
            case C0243l.View_paddingStart /*2*/:
                m1698v();
                this.f604y = true;
                return true;
            case C0243l.Toolbar_contentInsetStart /*5*/:
                m1698v();
                this.f605z = true;
                return true;
            case C0243l.Toolbar_titleTextAppearance /*10*/:
                m1698v();
                this.j = true;
                return true;
            case C0243l.AppCompatTheme_ratingBarStyleSmall /*108*/:
                m1698v();
                this.h = true;
                return true;
            case C0243l.AppCompatTheme_seekBarStyle /*109*/:
                m1698v();
                this.i = true;
                return true;
            default:
                return this.b.requestFeature(h);
        }
    }

    boolean m1724c(int i, KeyEvent keyEvent) {
        boolean z = true;
        switch (i) {
            case C0243l.View_theme /*4*/:
                if ((keyEvent.getFlags() & 128) == 0) {
                    z = false;
                }
                this.f584D = z;
                break;
            case C0243l.AppCompatTheme_colorPrimary /*82*/:
                m1688d(0, keyEvent);
                return true;
        }
        if (VERSION.SDK_INT < 11) {
            m1710a(i, keyEvent);
        }
        return false;
    }

    public void m1725d() {
        C0200a a = m1640a();
        if (a != null) {
            a.m1611d(true);
        }
    }

    public void m1726e() {
        C0200a a = m1640a();
        if (a == null || !a.m1613e()) {
            m1689e(0);
        }
    }

    public void m1727f() {
        super.m1651f();
        if (this.f != null) {
            this.f.m1616h();
            this.f = null;
        }
    }

    public void m1728g() {
        LayoutInflater from = LayoutInflater.from(this.a);
        if (from.getFactory() == null) {
            ab.m838a(from, this);
        } else if (!(ab.m837a(from) instanceof ae)) {
            Log.i("AppCompatDelegate", "The Activity's LayoutInflater already has a Factory installed so we can not install AppCompat's");
        }
    }

    public void m1729j() {
        m1694r();
        if (this.h && this.f == null) {
            if (this.c instanceof Activity) {
                this.f = new bd((Activity) this.c, this.i);
            } else if (this.c instanceof Dialog) {
                this.f = new bd((Dialog) this.c);
            }
            if (this.f != null) {
                this.f.m1609c(this.f588H);
            }
        }
    }

    boolean m1730q() {
        if (this.f592m != null) {
            this.f592m.m1886c();
            return true;
        }
        C0200a a = m1640a();
        return a != null && a.m1614f();
    }
}
