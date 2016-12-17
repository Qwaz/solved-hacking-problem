package android.support.v7.widget;

import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.PorterDuff.Mode;
import android.graphics.PorterDuffColorFilter;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.Drawable.ConstantState;
import android.graphics.drawable.LayerDrawable;
import android.os.Build.VERSION;
import android.support.v4.p002b.C0020a;
import android.support.v4.p006c.C0088a;
import android.support.v4.p006c.p007a.C0062a;
import android.support.v4.p012g.C0107a;
import android.support.v4.p012g.C0113f;
import android.support.v7.p015b.C0233b;
import android.support.v7.p015b.C0237f;
import android.util.Log;
import android.util.SparseArray;
import android.util.TypedValue;
import java.lang.ref.WeakReference;
import java.util.WeakHashMap;

public final class ao {
    private static final Mode f1305a;
    private static ao f1306b;
    private static final ar f1307c;
    private static final int[] f1308d;
    private static final int[] f1309e;
    private static final int[] f1310f;
    private static final int[] f1311g;
    private static final int[] f1312h;
    private static final int[] f1313i;
    private WeakHashMap f1314j;
    private C0107a f1315k;
    private SparseArray f1316l;
    private final Object f1317m;
    private final WeakHashMap f1318n;
    private TypedValue f1319o;

    static {
        f1305a = Mode.SRC_IN;
        f1307c = new ar(6);
        f1308d = new int[]{C0237f.abc_textfield_search_default_mtrl_alpha, C0237f.abc_textfield_default_mtrl_alpha, C0237f.abc_ab_share_pack_mtrl_alpha};
        f1309e = new int[]{C0237f.abc_ic_ab_back_mtrl_am_alpha, C0237f.abc_ic_go_search_api_mtrl_alpha, C0237f.abc_ic_search_api_mtrl_alpha, C0237f.abc_ic_commit_search_api_mtrl_alpha, C0237f.abc_ic_clear_mtrl_alpha, C0237f.abc_ic_menu_share_mtrl_alpha, C0237f.abc_ic_menu_copy_mtrl_am_alpha, C0237f.abc_ic_menu_cut_mtrl_alpha, C0237f.abc_ic_menu_selectall_mtrl_alpha, C0237f.abc_ic_menu_paste_mtrl_am_alpha, C0237f.abc_ic_menu_moreoverflow_mtrl_alpha, C0237f.abc_ic_voice_search_api_mtrl_alpha};
        f1310f = new int[]{C0237f.abc_textfield_activated_mtrl_alpha, C0237f.abc_textfield_search_activated_mtrl_alpha, C0237f.abc_cab_background_top_mtrl_alpha, C0237f.abc_text_cursor_material};
        f1311g = new int[]{C0237f.abc_popup_background_mtrl_mult, C0237f.abc_cab_background_internal_bg, C0237f.abc_menu_hardkey_panel_mtrl_mult};
        f1312h = new int[]{C0237f.abc_edit_text_material, C0237f.abc_tab_indicator_material, C0237f.abc_textfield_search_material, C0237f.abc_spinner_mtrl_am_alpha, C0237f.abc_spinner_textfield_background_material, C0237f.abc_ratingbar_full_material, C0237f.abc_switch_track_mtrl_alpha, C0237f.abc_switch_thumb_material, C0237f.abc_btn_default_mtrl_shape, C0237f.abc_btn_borderless_material};
        f1313i = new int[]{C0237f.abc_btn_check_material, C0237f.abc_btn_radio_material};
    }

    public ao() {
        this.f1317m = new Object();
        this.f1318n = new WeakHashMap(0);
    }

    private static long m2491a(TypedValue typedValue) {
        return (((long) typedValue.assetCookie) << 32) | ((long) typedValue.data);
    }

    private ColorStateList m2492a(Context context) {
        int a = dc.m2700a(context, C0233b.colorControlNormal);
        int a2 = dc.m2700a(context, C0233b.colorControlActivated);
        r2 = new int[7][];
        int[] iArr = new int[]{dc.f1504a, dc.m2704c(context, C0233b.colorControlNormal), dc.f1505b, a2, dc.f1506c, a2, dc.f1507d};
        iArr[3] = a2;
        r2[4] = dc.f1508e;
        iArr[4] = a2;
        r2[5] = dc.f1509f;
        iArr[5] = a2;
        r2[6] = dc.f1511h;
        iArr[6] = a;
        return new ColorStateList(r2, iArr);
    }

    public static PorterDuffColorFilter m2493a(int i, Mode mode) {
        PorterDuffColorFilter a = f1307c.m2526a(i, mode);
        if (a != null) {
            return a;
        }
        a = new PorterDuffColorFilter(i, mode);
        f1307c.m2527a(i, mode, a);
        return a;
    }

    private static PorterDuffColorFilter m2494a(ColorStateList colorStateList, Mode mode, int[] iArr) {
        return (colorStateList == null || mode == null) ? null : m2493a(colorStateList.getColorForState(iArr, 0), mode);
    }

    private Drawable m2495a(Context context, int i, boolean z, Drawable drawable) {
        ColorStateList b = m2522b(context, i);
        if (b != null) {
            if (bt.m2634b(drawable)) {
                drawable = drawable.mutate();
            }
            drawable = C0062a.m467f(drawable);
            C0062a.m458a(drawable, b);
            Mode a = m2519a(i);
            if (a == null) {
                return drawable;
            }
            C0062a.m461a(drawable, a);
            return drawable;
        } else if (i == C0237f.abc_seekbar_track_material) {
            r0 = (LayerDrawable) drawable;
            m2499a(r0.findDrawableByLayerId(16908288), dc.m2700a(context, C0233b.colorControlNormal), f1305a);
            m2499a(r0.findDrawableByLayerId(16908303), dc.m2700a(context, C0233b.colorControlNormal), f1305a);
            m2499a(r0.findDrawableByLayerId(16908301), dc.m2700a(context, C0233b.colorControlActivated), f1305a);
            return drawable;
        } else if (i != C0237f.abc_ratingbar_indicator_material && i != C0237f.abc_ratingbar_small_material) {
            return (m2503a(context, i, drawable) || !z) ? drawable : null;
        } else {
            r0 = (LayerDrawable) drawable;
            m2499a(r0.findDrawableByLayerId(16908288), dc.m2704c(context, C0233b.colorControlNormal), f1305a);
            m2499a(r0.findDrawableByLayerId(16908303), dc.m2700a(context, C0233b.colorControlActivated), f1305a);
            m2499a(r0.findDrawableByLayerId(16908301), dc.m2700a(context, C0233b.colorControlActivated), f1305a);
            return drawable;
        }
    }

    private Drawable m2496a(Context context, long j) {
        synchronized (this.f1317m) {
            C0113f c0113f = (C0113f) this.f1318n.get(context);
            if (c0113f == null) {
                return null;
            }
            WeakReference weakReference = (WeakReference) c0113f.m641a(j);
            if (weakReference != null) {
                ConstantState constantState = (ConstantState) weakReference.get();
                if (constantState != null) {
                    Drawable newDrawable = constantState.newDrawable(context.getResources());
                    return newDrawable;
                }
                c0113f.m645b(j);
            }
            return null;
        }
    }

    public static ao m2497a() {
        if (f1306b == null) {
            f1306b = new ao();
            m2501a(f1306b);
        }
        return f1306b;
    }

    private void m2498a(Context context, int i, ColorStateList colorStateList) {
        if (this.f1314j == null) {
            this.f1314j = new WeakHashMap();
        }
        SparseArray sparseArray = (SparseArray) this.f1314j.get(context);
        if (sparseArray == null) {
            sparseArray = new SparseArray();
            this.f1314j.put(context, sparseArray);
        }
        sparseArray.append(i, colorStateList);
    }

    private static void m2499a(Drawable drawable, int i, Mode mode) {
        if (bt.m2634b(drawable)) {
            drawable = drawable.mutate();
        }
        if (mode == null) {
            mode = f1305a;
        }
        drawable.setColorFilter(m2493a(i, mode));
    }

    public static void m2500a(Drawable drawable, df dfVar, int[] iArr) {
        if (!bt.m2634b(drawable) || drawable.mutate() == drawable) {
            if (dfVar.f1519d || dfVar.f1518c) {
                drawable.setColorFilter(m2494a(dfVar.f1519d ? dfVar.f1516a : null, dfVar.f1518c ? dfVar.f1517b : f1305a, iArr));
            } else {
                drawable.clearColorFilter();
            }
            if (VERSION.SDK_INT <= 23) {
                drawable.invalidateSelf();
                return;
            }
            return;
        }
        Log.d("AppCompatDrawableManager", "Mutated drawable is not the same instance as the input.");
    }

    private static void m2501a(ao aoVar) {
        int i = VERSION.SDK_INT;
        if (i < 23) {
            aoVar.m2502a("vector", new at());
            if (i >= 11) {
                aoVar.m2502a("animated-vector", new aq());
            }
        }
    }

    private void m2502a(String str, as asVar) {
        if (this.f1315k == null) {
            this.f1315k = new C0107a();
        }
        this.f1315k.put(str, asVar);
    }

    static boolean m2503a(Context context, int i, Drawable drawable) {
        int i2;
        Mode mode;
        boolean z;
        int i3;
        Mode mode2 = f1305a;
        if (m2505a(f1308d, i)) {
            i2 = C0233b.colorControlNormal;
            mode = mode2;
            z = true;
            i3 = -1;
        } else if (m2505a(f1310f, i)) {
            i2 = C0233b.colorControlActivated;
            mode = mode2;
            z = true;
            i3 = -1;
        } else if (m2505a(f1311g, i)) {
            z = true;
            mode = Mode.MULTIPLY;
            i2 = 16842801;
            i3 = -1;
        } else if (i == C0237f.abc_list_divider_mtrl_alpha) {
            i2 = 16842800;
            i3 = Math.round(40.8f);
            mode = mode2;
            z = true;
        } else {
            i3 = -1;
            i2 = 0;
            mode = mode2;
            z = false;
        }
        if (!z) {
            return false;
        }
        if (bt.m2634b(drawable)) {
            drawable = drawable.mutate();
        }
        drawable.setColorFilter(m2493a(dc.m2700a(context, i2), mode));
        if (i3 == -1) {
            return true;
        }
        drawable.setAlpha(i3);
        return true;
    }

    private boolean m2504a(Context context, long j, Drawable drawable) {
        ConstantState constantState = drawable.getConstantState();
        if (constantState == null) {
            return false;
        }
        synchronized (this.f1317m) {
            C0113f c0113f = (C0113f) this.f1318n.get(context);
            if (c0113f == null) {
                c0113f = new C0113f();
                this.f1318n.put(context, c0113f);
            }
            c0113f.m646b(j, new WeakReference(constantState));
        }
        return true;
    }

    private static boolean m2505a(int[] iArr, int i) {
        for (int i2 : iArr) {
            if (i2 == i) {
                return true;
            }
        }
        return false;
    }

    private ColorStateList m2506b(Context context) {
        r0 = new int[3][];
        int[] iArr = new int[]{dc.f1504a, dc.m2704c(context, C0233b.colorControlNormal), dc.f1508e};
        iArr[1] = dc.m2700a(context, C0233b.colorControlActivated);
        r0[2] = dc.f1511h;
        iArr[2] = dc.m2700a(context, C0233b.colorControlNormal);
        return new ColorStateList(r0, iArr);
    }

    private ColorStateList m2507c(Context context) {
        r0 = new int[3][];
        int[] iArr = new int[]{dc.f1504a, dc.m2701a(context, 16842800, 0.1f), dc.f1508e};
        iArr[1] = dc.m2701a(context, C0233b.colorControlActivated, 0.3f);
        r0[2] = dc.f1511h;
        iArr[2] = dc.m2701a(context, 16842800, 0.3f);
        return new ColorStateList(r0, iArr);
    }

    private Drawable m2508c(Context context, int i) {
        if (this.f1319o == null) {
            this.f1319o = new TypedValue();
        }
        TypedValue typedValue = this.f1319o;
        context.getResources().getValue(i, typedValue, true);
        long a = m2491a(typedValue);
        Drawable a2 = m2496a(context, a);
        if (a2 == null) {
            if (i == C0237f.abc_cab_background_top_material) {
                a2 = new LayerDrawable(new Drawable[]{m2520a(context, C0237f.abc_cab_background_internal_bg), m2520a(context, C0237f.abc_cab_background_top_mtrl_alpha)});
            }
            if (a2 != null) {
                a2.setChangingConfigurations(typedValue.changingConfigurations);
                m2504a(context, a, a2);
            }
        }
        return a2;
    }

    private ColorStateList m2509d(Context context) {
        int[][] iArr = new int[3][];
        int[] iArr2 = new int[3];
        ColorStateList b = dc.m2703b(context, C0233b.colorSwitchThumbNormal);
        if (b == null || !b.isStateful()) {
            iArr[0] = dc.f1504a;
            iArr2[0] = dc.m2704c(context, C0233b.colorSwitchThumbNormal);
            iArr[1] = dc.f1508e;
            iArr2[1] = dc.m2700a(context, C0233b.colorControlActivated);
            iArr[2] = dc.f1511h;
            iArr2[2] = dc.m2700a(context, C0233b.colorSwitchThumbNormal);
        } else {
            iArr[0] = dc.f1504a;
            iArr2[0] = b.getColorForState(iArr[0], 0);
            iArr[1] = dc.f1508e;
            iArr2[1] = dc.m2700a(context, C0233b.colorControlActivated);
            iArr[2] = dc.f1511h;
            iArr2[2] = b.getDefaultColor();
        }
        return new ColorStateList(iArr, iArr2);
    }

    /* JADX WARNING: inconsistent code. */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    private android.graphics.drawable.Drawable m2510d(android.content.Context r10, int r11) {
        /*
        r9 = this;
        r1 = 0;
        r8 = 2;
        r7 = 1;
        r0 = r9.f1315k;
        if (r0 == 0) goto L_0x00bf;
    L_0x0007:
        r0 = r9.f1315k;
        r0 = r0.isEmpty();
        if (r0 != 0) goto L_0x00bf;
    L_0x000f:
        r0 = r9.f1316l;
        if (r0 == 0) goto L_0x002f;
    L_0x0013:
        r0 = r9.f1316l;
        r0 = r0.get(r11);
        r0 = (java.lang.String) r0;
        r2 = "appcompat_skip_skip";
        r2 = r2.equals(r0);
        if (r2 != 0) goto L_0x002d;
    L_0x0023:
        if (r0 == 0) goto L_0x0036;
    L_0x0025:
        r2 = r9.f1315k;
        r0 = r2.get(r0);
        if (r0 != 0) goto L_0x0036;
    L_0x002d:
        r0 = r1;
    L_0x002e:
        return r0;
    L_0x002f:
        r0 = new android.util.SparseArray;
        r0.<init>();
        r9.f1316l = r0;
    L_0x0036:
        r0 = r9.f1319o;
        if (r0 != 0) goto L_0x0041;
    L_0x003a:
        r0 = new android.util.TypedValue;
        r0.<init>();
        r9.f1319o = r0;
    L_0x0041:
        r2 = r9.f1319o;
        r0 = r10.getResources();
        r0.getValue(r11, r2, r7);
        r4 = m2491a(r2);
        r1 = r9.m2496a(r10, r4);
        if (r1 == 0) goto L_0x0056;
    L_0x0054:
        r0 = r1;
        goto L_0x002e;
    L_0x0056:
        r3 = r2.string;
        if (r3 == 0) goto L_0x008a;
    L_0x005a:
        r3 = r2.string;
        r3 = r3.toString();
        r6 = ".xml";
        r3 = r3.endsWith(r6);
        if (r3 == 0) goto L_0x008a;
    L_0x0068:
        r3 = r0.getXml(r11);	 Catch:{ Exception -> 0x0082 }
        r6 = android.util.Xml.asAttributeSet(r3);	 Catch:{ Exception -> 0x0082 }
    L_0x0070:
        r0 = r3.next();	 Catch:{ Exception -> 0x0082 }
        if (r0 == r8) goto L_0x0078;
    L_0x0076:
        if (r0 != r7) goto L_0x0070;
    L_0x0078:
        if (r0 == r8) goto L_0x0095;
    L_0x007a:
        r0 = new org.xmlpull.v1.XmlPullParserException;	 Catch:{ Exception -> 0x0082 }
        r2 = "No start tag found";
        r0.<init>(r2);	 Catch:{ Exception -> 0x0082 }
        throw r0;	 Catch:{ Exception -> 0x0082 }
    L_0x0082:
        r0 = move-exception;
        r2 = "AppCompatDrawableManager";
        r3 = "Exception while inflating drawable";
        android.util.Log.e(r2, r3, r0);
    L_0x008a:
        r0 = r1;
    L_0x008b:
        if (r0 != 0) goto L_0x002e;
    L_0x008d:
        r1 = r9.f1316l;
        r2 = "appcompat_skip_skip";
        r1.append(r11, r2);
        goto L_0x002e;
    L_0x0095:
        r0 = r3.getName();	 Catch:{ Exception -> 0x0082 }
        r7 = r9.f1316l;	 Catch:{ Exception -> 0x0082 }
        r7.append(r11, r0);	 Catch:{ Exception -> 0x0082 }
        r7 = r9.f1315k;	 Catch:{ Exception -> 0x0082 }
        r0 = r7.get(r0);	 Catch:{ Exception -> 0x0082 }
        r0 = (android.support.v7.widget.as) r0;	 Catch:{ Exception -> 0x0082 }
        if (r0 == 0) goto L_0x00b0;
    L_0x00a8:
        r7 = r10.getTheme();	 Catch:{ Exception -> 0x0082 }
        r1 = r0.m2523a(r10, r3, r6, r7);	 Catch:{ Exception -> 0x0082 }
    L_0x00b0:
        if (r1 == 0) goto L_0x00bd;
    L_0x00b2:
        r0 = r2.changingConfigurations;	 Catch:{ Exception -> 0x0082 }
        r1.setChangingConfigurations(r0);	 Catch:{ Exception -> 0x0082 }
        r0 = r9.m2504a(r10, r4, r1);	 Catch:{ Exception -> 0x0082 }
        if (r0 == 0) goto L_0x00bd;
    L_0x00bd:
        r0 = r1;
        goto L_0x008b;
    L_0x00bf:
        r0 = r1;
        goto L_0x002e;
        */
        throw new UnsupportedOperationException("Method not decompiled: android.support.v7.widget.ao.d(android.content.Context, int):android.graphics.drawable.Drawable");
    }

    private ColorStateList m2511e(Context context) {
        r0 = new int[3][];
        int[] iArr = new int[]{dc.f1504a, dc.m2704c(context, C0233b.colorControlNormal), dc.f1510g};
        iArr[1] = dc.m2700a(context, C0233b.colorControlNormal);
        r0[2] = dc.f1511h;
        iArr[2] = dc.m2700a(context, C0233b.colorControlActivated);
        return new ColorStateList(r0, iArr);
    }

    private ColorStateList m2512e(Context context, int i) {
        if (this.f1314j == null) {
            return null;
        }
        SparseArray sparseArray = (SparseArray) this.f1314j.get(context);
        return sparseArray != null ? (ColorStateList) sparseArray.get(i) : null;
    }

    private ColorStateList m2513f(Context context) {
        return m2514f(context, dc.m2700a(context, C0233b.colorButtonNormal));
    }

    private ColorStateList m2514f(Context context, int i) {
        r0 = new int[4][];
        r1 = new int[4];
        int a = dc.m2700a(context, C0233b.colorControlHighlight);
        r0[0] = dc.f1504a;
        r1[0] = dc.m2704c(context, C0233b.colorButtonNormal);
        r0[1] = dc.f1507d;
        r1[1] = C0088a.m565a(a, i);
        r0[2] = dc.f1505b;
        r1[2] = C0088a.m565a(a, i);
        r0[3] = dc.f1511h;
        r1[3] = i;
        return new ColorStateList(r0, r1);
    }

    private ColorStateList m2515g(Context context) {
        return m2514f(context, 0);
    }

    private ColorStateList m2516h(Context context) {
        return m2514f(context, dc.m2700a(context, C0233b.colorAccent));
    }

    private ColorStateList m2517i(Context context) {
        r0 = new int[3][];
        int[] iArr = new int[]{dc.f1504a, dc.m2704c(context, C0233b.colorControlNormal), dc.f1510g};
        iArr[1] = dc.m2700a(context, C0233b.colorControlNormal);
        r0[2] = dc.f1511h;
        iArr[2] = dc.m2700a(context, C0233b.colorControlActivated);
        return new ColorStateList(r0, iArr);
    }

    private ColorStateList m2518j(Context context) {
        r0 = new int[2][];
        int[] iArr = new int[]{dc.f1504a, dc.m2704c(context, C0233b.colorControlActivated)};
        r0[1] = dc.f1511h;
        iArr[1] = dc.m2700a(context, C0233b.colorControlActivated);
        return new ColorStateList(r0, iArr);
    }

    final Mode m2519a(int i) {
        return i == C0237f.abc_switch_thumb_material ? Mode.MULTIPLY : null;
    }

    public Drawable m2520a(Context context, int i) {
        return m2521a(context, i, false);
    }

    public Drawable m2521a(Context context, int i, boolean z) {
        Drawable d = m2510d(context, i);
        if (d == null) {
            d = m2508c(context, i);
        }
        if (d == null) {
            d = C0020a.m74a(context, i);
        }
        if (d != null) {
            d = m2495a(context, i, z, d);
        }
        if (d != null) {
            bt.m2633a(d);
        }
        return d;
    }

    public final ColorStateList m2522b(Context context, int i) {
        ColorStateList e = m2512e(context, i);
        if (e == null) {
            if (i == C0237f.abc_edit_text_material) {
                e = m2511e(context);
            } else if (i == C0237f.abc_switch_track_mtrl_alpha) {
                e = m2507c(context);
            } else if (i == C0237f.abc_switch_thumb_material) {
                e = m2509d(context);
            } else if (i == C0237f.abc_btn_default_mtrl_shape) {
                e = m2513f(context);
            } else if (i == C0237f.abc_btn_borderless_material) {
                e = m2515g(context);
            } else if (i == C0237f.abc_btn_colored_material) {
                e = m2516h(context);
            } else if (i == C0237f.abc_spinner_mtrl_am_alpha || i == C0237f.abc_spinner_textfield_background_material) {
                e = m2517i(context);
            } else if (m2505a(f1309e, i)) {
                e = dc.m2703b(context, C0233b.colorControlNormal);
            } else if (m2505a(f1312h, i)) {
                e = m2492a(context);
            } else if (m2505a(f1313i, i)) {
                e = m2506b(context);
            } else if (i == C0237f.abc_seekbar_thumb_material) {
                e = m2518j(context);
            }
            if (e != null) {
                m2498a(context, i, e);
            }
        }
        return e;
    }
}
