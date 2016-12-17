package android.support.v7.p014a;

import android.content.Context;
import android.content.ContextWrapper;
import android.content.res.TypedArray;
import android.os.Build.VERSION;
import android.support.v4.p004h.bu;
import android.support.v4.p012g.C0107a;
import android.support.v7.p015b.C0243l;
import android.support.v7.view.C0249e;
import android.support.v7.widget.ai;
import android.support.v7.widget.ak;
import android.support.v7.widget.al;
import android.support.v7.widget.am;
import android.support.v7.widget.au;
import android.support.v7.widget.av;
import android.support.v7.widget.ax;
import android.support.v7.widget.ay;
import android.support.v7.widget.bc;
import android.support.v7.widget.bd;
import android.support.v7.widget.be;
import android.support.v7.widget.bg;
import android.support.v7.widget.bp;
import android.util.AttributeSet;
import android.util.Log;
import android.view.View;
import java.lang.reflect.Constructor;
import java.util.Map;

/* renamed from: android.support.v7.a.at */
class at {
    private static final Class[] f656a;
    private static final int[] f657b;
    private static final String[] f658c;
    private static final Map f659d;
    private final Object[] f660e;

    static {
        f656a = new Class[]{Context.class, AttributeSet.class};
        f657b = new int[]{16843375};
        f658c = new String[]{"android.widget.", "android.view.", "android.webkit."};
        f659d = new C0107a();
    }

    at() {
        this.f660e = new Object[2];
    }

    private static Context m1785a(Context context, AttributeSet attributeSet, boolean z, boolean z2) {
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, C0243l.View, 0, 0);
        int resourceId = z ? obtainStyledAttributes.getResourceId(C0243l.View_android_theme, 0) : 0;
        if (z2 && resourceId == 0) {
            resourceId = obtainStyledAttributes.getResourceId(C0243l.View_theme, 0);
            if (resourceId != 0) {
                Log.i("AppCompatViewInflater", "app:theme is now deprecated. Please move to using android:theme instead.");
            }
        }
        int i = resourceId;
        obtainStyledAttributes.recycle();
        return i != 0 ? ((context instanceof C0249e) && ((C0249e) context).m1998a() == i) ? context : new C0249e(context, i) : context;
    }

    private View m1786a(Context context, String str, AttributeSet attributeSet) {
        if (str.equals("view")) {
            str = attributeSet.getAttributeValue(null, "class");
        }
        try {
            this.f660e[0] = context;
            this.f660e[1] = attributeSet;
            View a;
            if (-1 == str.indexOf(46)) {
                for (String a2 : f658c) {
                    a = m1787a(context, str, a2);
                    if (a != null) {
                        return a;
                    }
                }
                this.f660e[0] = null;
                this.f660e[1] = null;
                return null;
            }
            a = m1787a(context, str, null);
            this.f660e[0] = null;
            this.f660e[1] = null;
            return a;
        } catch (Exception e) {
            return null;
        } finally {
            this.f660e[0] = null;
            this.f660e[1] = null;
        }
    }

    private View m1787a(Context context, String str, String str2) {
        Constructor constructor = (Constructor) f659d.get(str);
        if (constructor == null) {
            try {
                constructor = context.getClassLoader().loadClass(str2 != null ? str2 + str : str).asSubclass(View.class).getConstructor(f656a);
                f659d.put(str, constructor);
            } catch (Exception e) {
                return null;
            }
        }
        constructor.setAccessible(true);
        return (View) constructor.newInstance(this.f660e);
    }

    private void m1788a(View view, AttributeSet attributeSet) {
        Context context = view.getContext();
        if (!(context instanceof ContextWrapper)) {
            return;
        }
        if (VERSION.SDK_INT < 15 || bu.m1010s(view)) {
            TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, f657b);
            String string = obtainStyledAttributes.getString(0);
            if (string != null) {
                view.setOnClickListener(new au(view, string));
            }
            obtainStyledAttributes.recycle();
        }
    }

    public final View m1789a(View view, String str, Context context, AttributeSet attributeSet, boolean z, boolean z2, boolean z3) {
        Context context2 = (!z || view == null) ? context : view.getContext();
        if (z2 || z3) {
            context2 = at.m1785a(context2, attributeSet, z2, z3);
        }
        View view2 = null;
        Object obj = -1;
        switch (str.hashCode()) {
            case -1946472170:
                if (str.equals("RatingBar")) {
                    obj = 11;
                    break;
                }
                break;
            case -1455429095:
                if (str.equals("CheckedTextView")) {
                    obj = 8;
                    break;
                }
                break;
            case -1346021293:
                if (str.equals("MultiAutoCompleteTextView")) {
                    obj = 10;
                    break;
                }
                break;
            case -938935918:
                if (str.equals("TextView")) {
                    obj = null;
                    break;
                }
                break;
            case -937446323:
                if (str.equals("ImageButton")) {
                    obj = 5;
                    break;
                }
                break;
            case -658531749:
                if (str.equals("SeekBar")) {
                    obj = 12;
                    break;
                }
                break;
            case -339785223:
                if (str.equals("Spinner")) {
                    obj = 4;
                    break;
                }
                break;
            case 776382189:
                if (str.equals("RadioButton")) {
                    obj = 7;
                    break;
                }
                break;
            case 1125864064:
                if (str.equals("ImageView")) {
                    obj = 1;
                    break;
                }
                break;
            case 1413872058:
                if (str.equals("AutoCompleteTextView")) {
                    obj = 9;
                    break;
                }
                break;
            case 1601505219:
                if (str.equals("CheckBox")) {
                    obj = 6;
                    break;
                }
                break;
            case 1666676343:
                if (str.equals("EditText")) {
                    obj = 3;
                    break;
                }
                break;
            case 2001146706:
                if (str.equals("Button")) {
                    obj = 2;
                    break;
                }
                break;
        }
        switch (obj) {
            case C0243l.View_android_theme /*0*/:
                view2 = new bp(context2, attributeSet);
                break;
            case C0243l.View_android_focusable /*1*/:
                view2 = new ax(context2, attributeSet);
                break;
            case C0243l.View_paddingStart /*2*/:
                view2 = new ak(context2, attributeSet);
                break;
            case C0243l.View_paddingEnd /*3*/:
                view2 = new au(context2, attributeSet);
                break;
            case C0243l.View_theme /*4*/:
                view2 = new bg(context2, attributeSet);
                break;
            case C0243l.Toolbar_contentInsetStart /*5*/:
                view2 = new av(context2, attributeSet);
                break;
            case C0243l.Toolbar_contentInsetEnd /*6*/:
                view2 = new al(context2, attributeSet);
                break;
            case C0243l.Toolbar_contentInsetLeft /*7*/:
                view2 = new bc(context2, attributeSet);
                break;
            case C0243l.Toolbar_contentInsetRight /*8*/:
                view2 = new am(context2, attributeSet);
                break;
            case C0243l.Toolbar_popupTheme /*9*/:
                view2 = new ai(context2, attributeSet);
                break;
            case C0243l.Toolbar_titleTextAppearance /*10*/:
                view2 = new ay(context2, attributeSet);
                break;
            case C0243l.Toolbar_subtitleTextAppearance /*11*/:
                view2 = new bd(context2, attributeSet);
                break;
            case C0243l.Toolbar_titleMargins /*12*/:
                view2 = new be(context2, attributeSet);
                break;
        }
        View a = (view2 != null || context == context2) ? view2 : m1786a(context2, str, attributeSet);
        if (a != null) {
            m1788a(a, attributeSet);
        }
        return a;
    }
}
