package android.support.v7.widget;

import android.graphics.PorterDuff.Mode;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.Drawable.ConstantState;
import android.graphics.drawable.DrawableContainer;
import android.graphics.drawable.DrawableContainer.DrawableContainerState;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.InsetDrawable;
import android.graphics.drawable.LayerDrawable;
import android.graphics.drawable.ScaleDrawable;
import android.graphics.drawable.StateListDrawable;
import android.os.Build.VERSION;
import android.support.v4.p006c.p007a.C0063q;
import android.support.v7.p015b.C0243l;
import android.support.v7.p016c.p017a.C0244a;

public class bt {
    public static final Rect f1420a;
    private static Class f1421b;

    static {
        f1420a = new Rect();
        if (VERSION.SDK_INT >= 18) {
            try {
                f1421b = Class.forName("android.graphics.Insets");
            } catch (ClassNotFoundException e) {
            }
        }
    }

    static Mode m2632a(int i, Mode mode) {
        switch (i) {
            case C0243l.View_paddingEnd /*3*/:
                return Mode.SRC_OVER;
            case C0243l.Toolbar_contentInsetStart /*5*/:
                return Mode.SRC_IN;
            case C0243l.Toolbar_popupTheme /*9*/:
                return Mode.SRC_ATOP;
            case C0243l.Toolbar_titleMarginEnd /*14*/:
                return Mode.MULTIPLY;
            case C0243l.Toolbar_titleMarginTop /*15*/:
                return Mode.SCREEN;
            case C0243l.Toolbar_titleMarginBottom /*16*/:
                return VERSION.SDK_INT >= 11 ? Mode.valueOf("ADD") : mode;
            default:
                return mode;
        }
    }

    static void m2633a(Drawable drawable) {
        if (VERSION.SDK_INT == 21 && "android.graphics.drawable.VectorDrawable".equals(drawable.getClass().getName())) {
            m2635c(drawable);
        }
    }

    public static boolean m2634b(Drawable drawable) {
        if (drawable instanceof LayerDrawable) {
            return VERSION.SDK_INT >= 16;
        } else if (drawable instanceof InsetDrawable) {
            return VERSION.SDK_INT >= 14;
        } else {
            if (drawable instanceof StateListDrawable) {
                return VERSION.SDK_INT >= 8;
            } else {
                if (drawable instanceof GradientDrawable) {
                    return VERSION.SDK_INT >= 14;
                } else {
                    if (!(drawable instanceof DrawableContainer)) {
                        return drawable instanceof C0063q ? m2634b(((C0063q) drawable).m469a()) : drawable instanceof C0244a ? m2634b(((C0244a) drawable).m1984a()) : drawable instanceof ScaleDrawable ? m2634b(((ScaleDrawable) drawable).getDrawable()) : true;
                    } else {
                        ConstantState constantState = drawable.getConstantState();
                        if (!(constantState instanceof DrawableContainerState)) {
                            return true;
                        }
                        for (Drawable b : ((DrawableContainerState) constantState).getChildren()) {
                            if (!m2634b(b)) {
                                return false;
                            }
                        }
                        return true;
                    }
                }
            }
        }
    }

    private static void m2635c(Drawable drawable) {
        int[] state = drawable.getState();
        if (state == null || state.length == 0) {
            drawable.setState(dc.f1508e);
        } else {
            drawable.setState(dc.f1511h);
        }
        drawable.setState(state);
    }
}
